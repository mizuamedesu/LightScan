/// Code injection framework
///
/// リモートプロセスへのコード注入・DLL注入・任意関数呼び出しを提供。
/// 既存の invoke_method_impl のパターンを汎用化したもの。

use super::{EngineError, Result};
use crate::platform::windows::{read_process_memory, write_process_memory};
use windows::core::PCSTR;
use windows::Win32::Foundation::HANDLE as WinHandle;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{CreateRemoteThread, WaitForSingleObject, INFINITE};

/// プロセスハンドルを WinHandle に変換
fn to_handle(process_handle: usize) -> WinHandle {
    unsafe { std::mem::transmute::<usize, WinHandle>(process_handle) }
}

/// リモートプロセスにメモリを確保
pub fn allocate_remote(process_handle: usize, size: usize, executable: bool) -> Result<usize> {
    let handle = to_handle(process_handle);
    let protect = if executable {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };

    let addr = unsafe {
        VirtualAllocEx(handle, None, size, MEM_COMMIT | MEM_RESERVE, protect)
    };

    if addr.is_null() {
        return Err(EngineError::MemoryError(format!(
            "Failed to allocate {} bytes in remote process",
            size
        )));
    }

    tracing::debug!("Allocated {} bytes at 0x{:X} (executable={})", size, addr as usize, executable);
    Ok(addr as usize)
}

/// リモートプロセスのメモリを解放
pub fn free_remote(process_handle: usize, addr: usize) -> Result<()> {
    let handle = to_handle(process_handle);
    unsafe {
        VirtualFreeEx(handle, addr as *mut _, 0, MEM_RELEASE)
            .map_err(|e| EngineError::MemoryError(format!("Failed to free remote memory at 0x{:X}: {}", addr, e)))?;
    }
    Ok(())
}

/// リモートプロセスにメモリを書き込む
pub fn write_remote(process_handle: usize, addr: usize, data: &[u8]) -> Result<()> {
    let handle = to_handle(process_handle);
    write_process_memory(handle, addr, data)
        .map_err(|e| EngineError::MemoryError(format!("Failed to write remote memory: {}", e)))
}

/// リモートプロセスからメモリを読み取る
pub fn read_remote(process_handle: usize, addr: usize, size: usize) -> Result<Vec<u8>> {
    let handle = to_handle(process_handle);
    read_process_memory(handle, addr, size)
        .map_err(|e| EngineError::MemoryError(format!("Failed to read remote memory: {}", e)))
}

/// シェルコードをリモートプロセスに注入して実行
///
/// 戻り値: スレッドの終了コード
pub fn inject_code(process_handle: usize, shellcode: &[u8]) -> Result<u32> {
    let handle = to_handle(process_handle);

    // シェルコード用メモリ確保
    let code_addr = allocate_remote(process_handle, shellcode.len(), true)?;

    // シェルコード書き込み
    if let Err(e) = write_remote(process_handle, code_addr, shellcode) {
        let _ = free_remote(process_handle, code_addr);
        return Err(e);
    }

    // リモートスレッドで実行
    let result = execute_remote_thread(handle, code_addr, 0);

    // クリーンアップ
    let _ = free_remote(process_handle, code_addr);

    result
}

/// DLL をリモートプロセスに注入
///
/// LoadLibraryW を使用して DLL をロードする。
/// kernel32.dll は全プロセスで同じベースアドレスにロードされる前提。
pub fn inject_dll(process_handle: usize, dll_path: &str) -> Result<()> {
    let handle = to_handle(process_handle);

    // DLL パスを UTF-16LE に変換（null 終端付き）
    let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let path_bytes: Vec<u8> = wide_path.iter().flat_map(|c| c.to_le_bytes()).collect();

    // リモートプロセスにパス文字列を書き込む
    let path_addr = allocate_remote(process_handle, path_bytes.len(), false)?;
    if let Err(e) = write_remote(process_handle, path_addr, &path_bytes) {
        let _ = free_remote(process_handle, path_addr);
        return Err(e);
    }

    // LoadLibraryW のアドレスを取得
    let load_library_addr = get_kernel32_proc_address("LoadLibraryW")?;

    // CreateRemoteThread で LoadLibraryW(path) を実行
    let result = execute_remote_thread(handle, load_library_addr, path_addr);

    // パス文字列を解放
    let _ = free_remote(process_handle, path_addr);

    match result {
        Ok(exit_code) => {
            if exit_code == 0 {
                tracing::warn!("LoadLibraryW returned NULL (DLL load may have failed)");
            } else {
                tracing::info!("DLL injected successfully: '{}' (module handle: 0x{:X})", dll_path, exit_code);
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// x64 呼び出し規約に従ってリモート関数を呼び出す
///
/// 最大 4 引数（RCX, RDX, R8, R9）。5 引数以上はスタック経由。
/// 戻り値は RAX の下位 64bit。
pub fn call_remote_function(
    process_handle: usize,
    func_addr: usize,
    args: &[u64],
) -> Result<u64> {
    let handle = to_handle(process_handle);

    // シェルコード生成
    let shellcode = generate_call_shellcode(func_addr, args);

    // シェルコード用メモリ確保
    let code_addr = allocate_remote(process_handle, shellcode.len(), true)?;

    // 戻り値格納用メモリ確保（8 バイト）
    let result_addr = allocate_remote(process_handle, 8, false)?;

    // 戻り値の書き込み先をシェルコードにパッチ
    let patched_shellcode = patch_result_addr(&shellcode, result_addr);

    // シェルコード書き込み
    if let Err(e) = write_remote(process_handle, code_addr, &patched_shellcode) {
        let _ = free_remote(process_handle, code_addr);
        let _ = free_remote(process_handle, result_addr);
        return Err(e);
    }

    // 実行
    let thread_result = execute_remote_thread(handle, code_addr, 0);

    // 戻り値を読み取る
    let return_value = read_remote(process_handle, result_addr, 8)
        .map(|data| u64::from_le_bytes(data[..8].try_into().unwrap()))
        .unwrap_or(0);

    // クリーンアップ
    let _ = free_remote(process_handle, code_addr);
    let _ = free_remote(process_handle, result_addr);

    // スレッド実行自体がエラーだった場合はエラーを返す
    thread_result?;

    Ok(return_value)
}

/// x64 関数呼び出し用シェルコードを生成
///
/// Windows x64 ABI: RCX, RDX, R8, R9 で最初の 4 引数、以降はスタック。
/// 32 バイトのシャドウスペースが必要。
fn generate_call_shellcode(func_addr: usize, args: &[u64]) -> Vec<u8> {
    let mut code = Vec::new();

    // スタック引数がある場合の追加スペースを計算
    let stack_args = if args.len() > 4 { args.len() - 4 } else { 0 };
    // シャドウスペース(32) + スタック引数 + 戻り値保存用の mov 命令スペース
    // 16バイトアラインメントを維持
    let stack_reserve = ((32 + stack_args * 8 + 15) / 16) * 16 + 8; // +8 for alignment after call

    // sub rsp, stack_reserve
    code.extend_from_slice(&[0x48, 0x81, 0xEC]);
    code.extend_from_slice(&(stack_reserve as u32).to_le_bytes());

    // スタック引数を設定（5番目以降、逆順）
    for i in (4..args.len()).rev() {
        let stack_offset = 32 + (i - 4) * 8;
        // mov qword [rsp + stack_offset], imm64
        // mov rax, imm64
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&args[i].to_le_bytes());
        // mov [rsp + offset], rax
        code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        code.extend_from_slice(&(stack_offset as u32).to_le_bytes());
    }

    // RCX = arg0
    if !args.is_empty() {
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&args[0].to_le_bytes());
    }

    // RDX = arg1
    if args.len() > 1 {
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&args[1].to_le_bytes());
    }

    // R8 = arg2
    if args.len() > 2 {
        code.extend_from_slice(&[0x49, 0xB8]);
        code.extend_from_slice(&args[2].to_le_bytes());
    }

    // R9 = arg3
    if args.len() > 3 {
        code.extend_from_slice(&[0x49, 0xB9]);
        code.extend_from_slice(&args[3].to_le_bytes());
    }

    // mov rax, func_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&func_addr.to_le_bytes());

    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);

    // 戻り値を保存: mov [result_addr], rax
    // プレースホルダーとして result_addr = 0 を使用（後でパッチする）
    // mov rcx, result_addr_placeholder
    code.extend_from_slice(&[0x48, 0xB9]);
    let result_placeholder_offset = code.len();
    code.extend_from_slice(&0u64.to_le_bytes()); // パッチ対象

    // mov [rcx], rax
    code.extend_from_slice(&[0x48, 0x89, 0x01]);

    // add rsp, stack_reserve
    code.extend_from_slice(&[0x48, 0x81, 0xC4]);
    code.extend_from_slice(&(stack_reserve as u32).to_le_bytes());

    // ret
    code.push(0xC3);

    // メタデータ: パッチオフセットを末尾に埋め込む（呼び出し側で使用）
    // 最後の 4 バイトはパッチオフセット
    code.extend_from_slice(&(result_placeholder_offset as u32).to_le_bytes());

    code
}

/// シェルコード内の result_addr プレースホルダーをパッチ
fn patch_result_addr(shellcode: &[u8], result_addr: usize) -> Vec<u8> {
    let mut patched = shellcode.to_vec();

    // 末尾 4 バイトからパッチオフセットを読み取る
    let len = patched.len();
    let patch_offset = u32::from_le_bytes(patched[len - 4..len].try_into().unwrap()) as usize;

    // パッチ適用
    patched[patch_offset..patch_offset + 8].copy_from_slice(&result_addr.to_le_bytes());

    // メタデータ（末尾 4 バイト）を除去
    patched.truncate(len - 4);

    patched
}

/// CreateRemoteThread でリモートコードを実行
fn execute_remote_thread(handle: WinHandle, start_addr: usize, param: usize) -> Result<u32> {
    let param_ptr = if param == 0 {
        None
    } else {
        Some(param as *const _)
    };

    let thread = unsafe {
        CreateRemoteThread(
            handle,
            None,
            0,
            Some(std::mem::transmute(start_addr)),
            param_ptr,
            0,
            None,
        )
    };

    match thread {
        Ok(thread_handle) => {
            unsafe {
                WaitForSingleObject(thread_handle, INFINITE);
            }

            // スレッドの終了コードを取得
            let mut exit_code = 0u32;
            unsafe {
                let _ = windows::Win32::System::Threading::GetExitCodeThread(
                    thread_handle,
                    &mut exit_code,
                );
                let _ = windows::Win32::Foundation::CloseHandle(thread_handle);
            }

            Ok(exit_code)
        }
        Err(e) => Err(EngineError::InvocationFailed(format!(
            "CreateRemoteThread failed: {}",
            e
        ))),
    }
}

/// kernel32.dll から関数のアドレスを取得
///
/// 注意: 現在のプロセスでのアドレスを返す。
/// kernel32.dll は ASLR により起動ごとにベースが変わるが、
/// 同一起動内では全プロセスで同じアドレスにロードされる。
fn get_kernel32_proc_address(proc_name: &str) -> Result<usize> {
    unsafe {
        let module = GetModuleHandleW(windows::core::w!("kernel32.dll"))
            .map_err(|e| EngineError::MemoryError(format!("Failed to get kernel32.dll handle: {}", e)))?;

        let name_cstring = std::ffi::CString::new(proc_name)
            .map_err(|_| EngineError::InvalidArgument("Invalid proc name".into()))?;

        let addr = GetProcAddress(module, PCSTR(name_cstring.as_ptr() as *const u8))
            .ok_or_else(|| EngineError::MemoryError(format!("Failed to find {}", proc_name)))?;

        Ok(addr as usize)
    }
}

/// 生のバイト列をリモートプロセスに書き込んで実行可能にする
/// ユーザーが自分でシェルコードを組み立てて注入する場合に使用
pub fn write_executable(process_handle: usize, data: &[u8]) -> Result<usize> {
    let addr = allocate_remote(process_handle, data.len(), true)?;
    write_remote(process_handle, addr, data)?;
    Ok(addr)
}

/// メモリパッチ: リモートプロセスの任意のアドレスにバイト列を書き込む
/// フック先関数の注入に使用可能
pub fn patch_memory(process_handle: usize, addr: usize, data: &[u8]) -> Result<Vec<u8>> {
    let handle = to_handle(process_handle);

    // 元のバイト列を保存
    let original = read_process_memory(handle, addr, data.len())
        .map_err(|e| EngineError::MemoryError(format!("Failed to read original bytes: {}", e)))?;

    // メモリ保護を変更
    let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    unsafe {
        windows::Win32::System::Memory::VirtualProtectEx(
            handle,
            addr as *const _,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ).map_err(|e| EngineError::MemoryError(format!("VirtualProtectEx failed: {}", e)))?;
    }

    // 書き込み
    write_process_memory(handle, addr, data)
        .map_err(|e| EngineError::MemoryError(format!("Failed to write patch: {}", e)))?;

    // メモリ保護を復元
    let mut dummy = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    unsafe {
        let _ = windows::Win32::System::Memory::VirtualProtectEx(
            handle,
            addr as *const _,
            data.len(),
            old_protect,
            &mut dummy,
        );
    }

    Ok(original)
}
