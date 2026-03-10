/// Inline hooking infrastructure for x64
///
/// 関数の先頭を JMP で書き換えてフック関数に飛ばし、
/// トランポリンで元の命令を実行してから元の関数に戻る仕組み。
///
/// 制限事項:
/// - 先頭 14 バイト内に RIP 相対命令がある場合、トランポリンが壊れる可能性がある
/// - 逆アセンブラによる命令境界検出は未実装（固定 14 バイト）

use super::{EngineError, Result};
use crate::platform::windows::{read_process_memory, write_process_memory};
use windows::Win32::Foundation::HANDLE as WinHandle;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

/// x64 absolute JMP: FF 25 00 00 00 00 [8-byte addr] = 14 bytes
const JMP_ABS_SIZE: usize = 14;

/// トランポリンのサイズ（元の命令 + JMP back）
const TRAMPOLINE_SIZE: usize = 64;

/// x64 absolute JMP のバイト列を生成
fn make_abs_jmp(target: usize) -> [u8; JMP_ABS_SIZE] {
    let mut buf = [0u8; JMP_ABS_SIZE];
    buf[0] = 0xFF; // JMP
    buf[1] = 0x25; // [RIP+0]
    // buf[2..6] は 0x00000000（RIP相対オフセット = 直後の8バイト）
    buf[6..14].copy_from_slice(&target.to_le_bytes());
    buf
}

/// 1つのインラインフックの状態
pub struct InlineHook {
    /// フック対象の元のアドレス
    pub original_addr: usize,
    /// トランポリンのアドレス（リモートプロセス内）
    pub trampoline_addr: usize,
    /// 保存された元のバイト列
    pub original_bytes: Vec<u8>,
    /// フック関数のアドレス
    pub hook_fn_addr: usize,
    /// フックが有効かどうか
    pub active: bool,
}

/// フック管理
pub struct HookManager {
    process_handle: usize,
    hooks: Vec<InlineHook>,
}

impl HookManager {
    pub fn new(process_handle: usize) -> Self {
        Self {
            process_handle,
            hooks: Vec::new(),
        }
    }

    /// プロセスハンドルを WinHandle に変換
    fn handle(&self) -> WinHandle {
        unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) }
    }

    /// インラインフックをインストール
    ///
    /// target_addr の先頭を JMP に書き換えて hook_fn_addr に飛ばす。
    /// 元の命令はトランポリン経由で実行可能。
    ///
    /// 戻り値: トランポリンのアドレス（元の関数を呼ぶ場合はこのアドレスを call する）
    pub fn install_hook(&mut self, target_addr: usize, hook_fn_addr: usize) -> Result<usize> {
        let handle = self.handle();

        // 既にフック済みかチェック
        if self.hooks.iter().any(|h| h.original_addr == target_addr && h.active) {
            return Err(EngineError::InvalidArgument(
                format!("Address 0x{:X} is already hooked", target_addr),
            ));
        }

        // 1. 元のバイト列を保存
        let original_bytes = read_process_memory(handle, target_addr, JMP_ABS_SIZE)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read original bytes at 0x{:X}: {}", target_addr, e)))?;

        // 2. トランポリンを確保
        let trampoline_addr = unsafe {
            VirtualAllocEx(
                handle,
                None,
                TRAMPOLINE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if trampoline_addr.is_null() {
            return Err(EngineError::MemoryError("Failed to allocate trampoline".into()));
        }
        let trampoline_addr = trampoline_addr as usize;

        // 3. トランポリンに書き込む: 元の命令 + JMP back
        let jmp_back = make_abs_jmp(target_addr + JMP_ABS_SIZE);
        let mut trampoline_code = Vec::with_capacity(JMP_ABS_SIZE + JMP_ABS_SIZE);
        trampoline_code.extend_from_slice(&original_bytes);
        trampoline_code.extend_from_slice(&jmp_back);

        write_process_memory(handle, trampoline_addr, &trampoline_code)
            .map_err(|e| EngineError::MemoryError(format!("Failed to write trampoline: {}", e)))?;

        // 4. ターゲットのメモリ保護を変更
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtectEx(
                handle,
                target_addr as *const _,
                JMP_ABS_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ).map_err(|e| EngineError::MemoryError(format!("VirtualProtectEx failed: {}", e)))?;
        }

        // 5. ターゲットに JMP を書き込む
        let jmp_to_hook = make_abs_jmp(hook_fn_addr);
        write_process_memory(handle, target_addr, &jmp_to_hook)
            .map_err(|e| EngineError::MemoryError(format!("Failed to write hook JMP: {}", e)))?;

        // 6. メモリ保護を元に戻す
        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            let _ = VirtualProtectEx(
                handle,
                target_addr as *const _,
                JMP_ABS_SIZE,
                old_protect,
                &mut dummy,
            );
        }

        tracing::info!(
            "Installed hook: 0x{:X} -> 0x{:X} (trampoline at 0x{:X})",
            target_addr, hook_fn_addr, trampoline_addr
        );

        self.hooks.push(InlineHook {
            original_addr: target_addr,
            trampoline_addr,
            original_bytes,
            hook_fn_addr,
            active: true,
        });

        Ok(trampoline_addr)
    }

    /// フックを解除して元のバイト列を復元
    pub fn remove_hook(&mut self, target_addr: usize) -> Result<()> {
        let handle = self.handle();

        let hook = self.hooks.iter_mut()
            .find(|h| h.original_addr == target_addr && h.active)
            .ok_or_else(|| EngineError::InvalidArgument(
                format!("No active hook found at 0x{:X}", target_addr),
            ))?;

        // メモリ保護を変更
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtectEx(
                handle,
                target_addr as *const _,
                JMP_ABS_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ).map_err(|e| EngineError::MemoryError(format!("VirtualProtectEx failed: {}", e)))?;
        }

        // 元のバイト列を復元
        write_process_memory(handle, target_addr, &hook.original_bytes)
            .map_err(|e| EngineError::MemoryError(format!("Failed to restore original bytes: {}", e)))?;

        // メモリ保護を元に戻す
        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            let _ = VirtualProtectEx(
                handle,
                target_addr as *const _,
                JMP_ABS_SIZE,
                old_protect,
                &mut dummy,
            );
        }

        // トランポリンを解放
        unsafe {
            let _ = VirtualFreeEx(
                handle,
                hook.trampoline_addr as *mut _,
                0,
                MEM_RELEASE,
            );
        }

        hook.active = false;
        tracing::info!("Removed hook at 0x{:X}", target_addr);

        Ok(())
    }

    /// すべてのフックを解除
    pub fn remove_all(&mut self) -> Result<()> {
        let addrs: Vec<usize> = self.hooks.iter()
            .filter(|h| h.active)
            .map(|h| h.original_addr)
            .collect();

        for addr in addrs {
            if let Err(e) = self.remove_hook(addr) {
                tracing::warn!("Failed to remove hook at 0x{:X}: {}", addr, e);
            }
        }

        Ok(())
    }

    /// アクティブなフックの一覧を取得
    pub fn list_hooks(&self) -> Vec<&InlineHook> {
        self.hooks.iter().filter(|h| h.active).collect()
    }

    /// 指定アドレスのトランポリンアドレスを取得
    /// （フック関数から元の関数を呼びたい場合に使用）
    pub fn get_trampoline(&self, target_addr: usize) -> Option<usize> {
        self.hooks.iter()
            .find(|h| h.original_addr == target_addr && h.active)
            .map(|h| h.trampoline_addr)
    }
}

impl Drop for HookManager {
    fn drop(&mut self) {
        if let Err(e) = self.remove_all() {
            tracing::error!("Failed to cleanup hooks on drop: {}", e);
        }
    }
}
