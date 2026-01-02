/// Method enumeration and invocation

use super::structures::{UObject, UStruct};
use super::{EngineError, Result, UnrealEngine};
use crate::engine::types::*;
use crate::platform::windows::{read_process_memory, write_process_memory};
use windows::Win32::Foundation::HANDLE as WinHandle;
use windows::Win32::System::Threading::{
    CreateRemoteThread, WaitForSingleObject, INFINITE,
};
use windows::Win32::System::Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

impl UnrealEngine {
    /// UClass から情報を取得
    pub(super) fn get_class_info_impl(&self, class_addr: usize) -> Result<ClassInfo> {
        // デバッグ: 最初の数回だけログ出力
        static CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let should_log = count < 5;

        let name = match self.get_object_name_impl(class_addr) {
            Ok(n) => n,
            Err(e) => {
                if should_log {
                    tracing::warn!("get_class_info_impl: get_object_name failed for 0x{:X}: {}", class_addr, e);
                }
                return Err(e);
            }
        };

        if should_log {
            tracing::info!("get_class_info_impl: class at 0x{:X} has name '{}'", class_addr, name);
        }

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let ustruct = match UStruct::read(handle, class_addr) {
            Ok(u) => u,
            Err(e) => {
                if should_log {
                    tracing::warn!("get_class_info_impl: UStruct::read failed for 0x{:X}: {}", class_addr, e);
                }
                return Err(EngineError::InitializationFailed(format!("UStruct read failed: {}", e)));
            }
        };

        Ok(ClassInfo {
            name,
            handle: ClassHandle(class_addr),
            parent: if ustruct.super_struct != 0 {
                Some(ClassHandle(ustruct.super_struct))
            } else {
                None
            },
            size: ustruct.properties_size as usize,
        })
    }

    /// すべてのクラスを列挙
    ///
    /// UClass の検出ロジック:
    /// - UClass インスタンス: Class->Class == Class (自己参照)
    /// - BlueprintGeneratedClass インスタンス: Class->Class == UClass
    /// - WidgetBlueprintGeneratedClass インスタンス: Class->Class->Class == UClass
    ///
    /// つまり、Class ポインタを辿って最終的に自己参照するものが「クラス」
    pub(super) fn enumerate_classes_impl(&self) -> Result<Vec<ClassInfo>> {
        let all_objects = self.get_all_objects_impl()?;
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        tracing::info!("enumerate_classes_impl: checking {} objects", all_objects.len());

        let mut classes = Vec::new();
        let mut valid_obj_count = 0;
        let mut has_class_count = 0;
        let mut is_class_count = 0;
        let mut bp_class_count = 0;

        // Debug: show first few objects
        for (i, &obj_addr) in all_objects.iter().take(5).enumerate() {
            if let Ok(obj) = UObject::read(handle, obj_addr) {
                tracing::info!("  Object[{}] at 0x{:X}: vtable=0x{:X}, class=0x{:X}, name_idx={}, outer=0x{:X}",
                    i, obj_addr, obj.vtable, obj.class, obj.name.comparison_index, obj.outer);
            } else {
                tracing::warn!("  Object[{}] at 0x{:X}: failed to read", i, obj_addr);
            }
        }

        for obj_addr in &all_objects {
            if let Ok(obj) = UObject::read(handle, *obj_addr) {
                valid_obj_count += 1;
                if obj.class == 0 {
                    continue;
                }
                has_class_count += 1;

                // このオブジェクトが「クラス」かどうかを判定
                // クラスとは: UClass またはその派生 (BlueprintGeneratedClass など) のインスタンス
                //
                // 判定方法: Class ポインタを最大 3 回辿って自己参照に到達するか
                // - UClass: Class->Class == Class (1回で自己参照)
                // - BlueprintGeneratedClass: Class->Class->Class == Class->Class (2回で自己参照)

                let mut is_class_type = false;
                let mut current = obj.class;
                let mut visited = vec![current];

                for _ in 0..3 {
                    if let Ok(current_obj) = UObject::read(handle, current) {
                        if current_obj.class == current {
                            // 自己参照に到達 = これは UClass (またはそのメタクラス)
                            is_class_type = true;
                            break;
                        }
                        if visited.contains(&current_obj.class) {
                            // ループ検出 - 自己参照ではないが循環
                            break;
                        }
                        visited.push(current_obj.class);
                        current = current_obj.class;
                    } else {
                        break;
                    }
                }

                if is_class_type {
                    is_class_count += 1;

                    // Blueprint クラスかどうかチェック (Class->Class != Class の場合)
                    if let Ok(class_meta) = UObject::read(handle, obj.class) {
                        if class_meta.class != obj.class {
                            bp_class_count += 1;
                        }
                    }

                    if let Ok(info) = self.get_class_info_impl(*obj_addr) {
                        classes.push(info);
                    }
                }
            }
        }

        tracing::info!("enumerate_classes_impl stats: valid_obj={}, has_class={}, is_class={} (bp={}), final={}",
            valid_obj_count, has_class_count, is_class_count, bp_class_count, classes.len());

        Ok(classes)
    }

    /// UClass から UFunction を検索
    pub(super) fn find_method_impl(&self, class_addr: usize, method_name: &str) -> Result<usize> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let ustruct = UStruct::read(handle, class_addr)?;
        let mut current_field = ustruct.children;

        // Children リンクリストを辿る
        while current_field != 0 {
            if let Ok(field_name) = self.get_object_name_impl(current_field) {
                if field_name == method_name {
                    return Ok(current_field);
                }
            }

            // Next フィールドを読む (UField の offset)
            let next_data = read_process_memory(
                handle,
                current_field + std::mem::size_of::<UObject>(),
                8,
            )?;
            current_field = usize::from_le_bytes(next_data[..8].try_into().unwrap());
        }

        Err(EngineError::MethodNotFound(method_name.to_string()))
    }

    /// UFunction から情報を取得
    pub(super) fn get_method_info_impl(&self, method_addr: usize) -> Result<MethodInfo> {
        let name = self.get_object_name_impl(method_addr)?;

        // TODO: パラメータ情報を読み取る

        Ok(MethodInfo {
            name,
            handle: MethodHandle(method_addr),
            params: Vec::new(),
            return_type: None,
            is_static: false,
        })
    }

    /// UClass のすべてのメソッドを列挙
    pub(super) fn enumerate_methods_impl(&self, class_addr: usize) -> Result<Vec<MethodInfo>> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let ustruct = UStruct::read(handle, class_addr)?;
        let mut current_field = ustruct.children;
        let mut methods = Vec::new();

        while current_field != 0 {
            // UFunction かどうかをチェック（簡易版: 名前が取得できればメソッド候補）
            if let Ok(info) = self.get_method_info_impl(current_field) {
                methods.push(info);
            }

            let next_data = read_process_memory(
                handle,
                current_field + std::mem::size_of::<UObject>(),
                8,
            )?;
            current_field = usize::from_le_bytes(next_data[..8].try_into().unwrap());
        }

        Ok(methods)
    }

    /// ProcessEvent を呼び出してメソッドを実行
    pub(super) fn invoke_method_impl(
        &self,
        instance_addr: usize,
        method_addr: usize,
        _args: &[Value],
    ) -> Result<Value> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // パラメータ構造体を確保
        let params_size = 0x100; // 仮のサイズ
        let params_addr = unsafe {
            VirtualAllocEx(
                handle,
                None,
                params_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if params_addr.is_null() {
            return Err(EngineError::InvocationFailed(
                "Failed to allocate memory".into(),
            ));
        }

        // TODO: args を params に書き込む

        // シェルコードを生成して ProcessEvent を呼び出す
        // ProcessEvent(UObject* Context, UFunction* Function, void* Params)
        let shellcode = self.generate_process_event_shellcode(
            instance_addr,
            method_addr,
            params_addr as usize,
        )?;

        let shellcode_addr = unsafe {
            VirtualAllocEx(
                handle,
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if shellcode_addr.is_null() {
            unsafe {
                VirtualFreeEx(handle, params_addr, 0, MEM_RELEASE);
            }
            return Err(EngineError::InvocationFailed(
                "Failed to allocate shellcode".into(),
            ));
        }

        // シェルコードを書き込み
        write_process_memory(handle, shellcode_addr as usize, &shellcode)?;

        // リモートスレッドを作成して実行
        let thread = unsafe {
            CreateRemoteThread(
                handle,
                None,
                0,
                Some(std::mem::transmute(shellcode_addr)),
                None,
                0,
                None,
            )
        };

        if let Ok(thread_handle) = thread {
            unsafe {
                WaitForSingleObject(thread_handle, INFINITE);
            }

            // TODO: 戻り値を読み取る

            // クリーンアップ
            unsafe {
                VirtualFreeEx(handle, params_addr, 0, MEM_RELEASE);
                VirtualFreeEx(handle, shellcode_addr, 0, MEM_RELEASE);
            }

            Ok(Value::Null)
        } else {
            unsafe {
                VirtualFreeEx(handle, params_addr, 0, MEM_RELEASE);
                VirtualFreeEx(handle, shellcode_addr, 0, MEM_RELEASE);
            }
            Err(EngineError::InvocationFailed(
                "Failed to create remote thread".into(),
            ))
        }
    }

    /// ProcessEvent 呼び出し用のシェルコードを生成
    fn generate_process_event_shellcode(
        &self,
        instance: usize,
        function: usize,
        params: usize,
    ) -> Result<Vec<u8>> {
        // x64 calling convention (RCX, RDX, R8, R9)
        // ProcessEvent(this=instance, function, params)

        let mut code = Vec::new();

        // sub rsp, 0x28 (shadow space)
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // mov rcx, instance
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&instance.to_le_bytes());

        // mov rdx, function
        code.extend_from_slice(&[0x48, 0xBA]);
        code.extend_from_slice(&function.to_le_bytes());

        // mov r8, params
        code.extend_from_slice(&[0x49, 0xB8]);
        code.extend_from_slice(&params.to_le_bytes());

        // mov rax, ProcessEvent
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&self.process_event.to_le_bytes());

        // call rax
        code.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x28
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        // ret
        code.push(0xC3);

        Ok(code)
    }

    /// フィールドを読み取る
    pub(super) fn read_field_impl(
        &self,
        instance_addr: usize,
        field_offset: usize,
        field_type: &TypeInfo,
    ) -> Result<Value> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let addr = instance_addr + field_offset;

        match &field_type.kind {
            TypeKind::Primitive(prim) => {
                let data = read_process_memory(handle, addr, prim.size())?;
                match prim {
                    PrimitiveType::Bool => Ok(Value::Bool(data[0] != 0)),
                    PrimitiveType::I32 => Ok(Value::I32(i32::from_le_bytes(
                        data[..4].try_into().unwrap(),
                    ))),
                    PrimitiveType::I64 => Ok(Value::I64(i64::from_le_bytes(
                        data[..8].try_into().unwrap(),
                    ))),
                    PrimitiveType::F32 => Ok(Value::F32(f32::from_le_bytes(
                        data[..4].try_into().unwrap(),
                    ))),
                    PrimitiveType::F64 => Ok(Value::F64(f64::from_le_bytes(
                        data[..8].try_into().unwrap(),
                    ))),
                    _ => Ok(Value::Struct(data)),
                }
            }
            _ => {
                let data = read_process_memory(handle, addr, field_type.size)?;
                Ok(Value::Struct(data))
            }
        }
    }

    /// フィールドを書き込む
    pub(super) fn write_field_impl(
        &self,
        instance_addr: usize,
        field_offset: usize,
        value: &Value,
    ) -> Result<()> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let addr = instance_addr + field_offset;

        let data = match value {
            Value::Bool(v) => vec![if *v { 1u8 } else { 0u8 }],
            Value::I32(v) => v.to_le_bytes().to_vec(),
            Value::I64(v) => v.to_le_bytes().to_vec(),
            Value::F32(v) => v.to_le_bytes().to_vec(),
            Value::F64(v) => v.to_le_bytes().to_vec(),
            Value::Struct(v) => v.clone(),
            _ => {
                return Err(EngineError::TypeMismatch {
                    expected: "primitive or struct".into(),
                    got: format!("{:?}", value),
                })
            }
        };

        write_process_memory(handle, addr, &data)?;
        Ok(())
    }
}
