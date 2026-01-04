/// Method enumeration and invocation

use super::structures::{FField, FFieldClass, UObject, UStruct};
use super::{EngineError, Result, UnrealEngine};
use crate::engine::types::{
    ClassHandle, ClassInfo, FieldHandle, FieldInfo, InstanceHandle, MethodHandle, MethodInfo,
    ParamInfo, PrimitiveType, TypeInfo, TypeKind, Value,
};
use crate::platform::windows::{read_process_memory, write_process_memory};
use windows::Win32::Foundation::HANDLE as WinHandle;
use windows::Win32::System::Threading::{
    CreateRemoteThread, WaitForSingleObject, INFINITE,
};
use windows::Win32::System::Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

impl UnrealEngine {
    /// UClass から情報を取得
    pub(super) fn get_class_info_impl(&self, class_addr: usize) -> Result<ClassInfo> {
        let name = self.get_object_name_impl(class_addr)?;
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };
        let ustruct = UStruct::read(handle, class_addr)
            .map_err(|e| EngineError::InitializationFailed(format!("UStruct read failed: {}", e)))?;

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

        tracing::info!("enumerate_classes_impl: scanning {} objects", all_objects.len());

        let mut classes = Vec::new();
        let mut class_type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for obj_addr in &all_objects {
            if let Ok(obj) = UObject::read(handle, *obj_addr) {
                if obj.class == 0 {
                    continue;
                }

                // このオブジェクトが「クラス」かどうかを判定
                // クラスとは: UClass またはその派生 (BlueprintGeneratedClass など) のインスタンス
                //
                // 判定方法: Class ポインタを最大 3 回辿って自己参照に到達するか
                // - UClass: Class->Class == Class (1回で自己参照)
                // - BlueprintGeneratedClass: Class->Class->Class == Class->Class (2回で自己参照)

                let mut is_class_type = false;
                let mut current = obj.class;
                let mut visited = vec![current];
                let mut hops = 0;

                for _ in 0..3 {
                    if let Ok(current_obj) = UObject::read(handle, current) {
                        hops += 1;
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
                    if let Ok(info) = self.get_class_info_impl(*obj_addr) {
                        // クラスタイプ（Class名）を取得して統計
                        if let Ok(class_type_name) = self.get_object_name_impl(obj.class) {
                            *class_type_counts.entry(class_type_name).or_insert(0) += 1;
                        }
                        classes.push(info);
                    }
                }
            }
        }

        // クラスタイプの統計をログ
        let mut sorted_counts: Vec<_> = class_type_counts.into_iter().collect();
        sorted_counts.sort_by(|a, b| b.1.cmp(&a.1));
        tracing::info!("enumerate_classes_impl: found {} classes", classes.len());
        tracing::info!("enumerate_classes_impl: class type breakdown:");
        for (type_name, count) in sorted_counts.iter().take(10) {
            tracing::info!("  {}: {} instances", type_name, count);
        }

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
        let handle_win = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // UFunction のパラメータ情報を読み取る
        // UFunction は UStruct を継承しているので、ChildProperties からパラメータを取得
        let ustruct = UStruct::read(handle_win, method_addr)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read UFunction struct: {}", e)))?;

        let mut params = Vec::new();
        let mut return_type = None;
        let mut current_prop = ustruct.child_properties;

        // デバッグログ（メソッド情報用のカウンタ）
        static METHOD_LOG_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let should_log = METHOD_LOG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 20;
        if should_log {
            tracing::info!(
                "get_method_info_impl: method='{}' addr=0x{:X} child_properties=0x{:X} super=0x{:X} children=0x{:X}",
                name, method_addr, current_prop, ustruct.super_struct, ustruct.children
            );
        }

        // FProperty リンクリストを辿る
        let mut count = 0;
        let mut param_count = 0;
        while current_prop != 0 && count < 100 {
            count += 1;

            if let Ok(field) = FField::read(handle_win, current_prop) {
                if let Ok(prop_name) = self.get_fname_impl(field.name.comparison_index) {
                    param_count += 1;
                    if should_log {
                        tracing::info!(
                            "  param {}: '{}' class_private=0x{:X} next=0x{:X}",
                            param_count, prop_name, field.class_private, field.next
                        );
                    }
                    // CPF_ReturnParm (0x0400) フラグをチェック
                    // FProperty::PropertyFlags は FField の後に続く
                    // FField(48バイト) + ArrayDim(4) + ElementSize(4) + PropertyFlags(8) = offset 56
                    let prop_flags_offset = 48usize + 4 + 4; // FField + ArrayDim + ElementSize
                    let is_return_param = if let Ok(flags_data) = read_process_memory(handle_win, current_prop + prop_flags_offset, 8) {
                        let prop_flags = u64::from_le_bytes(flags_data[..8].try_into().unwrap());
                        (prop_flags & 0x0400) != 0 // CPF_ReturnParm
                    } else {
                        false
                    };

                    // FFieldClass から実際の型情報を取得
                    let type_info = self.get_property_type_info(handle_win, current_prop, &field);

                    if is_return_param {
                        return_type = Some(type_info);
                    } else {
                        params.push(ParamInfo {
                            name: prop_name,
                            type_info,
                        });
                    }
                }
                current_prop = field.next;
            } else {
                break;
            }
        }

        if should_log {
            tracing::info!("  total params: {}, return_type: {:?}", params.len(), return_type.as_ref().map(|t| &t.name));
        }

        // FUNC_Static (0x00000002) フラグをチェック
        // UFunction::FunctionFlags のオフセットを試す
        let function_flags_offsets = [0x88usize, 0x90, 0x98, 0xA0, 0xB0];
        let mut is_static = false;
        for &offset in &function_flags_offsets {
            if let Ok(data) = read_process_memory(handle_win, method_addr + offset, 4) {
                let flags = u32::from_le_bytes(data[..4].try_into().unwrap());
                if flags != 0 && flags < 0x80000000 {
                    is_static = (flags & 0x00000002) != 0; // FUNC_Static
                    break;
                }
            }
        }

        Ok(MethodInfo {
            name,
            handle: MethodHandle(method_addr),
            params,
            return_type,
            is_static,
        })
    }

    /// FFieldClass から実際の型情報を取得
    fn get_property_type_info(&self, handle: WinHandle, prop_addr: usize, field: &FField) -> TypeInfo {
        // FFieldClass から型名を取得
        let type_class_name = if field.class_private != 0 {
            FFieldClass::read_type_name(handle, field.class_private, |idx| {
                self.get_fname_impl(idx).map_err(|e| anyhow::anyhow!("{}", e))
            })
            .unwrap_or_else(|_| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // FProperty::ElementSize を読み取る (FField(48) + ArrayDim(4) の後)
        let element_size_offset = 48usize + 4;
        let element_size = if let Ok(data) = read_process_memory(handle, prop_addr + element_size_offset, 4) {
            i32::from_le_bytes(data[..4].try_into().unwrap()) as usize
        } else {
            0
        };

        // 型クラス名から TypeInfo を生成
        self.property_class_to_type_info(&type_class_name, element_size)
    }

    /// プロパティクラス名から TypeInfo を生成
    fn property_class_to_type_info(&self, class_name: &str, element_size: usize) -> TypeInfo {
        // UE のプロパティクラス名から型を判定
        let (type_name, size, kind) = match class_name {
            // 整数型
            "Int8Property" => ("int8", 1, TypeKind::Primitive(PrimitiveType::I8)),
            "Int16Property" => ("int16", 2, TypeKind::Primitive(PrimitiveType::I16)),
            "IntProperty" | "Int32Property" => ("int32", 4, TypeKind::Primitive(PrimitiveType::I32)),
            "Int64Property" => ("int64", 8, TypeKind::Primitive(PrimitiveType::I64)),

            // 符号なし整数
            "ByteProperty" | "UInt8Property" => ("uint8", 1, TypeKind::Primitive(PrimitiveType::U8)),
            "UInt16Property" => ("uint16", 2, TypeKind::Primitive(PrimitiveType::U16)),
            "UInt32Property" => ("uint32", 4, TypeKind::Primitive(PrimitiveType::U32)),
            "UInt64Property" => ("uint64", 8, TypeKind::Primitive(PrimitiveType::U64)),

            // 浮動小数点
            "FloatProperty" => ("float", 4, TypeKind::Primitive(PrimitiveType::F32)),
            "DoubleProperty" => ("double", 8, TypeKind::Primitive(PrimitiveType::F64)),

            // ブール
            "BoolProperty" => ("bool", 1, TypeKind::Primitive(PrimitiveType::Bool)),

            // 文字列系
            "StrProperty" => ("FString", 16, TypeKind::Unknown),
            "NameProperty" => ("FName", 8, TypeKind::Unknown),
            "TextProperty" => ("FText", 24, TypeKind::Unknown),

            // オブジェクト参照
            "ObjectProperty" | "ObjectPtrProperty" => ("UObject*", 8, TypeKind::Pointer(Box::new(TypeInfo {
                name: "UObject".to_string(),
                size: 8,
                kind: TypeKind::Unknown,
            }))),
            "ClassProperty" | "ClassPtrProperty" => ("UClass*", 8, TypeKind::Pointer(Box::new(TypeInfo {
                name: "UClass".to_string(),
                size: 8,
                kind: TypeKind::Unknown,
            }))),
            "SoftObjectProperty" => ("TSoftObjectPtr", 24, TypeKind::Unknown),
            "WeakObjectProperty" => ("TWeakObjectPtr", 8, TypeKind::Unknown),
            "LazyObjectProperty" => ("TLazyObjectPtr", 8, TypeKind::Unknown),
            "InterfaceProperty" => ("TScriptInterface", 16, TypeKind::Unknown),

            // 構造体
            "StructProperty" => ("struct", element_size.max(1), TypeKind::Unknown),

            // 配列
            "ArrayProperty" => ("TArray", 16, TypeKind::Unknown),
            "SetProperty" => ("TSet", 80, TypeKind::Unknown),
            "MapProperty" => ("TMap", 80, TypeKind::Unknown),

            // Enum
            "EnumProperty" => ("enum", element_size.max(1), TypeKind::Primitive(PrimitiveType::U8)),

            // デリゲート
            "DelegateProperty" => ("FDelegate", 16, TypeKind::Unknown),
            "MulticastDelegateProperty" | "MulticastInlineDelegateProperty" | "MulticastSparseDelegateProperty" =>
                ("FMulticastDelegate", 16, TypeKind::Unknown),

            // ベクトル/変換系
            name if name.contains("Vector") => ("FVector", 12, TypeKind::Unknown),
            name if name.contains("Rotator") => ("FRotator", 12, TypeKind::Unknown),
            name if name.contains("Transform") => ("FTransform", 48, TypeKind::Unknown),
            name if name.contains("Quat") => ("FQuat", 16, TypeKind::Unknown),

            // 不明
            _ => (class_name, element_size.max(8), TypeKind::Unknown),
        };

        TypeInfo {
            name: type_name.to_string(),
            size,
            kind,
        }
    }

    /// UClass のすべてのメソッドを列挙
    /// UE5.5: Children は TObjectPtr<UField> で、UFunction (UObject派生) のリンクリスト
    pub(super) fn enumerate_methods_impl(&self, class_addr: usize) -> Result<Vec<MethodInfo>> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // デバッグ: クラスのメモリをダンプして正しいオフセットを見つける
        static DEBUG_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = DEBUG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count < 3 {
            if let Ok(raw_data) = read_process_memory(handle, class_addr, 160) {
                tracing::info!("enumerate_methods_impl: raw class data at 0x{:X}:", class_addr);
                for i in 0..20 {
                    let offset = i * 8;
                    let val = usize::from_le_bytes(raw_data[offset..offset+8].try_into().unwrap());
                    tracing::info!("  [+{:3}] 0x{:02X}: 0x{:016X}", offset, offset, val);
                }
            }
        }

        let ustruct = UStruct::read(handle, class_addr)?;
        let mut current_field = ustruct.children;
        let mut methods = Vec::new();

        tracing::info!("enumerate_methods_impl: class 0x{:X}, children=0x{:X}, child_properties=0x{:X}",
            class_addr, ustruct.children, ustruct.child_properties);

        let mut count = 0;
        while current_field != 0 && count < 1000 {
            count += 1;

            // UFunction かどうかをチェック（簡易版: 名前が取得できればメソッド候補）
            if let Ok(info) = self.get_method_info_impl(current_field) {
                methods.push(info);
            }

            // UField::Next は UObject の直後 (offset 40)
            // UObject = vtable(8) + flags(4) + index(4) + class(8) + name(8) + outer(8) = 40 bytes
            let next_offset = 40usize; // UObject size
            match read_process_memory(handle, current_field + next_offset, 8) {
                Ok(next_data) => {
                    current_field = usize::from_le_bytes(next_data[..8].try_into().unwrap());
                }
                Err(_) => break,
            }
        }

        tracing::info!("enumerate_methods_impl: found {} methods", methods.len());
        Ok(methods)
    }

    /// ProcessEvent を呼び出してメソッドを実行
    pub(super) fn invoke_method_impl(
        &self,
        instance_addr: usize,
        method_addr: usize,
        args: &[Value],
    ) -> Result<Value> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // UFunction からパラメータ情報を取得
        let method_info = self.get_method_info_impl(method_addr)?;

        // UFunction の ParamsSize を読み取る
        // UStruct を継承しているので PropertiesSize がパラメータ構造体のサイズ
        let ustruct = UStruct::read(handle, method_addr)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read UFunction: {}", e)))?;

        let params_size = if ustruct.properties_size > 0 {
            ustruct.properties_size as usize
        } else {
            0x100 // フォールバック
        };

        // パラメータ構造体を確保
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

        // 引数を params に書き込む
        if let Err(e) = self.write_args_to_params(handle, params_addr as usize, method_addr, args) {
            unsafe {
                VirtualFreeEx(handle, params_addr, 0, MEM_RELEASE);
            }
            return Err(e);
        }

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

            // 戻り値を読み取る
            let return_value = self.read_return_value(handle, params_addr as usize, method_addr, &method_info)?;

            // クリーンアップ
            unsafe {
                VirtualFreeEx(handle, params_addr, 0, MEM_RELEASE);
                VirtualFreeEx(handle, shellcode_addr, 0, MEM_RELEASE);
            }

            Ok(return_value)
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

    /// 引数をパラメータ構造体に書き込む
    fn write_args_to_params(
        &self,
        handle: WinHandle,
        params_addr: usize,
        method_addr: usize,
        args: &[Value],
    ) -> Result<()> {
        // UFunction の ChildProperties からパラメータプロパティを取得
        let ustruct = UStruct::read(handle, method_addr)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read UFunction: {}", e)))?;

        let mut current_prop = ustruct.child_properties;
        let mut arg_index = 0;

        while current_prop != 0 && arg_index < args.len() {
            if let Ok(field) = FField::read(handle, current_prop) {
                // CPF_ReturnParm (0x0400) をスキップ
                let prop_flags_offset = 48usize + 4 + 4;
                let is_return = if let Ok(flags_data) = read_process_memory(handle, current_prop + prop_flags_offset, 8) {
                    let prop_flags = u64::from_le_bytes(flags_data[..8].try_into().unwrap());
                    (prop_flags & 0x0400) != 0
                } else {
                    false
                };

                if !is_return {
                    // プロパティのオフセットを取得
                    // FProperty::Offset_Internal は FField(48) + ArrayDim(4) + ElementSize(4) + PropertyFlags(8) + RepIndex(2) + padding(2) = 68
                    let offset_field_offset = 68usize;
                    if let Ok(offset_data) = read_process_memory(handle, current_prop + offset_field_offset, 4) {
                        let prop_offset = i32::from_le_bytes(offset_data[..4].try_into().unwrap()) as usize;

                        // 値をシリアライズして書き込み
                        let data = self.serialize_value(&args[arg_index]);
                        write_process_memory(handle, params_addr + prop_offset, &data)?;
                    }
                    arg_index += 1;
                }

                current_prop = field.next;
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Value をバイト列にシリアライズ
    fn serialize_value(&self, value: &Value) -> Vec<u8> {
        match value {
            Value::Null => vec![0; 8],
            Value::Bool(v) => vec![if *v { 1u8 } else { 0u8 }],
            Value::I8(v) => v.to_le_bytes().to_vec(),
            Value::I16(v) => v.to_le_bytes().to_vec(),
            Value::I32(v) => v.to_le_bytes().to_vec(),
            Value::I64(v) => v.to_le_bytes().to_vec(),
            Value::U8(v) => v.to_le_bytes().to_vec(),
            Value::U16(v) => v.to_le_bytes().to_vec(),
            Value::U32(v) => v.to_le_bytes().to_vec(),
            Value::U64(v) => v.to_le_bytes().to_vec(),
            Value::F32(v) => v.to_le_bytes().to_vec(),
            Value::F64(v) => v.to_le_bytes().to_vec(),
            Value::String(_) => vec![0; 16], // FString は複雑なので未サポート
            Value::Object(h) => h.0.to_le_bytes().to_vec(),
            Value::Array(_) => vec![0; 16], // TArray は複雑なので未サポート
            Value::Struct(data) => data.clone(),
        }
    }

    /// 戻り値をパラメータ構造体から読み取る
    fn read_return_value(
        &self,
        handle: WinHandle,
        params_addr: usize,
        method_addr: usize,
        method_info: &MethodInfo,
    ) -> Result<Value> {
        // 戻り値がない場合
        if method_info.return_type.is_none() {
            return Ok(Value::Null);
        }

        // UFunction の ReturnValueOffset を取得
        // UFunction 固有フィールドのオフセットを試す
        let return_offset_offsets = [0x8Cusize, 0x94, 0x9C, 0xA4];

        let mut return_value_offset = None;
        for &offset in &return_offset_offsets {
            if let Ok(data) = read_process_memory(handle, method_addr + offset, 2) {
                let ret_offset = u16::from_le_bytes(data[..2].try_into().unwrap()) as usize;
                // 妥当なオフセット値かチェック
                if ret_offset < 0x1000 {
                    return_value_offset = Some(ret_offset);
                    break;
                }
            }
        }

        // ReturnValueOffset が見つからない場合、ChildProperties から探す
        let return_offset = if let Some(offset) = return_value_offset {
            offset
        } else {
            // 最後のプロパティ（通常はReturnValue）のオフセットを使用
            let ustruct = UStruct::read(handle, method_addr)
                .map_err(|e| EngineError::MemoryError(format!("Failed to read UFunction: {}", e)))?;

            let mut current_prop = ustruct.child_properties;
            let mut last_return_offset = 0usize;

            while current_prop != 0 {
                if let Ok(field) = FField::read(handle, current_prop) {
                    let prop_flags_offset = 48usize + 4 + 4;
                    if let Ok(flags_data) = read_process_memory(handle, current_prop + prop_flags_offset, 8) {
                        let prop_flags = u64::from_le_bytes(flags_data[..8].try_into().unwrap());
                        if (prop_flags & 0x0400) != 0 {
                            // CPF_ReturnParm
                            let offset_field_offset = 68usize;
                            if let Ok(offset_data) = read_process_memory(handle, current_prop + offset_field_offset, 4) {
                                last_return_offset = i32::from_le_bytes(offset_data[..4].try_into().unwrap()) as usize;
                            }
                        }
                    }
                    current_prop = field.next;
                } else {
                    break;
                }
            }
            last_return_offset
        };

        // 戻り値を読み取る
        let return_type = method_info.return_type.as_ref().unwrap();
        let data = read_process_memory(handle, params_addr + return_offset, return_type.size.max(8))?;

        // 型に応じてデシリアライズ
        let value = match &return_type.kind {
            TypeKind::Primitive(prim) => match prim {
                PrimitiveType::Bool => Value::Bool(data[0] != 0),
                PrimitiveType::I8 => Value::I8(data[0] as i8),
                PrimitiveType::I16 => Value::I16(i16::from_le_bytes(data[..2].try_into().unwrap())),
                PrimitiveType::I32 => Value::I32(i32::from_le_bytes(data[..4].try_into().unwrap())),
                PrimitiveType::I64 => Value::I64(i64::from_le_bytes(data[..8].try_into().unwrap())),
                PrimitiveType::U8 => Value::U8(data[0]),
                PrimitiveType::U16 => Value::U16(u16::from_le_bytes(data[..2].try_into().unwrap())),
                PrimitiveType::U32 => Value::U32(u32::from_le_bytes(data[..4].try_into().unwrap())),
                PrimitiveType::U64 => Value::U64(u64::from_le_bytes(data[..8].try_into().unwrap())),
                PrimitiveType::F32 => Value::F32(f32::from_le_bytes(data[..4].try_into().unwrap())),
                PrimitiveType::F64 => Value::F64(f64::from_le_bytes(data[..8].try_into().unwrap())),
            },
            TypeKind::Class(_) | TypeKind::Pointer(_) => {
                let ptr = usize::from_le_bytes(data[..8].try_into().unwrap());
                if ptr == 0 {
                    Value::Null
                } else {
                    Value::Object(InstanceHandle(ptr))
                }
            }
            _ => Value::Struct(data[..return_type.size.max(1)].to_vec()),
        };

        Ok(value)
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

    // =========================================================================
    // フィールド (プロパティ) 関連の実装
    // =========================================================================

    /// UClass から FProperty を検索
    /// UE5 では ChildProperties (FField*) を使用
    pub(super) fn find_field_impl(&self, class_addr: usize, field_name: &str) -> Result<usize> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let ustruct = UStruct::read(handle, class_addr)?;
        let mut current_field = ustruct.child_properties;

        // FField リンクリストを辿る
        while current_field != 0 {
            if let Ok(field) = FField::read(handle, current_field) {
                if let Ok(name) = self.get_fname_impl(field.name.comparison_index) {
                    if name == field_name {
                        return Ok(current_field);
                    }
                }
                current_field = field.next;
            } else {
                break;
            }
        }

        Err(EngineError::FieldNotFound(field_name.to_string()))
    }

    /// FField (FProperty) から情報を取得
    pub(super) fn get_field_info_impl(&self, field_addr: usize) -> Result<FieldInfo> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let field = FField::read(handle, field_addr)?;
        let name = self.get_fname_impl(field.name.comparison_index)?;

        // FProperty の追加フィールドを読む
        // FProperty は FField を継承し、以下のフィールドを追加:
        // FField base: 36 bytes (ClassPrivate:8 + Owner:8 + Next:8 + NamePrivate:8 + FlagsPrivate:4)
        // - ArrayDim (4 bytes) at +36
        // - ElementSize (4 bytes) at +40
        // - PropertyFlags (8 bytes) at +44
        // - RepIndex (2 bytes) at +52
        // - BlueprintReplicationCondition (1 byte + padding) at +54
        // - Offset_Internal (4 bytes) at +56 (non-editor) or +60 (editor)
        //
        // ただし、FField の実サイズは 40 バイト (8バイトアライメント) の可能性あり
        // その場合: Offset_Internal は +60 または +64

        // 複数のオフセットを試す
        let mut offset = 0usize;
        for fprop_offset in [56usize, 60, 64, 68, 72, 44, 48, 52] {
            if let Ok(data) = read_process_memory(handle, field_addr + fprop_offset, 4) {
                let val = i32::from_le_bytes(data[..4].try_into().unwrap());
                // 妥当な offset 値かチェック (0-65536 範囲)
                if val >= 0 && val < 65536 {
                    offset = val as usize;
                    break;
                }
            }
        }

        Ok(FieldInfo {
            name,
            handle: FieldHandle(field_addr),
            offset,
            type_info: TypeInfo {
                name: "unknown".into(),
                size: 0,
                kind: TypeKind::Unknown,
            },
        })
    }

    /// UClass の全プロパティを列挙
    pub(super) fn enumerate_fields_impl(&self, class_addr: usize) -> Result<Vec<FieldInfo>> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let ustruct = UStruct::read(handle, class_addr)?;
        let mut current_field = ustruct.child_properties;
        let mut fields = Vec::new();

        tracing::info!("enumerate_fields_impl: class 0x{:X}, child_properties=0x{:X}",
            class_addr, current_field);

        // デバッグ: FFieldの生データをダンプ
        static FIELD_DEBUG_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let debug_count = FIELD_DEBUG_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if debug_count < 5 && current_field != 0 {
            if let Ok(raw_data) = read_process_memory(handle, current_field, 80) {
                tracing::info!("  FField raw data at 0x{:X}:", current_field);
                for i in 0..10 {
                    let offset = i * 8;
                    let val = usize::from_le_bytes(raw_data[offset..offset+8].try_into().unwrap());
                    tracing::info!("    [+{:2}] 0x{:02X}: 0x{:016X}", offset, offset, val);
                }

                // FField構造解釈 (UE5.5 新レイアウト: 8バイト追加)
                let class_private = usize::from_le_bytes(raw_data[0..8].try_into().unwrap());
                let metadata_or_pad = usize::from_le_bytes(raw_data[8..16].try_into().unwrap());
                let owner = usize::from_le_bytes(raw_data[16..24].try_into().unwrap());
                let next = usize::from_le_bytes(raw_data[24..32].try_into().unwrap());
                let name_index = u32::from_le_bytes(raw_data[32..36].try_into().unwrap());
                let name_number = u32::from_le_bytes(raw_data[36..40].try_into().unwrap());
                let flags = u32::from_le_bytes(raw_data[40..44].try_into().unwrap());

                tracing::info!("  FField parsed: ClassPrivate=0x{:X}, MetaOrPad=0x{:X}", class_private, metadata_or_pad);
                tracing::info!("  FField parsed: Owner=0x{:X}, Next=0x{:X}", owner, next);
                tracing::info!("  FField parsed: NameIndex=0x{:X}, NameNumber={}, Flags=0x{:X}",
                    name_index, name_number, flags);

                // 名前を取得してみる
                if let Ok(name) = self.get_fname_impl(name_index) {
                    tracing::info!("  FField name: '{}'", name);
                }
            }
        }

        let mut count = 0;
        while current_field != 0 && count < 1000 {
            // 無限ループ防止
            count += 1;

            // ポインタの妥当性チェック
            if current_field < 0x10000 || current_field > 0x7FFFFFFFFFFF {
                tracing::warn!("  Invalid field pointer: 0x{:X}", current_field);
                break;
            }

            match FField::read(handle, current_field) {
                Ok(field) => {
                    // 名前を取得してデバッグ
                    if count <= 10 {
                        if let Ok(name) = self.get_fname_impl(field.name.comparison_index) {
                            tracing::info!("  Field {}: '{}' at 0x{:X}, next=0x{:X}",
                                count, name, current_field, field.next);
                        }
                    }

                    if let Ok(info) = self.get_field_info_impl(current_field) {
                        fields.push(info);
                    }
                    current_field = field.next;
                }
                Err(e) => {
                    tracing::warn!("  Failed to read FField at 0x{:X}: {}", current_field, e);
                    break;
                }
            }
        }

        tracing::info!("enumerate_fields_impl: found {} properties", fields.len());
        Ok(fields)
    }

    // =========================================================================
    // インスタンス関連の実装
    // =========================================================================

    /// 指定されたクラス（またはその派生クラス）のすべてのインスタンスを取得
    pub(super) fn get_instances_impl(&self, class_addr: usize) -> Result<Vec<InstanceHandle>> {
        let all_objects = self.get_all_objects_impl()?;
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let mut instances = Vec::new();

        for obj_addr in &all_objects {
            if let Ok(obj) = UObject::read(handle, *obj_addr) {
                // このオブジェクトが指定されたクラスのインスタンスかどうかをチェック
                // 直接一致、または派生クラスのインスタンスかを確認
                if self.is_instance_of(handle, obj.class, class_addr) {
                    instances.push(InstanceHandle(*obj_addr));
                }
            }
        }

        tracing::info!("get_instances_impl: found {} instances of class 0x{:X}", instances.len(), class_addr);
        Ok(instances)
    }

    /// obj_class が target_class またはその派生クラスかどうかを判定
    fn is_instance_of(&self, handle: WinHandle, obj_class: usize, target_class: usize) -> bool {
        if obj_class == 0 {
            return false;
        }

        // 直接一致
        if obj_class == target_class {
            return true;
        }

        // 継承チェーン (SuperStruct) を辿って確認
        // 最大 20 レベルまで（無限ループ防止）
        let mut current = obj_class;
        for _ in 0..20 {
            if let Ok(ustruct) = UStruct::read(handle, current) {
                if ustruct.super_struct == 0 {
                    break;
                }
                if ustruct.super_struct == target_class {
                    return true;
                }
                current = ustruct.super_struct;
            } else {
                break;
            }
        }

        false
    }
}
