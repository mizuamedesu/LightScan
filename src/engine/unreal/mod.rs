/// Unreal Engine backend implementation

use super::error::{EngineError, Result};
use super::types::*;
use super::GameEngine;
use std::any::Any;
use std::collections::HashMap;

pub mod hook;
pub mod implementation;
pub mod inject;
pub mod methods;
pub mod offsets;
pub mod scanner;
pub mod signatures;
pub mod structures;
pub mod trace;

/// Unreal Engine のバージョン
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UEVersion {
    UE4_20,
    UE4_21,
    UE4_22,
    UE4_23,
    UE4_24,
    UE4_25,
    UE4_26,
    UE4_27,
    UE5_0,
    UE5_1,
    UE5_2,
    UE5_3,
    UE5_4,
    Unknown,
}

/// Unreal Engine バックエンド
pub struct UnrealEngine {
    /// プロセスハンドル（usize として保持）
    process_handle: usize,

    /// プロセスID
    process_id: u32,

    /// モジュールベースアドレス
    module_base: usize,

    /// モジュールサイズ
    module_size: usize,

    /// GNames ポインタのアドレス（実際のFNamePoolへのポインタ）
    gnames_ptr: usize,

    /// GNames の実際のアドレス（キャッシュ）
    gnames: usize,

    /// GObjects ポインタのアドレス
    gobjects_ptr: usize,

    /// GObjects の実際のアドレス（キャッシュ）
    gobjects: usize,

    /// ProcessEvent のアドレス
    process_event: usize,

    /// UE バージョン
    version: UEVersion,

    /// 初期化済みフラグ
    initialized: bool,

    /// クラス名キャッシュ（ClassHandle -> 名前）
    class_cache: HashMap<ClassHandle, String>,

    /// メソッドキャッシュ（MethodHandle -> 情報）
    method_cache: HashMap<MethodHandle, MethodInfo>,
}

impl UnrealEngine {
    /// 新しい UE バックエンドを作成
    pub fn new(process_handle: usize, process_id: u32) -> Self {
        Self {
            process_handle,
            process_id,
            module_base: 0,
            module_size: 0,
            gnames_ptr: 0,
            gnames: 0,
            gobjects_ptr: 0,
            gobjects: 0,
            process_event: 0,
            version: UEVersion::Unknown,
            initialized: false,
            class_cache: HashMap::new(),
            method_cache: HashMap::new(),
        }
    }

    /// GNames のアドレスを検索
    fn find_gnames(&self) -> Result<usize> {
        self.find_gnames_impl()
    }

    /// GObjects のアドレスを検索
    fn find_gobjects(&self) -> Result<usize> {
        self.find_gobjects_impl()
    }

    /// ProcessEvent のアドレスを検索
    fn find_process_event(&self) -> Result<usize> {
        self.find_process_event_impl()
    }

    /// UE バージョンを検出
    fn detect_version(&self) -> UEVersion {
        // TODO: バージョン検出ロジック
        UEVersion::Unknown
    }

    /// GNames から名前を取得
    fn get_fname(&self, index: u32) -> Result<String> {
        self.get_fname_impl(index)
    }

    /// UObject の名前を取得
    fn get_object_name(&self, obj_addr: usize) -> Result<String> {
        self.get_object_name_impl(obj_addr)
    }

    /// UE 固有: Blueprint 関数の一覧を取得
    /// FUNC_BlueprintCallable フラグを持つ UFunction を列挙
    pub fn enumerate_blueprint_functions(&self, class: ClassHandle) -> Result<Vec<MethodInfo>> {
        use crate::platform::windows::read_process_memory;
        use windows::Win32::Foundation::HANDLE as WinHandle;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // FUNC_BlueprintCallable = 0x04000000
        const FUNC_BLUEPRINT_CALLABLE: u32 = 0x04000000;

        // UFunction の FunctionFlags オフセット
        // UObject(40) + UField::Next(8) + UStruct部(可変) の後
        // 実際には UStruct::read と同様に複数オフセットを試す
        let function_flags_offsets = [0x88usize, 0x90, 0x98, 0xA0, 0xB0];

        let all_methods = self.enumerate_methods_impl(class.0)?;
        let mut blueprint_functions = Vec::new();

        for method in all_methods {
            // UFunction の FunctionFlags を読み取る
            for &offset in &function_flags_offsets {
                if let Ok(data) = read_process_memory(handle, method.handle.0 + offset, 4) {
                    let flags = u32::from_le_bytes(data[..4].try_into().unwrap());

                    // 妥当なフラグ値かチェック（上位ビットが多すぎないか）
                    if flags != 0 && flags < 0x80000000 {
                        if (flags & FUNC_BLUEPRINT_CALLABLE) != 0 {
                            blueprint_functions.push(method.clone());
                        }
                        break;
                    }
                }
            }
        }

        tracing::info!(
            "enumerate_blueprint_functions: found {} blueprint callable functions",
            blueprint_functions.len()
        );

        Ok(blueprint_functions)
    }

    /// UE 固有: コンソールコマンド実行
    pub fn execute_console_command(&self, _command: &str) -> Result<()> {
        // TODO: UE コンソールコマンド実行
        Err(EngineError::UnsupportedOperation(
            "Console command not implemented".into(),
        ))
    }

    /// GNamesの実際の値を更新
    fn refresh_gnames(&mut self) -> Result<()> {
        use crate::platform::windows::read_process_memory;
        use windows::Win32::Foundation::HANDLE as WinHandle;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // まず、ポインタのアドレスで実際のバイトデータを確認
        let ptr_data = read_process_memory(handle, self.gnames_ptr, 8)?;
        tracing::info!("Reading GNames pointer at 0x{:X}: {:02X?}", self.gnames_ptr, ptr_data);

        let gnames = usize::from_le_bytes(ptr_data[..8].try_into().unwrap());

        if gnames == 0 {
            // UE5.5では、見つかったアドレスが既にGNames自体の可能性がある
            // ポインタではなく、直接構造体の場合を試す
            tracing::warn!("Pointer at 0x{:X} is null. Trying to use address as direct GNames location...", self.gnames_ptr);

            // 見つかったアドレス自体を GNames として扱ってみる
            // FNamePool の先頭を読んでみて、妥当そうなデータか確認
            match read_process_memory(handle, self.gnames_ptr, 32) {
                Ok(test_data) => {
                    tracing::info!("Data at GNames location: {:02X?}", &test_data[..16]);
                    // とりあえずアドレスをそのまま使用
                    self.gnames = self.gnames_ptr;
                    tracing::info!("Using GNames directly at 0x{:X}", self.gnames);
                    return Ok(());
                }
                Err(e) => {
                    return Err(EngineError::InitializationFailed(
                        format!("GNames not initialized yet (pointer is null at 0x{:X}). Try again after the game fully loads. Error: {}", self.gnames_ptr, e),
                    ));
                }
            }
        }

        self.gnames = gnames;
        tracing::info!("GNames value: 0x{:X}", gnames);
        Ok(())
    }

    /// GObjectsの実際の値を更新
    /// find_gobjects_impl がブルートフォース方式で検証済みアドレスを返すため、
    /// ここでは単純にそのアドレスを使用する
    fn refresh_gobjects(&mut self) -> Result<()> {
        // find_gobjects_impl は既に実際にUObjectが読めることを確認済みのアドレスを返す
        // そのため追加検証は不要で、そのまま使用する
        tracing::info!("Using GObjects at 0x{:X} (pre-validated by find_gobjects_impl)", self.gobjects_ptr);
        self.gobjects = self.gobjects_ptr;
        Ok(())
    }
}

impl GameEngine for UnrealEngine {
    fn name(&self) -> &'static str {
        "Unreal Engine"
    }

    fn version(&self) -> Option<String> {
        Some(format!("{:?}", self.version))
    }

    fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // 全モジュール一覧を取得
        let modules = crate::platform::module::list_modules(self.process_id)
            .map_err(|e| EngineError::InitializationFailed(format!("Failed to list modules: {}", e)))?;

        if modules.is_empty() {
            return Err(EngineError::InitializationFailed("No modules found".into()));
        }

        // メインモジュール（最初）を優先し、残りはサイズ降順
        let main_module = modules[0].clone();
        let mut try_order = vec![main_module.clone()];
        let mut others: Vec<_> = modules.into_iter()
            .filter(|m| m.base_address != main_module.base_address)
            .collect();
        others.sort_by(|a, b| b.size.cmp(&a.size));
        try_order.extend(others);

        tracing::info!("Found {} modules. Main: {} (0x{:X}, size: 0x{:X})",
            try_order.len(), main_module.name, main_module.base_address, main_module.size);

        // 各モジュールで GObjects を検索
        let mut last_error = None;
        for module in &try_order {
            // 小さすぎるモジュール（64KB未満）はスキップ（メインモジュールは常に試す）
            if module.size < 0x10000 && module.base_address != main_module.base_address {
                continue;
            }

            self.module_base = module.base_address;
            self.module_size = module.size;

            tracing::info!("Trying module: {} at 0x{:X} (size: 0x{:X})",
                module.name, module.base_address, module.size);

            match self.find_gobjects() {
                Ok(ptr) => {
                    self.gobjects_ptr = ptr;
                    self.refresh_gobjects()?;
                    tracing::info!("GObjects found in module: {}", module.name);

                    // GNames: 同じモジュールでまず試す、ダメなら他モジュール
                    let gobjects_module_base = module.base_address;
                    let gobjects_module_size = module.size;
                    match self.find_gnames() {
                        Ok(gnames_ptr) => {
                            self.gnames_ptr = gnames_ptr;
                        }
                        Err(_) => {
                            tracing::info!("GNames not in {}, searching other modules...", module.name);
                            let mut gnames_found = false;
                            for gn_mod in &try_order {
                                if gn_mod.base_address == gobjects_module_base {
                                    continue;
                                }
                                self.module_base = gn_mod.base_address;
                                self.module_size = gn_mod.size;
                                if let Ok(gnames_ptr) = self.find_gnames() {
                                    self.gnames_ptr = gnames_ptr;
                                    gnames_found = true;
                                    tracing::info!("GNames found in module: {}", gn_mod.name);
                                    break;
                                }
                            }
                            if !gnames_found {
                                return Err(EngineError::InitializationFailed(
                                    "GNames not found in any module".into(),
                                ));
                            }
                            // モジュール情報を GObjects のモジュールに戻す
                            self.module_base = gobjects_module_base;
                            self.module_size = gobjects_module_size;
                        }
                    }
                    self.refresh_gnames()?;

                    // ProcessEvent（見つからなくても続行）
                    self.process_event = self.find_process_event().unwrap_or(0);
                    self.version = self.detect_version();
                    self.initialized = true;
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!("GObjects not found in {}: {}", module.name, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| EngineError::InitializationFailed(
            "GObjects not found in any module".into(),
        )))
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn find_class(&self, name: &str) -> Result<ClassHandle> {
        if !self.initialized {
            return Err(EngineError::NotInitialized);
        }

        let class_addr = self.find_class_by_name_impl(name)?;
        Ok(ClassHandle(class_addr))
    }

    fn get_class_info(&self, class: ClassHandle) -> Result<ClassInfo> {
        self.get_class_info_impl(class.0)
    }

    fn enumerate_classes(&self) -> Result<Vec<ClassInfo>> {
        self.enumerate_classes_impl()
    }

    fn find_method(&self, class: ClassHandle, name: &str) -> Result<MethodHandle> {
        let method_addr = self.find_method_impl(class.0, name)?;
        Ok(MethodHandle(method_addr))
    }

    fn get_method_info(&self, method: MethodHandle) -> Result<MethodInfo> {
        self.get_method_info_impl(method.0)
    }

    fn enumerate_methods(&self, class: ClassHandle) -> Result<Vec<MethodInfo>> {
        self.enumerate_methods_impl(class.0)
    }

    fn find_field(&self, class: ClassHandle, name: &str) -> Result<FieldHandle> {
        let field_addr = self.find_field_impl(class.0, name)?;
        Ok(FieldHandle(field_addr))
    }

    fn get_field_info(&self, field: FieldHandle) -> Result<FieldInfo> {
        self.get_field_info_impl(field.0)
    }

    fn enumerate_fields(&self, class: ClassHandle) -> Result<Vec<FieldInfo>> {
        self.enumerate_fields_impl(class.0)
    }

    fn get_instances(&self, class: ClassHandle) -> Result<Vec<InstanceHandle>> {
        self.get_instances_impl(class.0)
    }

    fn get_instance_class(&self, instance: InstanceHandle) -> Result<ClassHandle> {
        use crate::platform::windows::read_process_memory;
        use windows::Win32::Foundation::HANDLE as WinHandle;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // UObject の class フィールドを読み取る
        // UObject レイアウト: vtable(8) + flags(4) + index(4) + class(8)
        // class は offset 16 にある
        let class_offset = 16usize;
        let data = read_process_memory(handle, instance.0 + class_offset, 8)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read class pointer: {}", e)))?;

        let class_addr = usize::from_le_bytes(data[..8].try_into().unwrap());

        if class_addr == 0 {
            return Err(EngineError::InvalidArgument("Instance has null class".into()));
        }

        Ok(ClassHandle(class_addr))
    }

    fn invoke(
        &self,
        instance: Option<InstanceHandle>,
        method: MethodHandle,
        args: &[Value],
    ) -> Result<Value> {
        if !self.initialized {
            return Err(EngineError::NotInitialized);
        }

        let instance_addr = instance
            .ok_or(EngineError::InvocationFailed(
                "UE requires instance for method call".into(),
            ))?
            .0;

        self.invoke_method_impl(instance_addr, method.0, args)
    }

    fn read_field(&self, instance: InstanceHandle, field: FieldHandle) -> Result<Value> {
        let field_info = self.get_field_info_impl(field.0)?;
        self.read_field_impl(instance.0, field_info.offset, &field_info.type_info)
    }

    fn write_field(
        &self,
        instance: InstanceHandle,
        field: FieldHandle,
        value: &Value,
    ) -> Result<()> {
        let field_info = self.get_field_info_impl(field.0)?;
        self.write_field_impl(instance.0, field_info.offset, value)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
