/// Unreal Engine backend implementation

use super::error::{EngineError, Result};
use super::types::*;
use super::GameEngine;
use std::any::Any;
use std::collections::HashMap;

pub mod implementation;
pub mod methods;
pub mod offsets;
pub mod scanner;
pub mod signatures;
pub mod structures;

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
    pub fn enumerate_blueprint_functions(&self, _class: ClassHandle) -> Result<Vec<MethodInfo>> {
        // TODO: FUNC_BlueprintCallable フラグを持つ UFunction を列挙
        Err(EngineError::UnsupportedOperation(
            "Blueprint enumeration not implemented".into(),
        ))
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

        // メインモジュールの情報を取得
        let module = crate::platform::module::get_main_module(self.process_id)
            .map_err(|e| EngineError::InitializationFailed(format!("Failed to get module info: {}", e)))?;

        self.module_base = module.base_address;
        self.module_size = module.size;

        tracing::info!("Module: {} at 0x{:X} (size: 0x{:X})", module.name, self.module_base, self.module_size);

        // GObjects を先に検索（ヒープアドレス推定に使用）
        self.gobjects_ptr = self.find_gobjects()?;
        self.refresh_gobjects()?;

        // GNames を検索（GObjects のヒープアドレスを参考にする）
        self.gnames_ptr = self.find_gnames()?;
        self.refresh_gnames()?;

        // ProcessEvent を検索
        self.process_event = self.find_process_event()?;
        self.version = self.detect_version();

        self.initialized = true;
        Ok(())
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

    fn find_field(&self, _class: ClassHandle, _name: &str) -> Result<FieldHandle> {
        // TODO: UProperty を探す
        Err(EngineError::FieldNotFound(_name.to_string()))
    }

    fn get_field_info(&self, _field: FieldHandle) -> Result<FieldInfo> {
        // TODO: UProperty から情報を読み取る
        Err(EngineError::UnsupportedOperation(
            "Field info reading not implemented".into(),
        ))
    }

    fn enumerate_fields(&self, _class: ClassHandle) -> Result<Vec<FieldInfo>> {
        // TODO: UClass の全 UProperty を列挙
        Err(EngineError::UnsupportedOperation(
            "Field enumeration not implemented".into(),
        ))
    }

    fn get_instances(&self, _class: ClassHandle) -> Result<Vec<InstanceHandle>> {
        // TODO: GObjects を走査してインスタンスを収集
        Ok(Vec::new())
    }

    fn get_instance_class(&self, _instance: InstanceHandle) -> Result<ClassHandle> {
        // TODO: UObject->Class を読み取る
        Err(EngineError::UnsupportedOperation(
            "Instance class reading not implemented".into(),
        ))
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
        // フィールドハンドルから offset と type を取得する必要があるが、
        // 簡略化のため field.0 を offset として扱う
        let type_info = TypeInfo {
            name: "unknown".into(),
            size: 4,
            kind: TypeKind::Primitive(PrimitiveType::I32),
        };
        self.read_field_impl(instance.0, field.0, &type_info)
    }

    fn write_field(
        &self,
        instance: InstanceHandle,
        field: FieldHandle,
        value: &Value,
    ) -> Result<()> {
        self.write_field_impl(instance.0, field.0, value)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
