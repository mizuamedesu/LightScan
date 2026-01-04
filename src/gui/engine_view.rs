/// Engine abstraction GUI view

use crate::engine::{GameEngine, *};
use eframe::egui;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// インスタンスのプロパティ値とその編集用文字列
#[derive(Clone, Debug)]
struct PropertyState {
    value: Value,
    edit_string: String,
    is_dirty: bool,
}

/// メソッドの引数入力状態
#[derive(Clone, Debug, Default)]
struct MethodInvokeState {
    arg_strings: Vec<String>,
}

pub struct EngineView {
    /// エンジンインスタンス
    engine: Option<Arc<Mutex<Box<dyn GameEngine>>>>,

    /// 初期化済みフラグ
    initialized: bool,

    /// 選択されたクラス
    selected_class: Option<ClassHandle>,
    selected_class_name: String,

    /// クラス一覧
    classes: Vec<ClassInfo>,

    /// 選択されたクラスのメソッド
    methods: Vec<MethodInfo>,

    /// 選択されたクラスのフィールド
    fields: Vec<FieldInfo>,

    /// 選択されたメソッド
    selected_method: Option<MethodHandle>,

    /// インスタンス一覧
    instances: Vec<InstanceHandle>,

    /// 選択されたインスタンス
    selected_instance: Option<InstanceHandle>,

    /// 関数呼び出しパラメータ
    invoke_param: String,

    /// ステータスメッセージ
    status_message: String,

    /// エラーメッセージ
    error_message: String,

    /// 検索フィルタ
    class_filter: String,
    method_filter: String,
    field_filter: String,

    // ===== インスタンス詳細パネル用 =====
    /// 選択されたインスタンスのプロパティ値（FieldHandle -> PropertyState）
    instance_properties: HashMap<FieldHandle, PropertyState>,

    /// 選択されたインスタンスのメソッド一覧
    instance_methods: Vec<MethodInfo>,

    /// Blueprint関数のハンドルセット
    blueprint_method_handles: std::collections::HashSet<MethodHandle>,

    /// メソッドごとの引数入力状態（MethodHandle -> MethodInvokeState）
    method_invoke_states: HashMap<MethodHandle, MethodInvokeState>,

    /// 詳細パネル用メソッドフィルタ
    instance_method_filter: String,

    /// 詳細パネル用プロパティフィルタ
    instance_property_filter: String,

    /// 最後のメソッド呼び出し結果
    last_invoke_result: Option<String>,

    /// 選択されたインスタンスのクラス名
    selected_instance_class_name: Option<String>,

    /// Blueprint関数のみ表示フラグ
    show_blueprint_only: bool,
}

impl Default for EngineView {
    fn default() -> Self {
        Self {
            engine: None,
            initialized: false,
            selected_class: None,
            selected_class_name: String::new(),
            classes: Vec::new(),
            methods: Vec::new(),
            fields: Vec::new(),
            selected_method: None,
            instances: Vec::new(),
            selected_instance: None,
            invoke_param: String::new(),
            status_message: String::new(),
            error_message: String::new(),
            class_filter: String::new(),
            method_filter: String::new(),
            field_filter: String::new(),
            instance_properties: HashMap::new(),
            instance_methods: Vec::new(),
            blueprint_method_handles: std::collections::HashSet::new(),
            method_invoke_states: HashMap::new(),
            instance_method_filter: String::new(),
            instance_property_filter: String::new(),
            last_invoke_result: None,
            selected_instance_class_name: None,
            show_blueprint_only: false,
        }
    }
}

impl EngineView {
    pub fn set_engine(&mut self, engine: Box<dyn GameEngine>) {
        self.engine = Some(Arc::new(Mutex::new(engine)));
        self.initialized = false;
        self.classes.clear();
        self.methods.clear();
        self.fields.clear();
        self.instances.clear();
        self.instance_properties.clear();
        self.instance_methods.clear();
        self.blueprint_method_handles.clear();
        self.method_invoke_states.clear();
        self.selected_instance = None;
        self.selected_instance_class_name = None;
        self.show_blueprint_only = false;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        if self.engine.is_none() {
            ui.heading("Engine Abstraction");
            ui.separator();
            ui.label("No engine detected. This feature requires Unreal Engine game.");
            ui.label("Unity and Native support coming soon.");
            return;
        }

        // 全体をスクロール可能にする
        egui::ScrollArea::vertical()
            .id_salt("engine_view_main_scroll")
            .show(ui, |ui| {
                self.render_main_ui(ui);
            });
    }

    /// メインUIを描画（スクロール内部）
    fn render_main_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Engine Abstraction");
        ui.separator();

        // エンジン情報
        if let Some(engine) = &self.engine {
            if let Ok(eng) = engine.lock() {
                ui.horizontal(|ui| {
                    ui.label("Engine:");
                    ui.label(egui::RichText::new(eng.name()).strong());
                    if let Some(version) = eng.version() {
                        ui.label(format!("({})", version));
                    }
                });
            }
        }

        ui.separator();

        // 初期化ボタン
        if !self.initialized {
            ui.horizontal(|ui| {
                if ui.button("Initialize Engine").clicked() {
                    self.initialize_engine();
                }

                ui.label("Wait for the game to fully load before initializing.");
            });

            if !self.status_message.is_empty() {
                ui.colored_label(egui::Color32::GREEN, &self.status_message);
            }

            if !self.error_message.is_empty() {
                ui.colored_label(egui::Color32::RED, &self.error_message);

                // エラーの場合、リトライボタンを表示
                if self.error_message.contains("not initialized yet") {
                    if ui.button("Retry Initialization").clicked() {
                        self.initialize_engine();
                    }
                }
            }

            return;
        }

        // クラスブラウザ
        ui.collapsing("Class Browser", |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.class_filter);
                if ui.button("Refresh Classes").clicked() {
                    self.load_classes();
                }
            });

            ui.separator();

            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                let filter = self.class_filter.to_lowercase();
                let filtered: Vec<_> = self
                    .classes
                    .iter()
                    .filter(|c| filter.is_empty() || c.name.to_lowercase().contains(&filter))
                    .collect();

                let mut clicked_class: Option<(ClassHandle, String)> = None;

                for class in filtered {
                    let selected = self
                        .selected_class
                        .map(|c| c == class.handle)
                        .unwrap_or(false);

                    if ui.selectable_label(selected, &class.name).clicked() {
                        clicked_class = Some((class.handle, class.name.clone()));
                    }
                }

                if let Some((handle, name)) = clicked_class {
                    self.selected_class = Some(handle);
                    self.selected_class_name = name;
                    self.load_methods();
                    self.load_fields();
                    self.load_instances();
                }
            });

            if !self.selected_class_name.is_empty() {
                ui.label(format!("Selected: {}", self.selected_class_name));
            }
        });

        ui.separator();

        // メソッドビューア
        if self.selected_class.is_some() {
            ui.collapsing("Methods", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Filter:");
                    ui.text_edit_singleline(&mut self.method_filter);
                });

                ui.label(format!("Found {} methods", self.methods.len()));

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    let filtered: Vec<_> = self
                        .methods
                        .iter()
                        .filter(|m| {
                            self.method_filter.is_empty()
                                || m.name
                                    .to_lowercase()
                                    .contains(&self.method_filter.to_lowercase())
                        })
                        .collect();

                    for method in filtered {
                        let selected = self
                            .selected_method
                            .map(|m| m == method.handle)
                            .unwrap_or(false);

                        if ui.selectable_label(selected, &method.name).clicked() {
                            self.selected_method = Some(method.handle);
                        }
                    }
                });
            });

            ui.separator();

            // フィールド（プロパティ）ビューア
            ui.collapsing("Fields / Properties", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Filter:");
                    ui.text_edit_singleline(&mut self.field_filter);
                });

                ui.label(format!("Found {} fields", self.fields.len()));

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    let filtered: Vec<_> = self
                        .fields
                        .iter()
                        .filter(|f| {
                            self.field_filter.is_empty()
                                || f.name
                                    .to_lowercase()
                                    .contains(&self.field_filter.to_lowercase())
                        })
                        .collect();

                    for field in filtered {
                        let label = format!("{} (offset: 0x{:X})", field.name, field.offset);
                        ui.label(label);
                    }
                });
            });

            ui.separator();

            // インスタンス選択
            ui.collapsing("Instances", |ui| {
                ui.label(format!("Found {} instances", self.instances.len()));

                let mut clicked_instance: Option<InstanceHandle> = None;
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for (i, instance) in self.instances.iter().enumerate() {
                        let selected = self
                            .selected_instance
                            .map(|inst| inst == *instance)
                            .unwrap_or(false);

                        let label = format!("Instance #{} @ 0x{:X}", i, instance.0);
                        if ui.selectable_label(selected, label).clicked() {
                            clicked_instance = Some(*instance);
                        }
                    }
                });

                if let Some(instance) = clicked_instance {
                    self.selected_instance = Some(instance);
                    self.load_instance_details();
                }
            });

            ui.separator();

            // インスタンス詳細パネル（プロパティとメソッド）
            if let Some(instance) = self.selected_instance {
                self.render_instance_detail_panel(ui, instance);
            }
        }

        // ステータス表示
        if !self.status_message.is_empty() {
            ui.separator();
            ui.colored_label(egui::Color32::GREEN, &self.status_message);
        }

        if !self.error_message.is_empty() {
            ui.separator();
            ui.colored_label(egui::Color32::RED, &self.error_message);
        }
    }

    fn initialize_engine(&mut self) {
        let result = if let Some(engine) = &self.engine {
            if let Ok(mut eng) = engine.lock() {
                eng.initialize()
            } else {
                return;
            }
        } else {
            return;
        };

        self.status_message = "Initializing engine...".to_string();
        self.error_message.clear();

        match result {
            Ok(_) => {
                self.initialized = true;
                self.status_message = "Engine initialized successfully!".to_string();
                self.load_classes();
            }
            Err(e) => {
                self.error_message = format!("Failed to initialize: {}", e);
                self.status_message.clear();
            }
        }
    }

    fn load_classes(&mut self) {
        if let Some(engine) = &self.engine {
            if let Ok(eng) = engine.lock() {
                match eng.enumerate_classes() {
                    Ok(classes) => {
                        self.classes = classes;
                        self.status_message = format!("Loaded {} classes", self.classes.len());
                        self.error_message.clear();
                    }
                    Err(e) => {
                        self.error_message = format!("Failed to load classes: {}", e);
                    }
                }
            }
        }
    }

    fn load_methods(&mut self) {
        if let Some(class) = self.selected_class {
            if let Some(engine) = &self.engine {
                if let Ok(eng) = engine.lock() {
                    match eng.enumerate_methods(class) {
                        Ok(methods) => {
                            self.methods = methods;
                            self.status_message =
                                format!("Loaded {} methods", self.methods.len());
                            self.error_message.clear();
                        }
                        Err(e) => {
                            self.error_message = format!("Failed to load methods: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn load_fields(&mut self) {
        if let Some(class) = self.selected_class {
            if let Some(engine) = &self.engine {
                if let Ok(eng) = engine.lock() {
                    match eng.enumerate_fields(class) {
                        Ok(fields) => {
                            self.fields = fields;
                            self.status_message =
                                format!("Loaded {} fields", self.fields.len());
                            self.error_message.clear();
                        }
                        Err(e) => {
                            self.error_message = format!("Failed to load fields: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn load_instances(&mut self) {
        if let Some(class) = self.selected_class {
            if let Some(engine) = &self.engine {
                if let Ok(eng) = engine.lock() {
                    match eng.get_instances(class) {
                        Ok(instances) => {
                            self.instances = instances;
                            self.status_message =
                                format!("Found {} instances", self.instances.len());
                            self.error_message.clear();
                        }
                        Err(e) => {
                            self.error_message = format!("Failed to get instances: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn invoke_method(&mut self) {
        if let (Some(method), Some(instance)) = (self.selected_method, self.selected_instance) {
            if let Some(engine) = &self.engine {
                if let Ok(eng) = engine.lock() {
                    // パラメータをパース
                    let args = if self.invoke_param.is_empty() {
                        vec![]
                    } else if let Ok(val) = self.invoke_param.parse::<i32>() {
                        vec![Value::I32(val)]
                    } else {
                        self.error_message = "Invalid parameter (must be i32)".to_string();
                        return;
                    };

                    match eng.invoke(Some(instance), method, &args) {
                        Ok(result) => {
                            self.status_message = format!("Method invoked! Result: {:?}", result);
                            self.error_message.clear();
                        }
                        Err(e) => {
                            self.error_message = format!("Invocation failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// インスタンス詳細（プロパティ値とメソッド）をロード
    fn load_instance_details(&mut self) {
        let Some(instance) = self.selected_instance else {
            return;
        };
        let Some(class) = self.selected_class else {
            return;
        };
        let Some(engine) = &self.engine else {
            return;
        };
        let Ok(eng) = engine.lock() else {
            return;
        };

        // インスタンスのクラス名を取得
        self.selected_instance_class_name = None;
        if let Ok(instance_class) = eng.get_instance_class(instance) {
            if let Ok(class_info) = eng.get_class_info(instance_class) {
                self.selected_instance_class_name = Some(class_info.name);
            }
        }

        // プロパティ値をロード
        self.instance_properties.clear();
        for field in &self.fields {
            match eng.read_field(instance, field.handle) {
                Ok(value) => {
                    let edit_string = Self::value_to_edit_string(&value);
                    self.instance_properties.insert(
                        field.handle,
                        PropertyState {
                            value,
                            edit_string,
                            is_dirty: false,
                        },
                    );
                }
                Err(_) => {
                    // 読み取れないフィールドはスキップ
                }
            }
        }

        // メソッドをロード（fieldsと同じクラスから）
        match eng.enumerate_methods(class) {
            Ok(methods) => {
                self.instance_methods = methods;
                // 引数入力状態を初期化
                self.method_invoke_states.clear();
                for method in &self.instance_methods {
                    let arg_strings = method.params.iter().map(|_| String::new()).collect();
                    self.method_invoke_states.insert(
                        method.handle,
                        MethodInvokeState { arg_strings },
                    );
                }
            }
            Err(e) => {
                self.error_message = format!("Failed to load methods: {}", e);
            }
        }

        // Blueprint関数リストを取得（UnrealEngine固有機能）
        self.blueprint_method_handles.clear();
        if let Some(ue) = eng.as_any().downcast_ref::<crate::engine::unreal::UnrealEngine>() {
            if let Ok(bp_methods) = ue.enumerate_blueprint_functions(class) {
                for method in bp_methods {
                    self.blueprint_method_handles.insert(method.handle);
                }
            }
        }

        self.status_message = format!(
            "Loaded {} properties, {} methods ({} blueprint) for instance @ 0x{:X}",
            self.instance_properties.len(),
            self.instance_methods.len(),
            self.blueprint_method_handles.len(),
            instance.0
        );
    }

    /// インスタンス詳細パネルを描画
    fn render_instance_detail_panel(&mut self, ui: &mut egui::Ui, instance: InstanceHandle) {
        ui.heading(format!("Instance Detail @ 0x{:X}", instance.0));

        // クラス名を表示
        if let Some(class_name) = &self.selected_instance_class_name {
            ui.horizontal(|ui| {
                ui.label("Class:");
                ui.label(egui::RichText::new(class_name).strong().color(egui::Color32::LIGHT_BLUE));
            });
        }

        ui.horizontal(|ui| {
            if ui.button("Refresh Values").clicked() {
                self.load_instance_details();
            }
        });

        ui.separator();

        // ===== プロパティセクション =====
        ui.collapsing("Properties (Live Values)", |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.instance_property_filter);
            });

            ui.label(format!("{} readable properties", self.instance_properties.len()));

            egui::ScrollArea::vertical()
                .id_salt("instance_properties_scroll")
                .max_height(250.0)
                .show(ui, |ui| {
                    self.render_properties_editor(ui, instance);
                });
        });

        ui.separator();

        // ===== メソッドセクション =====
        ui.collapsing("Methods (Invoke)", |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.instance_method_filter);
                ui.checkbox(&mut self.show_blueprint_only, "Blueprint Only");
            });

            ui.label(format!("{} methods available", self.instance_methods.len()));

            // 最後の呼び出し結果
            if let Some(result) = &self.last_invoke_result {
                ui.horizontal(|ui| {
                    ui.label("Last result:");
                    ui.colored_label(egui::Color32::LIGHT_GREEN, result);
                });
            }

            egui::ScrollArea::vertical()
                .id_salt("instance_methods_scroll")
                .max_height(300.0)
                .show(ui, |ui| {
                    self.render_methods_invoker(ui, instance);
                });
        });
    }

    /// プロパティエディタを描画
    fn render_properties_editor(&mut self, ui: &mut egui::Ui, instance: InstanceHandle) {
        let filter = self.instance_property_filter.to_lowercase();

        // フィールドとプロパティ状態を事前にクローンして借用問題を回避
        let fields_with_state: Vec<_> = self
            .fields
            .iter()
            .filter(|f| filter.is_empty() || f.name.to_lowercase().contains(&filter))
            .filter_map(|f| {
                self.instance_properties
                    .get(&f.handle)
                    .map(|state| (f.clone(), state.clone()))
            })
            .collect();

        // 書き込み要求を収集
        let mut write_requests: Vec<(FieldHandle, Value, TypeInfo)> = Vec::new();
        let mut edit_updates: Vec<(FieldHandle, String, bool)> = Vec::new();

        for (field, prop_state) in &fields_with_state {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    // フィールド名と型
                    ui.label(egui::RichText::new(&field.name).strong());
                    ui.label(format!("({})", field.type_info.name));
                    ui.label(format!("[0x{:X}]", field.offset));
                });

                ui.horizontal(|ui| {
                    ui.label("Value:");

                    let mut edit_string = prop_state.edit_string.clone();
                    let response = ui.text_edit_singleline(&mut edit_string);

                    // 編集されたら dirty フラグを立てる
                    if response.changed() {
                        let is_dirty = edit_string != Self::value_to_edit_string(&prop_state.value);
                        edit_updates.push((field.handle, edit_string, is_dirty));
                    }

                    // 現在値表示
                    ui.label(format!("(current: {})", prop_state.value));
                });

                // dirty なら Write ボタンを表示
                if prop_state.is_dirty {
                    ui.horizontal(|ui| {
                        if ui.button("Write").clicked() {
                            if let Some(new_value) = Self::parse_value_from_string_static(
                                &prop_state.edit_string,
                                &field.type_info,
                            ) {
                                write_requests.push((field.handle, new_value, field.type_info.clone()));
                            }
                        }
                        if ui.button("Reset").clicked() {
                            let original = Self::value_to_edit_string(&prop_state.value);
                            edit_updates.push((field.handle, original, false));
                        }
                    });
                }
            });
        }

        // 編集状態を更新
        for (handle, new_edit, is_dirty) in edit_updates {
            if let Some(state) = self.instance_properties.get_mut(&handle) {
                state.edit_string = new_edit;
                state.is_dirty = is_dirty;
            }
        }

        // 書き込み失敗時のエラーメッセージを収集
        let mut error_fields: Vec<String> = Vec::new();
        for (field_handle, new_value, type_info) in &write_requests {
            if new_value == &Value::Null && type_info.kind != TypeKind::Unknown {
                // パースに失敗した可能性
                error_fields.push(format!("{:?}", field_handle));
            }
        }

        // 書き込み実行
        for (field_handle, new_value, _) in write_requests {
            self.write_property(instance, field_handle, new_value);
        }

        if !error_fields.is_empty() {
            self.error_message = format!("Failed to parse values for some fields");
        }
    }

    /// メソッド呼び出しUIを描画
    fn render_methods_invoker(&mut self, ui: &mut egui::Ui, instance: InstanceHandle) {
        let filter = self.instance_method_filter.to_lowercase();
        let show_bp_only = self.show_blueprint_only;
        let bp_handles = &self.blueprint_method_handles;

        // メソッドと引数状態を事前にクローンして借用問題を回避
        let methods_with_state: Vec<_> = self
            .instance_methods
            .iter()
            .filter(|m| filter.is_empty() || m.name.to_lowercase().contains(&filter))
            .filter(|m| !show_bp_only || bp_handles.contains(&m.handle))
            .map(|m| {
                let state = self
                    .method_invoke_states
                    .get(&m.handle)
                    .cloned()
                    .unwrap_or_default();
                (m.clone(), state)
            })
            .collect();

        // 呼び出し要求を収集
        let mut invoke_requests: Vec<(MethodHandle, Vec<Value>)> = Vec::new();
        let mut arg_updates: Vec<(MethodHandle, usize, String)> = Vec::new();
        let mut parse_errors: Vec<String> = Vec::new();

        for (method, invoke_state) in &methods_with_state {
            let is_blueprint = bp_handles.contains(&method.handle);

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&method.name).strong());
                    if is_blueprint {
                        ui.label(egui::RichText::new("[BP]").color(egui::Color32::LIGHT_GREEN));
                    }
                    if method.is_static {
                        ui.label("[static]");
                    }
                    if let Some(ret_type) = &method.return_type {
                        ui.label(format!("-> {}", ret_type.name));
                    }
                });

                // パラメータ入力
                if !method.params.is_empty() {
                    ui.label("Parameters:");
                    ui.indent(format!("params_{}", method.handle.0), |ui| {
                        for (i, param) in method.params.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(format!("{} ({}):", param.name, param.type_info.name));
                                let mut arg_str = invoke_state
                                    .arg_strings
                                    .get(i)
                                    .cloned()
                                    .unwrap_or_default();
                                if ui.text_edit_singleline(&mut arg_str).changed() {
                                    arg_updates.push((method.handle, i, arg_str));
                                }
                            });
                        }
                    });
                }

                // Invoke ボタン
                if ui.button("Invoke").clicked() {
                    // 引数をパース
                    let mut args = Vec::new();
                    let mut parse_ok = true;

                    for (i, param) in method.params.iter().enumerate() {
                        let arg_str = invoke_state.arg_strings.get(i).map(|s| s.as_str()).unwrap_or("");
                        if let Some(val) = Self::parse_value_from_string_static(arg_str, &param.type_info) {
                            args.push(val);
                        } else {
                            parse_errors.push(format!(
                                "Failed to parse argument '{}' for method {}",
                                param.name, method.name
                            ));
                            parse_ok = false;
                            break;
                        }
                    }

                    if parse_ok {
                        invoke_requests.push((method.handle, args));
                    }
                }
            });
        }

        // 引数更新
        for (handle, idx, new_val) in arg_updates {
            if let Some(state) = self.method_invoke_states.get_mut(&handle) {
                if idx < state.arg_strings.len() {
                    state.arg_strings[idx] = new_val;
                }
            }
        }

        // パースエラーがあれば表示
        if let Some(err) = parse_errors.first() {
            self.error_message = err.clone();
        }

        // メソッド呼び出し実行
        for (method_handle, args) in invoke_requests {
            self.invoke_instance_method(instance, method_handle, args);
        }
    }

    /// プロパティを書き込む
    fn write_property(&mut self, instance: InstanceHandle, field_handle: FieldHandle, value: Value) {
        let Some(engine) = &self.engine else { return };
        let Ok(eng) = engine.lock() else { return };

        match eng.write_field(instance, field_handle, &value) {
            Ok(_) => {
                // 成功したら値を更新
                if let Some(state) = self.instance_properties.get_mut(&field_handle) {
                    state.value = value.clone();
                    state.edit_string = Self::value_to_edit_string(&value);
                    state.is_dirty = false;
                }
                self.status_message = "Property written successfully".to_string();
                self.error_message.clear();
            }
            Err(e) => {
                self.error_message = format!("Failed to write property: {}", e);
            }
        }
    }

    /// インスタンスのメソッドを呼び出す
    fn invoke_instance_method(
        &mut self,
        instance: InstanceHandle,
        method_handle: MethodHandle,
        args: Vec<Value>,
    ) {
        let Some(engine) = &self.engine else { return };
        let Ok(eng) = engine.lock() else { return };

        match eng.invoke(Some(instance), method_handle, &args) {
            Ok(result) => {
                let result_str = format!("{}", result);
                self.last_invoke_result = Some(result_str.clone());
                self.status_message = format!("Method invoked! Result: {}", result_str);
                self.error_message.clear();

                // 呼び出し後にプロパティを再読み込み（値が変わった可能性）
                drop(eng);
                self.load_instance_details();
            }
            Err(e) => {
                self.error_message = format!("Invocation failed: {}", e);
                self.last_invoke_result = Some(format!("Error: {}", e));
            }
        }
    }

    /// Value を編集用文字列に変換
    fn value_to_edit_string(value: &Value) -> String {
        match value {
            Value::Null => "null".to_string(),
            Value::Bool(v) => v.to_string(),
            Value::I8(v) => v.to_string(),
            Value::I16(v) => v.to_string(),
            Value::I32(v) => v.to_string(),
            Value::I64(v) => v.to_string(),
            Value::U8(v) => v.to_string(),
            Value::U16(v) => v.to_string(),
            Value::U32(v) => v.to_string(),
            Value::U64(v) => v.to_string(),
            Value::F32(v) => v.to_string(),
            Value::F64(v) => v.to_string(),
            Value::String(v) => v.clone(),
            Value::Object(h) => format!("0x{:X}", h.0),
            Value::Array(arr) => format!("[{} items]", arr.len()),
            Value::Struct(bytes) => format!("Struct[{} bytes]", bytes.len()),
        }
    }

    /// 文字列から Value をパース（static版）
    fn parse_value_from_string_static(s: &str, type_info: &TypeInfo) -> Option<Value> {
        let s = s.trim();

        // 空文字列は Null として扱う（引数なしの場合）
        if s.is_empty() {
            return Some(Value::Null);
        }

        match &type_info.kind {
            TypeKind::Primitive(prim) => match prim {
                PrimitiveType::Bool => {
                    match s.to_lowercase().as_str() {
                        "true" | "1" => Some(Value::Bool(true)),
                        "false" | "0" => Some(Value::Bool(false)),
                        _ => None,
                    }
                }
                PrimitiveType::I8 => s.parse().ok().map(Value::I8),
                PrimitiveType::I16 => s.parse().ok().map(Value::I16),
                PrimitiveType::I32 => s.parse().ok().map(Value::I32),
                PrimitiveType::I64 => s.parse().ok().map(Value::I64),
                PrimitiveType::U8 => Self::parse_u64(s).and_then(|v| u8::try_from(v).ok()).map(Value::U8),
                PrimitiveType::U16 => Self::parse_u64(s).and_then(|v| u16::try_from(v).ok()).map(Value::U16),
                PrimitiveType::U32 => Self::parse_u64(s).and_then(|v| u32::try_from(v).ok()).map(Value::U32),
                PrimitiveType::U64 => Self::parse_u64(s).map(Value::U64),
                PrimitiveType::F32 => s.parse().ok().map(Value::F32),
                PrimitiveType::F64 => s.parse().ok().map(Value::F64),
            },
            TypeKind::Class(_) | TypeKind::Pointer(_) => {
                // オブジェクト/ポインタは 16進数アドレスとしてパース
                Self::parse_u64(s).map(|addr| Value::Object(InstanceHandle(addr as usize)))
            }
            TypeKind::Unknown => {
                // 不明な型は i32 として試す
                s.parse::<i32>().ok().map(Value::I32)
            }
            _ => None,
        }
    }

    /// 16進数または10進数の u64 をパース
    fn parse_u64(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).ok()
        } else {
            s.parse().ok()
        }
    }
}
