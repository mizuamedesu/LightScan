/// Engine abstraction GUI view

use crate::engine::{GameEngine, *};
use eframe::egui;
use std::sync::{Arc, Mutex};

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
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        if self.engine.is_none() {
            ui.heading("Engine Abstraction");
            ui.separator();
            ui.label("No engine detected. This feature requires Unreal Engine game.");
            ui.label("Unity and Native support coming soon.");
            return;
        }

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

                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for (i, instance) in self.instances.iter().enumerate() {
                        let selected = self
                            .selected_instance
                            .map(|inst| inst == *instance)
                            .unwrap_or(false);

                        let label = format!("Instance #{} @ 0x{:X}", i, instance.0);
                        if ui.selectable_label(selected, label).clicked() {
                            self.selected_instance = Some(*instance);
                        }
                    }
                });
            });

            ui.separator();

            // メソッド呼び出し
            if self.selected_method.is_some() && self.selected_instance.is_some() {
                ui.collapsing("Invoke Method", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Parameter (i32):");
                        ui.text_edit_singleline(&mut self.invoke_param);
                    });

                    if ui.button("Invoke").clicked() {
                        self.invoke_method();
                    }
                });
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
}
