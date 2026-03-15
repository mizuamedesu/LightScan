/// Real-time UFunction call tracing and property change monitoring
///
/// - Trace Log: 関数呼び出しとプロパティ変更の時系列ログ
/// - Controls: トレース開始/停止、フィルタ、統計表示

use crate::engine::types::*;
use crate::engine::unreal::trace::*;
use crate::engine::unreal::UnrealEngine;
use crate::engine::GameEngine;
use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const DEFAULT_POLL_MS: u64 = 50;

/// トレース開始リクエスト（EngineView → MonitorView）
#[derive(Clone)]
pub struct TraceRequest {
    pub instance: InstanceHandle,
    pub class: ClassHandle,
    pub class_name: String,
    pub trace_functions: bool,
    pub trace_properties: bool,
}

/// ウォッチ追加リクエスト（後方互換用）
#[derive(Clone)]
pub struct WatchRequest {
    pub instance: InstanceHandle,
    pub field: FieldHandle,
    pub field_name: String,
    pub class_name: String,
    pub type_info: TypeInfo,
}

/// リプレイダイアログの状態
struct ReplayDialog {
    /// 対象の関数アドレス
    function_addr: usize,
    /// 関数名
    function_name: String,
    /// クラス名
    class_name: String,
    /// インスタンスアドレス（編集可能）
    instance_addr_str: String,
    /// パラメータ情報（解決済み）
    params: Vec<ReplayParam>,
    /// 実行結果
    result_message: Option<String>,
    /// エラーメッセージ
    error_message: Option<String>,
    /// ウィンドウを開くか
    open: bool,
}

/// リプレイ用パラメータ1つ分
struct ReplayParam {
    name: String,
    type_name: String,
    kind: crate::engine::types::TypeKind,
    /// ユーザーが編集するテキスト
    value_str: String,
}

pub struct MonitorView {
    /// アクティブなトレースセッション
    session: Option<TraceSession>,

    /// エンジン参照
    engine: Option<Arc<Mutex<Box<dyn GameEngine>>>>,

    /// UIフィルタ
    filter_text: String,
    show_function_calls: bool,
    show_property_changes: bool,
    auto_scroll: bool,

    /// ポーリング設定
    poll_interval_ms: u64,
    last_poll: Instant,
    paused: bool,

    /// 表示用イベントキャッシュ（フィルタ済み）
    filtered_events: Vec<TraceEvent>,
    filter_dirty: bool,

    /// リプレイダイアログ
    replay_dialog: Option<ReplayDialog>,
}

impl Default for MonitorView {
    fn default() -> Self {
        Self {
            session: None,
            engine: None,
            filter_text: String::new(),
            show_function_calls: true,
            show_property_changes: true,
            auto_scroll: true,
            poll_interval_ms: DEFAULT_POLL_MS,
            last_poll: Instant::now(),
            paused: false,
            filtered_events: Vec::new(),
            filter_dirty: true,
            replay_dialog: None,
        }
    }
}

impl MonitorView {
    pub fn set_engine(&mut self, engine: Arc<Mutex<Box<dyn GameEngine>>>) {
        if self.engine.is_none() {
            self.engine = Some(engine);
        }
    }

    /// 後方互換: has_watches
    pub fn has_watches(&self) -> bool {
        self.session.as_ref().map(|s| s.active).unwrap_or(false)
    }

    /// 後方互換: add_watch（無視する - 新UIではTraceRequestを使う）
    pub fn add_watch(&mut self, _req: WatchRequest) {
        // Legacy - トレースシステムに移行済み
    }

    /// トレースリクエストを処理
    pub fn handle_trace_request(&mut self, req: TraceRequest) {
        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => return,
        };
        let Ok(mut eng) = engine.lock() else { return };

        let target = TraceTarget {
            instance: req.instance,
            class: req.class,
            class_name: req.class_name.clone(),
            trace_functions: req.trace_functions,
            trace_properties: req.trace_properties,
            function_filter: String::new(),
        };

        let mut session = TraceSession::new(target);

        // プロパティトレースの場合: 全フィールドを収集してポーラーを初期化
        if req.trace_properties {
            if let Some(ue) = eng.as_any().downcast_ref::<UnrealEngine>() {
                if let Ok(fields) = ue.enumerate_all_fields_inherited(req.class) {
                    let poller = PropertyPoller::new(
                        req.instance,
                        req.class_name.clone(),
                        fields,
                    );
                    session.property_poller = Some(poller);
                    tracing::info!("Property poller initialized with {} fields",
                        session.property_poller.as_ref().map(|p| p.fields.len()).unwrap_or(0));
                }
            }
        }

        // 関数トレースの場合: ProcessEventフック
        if req.trace_functions {
            if let Some(ue) = eng.as_any_mut().downcast_mut::<UnrealEngine>() {
                match ue.start_function_trace(&mut session) {
                    Ok(_) => {
                        tracing::info!("Function tracing started successfully");
                    }
                    Err(e) => {
                        tracing::error!("Failed to start function trace: {}", e);
                        // プロパティトレースのみで続行
                    }
                }
            }
        }

        self.session = Some(session);
        self.filter_dirty = true;
    }

    /// トレースを停止
    fn stop_trace(&mut self) {
        if let Some(session) = &mut self.session {
            if let Some(engine) = &self.engine {
                if let Ok(mut eng) = engine.lock() {
                    if let Some(ue) = eng.as_any_mut().downcast_mut::<UnrealEngine>() {
                        let _ = ue.stop_function_trace(session);
                    }
                }
            }
            session.active = false;
        }
    }

    /// イベントポーリング
    fn poll_events(&mut self) {
        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => return,
        };
        let Ok(eng) = engine.lock() else { return };

        let session = match &mut self.session {
            Some(s) if s.active => s,
            _ => return,
        };

        // プロパティポーリング
        if let Some(poller) = &mut session.property_poller {
            let events = poller.poll(&**eng);
            for event in events {
                session.push_event(event);
                self.filter_dirty = true;
            }
        }

        // 関数イベントポーリング
        if session.ring_buffer_addr.is_some() {
            if let Some(ue) = eng.as_any().downcast_ref::<UnrealEngine>() {
                match ue.poll_function_events(session) {
                    Ok(events) => {
                        if !events.is_empty() {
                            self.filter_dirty = true;
                        }
                        for event in events {
                            session.push_event(event);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to poll function events: {}", e);
                    }
                }
            }
        }

        session.update_stats();
        self.last_poll = Instant::now();
    }

    /// フィルタ済みイベントを再構築
    fn rebuild_filtered_events(&mut self) {
        let session = match &self.session {
            Some(s) => s,
            None => {
                self.filtered_events.clear();
                return;
            }
        };

        let filter_lower = self.filter_text.to_lowercase();

        self.filtered_events = session.events.iter()
            .filter(|event| {
                match event {
                    TraceEvent::FunctionCall(_) if !self.show_function_calls => false,
                    TraceEvent::PropertyChange(_) if !self.show_property_changes => false,
                    TraceEvent::FunctionCall(e) => {
                        filter_lower.is_empty()
                            || e.function_name.to_lowercase().contains(&filter_lower)
                            || e.class_name.to_lowercase().contains(&filter_lower)
                    }
                    TraceEvent::PropertyChange(e) => {
                        filter_lower.is_empty()
                            || e.field_name.to_lowercase().contains(&filter_lower)
                            || e.class_name.to_lowercase().contains(&filter_lower)
                    }
                }
            })
            .cloned()
            .collect();

        self.filter_dirty = false;
    }

    /// UI描画
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        // 自動ポーリング
        if !self.paused && self.session.as_ref().map(|s| s.active).unwrap_or(false) {
            let since_last = self.last_poll.elapsed().as_millis() as u64;
            if since_last >= self.poll_interval_ms {
                self.poll_events();
            }
            ui.ctx().request_repaint_after(
                std::time::Duration::from_millis(self.poll_interval_ms),
            );
        }

        if self.filter_dirty {
            self.rebuild_filtered_events();
        }

        // リプレイダイアログ（フローティングウィンドウ）
        let ctx = ui.ctx().clone();
        self.render_replay_dialog(&ctx);

        ui.heading("Trace Monitor");
        ui.separator();

        // ===== コントロールバー =====
        self.render_controls(ui);
        ui.separator();

        // ===== セッションが無い場合 =====
        if self.session.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(
                    egui::RichText::new("No active trace")
                        .size(20.0)
                        .weak(),
                );
                ui.add_space(10.0);
                ui.label("Engine Functions tab > select instance > click [Trace] to start");
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Traces ALL UFunction calls and property changes on the target instance").weak());
            });
            return;
        }

        // ===== 統計バー =====
        self.render_stats(ui);
        ui.separator();

        // ===== フィルタバー =====
        self.render_filter(ui);
        ui.separator();

        // ===== イベントログ =====
        self.render_event_log(ui);
    }

    fn render_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let has_session = self.session.is_some();
            let is_active = self.session.as_ref().map(|s| s.active).unwrap_or(false);

            if is_active {
                if ui.button(egui::RichText::new("Stop Trace").color(egui::Color32::RED)).clicked() {
                    self.stop_trace();
                }
            }

            let pause_label = if self.paused { "Resume" } else { "Pause" };
            ui.add_enabled(is_active, egui::Button::new(pause_label))
                .clicked()
                .then(|| self.paused = !self.paused);

            if has_session {
                if ui.button("Clear Log").clicked() {
                    if let Some(session) = &mut self.session {
                        session.events.clear();
                        session.stats = TraceStats::default();
                    }
                    self.filter_dirty = true;
                }
            }

            ui.separator();

            ui.label("Poll:");
            let mut interval = self.poll_interval_ms as f32;
            if ui.add(egui::Slider::new(&mut interval, 10.0..=500.0).suffix("ms")).changed() {
                self.poll_interval_ms = interval as u64;
            }
        });
    }

    fn render_stats(&self, ui: &mut egui::Ui) {
        let session = match &self.session {
            Some(s) => s,
            None => return,
        };

        ui.horizontal(|ui| {
            let status_color = if session.active {
                egui::Color32::GREEN
            } else {
                egui::Color32::GRAY
            };
            let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 5.0, status_color);

            ui.label(egui::RichText::new(if session.active { "LIVE" } else { "STOPPED" })
                .color(status_color).strong());

            ui.separator();

            ui.label(format!("Target: {}", session.target.class_name));
            ui.label(format!("@ 0x{:X}", session.target.instance.0));

            ui.separator();

            ui.label(egui::RichText::new(format!(
                "Calls: {} | Props: {} | {:.0}/s | Events: {}",
                session.stats.total_function_calls,
                session.stats.total_property_changes,
                session.stats.calls_per_sec,
                session.events.len(),
            )).weak());
        });
    }

    fn render_filter(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            if ui.text_edit_singleline(&mut self.filter_text).changed() {
                self.filter_dirty = true;
            }

            ui.separator();

            let mut fc = self.show_function_calls;
            if ui.checkbox(&mut fc, egui::RichText::new("Functions").color(
                egui::Color32::from_rgb(100, 200, 255)
            )).changed() {
                self.show_function_calls = fc;
                self.filter_dirty = true;
            }

            let mut pc = self.show_property_changes;
            if ui.checkbox(&mut pc, egui::RichText::new("Properties").color(
                egui::Color32::from_rgb(255, 200, 50)
            )).changed() {
                self.show_property_changes = pc;
                self.filter_dirty = true;
            }

            ui.separator();
            ui.checkbox(&mut self.auto_scroll, "Auto-scroll");

            ui.separator();
            ui.label(egui::RichText::new(format!("{} shown", self.filtered_events.len())).weak());
        });
    }

    fn render_event_log(&mut self, ui: &mut egui::Ui) {
        let row_height = 20.0;
        let num_events = self.filtered_events.len();

        // リプレイボタンが押されたイベントを記録
        let mut replay_request: Option<FunctionCallEvent> = None;

        egui::ScrollArea::vertical()
            .id_salt("trace_event_log")
            .stick_to_bottom(self.auto_scroll)
            .show_rows(ui, row_height, num_events, |ui, row_range| {
                for i in row_range {
                    if i >= num_events {
                        break;
                    }
                    let event = &self.filtered_events[i];
                    match event {
                        TraceEvent::FunctionCall(e) => {
                            ui.horizontal(|ui| {
                                // Replay ボタン
                                if ui.small_button("Replay").clicked() {
                                    replay_request = Some(e.clone());
                                }

                                // タイムスタンプ
                                ui.label(egui::RichText::new(format!("[{:8.3}s]", e.elapsed_secs))
                                    .monospace().small().color(egui::Color32::GRAY));

                                // FUNC タグ
                                ui.label(egui::RichText::new("FUNC")
                                    .monospace().small().strong()
                                    .color(egui::Color32::from_rgb(100, 200, 255)));

                                // クラス::関数名
                                ui.label(egui::RichText::new(format!(
                                    "{}::{}",
                                    e.class_name, e.function_name
                                )).monospace().small());

                                // インスタンスアドレス
                                ui.label(egui::RichText::new(format!("@ 0x{:X}", e.instance_addr))
                                    .monospace().small().color(egui::Color32::DARK_GRAY));
                            });
                        }
                        TraceEvent::PropertyChange(e) => {
                            ui.horizontal(|ui| {
                                // タイムスタンプ
                                ui.label(egui::RichText::new(format!("[{:8.3}s]", e.elapsed_secs))
                                    .monospace().small().color(egui::Color32::GRAY));

                                // PROP タグ
                                ui.label(egui::RichText::new("PROP")
                                    .monospace().small().strong()
                                    .color(egui::Color32::from_rgb(255, 200, 50)));

                                // フィールド名
                                ui.label(egui::RichText::new(format!(
                                    "{}.{}:",
                                    e.class_name, e.field_name
                                )).monospace().small());

                                // 値の変化
                                ui.label(egui::RichText::new(&e.old_value)
                                    .monospace().small().color(egui::Color32::from_rgb(255, 100, 100)));
                                ui.label(egui::RichText::new("->").monospace().small().weak());
                                ui.label(egui::RichText::new(&e.new_value)
                                    .monospace().small().color(egui::Color32::from_rgb(100, 255, 100)));
                            });
                        }
                    }
                }
            });

        // リプレイダイアログを開く
        if let Some(call_event) = replay_request {
            self.open_replay_dialog(&call_event);
        }
    }

    /// リプレイダイアログを開く（パラメータ情報を解決）
    fn open_replay_dialog(&mut self, event: &FunctionCallEvent) {
        let mut params = Vec::new();

        // エンジンからパラメータ情報を取得
        if let Some(engine) = &self.engine {
            if let Ok(eng) = engine.lock() {
                if let Ok(method_info) = eng.get_method_info(MethodHandle(event.function_addr)) {
                    for p in &method_info.params {
                        params.push(ReplayParam {
                            name: p.name.clone(),
                            type_name: p.type_info.name.clone(),
                            kind: p.type_info.kind.clone(),
                            value_str: String::new(),
                        });
                    }
                }
            }
        }

        self.replay_dialog = Some(ReplayDialog {
            function_addr: event.function_addr,
            function_name: event.function_name.clone(),
            class_name: event.class_name.clone(),
            instance_addr_str: format!("0x{:X}", event.instance_addr),
            params,
            result_message: None,
            error_message: None,
            open: true,
        });
    }

    /// リプレイダイアログの描画（egui::Window として）
    fn render_replay_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.replay_dialog else { return };
        if !dialog.open {
            self.replay_dialog = None;
            return;
        }

        let mut open = dialog.open;
        let mut execute_requested = false;

        egui::Window::new(format!("Replay: {}::{}", dialog.class_name, dialog.function_name))
            .open(&mut open)
            .resizable(true)
            .default_width(450.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Function:");
                    ui.label(egui::RichText::new(format!(
                        "{}::{}", dialog.class_name, dialog.function_name
                    )).monospace().strong());
                    ui.label(egui::RichText::new(format!("(0x{:X})", dialog.function_addr))
                        .monospace().small().weak());
                });

                ui.separator();

                // Instance address (編集可能)
                ui.horizontal(|ui| {
                    ui.label("Instance:");
                    ui.text_edit_singleline(&mut dialog.instance_addr_str);
                });

                ui.separator();

                // パラメータ編集
                if dialog.params.is_empty() {
                    ui.label(egui::RichText::new("No parameters").weak());
                } else {
                    ui.label(egui::RichText::new("Parameters:").strong());
                    egui::Grid::new("replay_params_grid")
                        .num_columns(3)
                        .spacing([8.0, 4.0])
                        .striped(true)
                        .show(ui, |ui| {
                            for param in dialog.params.iter_mut() {
                                ui.label(egui::RichText::new(&param.name).monospace());
                                ui.label(egui::RichText::new(&param.type_name).monospace().weak());
                                ui.add(egui::TextEdit::singleline(&mut param.value_str)
                                    .desired_width(150.0)
                                    .hint_text("value"));
                                ui.end_row();
                            }
                        });
                }

                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button(egui::RichText::new("Execute").strong()
                        .color(egui::Color32::from_rgb(100, 255, 100))).clicked()
                    {
                        execute_requested = true;
                    }
                    if ui.button("Close").clicked() {
                        dialog.open = false;
                    }
                });

                // 結果表示
                if let Some(msg) = &dialog.result_message {
                    ui.separator();
                    ui.label(egui::RichText::new(msg)
                        .color(egui::Color32::from_rgb(100, 255, 100)).monospace());
                }
                if let Some(msg) = &dialog.error_message {
                    ui.separator();
                    ui.label(egui::RichText::new(msg)
                        .color(egui::Color32::from_rgb(255, 100, 100)).monospace());
                }
            });

        if let Some(dialog) = &mut self.replay_dialog {
            dialog.open = open;
        }

        if execute_requested {
            self.execute_replay();
        }
    }

    /// リプレイを実行
    fn execute_replay(&mut self) {
        let Some(dialog) = &mut self.replay_dialog else { return };
        dialog.result_message = None;
        dialog.error_message = None;

        // インスタンスアドレスをパース
        let instance_addr = parse_hex_or_dec(&dialog.instance_addr_str);
        let instance_addr = match instance_addr {
            Some(addr) => addr,
            None => {
                dialog.error_message = Some("Invalid instance address".into());
                return;
            }
        };

        // パラメータを Value に変換
        let mut args = Vec::new();
        for param in &dialog.params {
            match parse_value_from_str(&param.value_str, &param.kind) {
                Some(v) => args.push(v),
                None => {
                    dialog.error_message = Some(format!(
                        "Failed to parse param '{}': '{}'", param.name, param.value_str
                    ));
                    return;
                }
            }
        }

        let function_addr = dialog.function_addr;
        let func_name = format!("{}::{}", dialog.class_name, dialog.function_name);

        // エンジン経由で実行
        if let Some(engine) = &self.engine {
            if let Ok(eng) = engine.lock() {
                match eng.invoke(
                    Some(InstanceHandle(instance_addr)),
                    MethodHandle(function_addr),
                    &args,
                ) {
                    Ok(result) => {
                        let msg = format!("OK: {} -> {}", func_name, result);
                        tracing::info!("Replay: {}", msg);
                        if let Some(d) = &mut self.replay_dialog {
                            d.result_message = Some(msg);
                        }
                    }
                    Err(e) => {
                        let msg = format!("Error: {}", e);
                        tracing::error!("Replay failed: {}", msg);
                        if let Some(d) = &mut self.replay_dialog {
                            d.error_message = Some(msg);
                        }
                    }
                }
            }
        }
    }
}

/// 16進数 (0x...) またはデミシカル文字列をパース
fn parse_hex_or_dec(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

/// 文字列から Value にパース
fn parse_value_from_str(s: &str, kind: &TypeKind) -> Option<Value> {
    let s = s.trim();

    // 空文字列はデフォルト値
    if s.is_empty() {
        return match kind {
            TypeKind::Primitive(p) => Some(match p {
                PrimitiveType::Bool => Value::Bool(false),
                PrimitiveType::I8 => Value::I8(0),
                PrimitiveType::I16 => Value::I16(0),
                PrimitiveType::I32 => Value::I32(0),
                PrimitiveType::I64 => Value::I64(0),
                PrimitiveType::U8 => Value::U8(0),
                PrimitiveType::U16 => Value::U16(0),
                PrimitiveType::U32 => Value::U32(0),
                PrimitiveType::U64 => Value::U64(0),
                PrimitiveType::F32 => Value::F32(0.0),
                PrimitiveType::F64 => Value::F64(0.0),
            }),
            _ => Some(Value::Null),
        };
    }

    match kind {
        TypeKind::Primitive(p) => match p {
            PrimitiveType::Bool => {
                match s.to_lowercase().as_str() {
                    "true" | "1" => Some(Value::Bool(true)),
                    "false" | "0" => Some(Value::Bool(false)),
                    _ => None,
                }
            }
            PrimitiveType::I8 => s.parse().ok().map(Value::I8),
            PrimitiveType::I16 => s.parse().ok().map(Value::I16),
            PrimitiveType::I32 => parse_int_flexible(s).map(|v| Value::I32(v as i32)),
            PrimitiveType::I64 => parse_int_flexible(s).map(|v| Value::I64(v)),
            PrimitiveType::U8 => parse_uint_flexible(s).map(|v| Value::U8(v as u8)),
            PrimitiveType::U16 => parse_uint_flexible(s).map(|v| Value::U16(v as u16)),
            PrimitiveType::U32 => parse_uint_flexible(s).map(|v| Value::U32(v as u32)),
            PrimitiveType::U64 => parse_uint_flexible(s).map(Value::U64),
            PrimitiveType::F32 => s.parse().ok().map(Value::F32),
            PrimitiveType::F64 => s.parse().ok().map(Value::F64),
        },
        TypeKind::Class(_) | TypeKind::Pointer(_) => {
            // ポインタ/オブジェクト: 0xアドレスとしてパース
            parse_hex_or_dec(s).map(|addr| Value::Object(InstanceHandle(addr)))
        }
        TypeKind::Struct(_) => {
            // Struct: 16進バイト列 "AA BB CC ..." としてパース
            let bytes: Option<Vec<u8>> = s.split_whitespace()
                .map(|b| u8::from_str_radix(b, 16).ok())
                .collect();
            bytes.map(Value::Struct)
        }
        _ => {
            // Unknown: i64 or hex としてパース試行
            if let Some(v) = parse_int_flexible(s) {
                Some(Value::I64(v))
            } else {
                Some(Value::Null)
            }
        }
    }
}

fn parse_int_flexible(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_uint_flexible(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse().ok()
    }
}
