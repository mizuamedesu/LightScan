/// Real-time UFunction call tracing and property change monitoring
///
/// - Trace Log: 関数呼び出しとプロパティ変更の時系列ログ
/// - Controls: トレース開始/停止、フィルタ、統計表示

use crate::engine::types::*;
use crate::engine::unreal::trace::*;
use crate::engine::unreal::UnrealEngine;
use crate::engine::GameEngine;
use eframe::egui;
use std::collections::VecDeque;
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

    fn render_event_log(&self, ui: &mut egui::Ui) {
        let row_height = 20.0;
        let events = &self.filtered_events;

        egui::ScrollArea::vertical()
            .id_salt("trace_event_log")
            .stick_to_bottom(self.auto_scroll)
            .show_rows(ui, row_height, events.len(), |ui, row_range| {
                for i in row_range {
                    if i >= events.len() {
                        break;
                    }
                    self.render_event_row(ui, &events[i]);
                }
            });
    }

    fn render_event_row(&self, ui: &mut egui::Ui, event: &TraceEvent) {
        match event {
            TraceEvent::FunctionCall(e) => {
                ui.horizontal(|ui| {
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
}
