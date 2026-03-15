/// Real-time variable/function monitoring with visualization
///
/// ウォッチリストで選択したフィールドの値変化をリアルタイムに表示。
/// 数値型はスパークライングラフで推移を可視化。

use crate::engine::types::*;
use crate::engine::GameEngine;
use eframe::egui;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MAX_HISTORY: usize = 300;
const DEFAULT_REFRESH_MS: u64 = 100;
const SPARKLINE_WIDTH: f32 = 200.0;
const SPARKLINE_HEIGHT: f32 = 32.0;

/// ウォッチ対象の1エントリ
pub struct WatchEntry {
    pub instance: InstanceHandle,
    pub field: FieldHandle,
    pub field_name: String,
    pub class_name: String,
    pub type_info: TypeInfo,
    /// (経過秒, 値)
    pub history: VecDeque<(f64, Value)>,
    pub last_change_secs: Option<f64>,
    pub active: bool,
    pub visible: bool,
}

/// 変更ログエントリ
pub struct ChangeLogEntry {
    pub elapsed_secs: f64,
    pub field_name: String,
    pub class_name: String,
    pub old_display: String,
    pub new_display: String,
}

/// ウォッチ追加リクエスト（EngineView から MonitorView への通信用）
#[derive(Clone)]
pub struct WatchRequest {
    pub instance: InstanceHandle,
    pub field: FieldHandle,
    pub field_name: String,
    pub class_name: String,
    pub type_info: TypeInfo,
}

pub struct MonitorView {
    watches: Vec<WatchEntry>,
    change_log: VecDeque<ChangeLogEntry>,
    auto_refresh: bool,
    refresh_interval_ms: u64,
    last_refresh: Instant,
    paused: bool,
    show_log: bool,
    max_log_entries: usize,
    engine: Option<Arc<Mutex<Box<dyn GameEngine>>>>,
    start_time: Instant,
    poll_count: u64,
}

impl Default for MonitorView {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            watches: Vec::new(),
            change_log: VecDeque::new(),
            auto_refresh: true,
            refresh_interval_ms: DEFAULT_REFRESH_MS,
            last_refresh: now,
            paused: false,
            show_log: true,
            max_log_entries: 200,
            engine: None,
            start_time: now,
            poll_count: 0,
        }
    }
}

impl MonitorView {
    pub fn set_engine(&mut self, engine: Arc<Mutex<Box<dyn GameEngine>>>) {
        if self.engine.is_none() {
            self.engine = Some(engine);
        }
    }

    pub fn add_watch(&mut self, req: WatchRequest) {
        // 重複チェック
        if self
            .watches
            .iter()
            .any(|w| w.instance == req.instance && w.field == req.field)
        {
            return;
        }
        self.watches.push(WatchEntry {
            instance: req.instance,
            field: req.field,
            field_name: req.field_name,
            class_name: req.class_name,
            type_info: req.type_info,
            history: VecDeque::new(),
            last_change_secs: None,
            active: true,
            visible: true,
        });
    }

    pub fn has_watches(&self) -> bool {
        !self.watches.is_empty()
    }

    /// 全ウォッチをポーリング
    fn poll_values(&mut self) {
        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => return,
        };
        let engine = match engine.lock() {
            Ok(e) => e,
            Err(_) => return,
        };

        let elapsed = self.start_time.elapsed().as_secs_f64();

        for watch in &mut self.watches {
            if !watch.active {
                continue;
            }
            match engine.read_field(watch.instance, watch.field) {
                Ok(value) => {
                    // 変更検出
                    let changed = watch
                        .history
                        .back()
                        .map(|(_, v)| v != &value)
                        .unwrap_or(true);

                    if changed {
                        if let Some((_, old_val)) = watch.history.back() {
                            // ログに記録しない最初の値
                            let old_display = format!("{}", old_val);
                            let new_display = format!("{}", &value);
                            // change_log はこのループ外で追加できないのでここで直接は無理
                            // → 後で処理する
                            let _ = (old_display, new_display);
                        }
                        watch.last_change_secs = Some(elapsed);
                    }

                    watch.history.push_back((elapsed, value));
                    if watch.history.len() > MAX_HISTORY {
                        watch.history.pop_front();
                    }
                }
                Err(_) => {
                    watch.active = false;
                }
            }
        }

        self.poll_count += 1;
        self.last_refresh = Instant::now();
    }

    /// 変更ログを更新（poll後に呼ぶ）
    fn update_change_log(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();

        for watch in &self.watches {
            if !watch.active {
                continue;
            }
            let len = watch.history.len();
            if len >= 2 {
                let (_, prev) = &watch.history[len - 2];
                let (_, curr) = &watch.history[len - 1];
                if prev != curr {
                    self.change_log.push_back(ChangeLogEntry {
                        elapsed_secs: elapsed,
                        field_name: watch.field_name.clone(),
                        class_name: watch.class_name.clone(),
                        old_display: format!("{}", prev),
                        new_display: format!("{}", curr),
                    });
                    if self.change_log.len() > self.max_log_entries {
                        self.change_log.pop_front();
                    }
                }
            }
        }
    }

    /// UI描画
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        // 自動リフレッシュ
        if self.auto_refresh && !self.paused && self.engine.is_some() && !self.watches.is_empty() {
            let since_last = self.last_refresh.elapsed().as_millis() as u64;
            if since_last >= self.refresh_interval_ms {
                self.poll_values();
                self.update_change_log();
            }
            // 継続的に再描画を要求
            ui.ctx().request_repaint_after(
                std::time::Duration::from_millis(self.refresh_interval_ms),
            );
        }

        ui.heading("Monitor");

        // コントロールバー
        ui.horizontal(|ui| {
            let pause_label = if self.paused { "Resume" } else { "Pause" };
            if ui.button(pause_label).clicked() {
                self.paused = !self.paused;
            }

            if ui.button("Clear History").clicked() {
                for w in &mut self.watches {
                    w.history.clear();
                    w.last_change_secs = None;
                }
                self.change_log.clear();
            }

            if ui.button("Remove All").clicked() {
                self.watches.clear();
                self.change_log.clear();
            }

            ui.separator();

            ui.label("Interval:");
            let mut interval = self.refresh_interval_ms as f32;
            if ui
                .add(egui::Slider::new(&mut interval, 16.0..=2000.0).suffix("ms"))
                .changed()
            {
                self.refresh_interval_ms = interval as u64;
            }

            ui.separator();
            ui.checkbox(&mut self.show_log, "Change Log");

            ui.separator();
            ui.label(
                egui::RichText::new(format!(
                    "Polls: {} | Watches: {}",
                    self.poll_count,
                    self.watches.iter().filter(|w| w.active).count()
                ))
                .weak(),
            );
        });

        ui.separator();

        if self.watches.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(
                    egui::RichText::new("No watches added")
                        .size(18.0)
                        .weak(),
                );
                ui.label("Go to Engine Functions > select instance > click [Watch] on a field");
                ui.add_space(40.0);
            });
            return;
        }

        // ウォッチリスト
        let available_height = if self.show_log {
            ui.available_height() * 0.6
        } else {
            ui.available_height()
        };

        egui::ScrollArea::vertical()
            .id_salt("monitor_watches")
            .max_height(available_height)
            .show(ui, |ui| {
                self.render_watches(ui);
            });

        // 変更ログ
        if self.show_log {
            ui.separator();
            ui.collapsing(
                egui::RichText::new(format!("Change Log ({})", self.change_log.len())).strong(),
                |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("monitor_changelog")
                        .max_height(200.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            self.render_change_log(ui);
                        });
                },
            );
        }
    }

    fn render_watches(&mut self, ui: &mut egui::Ui) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let mut remove_idx: Option<usize> = None;

        for (i, watch) in self.watches.iter().enumerate() {
            let recently_changed = watch
                .last_change_secs
                .map(|t| elapsed - t < 0.5)
                .unwrap_or(false);

            let bg_color = if recently_changed {
                egui::Color32::from_rgba_unmultiplied(255, 255, 0, 20)
            } else if !watch.active {
                egui::Color32::from_rgba_unmultiplied(255, 0, 0, 10)
            } else {
                egui::Color32::TRANSPARENT
            };

            let frame = egui::Frame::NONE
                .fill(bg_color)
                .inner_margin(egui::Margin::same(4))
                .corner_radius(egui::CornerRadius::same(3));

            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    // 削除ボタン
                    if ui
                        .button(egui::RichText::new("x").small().color(egui::Color32::RED))
                        .clicked()
                    {
                        remove_idx = Some(i);
                    }

                    // ステータスインジケータ
                    let status_color = if !watch.active {
                        egui::Color32::RED
                    } else if recently_changed {
                        egui::Color32::YELLOW
                    } else {
                        egui::Color32::GREEN
                    };
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(8.0, 8.0),
                        egui::Sense::hover(),
                    );
                    ui.painter()
                        .circle_filled(rect.center(), 4.0, status_color);

                    // フィールド名とクラス
                    ui.label(
                        egui::RichText::new(&watch.field_name)
                            .strong()
                            .size(14.0),
                    );
                    ui.label(
                        egui::RichText::new(format!("({})", watch.class_name))
                            .weak()
                            .small(),
                    );
                    ui.label(
                        egui::RichText::new(format!("[{}]", watch.type_info.name))
                            .weak()
                            .small(),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // 現在値
                        if let Some((_, val)) = watch.history.back() {
                            let val_text = format!("{}", val);
                            let val_color = if recently_changed {
                                egui::Color32::YELLOW
                            } else {
                                egui::Color32::WHITE
                            };
                            ui.label(
                                egui::RichText::new(&val_text)
                                    .monospace()
                                    .color(val_color)
                                    .size(13.0),
                            );
                        } else {
                            ui.label(egui::RichText::new("--").weak());
                        }
                    });
                });

                // スパークライン（数値型のみ）
                if watch.history.len() >= 2 {
                    if let Some(points) = self.extract_numeric_history(watch) {
                        self.draw_sparkline(ui, &points, recently_changed);
                    }
                }
            });

            ui.add_space(2.0);
        }

        if let Some(idx) = remove_idx {
            self.watches.remove(idx);
        }
    }

    /// 数値履歴を f64 のベクタに変換
    fn extract_numeric_history(&self, watch: &WatchEntry) -> Option<Vec<(f64, f64)>> {
        let points: Vec<(f64, f64)> = watch
            .history
            .iter()
            .filter_map(|(t, v)| value_to_f64(v).map(|f| (*t, f)))
            .collect();
        if points.len() >= 2 {
            Some(points)
        } else {
            None
        }
    }

    /// スパークライングラフ描画
    fn draw_sparkline(&self, ui: &mut egui::Ui, points: &[(f64, f64)], highlight: bool) {
        let desired_size = egui::vec2(
            ui.available_width().min(SPARKLINE_WIDTH),
            SPARKLINE_HEIGHT,
        );
        let (rect, _response) = ui.allocate_exact_size(desired_size, egui::Sense::hover());

        if points.is_empty() || rect.width() < 2.0 {
            return;
        }

        let painter = ui.painter_at(rect);

        // 背景
        painter.rect_filled(
            rect,
            egui::CornerRadius::same(2),
            egui::Color32::from_gray(30),
        );

        // Y 軸の範囲
        let min_val = points.iter().map(|(_, v)| *v).fold(f64::MAX, f64::min);
        let max_val = points.iter().map(|(_, v)| *v).fold(f64::MIN, f64::max);
        let range = if (max_val - min_val).abs() < 1e-10 {
            1.0
        } else {
            max_val - min_val
        };

        // X 軸の範囲（時間）
        let t_min = points.first().unwrap().0;
        let t_max = points.last().unwrap().0;
        let t_range = if (t_max - t_min).abs() < 1e-10 {
            1.0
        } else {
            t_max - t_min
        };

        // ポイントをピクセル座標に変換
        let margin = 2.0;
        let plot_rect = rect.shrink(margin);
        let screen_points: Vec<egui::Pos2> = points
            .iter()
            .map(|(t, v)| {
                let x = plot_rect.left()
                    + ((t - t_min) / t_range) as f32 * plot_rect.width();
                let y = plot_rect.bottom()
                    - ((v - min_val) / range) as f32 * plot_rect.height();
                egui::pos2(x, y)
            })
            .collect();

        // グラフ下の塗りつぶし
        let fill_color = if highlight {
            egui::Color32::from_rgba_unmultiplied(255, 200, 0, 30)
        } else {
            egui::Color32::from_rgba_unmultiplied(0, 180, 255, 20)
        };
        for pair in screen_points.windows(2) {
            let p0 = pair[0];
            let p1 = pair[1];
            let bottom_left = egui::pos2(p0.x, plot_rect.bottom());
            let bottom_right = egui::pos2(p1.x, plot_rect.bottom());
            // 四角形で塗りつぶし
            painter.rect_filled(
                egui::Rect::from_two_pos(
                    egui::pos2(p0.x, p0.y.min(p1.y)),
                    bottom_right,
                ),
                egui::CornerRadius::ZERO,
                fill_color,
            );
        }

        // ライン描画
        let line_color = if highlight {
            egui::Color32::from_rgb(255, 220, 50)
        } else {
            egui::Color32::from_rgb(0, 200, 255)
        };
        for pair in screen_points.windows(2) {
            painter.line_segment([pair[0], pair[1]], egui::Stroke::new(1.5, line_color));
        }

        // 最新値のドット
        if let Some(&last) = screen_points.last() {
            painter.circle_filled(last, 3.0, line_color);
        }

        // min/max ラベル
        painter.text(
            egui::pos2(plot_rect.right() - 2.0, plot_rect.top()),
            egui::Align2::RIGHT_TOP,
            format_compact(max_val),
            egui::FontId::monospace(9.0),
            egui::Color32::from_gray(120),
        );
        painter.text(
            egui::pos2(plot_rect.right() - 2.0, plot_rect.bottom()),
            egui::Align2::RIGHT_BOTTOM,
            format_compact(min_val),
            egui::FontId::monospace(9.0),
            egui::Color32::from_gray(120),
        );
    }

    fn render_change_log(&self, ui: &mut egui::Ui) {
        if self.change_log.is_empty() {
            ui.label(egui::RichText::new("No changes recorded yet").weak());
            return;
        }

        egui::Grid::new("change_log_grid")
            .striped(true)
            .num_columns(5)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Time").strong().small());
                ui.label(egui::RichText::new("Class").strong().small());
                ui.label(egui::RichText::new("Field").strong().small());
                ui.label(egui::RichText::new("Old").strong().small());
                ui.label(egui::RichText::new("New").strong().small());
                ui.end_row();

                // 最新のログを末尾から表示
                for entry in self.change_log.iter().rev().take(100) {
                    ui.label(
                        egui::RichText::new(format!("{:.1}s", entry.elapsed_secs))
                            .monospace()
                            .small()
                            .color(egui::Color32::GRAY),
                    );
                    ui.label(
                        egui::RichText::new(&entry.class_name)
                            .small()
                            .color(egui::Color32::LIGHT_BLUE),
                    );
                    ui.label(egui::RichText::new(&entry.field_name).small());
                    ui.label(
                        egui::RichText::new(&entry.old_display)
                            .monospace()
                            .small()
                            .color(egui::Color32::from_rgb(255, 100, 100)),
                    );
                    ui.label(
                        egui::RichText::new(&entry.new_display)
                            .monospace()
                            .small()
                            .color(egui::Color32::from_rgb(100, 255, 100)),
                    );
                    ui.end_row();
                }
            });
    }
}

/// Value を f64 に変換（数値型のみ）
fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::I8(v) => Some(*v as f64),
        Value::I16(v) => Some(*v as f64),
        Value::I32(v) => Some(*v as f64),
        Value::I64(v) => Some(*v as f64),
        Value::U8(v) => Some(*v as f64),
        Value::U16(v) => Some(*v as f64),
        Value::U32(v) => Some(*v as f64),
        Value::U64(v) => Some(*v as f64),
        Value::F32(v) => Some(*v as f64),
        Value::F64(v) => Some(*v),
        _ => None,
    }
}

/// 数値のコンパクト表示
fn format_compact(v: f64) -> String {
    if v.abs() < 0.01 && v != 0.0 {
        format!("{:.2e}", v)
    } else if v.abs() >= 1_000_000.0 {
        format!("{:.1e}", v)
    } else if v == v.floor() {
        format!("{:.0}", v)
    } else {
        format!("{:.2}", v)
    }
}
