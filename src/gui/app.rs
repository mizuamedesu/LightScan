use crate::gui::{process_list::ProcessListView, results_view::ResultsView, scan_view::ScanView};
use crate::platform::ProcessInfo;
use crate::scanner::{Process, Scanner};
use crate::types::{ScanOptions, ScanValue, ValueType};
use eframe::egui;
use std::sync::{Arc, Mutex};

/// Main application state
pub struct LightScanApp {
    // Process management
    process_list_view: ProcessListView,
    selected_process: Option<ProcessInfo>,
    scanner: Option<Arc<Mutex<Scanner>>>,

    // Scanning
    scan_view: ScanView,
    results_view: ResultsView,

    // UI state
    show_process_list: bool,
    error_message: Option<String>,
    status_message: String,
    is_elevated: bool,
}

impl Default for LightScanApp {
    fn default() -> Self {
        let is_elevated = crate::platform::elevation::is_elevated().unwrap_or(false);

        Self {
            process_list_view: ProcessListView::default(),
            selected_process: None,
            scanner: None,
            scan_view: ScanView::default(),
            results_view: ResultsView::default(),
            show_process_list: false,
            error_message: None,
            status_message: if is_elevated {
                "Ready. Select a process to begin.".to_string()
            } else {
                "Running without administrator privileges. Some processes may be inaccessible.".to_string()
            },
            is_elevated,
        }
    }
}

impl LightScanApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    fn select_process(&mut self, process_info: ProcessInfo) {
        match Process::from_info(&process_info) {
            Ok(process) => {
                self.selected_process = Some(process_info.clone());
                self.scanner = Some(Arc::new(Mutex::new(Scanner::new(process))));
                self.status_message = format!("Process {} ({}) opened successfully",
                    process_info.name, process_info.pid);
                self.error_message = None;
                self.show_process_list = false;

                // Reset scan state
                self.scan_view.reset();
                self.results_view.clear();
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to open process: {}", e));
                self.scanner = None;
            }
        }
    }

    fn perform_first_scan(&mut self) {
        if let Some(scanner) = &self.scanner {
            let value_str = &self.scan_view.value_input;
            let value_type = self.scan_view.selected_value_type;
            let scan_type = self.scan_view.selected_scan_type;

            // Parse value
            let value = match self.parse_value(value_str, value_type) {
                Ok(v) => v,
                Err(e) => {
                    self.error_message = Some(format!("Invalid value: {}", e));
                    return;
                }
            };

            // Create scan options
            let options = ScanOptions::new(value_type)
                .with_alignment(self.scan_view.alignment);

            // Perform scan
            self.status_message = "Scanning...".to_string();
            self.error_message = None;

            match scanner.lock() {
                Ok(mut scanner) => {
                    match scanner.first_scan(&value, scan_type, &options) {
                        Ok(count) => {
                            self.status_message = format!("First scan complete. Found {} results", count);
                            self.results_view.update_from_scanner(&scanner);
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Scan failed: {}", e));
                            self.status_message = "Scan failed".to_string();
                        }
                    }
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to lock scanner: {}", e));
                }
            }
        }
    }

    fn perform_next_scan(&mut self) {
        if let Some(scanner) = &self.scanner {
            let value_str = &self.scan_view.value_input;
            let value_type = self.scan_view.selected_value_type;
            let scan_type = self.scan_view.selected_scan_type;

            // Parse value if needed
            let value = if scan_type.requires_value() {
                match self.parse_value(value_str, value_type) {
                    Ok(v) => v,
                    Err(e) => {
                        self.error_message = Some(format!("Invalid value: {}", e));
                        return;
                    }
                }
            } else {
                ScanValue::I32(0) // Dummy value for scans that don't need it
            };

            self.status_message = "Scanning...".to_string();
            self.error_message = None;

            match scanner.lock() {
                Ok(mut scanner) => {
                    match scanner.next_scan(&value, scan_type) {
                        Ok(count) => {
                            self.status_message = format!("Next scan complete. {} results remaining", count);
                            self.results_view.update_from_scanner(&scanner);
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Scan failed: {}", e));
                            self.status_message = "Scan failed".to_string();
                        }
                    }
                }
                Err(e) => {
                    self.error_message = Some(format!("Failed to lock scanner: {}", e));
                }
            }
        }
    }

    fn reset_scan(&mut self) {
        if let Some(scanner) = &self.scanner {
            if let Ok(mut scanner) = scanner.lock() {
                scanner.reset();
                self.results_view.clear();
                self.scan_view.reset();
                self.status_message = "Scan reset".to_string();
            }
        }
    }

    fn parse_value(&self, value_str: &str, value_type: ValueType) -> Result<ScanValue, String> {
        match value_type {
            ValueType::I8 => value_str
                .parse::<i8>()
                .map(ScanValue::I8)
                .map_err(|e| e.to_string()),
            ValueType::I16 => value_str
                .parse::<i16>()
                .map(ScanValue::I16)
                .map_err(|e| e.to_string()),
            ValueType::I32 => value_str
                .parse::<i32>()
                .map(ScanValue::I32)
                .map_err(|e| e.to_string()),
            ValueType::I64 => value_str
                .parse::<i64>()
                .map(ScanValue::I64)
                .map_err(|e| e.to_string()),
            ValueType::U8 => value_str
                .parse::<u8>()
                .map(ScanValue::U8)
                .map_err(|e| e.to_string()),
            ValueType::U16 => value_str
                .parse::<u16>()
                .map(ScanValue::U16)
                .map_err(|e| e.to_string()),
            ValueType::U32 => value_str
                .parse::<u32>()
                .map(ScanValue::U32)
                .map_err(|e| e.to_string()),
            ValueType::U64 => value_str
                .parse::<u64>()
                .map(ScanValue::U64)
                .map_err(|e| e.to_string()),
            ValueType::F32 => value_str
                .parse::<f32>()
                .map(ScanValue::F32)
                .map_err(|e| e.to_string()),
            ValueType::F64 => value_str
                .parse::<f64>()
                .map(ScanValue::F64)
                .map_err(|e| e.to_string()),
            ValueType::ByteArray(_) => Err("Byte array input not yet implemented".to_string()),
        }
    }
}

impl eframe::App for LightScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel with menu
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Select Process").clicked() {
                        self.show_process_list = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Edit", |ui| {
                    if ui.button("Reset Scan").clicked() {
                        self.reset_scan();
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        ui.close_menu();
                    }
                });
            });
        });

        // Bottom panel with status bar
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.label(&self.status_message);
            });
        });

        // Process list dialog
        if self.show_process_list {
            egui::Window::new("Select Process")
                .collapsible(false)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    if let Some(selected) = self.process_list_view.ui(ui) {
                        self.select_process(selected);
                    }

                    ui.separator();
                    if ui.button("Close").clicked() {
                        self.show_process_list = false;
                    }
                });
        }

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            // Administrator privilege warning banner
            if !self.is_elevated {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 200, 0),
                        "⚠ Not running with administrator privileges.",
                    );
                    ui.label("Some processes may be inaccessible.");

                    if ui.button("Restart as Administrator").clicked() {
                        if let Err(e) = crate::platform::elevation::restart_as_admin() {
                            self.error_message = Some(format!("Failed to restart: {}", e));
                        }
                    }
                });
                ui.separator();
            }

            // Process selection header
            ui.horizontal(|ui| {
                ui.label("Process:");
                if let Some(ref process) = self.selected_process {
                    ui.label(format!("{} ({})", process.name, process.pid));
                } else {
                    ui.label("None selected");
                }

                if ui.button("Select Process").clicked() {
                    self.show_process_list = true;
                }
            });

            ui.separator();

            // Error message
            if let Some(ref error) = self.error_message {
                ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                ui.separator();
            }

            // Only show scan UI if a process is selected
            if self.scanner.is_some() {
                ui.columns(2, |columns| {
                    // Left panel - Scan controls
                    columns[0].vertical(|ui| {
                        ui.heading("Scan");

                        self.scan_view.ui(ui);

                        ui.separator();

                        // Scan buttons
                        ui.horizontal(|ui| {
                            if ui.button("First Scan").clicked() {
                                self.perform_first_scan();
                            }

                            if ui.button("Next Scan").clicked() {
                                self.perform_next_scan();
                            }
                        });

                        ui.horizontal(|ui| {
                            if ui.button("Reset").clicked() {
                                self.reset_scan();
                            }
                        });

                        ui.separator();
                        ui.label(format!("Results: {}", self.results_view.result_count()));
                    });

                    // Right panel - Results
                    columns[1].vertical(|ui| {
                        ui.heading("Results");
                        self.results_view.ui(ui, &self.scanner);
                    });
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.heading("No Process Selected");
                    ui.label("Click 'Select Process' to choose a process to scan");
                });
            }
        });
    }
}
