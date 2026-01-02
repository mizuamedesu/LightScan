// LightScan - High-performance memory scanner
// Main entry point for the GUI application

use lightscan::LightScanApp;

fn main() -> eframe::Result<()> {
    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_target(false)
        .with_level(false)
        .init();

    tracing::info!("Starting LightScan...");

    // Configure the native window options
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LightScan - Memory Scanner")
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "LightScan",
        native_options,
        Box::new(|cc| Ok(Box::new(LightScanApp::new(cc)))),
    )
}
