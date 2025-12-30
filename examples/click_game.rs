// Simple click game for testing LightScan
// GUI version using eframe/egui

use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct GameState {
    score: i32,
    coins: i32,
    hp: i32,
    max_hp: i32,
    level: i32,
    experience: i32,
    last_regen: Instant,
    message: String,
}

impl GameState {
    fn new() -> Self {
        Self {
            score: 0,
            coins: 100,
            hp: 100,
            max_hp: 100,
            level: 1,
            experience: 0,
            last_regen: Instant::now(),
            message: String::new(),
        }
    }

    fn click(&mut self) {
        self.score += 1;
        self.experience += 10;
        self.message = "Clicked! +1 score, +10 exp".to_string();
        self.check_level_up();
    }

    fn buy_health_potion(&mut self) {
        if self.coins >= 50 {
            self.coins -= 50;
            self.hp = (self.hp + 20).min(self.max_hp);
            self.message = "Bought potion! +20 HP, -50 coins".to_string();
        } else {
            self.message = "Not enough coins! Need 50".to_string();
        }
    }

    fn take_damage(&mut self) {
        self.hp = (self.hp - 10).max(0);
        self.message = "Took damage! -10 HP".to_string();
    }

    fn work(&mut self) {
        self.coins += 50;
        self.message = "Worked! +50 coins".to_string();
    }

    fn check_level_up(&mut self) {
        let exp_needed = self.level * 100;
        if self.experience >= exp_needed {
            self.level += 1;
            self.experience -= exp_needed;
            self.max_hp += 10;
            self.hp = self.max_hp;
            self.message = format!("LEVEL UP! Now level {}", self.level);
        }
    }

    fn update(&mut self) {
        if self.last_regen.elapsed() >= Duration::from_secs(5) {
            if self.hp > 0 && self.hp < self.max_hp {
                self.hp = (self.hp + 5).min(self.max_hp);
            }
            self.last_regen = Instant::now();
        }
    }
}

struct ClickGameApp {
    state: GameState,
}

impl Default for ClickGameApp {
    fn default() -> Self {
        Self {
            state: GameState::new(),
        }
    }
}

impl eframe::App for ClickGameApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.update();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Click Game - Memory Scanner Test");
            ui.label(format!("Process ID: {}", std::process::id()));
            ui.separator();

            // Stats display
            egui::Grid::new("stats").show(ui, |ui| {
                ui.label("Score:");
                ui.label(format!("{}", self.state.score));
                ui.label(format!("Address: {:p}", &self.state.score));
                ui.end_row();

                ui.label("Coins:");
                ui.label(format!("{}", self.state.coins));
                ui.label(format!("Address: {:p}", &self.state.coins));
                ui.end_row();

                ui.label("HP:");
                ui.add(egui::ProgressBar::new(self.state.hp as f32 / self.state.max_hp as f32)
                    .text(format!("{}/{}", self.state.hp, self.state.max_hp)));
                ui.label(format!("Address: {:p}", &self.state.hp));
                ui.end_row();

                ui.label("Level:");
                ui.label(format!("{}", self.state.level));
                ui.label(format!("Address: {:p}", &self.state.level));
                ui.end_row();

                ui.label("Experience:");
                let exp_needed = self.state.level * 100;
                ui.add(egui::ProgressBar::new(self.state.experience as f32 / exp_needed as f32)
                    .text(format!("{}/{}", self.state.experience, exp_needed)));
                ui.label(format!("Address: {:p}", &self.state.experience));
                ui.end_row();
            });

            ui.separator();

            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("Click (+1 score)").clicked() {
                    self.state.click();
                }
                if ui.button("Buy Potion (50 coins)").clicked() {
                    self.state.buy_health_potion();
                }
            });

            ui.horizontal(|ui| {
                if ui.button("Take Damage (-10 HP)").clicked() {
                    self.state.take_damage();
                }
                if ui.button("Work (+50 coins)").clicked() {
                    self.state.work();
                }
            });

            ui.separator();

            // Message
            if !self.state.message.is_empty() {
                ui.colored_label(egui::Color32::from_rgb(100, 200, 100), &self.state.message);
            }

            ui.separator();
            ui.label("HP regenerates +5 every 5 seconds");
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Click Game")
            .with_inner_size([500.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Click Game",
        options,
        Box::new(|_cc| Ok(Box::new(ClickGameApp::default()))),
    )
}
