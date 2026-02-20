// Terminal UI utilities
// This module can be expanded with custom widgets, tables, etc.

use colored::Colorize;

pub fn print_header(title: &str) {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!("{}", format!("║  {:<58}║", title).bright_blue());
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();
}

pub fn print_success(message: &str) {
    println!("{}", format!("✅ {}", message).bright_green().bold());
}

pub fn print_error(message: &str) {
    eprintln!("{}", format!("❌ {}", message).bright_red().bold());
}

pub fn print_info(message: &str) {
    println!("{}", format!("ℹ️  {}", message).bright_cyan());
}

pub fn print_warning(message: &str) {
    println!("{}", format!("⚠️  {}", message).bright_yellow());
}
