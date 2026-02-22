//! Ruby gem lifecycle commands
//!
//! Provides build and push operations for publishing Ruby gems to RubyGems.org.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tracing::info;

/// Detect the gem name from a directory by finding the single *.gemspec file.
fn detect_gem_name(dir: &Path) -> Result<String> {
    let gemspecs: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.ends_with(".gemspec"))
                .unwrap_or(false)
        })
        .collect();

    match gemspecs.len() {
        0 => bail!("No .gemspec file found in {}", dir.display()),
        1 => {
            let name = gemspecs[0]
                .file_name()
                .to_str()
                .unwrap()
                .trim_end_matches(".gemspec")
                .to_string();
            Ok(name)
        }
        n => bail!(
            "Found {} .gemspec files in {} — use --name to specify which one",
            n,
            dir.display()
        ),
    }
}

/// Build a .gem file from a gemspec.
pub fn build(working_dir: &str, name: Option<String>) -> Result<String> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    let gemspec = format!("{}.gemspec", gem_name);
    let gemspec_path = dir.join(&gemspec);
    if !gemspec_path.exists() {
        bail!("Gemspec not found: {}", gemspec_path.display());
    }

    info!("Building gem: {}", gem_name);

    // Clean previous .gem files for this gem
    for entry in std::fs::read_dir(dir)? {
        if let Ok(e) = entry {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with(&gem_name) && name.ends_with(".gem") {
                    std::fs::remove_file(e.path())?;
                }
            }
        }
    }

    // gem build
    let status = Command::new("gem")
        .args(["build", &gemspec])
        .current_dir(dir)
        .status()
        .context("Failed to run gem build")?;

    if !status.success() {
        bail!("gem build failed for {}", gemspec);
    }

    // Find the built .gem file
    let gem_file = find_gem_file(dir, &gem_name)?;
    info!("Built: {}", gem_file);
    Ok(gem_file)
}

/// Build and push a gem to RubyGems.org.
pub fn push(working_dir: &str, name: Option<String>, api_key: Option<String>) -> Result<()> {
    // Resolve API key
    let key = match api_key {
        Some(k) => k,
        None => {
            // Try reading from file
            let home = std::env::var("HOME").context("HOME not set")?;
            let key_file = Path::new(&home).join(".config/rubygems/api-key");

            if key_file.exists() {
                std::fs::read_to_string(&key_file)
                    .context("Failed to read ~/.config/rubygems/api-key")?
                    .trim()
                    .to_string()
            } else {
                bail!(
                    "No API key provided. Set GEM_HOST_API_KEY env var, \
                     pass --api-key, or create ~/.config/rubygems/api-key"
                );
            }
        }
    };

    info!("=== Build ===");
    let gem_file = build(working_dir, name)?;

    info!("=== Push ===");
    let gem_path = Path::new(working_dir).join(&gem_file);

    let status = Command::new("gem")
        .args(["push", gem_path.to_str().unwrap()])
        .env("GEM_HOST_API_KEY", &key)
        .status()
        .context("Failed to run gem push")?;

    if !status.success() {
        bail!("gem push failed for {}", gem_file);
    }

    info!("Published: {}", gem_file);
    Ok(())
}

// --- Helpers ---

fn find_gem_file(dir: &Path, prefix: &str) -> Result<String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix) && n.ends_with(".gem") && !n.ends_with(".gemspec"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    entries
        .first()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .context(format!("No .gem file found for {} in {}", prefix, dir.display()))
}
