//! Ruby gem lifecycle commands
//!
//! Provides build, push, and version bump operations for Ruby gems.

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

/// Find the version.rb file for a gem.
///
/// Searches for the pattern `lib/<gem-name>/version.rb` where the gem name
/// may use hyphens in the directory name (e.g., `lib/abstract-synthesizer/version.rb`).
fn find_version_file(dir: &Path, gem_name: &str) -> Result<std::path::PathBuf> {
    // Try hyphenated name first (abstract-synthesizer → lib/abstract-synthesizer/version.rb)
    let path = dir.join("lib").join(gem_name).join("version.rb");
    if path.exists() {
        return Ok(path);
    }

    // Try underscored name (abstract-synthesizer → lib/abstract_synthesizer/version.rb)
    let underscored = gem_name.replace('-', "_");
    let path = dir.join("lib").join(&underscored).join("version.rb");
    if path.exists() {
        return Ok(path);
    }

    bail!(
        "Version file not found. Tried:\n  lib/{}/version.rb\n  lib/{}/version.rb",
        gem_name,
        underscored
    )
}

/// Parse a semver version string into (major, minor, patch).
fn parse_version(version: &str) -> Result<(u64, u64, u64)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid version format '{}' — expected X.Y.Z", version);
    }

    let major = parts[0].parse::<u64>().context("Invalid major version")?;
    let minor = parts[1].parse::<u64>().context("Invalid minor version")?;
    let patch = parts[2].parse::<u64>().context("Invalid patch version")?;

    Ok((major, minor, patch))
}

/// Bump a version by the given level.
fn bump_version(major: u64, minor: u64, patch: u64, level: &str) -> Result<String> {
    match level {
        "patch" => Ok(format!("{}.{}.{}", major, minor, patch + 1)),
        "minor" => Ok(format!("{}.{}.0", major, minor + 1)),
        "major" => Ok(format!("{}.0.0", major + 1)),
        _ => bail!("Invalid bump level '{}' — use patch, minor, or major", level),
    }
}

/// Bump the version in a gem's version.rb file.
///
/// Finds `VERSION = %(X.Y.Z).freeze` and updates it.
/// Returns (old_version, new_version).
pub fn bump(working_dir: &str, level: &str, name: Option<String>) -> Result<(String, String)> {
    let dir = Path::new(working_dir);
    if !dir.exists() {
        bail!("Working directory not found: {}", working_dir);
    }

    let gem_name = match name {
        Some(n) => n,
        None => detect_gem_name(dir)?,
    };

    let version_file = find_version_file(dir, &gem_name)?;
    let content = std::fs::read_to_string(&version_file)
        .with_context(|| format!("Failed to read {}", version_file.display()))?;

    // Match VERSION = %(X.Y.Z).freeze
    let re = regex::Regex::new(r#"VERSION\s*=\s*%\((\d+\.\d+\.\d+)\)\.freeze"#)
        .context("Failed to compile version regex")?;

    let caps = re
        .captures(&content)
        .with_context(|| format!("No VERSION = %(X.Y.Z).freeze found in {}", version_file.display()))?;

    let old_version = caps[1].to_string();
    let (major, minor, patch) = parse_version(&old_version)?;
    let new_version = bump_version(major, minor, patch, level)?;

    // Replace in file
    let new_content = content.replace(
        &format!("VERSION = %({}).freeze", old_version),
        &format!("VERSION = %({}).freeze", new_version),
    );

    std::fs::write(&version_file, &new_content)
        .with_context(|| format!("Failed to write {}", version_file.display()))?;

    info!(
        "{}: {} → {} ({})",
        gem_name, old_version, new_version, level
    );

    Ok((old_version, new_version))
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
pub fn push(
    working_dir: &str,
    name: Option<String>,
    api_key: Option<String>,
    otp: Option<String>,
) -> Result<()> {
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

    // Write credentials file (gem push reads from ~/.gem/credentials)
    let home = std::env::var("HOME").context("HOME not set")?;
    let gem_dir = Path::new(&home).join(".gem");
    std::fs::create_dir_all(&gem_dir)?;
    let creds_path = gem_dir.join("credentials");
    let creds_content = format!("---\n:rubygems_api_key: {}\n", key);
    std::fs::write(&creds_path, &creds_content)?;

    // Set permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("=== Build ===");
    let gem_file = build(working_dir, name)?;

    info!("=== Push ===");
    let gem_path = Path::new(working_dir).join(&gem_file);

    let mut args = vec!["push".to_string(), gem_path.to_str().unwrap().to_string()];
    if let Some(otp_code) = &otp {
        args.push("--otp".to_string());
        args.push(otp_code.clone());
    }

    let status = Command::new("gem")
        .args(&args)
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
