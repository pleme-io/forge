//! Nix builder entrypoint
//!
//! Simple entrypoint that starts nix-daemon and sshd after provisioning is complete.
//! Replaces the shell script entrypoint with pure Rust implementation.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Recursively copy directory contents from src to dst
/// Handles cross-filesystem copying (unlike fs::rename)
fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // Skip if destination already exists
        if dst_path.exists() {
            continue;
        }

        if src_path.is_dir() {
            // Recursively copy subdirectory
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            // Copy file
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Setup shared storage directories and create symlinks
/// Creates directories in /var/lib/nix-builder and symlinks system paths to them
fn setup_shared_storage() -> std::io::Result<()> {
    const SHARED_BASE: &str = "/var/lib/nix-builder";

    // Create base directory
    fs::create_dir_all(SHARED_BASE)?;

    // Define directories and files we need to share between init and main containers
    let shared_items = vec![
        ("root", "/root"),
        ("etc-ssh", "/etc/ssh"),
        ("etc-nix", "/etc/nix"),
        ("etc-passwd", "/etc/passwd"),
        ("etc-shadow", "/etc/shadow"),
        ("etc-group", "/etc/group"),
        ("usr-bin", "/usr/bin"),
    ];

    for (subdir, system_path) in shared_items {
        let shared_path = format!("{}/{}", SHARED_BASE, subdir);

        // Check if system path is already a symlink to the correct location
        if let Ok(link_target) = fs::read_link(system_path) {
            if link_target.to_str() == Some(&shared_path) {
                println!("✓ {} already symlinked to {}", system_path, shared_path);
                continue;
            }
            // Wrong symlink, remove it
            fs::remove_file(system_path)?;
        }

        // Handle system path based on its type
        if let Ok(metadata) = fs::symlink_metadata(system_path) {
            if metadata.is_dir() {
                // Create directory in shared storage if it doesn't exist
                if !Path::new(&shared_path).exists() {
                    fs::create_dir_all(&shared_path)?;
                }

                // Copy contents from system path to shared storage
                println!("Copying contents from {} to {}", system_path, shared_path);
                copy_dir_contents(Path::new(system_path), Path::new(&shared_path))?;

                // Remove original directory
                fs::remove_dir_all(system_path)?;
            } else if metadata.is_file() {
                // For files, copy the file if it doesn't exist in shared storage
                if !Path::new(&shared_path).exists() {
                    println!("Copying file from {} to {}", system_path, shared_path);
                    fs::copy(system_path, &shared_path)?;
                }

                // Remove original file
                fs::remove_file(system_path)?;
            }
        } else {
            // System path doesn't exist yet, create parent directory in shared storage if needed
            if let Some(parent) = Path::new(&shared_path).parent() {
                fs::create_dir_all(parent)?;
            }
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = Path::new(system_path).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        // Create symlink from system path to shared storage
        #[cfg(unix)]
        std::os::unix::fs::symlink(&shared_path, system_path)?;

        println!("✓ {} -> {}", system_path, shared_path);
    }

    Ok(())
}

/// Find a binary in PATH using 'which'
fn find_binary(name: &str) -> Option<String> {
    if let Ok(output) = Command::new("which").arg(name).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    None
}

fn main() {
    // Setup shared storage symlinks (same as init container)
    println!("Setting up shared storage symlinks...");
    if let Err(e) = setup_shared_storage() {
        eprintln!("Failed to setup shared storage: {}", e);
        std::process::exit(1);
    }

    println!("Starting nix-daemon in background...");

    // Find nix-daemon in PATH, fallback to common location
    let nix_daemon_path = find_binary("nix-daemon")
        .unwrap_or_else(|| "/root/.nix-profile/bin/nix-daemon".to_string());

    // Start nix-daemon in background
    let nix_daemon = Command::new(&nix_daemon_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn();

    match nix_daemon {
        Ok(mut child) => {
            // Spawn a thread to wait for the child process
            // This prevents it from becoming a zombie
            thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            eprintln!("Failed to start nix-daemon: {}", e);
            std::process::exit(1);
        }
    }

    // Wait for nix-daemon to be ready
    println!("Waiting for nix-daemon to be ready...");
    thread::sleep(Duration::from_secs(2));

    // Start SSH daemon (exec into it - becomes PID 1 replacement)
    println!("Starting SSH daemon...");

    // Debug: List SSH directory contents
    println!("DEBUG: Listing /etc/ssh directory:");
    if let Ok(entries) = std::fs::read_dir("/etc/ssh") {
        for entry in entries {
            if let Ok(entry) = entry {
                let metadata = entry.metadata().ok();
                let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                println!("  - {} ({} bytes)", entry.file_name().to_string_lossy(), size);
            }
        }
    } else {
        eprintln!("✗ Cannot read /etc/ssh directory!");
    }

    // Verify SSH host keys exist
    let key_types = vec!["rsa", "ed25519"];
    for key_type in &key_types {
        let key_path = format!("/etc/ssh/ssh_host_{}_key", key_type);
        match std::fs::metadata(&key_path) {
            Ok(metadata) => {
                println!("✓ SSH {} host key exists (permissions: {:o})", key_type, metadata.permissions().mode());
            }
            Err(e) => {
                eprintln!("✗ SSH {} host key missing: {}", key_type, e);
            }
        }
    }

    // Find sshd in PATH, fallback to profile location
    let sshd_path = find_binary("sshd")
        .unwrap_or_else(|| "/root/.nix-profile/bin/sshd".to_string());

    println!("Using sshd at: {}", sshd_path);

    // Test sshd configuration before exec
    println!("Testing sshd configuration...");
    let test_result = Command::new(&sshd_path)
        .arg("-t")  // Test configuration
        .output();

    match test_result {
        Ok(output) => {
            if !output.status.success() {
                eprintln!("sshd configuration test failed:");
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            } else {
                println!("✓ sshd configuration is valid");
            }
        }
        Err(e) => {
            eprintln!("Failed to test sshd configuration: {}", e);
        }
    }

    // Exec into sshd (replaces current process)
    let err = Command::new(&sshd_path)
        .arg("-D")  // Don't daemonize
        .arg("-e")  // Log to stderr
        .exec();    // This never returns if successful

    // If we get here, exec failed
    eprintln!("Failed to exec into sshd: {}", err);
    std::process::exit(1);
}
