//! Nix builder provisioning
//!
//! Handles idempotent provisioning of Nix remote builders with SSH access,
//! cache configuration, and system setup.

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

use crate::config::NixBuilderConfig;

/// Provision a Nix builder from YAML configuration (idempotent)
///
/// Configures a complete Nix remote builder with:
/// - System user setup (root account, sshd user)
/// - SSH server configuration
/// - Nix daemon configuration with binary cache
/// - Attic cache authentication (optional)
/// - PATH setup for remote builds
///
/// Safe to run multiple times - will skip or update existing configuration.
///
/// # Arguments
/// * `config` - Nix builder provisioning configuration
pub async fn provision_from_config(config: NixBuilderConfig) -> Result<()> {
    info!("=== Nix Builder Provisioning (Idempotent) ===");
    info!("SSH port: {}", config.ssh.port);
    info!(
        "Nix substituters: {}",
        config.nix.substituters.join(", ")
    );

    // Read SSH authorized keys from environment
    let authorized_keys = env::var(&config.ssh_keys_env).with_context(|| {
        format!(
            "Failed to read SSH authorized_keys from environment variable: {}",
            config.ssh_keys_env
        )
    })?;

    if authorized_keys.trim().is_empty() {
        anyhow::bail!(
            "SSH authorized_keys from environment variable {} is empty",
            config.ssh_keys_env
        );
    }

    // 0. Setup shared storage directories and symlinks
    info!("1. Setting up shared storage directories...");
    setup_shared_storage()?;

    // 1. Install required packages into Nix profile
    info!("2. Installing required packages into Nix profile...");
    install_nix_packages(&config.nix.packages_to_install)?;

    // 2. Setup system users
    info!("3. Setting up system users...");
    setup_system_users()?;

    // 4. Configure SSH
    info!("4. Configuring SSH server...");
    configure_ssh(&config.ssh, &authorized_keys)?;

    // 5. Generate SSH host keys
    info!("5. Generating SSH host keys...");
    generate_ssh_host_keys(&config.ssh.host_key_types)?;

    // Debug: List SSH directory contents
    if let Ok(entries) = fs::read_dir("/etc/ssh") {
        info!("DEBUG: Contents of /etc/ssh after key generation:");
        for entry in entries {
            if let Ok(entry) = entry {
                let metadata = entry.metadata().ok();
                let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                info!("  - {} ({} bytes)", entry.file_name().to_string_lossy(), size);
            }
        }
    }

    // 6. Configure Nix daemon
    info!("6. Configuring Nix daemon...");
    configure_nix(&config.nix, config.attic.as_ref())?;

    // 7. Configure Attic cache (if enabled)
    if let Some(attic_config) = &config.attic {
        info!("7. Configuring Attic cache authentication...");
        configure_attic(attic_config)?;
    } else {
        info!("7. Attic cache configuration skipped (not enabled)");
    }

    // 8. Setup PATH symlinks
    info!("8. Creating symlinks for Nix binaries...");
    setup_nix_symlinks(&config.nix.binaries_to_symlink)?;

    // 9. Setup .profile for interactive sessions
    info!("9. Setting up .profile...");
    setup_profile()?;

    info!("");
    info!("=== Nix Builder Provisioning Complete ===");
    info!("✓ SSH server is configured on port {}", config.ssh.port);
    info!("✓ Nix daemon is configured with binary caches");
    if config.attic.is_some() {
        info!("✓ Attic cache authentication is configured");
    }
    info!("");
    info!("To start services, run:");
    info!("  nix-daemon & ");
    info!("  /root/.nix-profile/bin/sshd -D");

    Ok(())
}

/// Recursively copy directory contents from src to dst
/// Handles cross-filesystem copying (unlike fs::rename)
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create destination directory {:?}", dst))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("Failed to read source directory {:?}", src))?
    {
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
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("Failed to copy {:?} to {:?}", src_path, dst_path))?;
        }
    }

    Ok(())
}

/// Setup shared storage directories and create symlinks
/// Creates directories in /var/lib/nix-builder and symlinks system paths to them
fn setup_shared_storage() -> Result<()> {
    const SHARED_BASE: &str = "/var/lib/nix-builder";

    // Create base directory
    fs::create_dir_all(SHARED_BASE)
        .context("Failed to create shared storage base directory")?;

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
            if link_target == Path::new(&shared_path) {
                info!("✓ {} already symlinked to {}", system_path, shared_path);
                continue;
            }
            // Wrong symlink, remove it
            fs::remove_file(system_path)
                .with_context(|| format!("Failed to remove incorrect symlink {}", system_path))?;
        }

        // Handle system path based on its type
        if let Ok(metadata) = fs::symlink_metadata(system_path) {
            if metadata.is_dir() {
                // Create directory in shared storage if it doesn't exist
                if !Path::new(&shared_path).exists() {
                    fs::create_dir_all(&shared_path)
                        .with_context(|| format!("Failed to create {}", shared_path))?;
                }

                // Copy contents from system path to shared storage
                info!("Copying contents from {} to {}", system_path, shared_path);
                copy_dir_contents(Path::new(system_path), Path::new(&shared_path))?;

                // Remove original directory
                fs::remove_dir_all(system_path)
                    .with_context(|| format!("Failed to remove directory {}", system_path))?;
            } else if metadata.is_file() {
                // For files, copy the file if it doesn't exist in shared storage
                if !Path::new(&shared_path).exists() {
                    info!("Copying file from {} to {}", system_path, shared_path);
                    fs::copy(system_path, &shared_path)
                        .with_context(|| format!("Failed to copy file {} to {}", system_path, shared_path))?;
                }

                // Remove original file
                fs::remove_file(system_path)
                    .with_context(|| format!("Failed to remove file {}", system_path))?;
            }
        } else {
            // System path doesn't exist yet, create parent directory in shared storage if needed
            if let Some(parent) = Path::new(&shared_path).parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
            }
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = Path::new(system_path).parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
            }
        }

        // Create symlink from system path to shared storage
        #[cfg(unix)]
        std::os::unix::fs::symlink(&shared_path, system_path)
            .with_context(|| format!("Failed to symlink {} -> {}", system_path, shared_path))?;

        info!("✓ {} -> {}", system_path, shared_path);
    }

    Ok(())
}

/// Setup Nix profile by finding and symlinking binaries from /nix/store
/// Packages are in the container image but not in a profile directory
fn install_nix_packages(_packages: &[String]) -> Result<()> {
    // Create /root/.nix-profile/bin directory if it doesn't exist
    let profile_bin = Path::new("/root/.nix-profile/bin");
    if !profile_bin.exists() {
        fs::create_dir_all(profile_bin)
            .context("Failed to create /root/.nix-profile/bin directory")?;
    } else if !profile_bin.is_dir() {
        // If it exists but is not a directory, remove it and create directory
        fs::remove_file(profile_bin)
            .context("Failed to remove non-directory at /root/.nix-profile/bin")?;
        fs::create_dir_all(profile_bin)
            .context("Failed to create /root/.nix-profile/bin directory")?;
    }

    info!("Setting up Nix profile from container packages...");

    // List of binaries we need to find and symlink
    let required_binaries = vec![
        "ssh-keygen", "sshd", "ssh", "nix", "nix-env", "nix-build",
        "nix-shell", "nix-store", "bash", "attic", "find"
    ];

    for binary in required_binaries {
        // Try to find the binary using 'which'
        if let Ok(output) = Command::new("which").arg(binary).output() {
            if output.status.success() {
                let binary_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !binary_path.is_empty() {
                    let target_path = format!("/root/.nix-profile/bin/{}", binary);

                    // Remove existing symlink if present
                    if Path::new(&target_path).exists() {
                        fs::remove_file(&target_path).ok();
                    }

                    // Create symlink
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&binary_path, &target_path).ok();
                }
            }
        }
    }

    info!("✓ Nix profile configured");

    Ok(())
}

/// Setup system users (root and sshd)
fn setup_system_users() -> Result<()> {
    // Ensure /etc/passwd exists with root user
    let passwd_path = Path::new("/etc/passwd");
    let passwd_content = if passwd_path.exists() {
        fs::read_to_string(passwd_path)
            .context("Failed to read /etc/passwd")?
    } else {
        info!("Creating /etc/passwd");
        String::new()
    };

    // Ensure root user exists in passwd
    let mut updated_passwd = passwd_content.clone();
    if !passwd_content.contains("root:") {
        info!("Adding root user to /etc/passwd");
        if !updated_passwd.is_empty() && !updated_passwd.ends_with('\n') {
            updated_passwd.push('\n');
        }
        updated_passwd.push_str("root:x:0:0:root:/root:/bin/sh\n");
    }

    // Add sshd user if not present
    if !passwd_content.contains("sshd:") {
        info!("Adding sshd user to /etc/passwd");
        updated_passwd.push_str("sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n");
    }

    // Write updated passwd if changed
    if updated_passwd != passwd_content {
        fs::write(passwd_path, &updated_passwd)
            .context("Failed to write /etc/passwd")?;
        info!("✓ Updated /etc/passwd");
    }

    // Ensure /etc/shadow exists with root entry
    let shadow_path = Path::new("/etc/shadow");
    let shadow_content = if shadow_path.exists() {
        fs::read_to_string(shadow_path)
            .context("Failed to read /etc/shadow")?
    } else {
        info!("Creating /etc/shadow");
        String::new()
    };

    // Update shadow file with root entry (no password)
    let new_shadow: Vec<String> = shadow_content
        .lines()
        .filter(|line| !line.starts_with("root:"))
        .map(|s| s.to_string())
        .collect();

    let mut updated_shadow = new_shadow.join("\n");
    if !updated_shadow.is_empty() && !updated_shadow.ends_with('\n') {
        updated_shadow.push('\n');
    }
    updated_shadow.push_str("root::19900:0:99999:7:::\n");

    fs::write(shadow_path, &updated_shadow)
        .context("Failed to write /etc/shadow")?;

    let mut perms = fs::metadata(shadow_path)?.permissions();
    perms.set_mode(0o640);
    fs::set_permissions(shadow_path, perms)?;

    info!("✓ Root account configured for SSH");

    // Ensure /etc/group exists with root and sshd groups
    let group_path = Path::new("/etc/group");
    let group_content = if group_path.exists() {
        fs::read_to_string(group_path)?
    } else {
        info!("Creating /etc/group");
        String::new()
    };

    let mut updated_group = group_content.clone();
    if !group_content.contains("root:") {
        info!("Adding root group to /etc/group");
        if !updated_group.is_empty() && !updated_group.ends_with('\n') {
            updated_group.push('\n');
        }
        updated_group.push_str("root:x:0:\n");
    }

    if !group_content.contains("sshd:") {
        info!("Adding sshd group to /etc/group");
        if !updated_group.is_empty() && !updated_group.ends_with('\n') {
            updated_group.push('\n');
        }
        updated_group.push_str("sshd:x:74:\n");
    }

    if updated_group != group_content {
        fs::write(group_path, &updated_group)?;
        info!("✓ Updated /etc/group");
    }

    // Create sshd home directory
    fs::create_dir_all("/var/empty/sshd")?;
    let mut perms = fs::metadata("/var/empty/sshd")?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions("/var/empty/sshd", perms)?;

    info!("✓ System users configured");

    Ok(())
}

/// Configure SSH server
fn configure_ssh(
    ssh_config: &crate::config::SshConfig,
    authorized_keys: &str,
) -> Result<()> {
    // Create SSH directories
    fs::create_dir_all("/root/.ssh")
        .context("Failed to create /root/.ssh directory")?;
    fs::create_dir_all("/etc/ssh")
        .context("Failed to create /etc/ssh directory")?;

    let mut perms = fs::metadata("/root/.ssh")?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions("/root/.ssh", perms)?;

    // Write authorized_keys
    let auth_keys_path = Path::new("/root/.ssh/authorized_keys");
    fs::write(auth_keys_path, authorized_keys)
        .context("Failed to write authorized_keys file")?;

    let mut perms = fs::metadata(auth_keys_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(auth_keys_path, perms)?;

    info!("✓ SSH authorized_keys configured");

    // Write sshd_config
    let sshd_config = format!(
        "Port {}
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin {}
PubkeyAuthentication yes
AuthorizedKeysFile /root/.ssh/authorized_keys
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM {}
X11Forwarding no
PrintMotd no
",
        ssh_config.port,
        if ssh_config.permit_root_login {
            "yes"
        } else {
            "no"
        },
        if ssh_config.use_pam { "yes" } else { "no" }
    );

    fs::write("/etc/ssh/sshd_config", sshd_config)
        .context("Failed to write sshd_config")?;

    info!("✓ SSH server configuration written");

    Ok(())
}

/// Generate SSH host keys
fn generate_ssh_host_keys(key_types: &[String]) -> Result<()> {
    // Find ssh-keygen in PATH
    let ssh_keygen = find_binary("ssh-keygen")
        .unwrap_or_else(|| "/root/.nix-profile/bin/ssh-keygen".to_string());

    info!("Using ssh-keygen at: {}", ssh_keygen);

    for key_type in key_types {
        let key_path = format!("/etc/ssh/ssh_host_{}_key", key_type);
        if !Path::new(&key_path).exists() {
            info!("Generating {} host key at {}", key_type, key_path);

            let output = Command::new(&ssh_keygen)
                .arg("-t")
                .arg(key_type)
                .arg("-f")
                .arg(&key_path)
                .arg("-N")
                .arg("")
                .arg("-q")
                .output()
                .with_context(|| format!("Failed to execute ssh-keygen for {} host key", key_type))?;

            if !output.status.success() {
                anyhow::bail!(
                    "ssh-keygen failed for {} host key: {}",
                    key_type,
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            // Verify the key was actually created
            if !Path::new(&key_path).exists() {
                anyhow::bail!(
                    "ssh-keygen reported success but {} host key file was not created at {}",
                    key_type,
                    key_path
                );
            }

            info!("✓ Generated SSH {} host key", key_type);
        } else {
            info!("✓ SSH {} host key already exists", key_type);
        }
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

/// Configure Nix daemon
fn configure_nix(
    nix_config: &crate::config::NixConfig,
    attic_config: Option<&crate::config::NixBuilderAtticConfig>,
) -> Result<()> {
    fs::create_dir_all("/etc/nix")
        .context("Failed to create /etc/nix directory")?;

    // Build substituters list (Attic first if configured, then others)
    let mut substituters = Vec::new();
    if let Some(attic) = attic_config {
        substituters.push(format!("{}/{}", attic.cache_url, attic.cache_name));
    }
    substituters.extend(nix_config.substituters.clone());

    let nix_conf = format!(
        "substituters = {}
trusted-public-keys = {}
trusted-users = root
experimental-features = {}
max-jobs = {}
cores = {}
netrc-file = /root/.netrc
",
        substituters.join(" "),
        nix_config.trusted_public_keys.join(" "),
        nix_config.experimental_features.join(" "),
        nix_config.max_jobs,
        nix_config.cores
    );

    fs::write("/etc/nix/nix.conf", nix_conf)
        .context("Failed to write /etc/nix/nix.conf")?;

    info!("✓ Nix configuration written");

    Ok(())
}

/// Configure Attic cache authentication
fn configure_attic(
    attic_config: &crate::config::NixBuilderAtticConfig,
) -> Result<()> {
    // Read Attic token from environment
    let attic_token = env::var(&attic_config.token_env).with_context(|| {
        format!(
            "Failed to read Attic token from environment variable: {}",
            attic_config.token_env
        )
    })?;

    if attic_token.trim().is_empty() {
        anyhow::bail!(
            "Attic token from environment variable {} is empty",
            attic_config.token_env
        );
    }

    // Extract hostname from cache URL
    let cache_host = attic_config
        .cache_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Create .netrc file for Nix HTTP authentication
    fs::create_dir_all("/root")?;

    let netrc_content = format!(
        "machine {}\npassword {}\n",
        cache_host, attic_token
    );

    fs::write("/root/.netrc", netrc_content)
        .context("Failed to write /root/.netrc")?;

    let mut perms = fs::metadata("/root/.netrc")?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions("/root/.netrc", perms)?;

    info!("✓ Netrc configured at /root/.netrc");

    // Configure attic CLI
    let attic_login_result = Command::new("attic")
        .args(["login", &attic_config.cache_name, &attic_config.cache_url, &attic_token])
        .output();

    match attic_login_result {
        Ok(output) if output.status.success() => {
            info!("✓ Attic CLI authenticated");
        }
        Ok(output) => {
            warn!(
                "attic login warning: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(e) => {
            warn!("attic login failed (continuing anyway): {}", e);
        }
    }

    // Set attic cache
    let attic_use_result = Command::new("attic")
        .args(["use", &attic_config.cache_name])
        .output();

    match attic_use_result {
        Ok(output) if output.status.success() => {
            info!("✓ Attic cache '{}' configured", attic_config.cache_name);
        }
        Ok(output) => {
            warn!(
                "attic use warning: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(e) => {
            warn!("attic use failed (continuing anyway): {}", e);
        }
    }

    Ok(())
}

/// Setup symlinks for Nix binaries in /usr/bin
fn setup_nix_symlinks(binaries: &[String]) -> Result<()> {
    fs::create_dir_all("/usr/bin")
        .context("Failed to create /usr/bin directory")?;

    for binary in binaries {
        let nix_path = format!("/root/.nix-profile/bin/{}", binary);
        let usr_path = format!("/usr/bin/{}", binary);

        if Path::new(&nix_path).exists() {
            // Remove existing symlink if present
            if Path::new(&usr_path).exists() {
                fs::remove_file(&usr_path).ok();
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(&nix_path, &usr_path)
                .with_context(|| format!("Failed to create symlink for {}", binary))?;

            info!("✓ Symlink created: {} -> {}", usr_path, nix_path);
        }
    }

    Ok(())
}

/// Setup .profile for interactive sessions
fn setup_profile() -> Result<()> {
    let profile_content = r#"export PATH="/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:$PATH"
export NIX_SSL_CERT_FILE="/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt"
"#;

    fs::write("/root/.profile", profile_content)
        .context("Failed to write /root/.profile")?;

    info!("✓ Profile configured");

    Ok(())
}
