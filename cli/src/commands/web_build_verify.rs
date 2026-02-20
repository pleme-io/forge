use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Verifies web build has no hardcoded API URLs and prepares runtime env.js
pub async fn execute(dist_dir: PathBuf, template_path: PathBuf) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║  Web Build Verification (NO SHELL SCRIPTS)                ║".bright_blue()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    verify_no_hardcoded_urls(&dist_dir)?;
    verify_bundle_consistency(&dist_dir)?;
    verify_cache_policy(&dist_dir)?;
    copy_and_compress_env_template(&dist_dir, &template_path)?;

    println!();
    println!("{}", "✅ Web build verification passed".bright_green());
    println!();

    Ok(())
}

/// Verifies NO hardcoded API URLs are baked into JavaScript bundles
fn verify_no_hardcoded_urls(dist_dir: &Path) -> Result<()> {
    info!("🔍 Verifying NO hardcoded API URLs in bundles...");

    let assets_dir = dist_dir.join("assets");
    if !assets_dir.exists() {
        bail!("Assets directory not found: {}", assets_dir.display());
    }

    // Search all .js files in dist/assets/ for hardcoded API URLs
    let js_files: Vec<PathBuf> = fs::read_dir(&assets_dir)
        .context("Failed to read assets directory")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "js")
                .unwrap_or(false)
        })
        .map(|entry| entry.path())
        .collect();

    if js_files.is_empty() {
        bail!("No JavaScript files found in assets directory");
    }

    info!("   Checking {} JavaScript bundles", js_files.len());

    let bad_patterns = vec![
        "api-staging.example",     // Wrong format (staging)
        "api.staging.example",     // Wrong format (with dot)
        "api.example.com",         // Production URL
        "api-staging.example.com", // Staging URL (should be runtime only)
    ];

    for js_file in js_files {
        let mut content = String::new();
        fs::File::open(&js_file)
            .context(format!("Failed to open {}", js_file.display()))?
            .read_to_string(&mut content)
            .context("Failed to read JavaScript file")?;

        for pattern in &bad_patterns {
            if content.contains(pattern) {
                bail!(
                    "❌ Found hardcoded API URL '{}' in {}\n\
                    API URLs must ONLY come from runtime window.ENV (ConfigMap)",
                    pattern,
                    js_file.display()
                );
            }
        }
    }

    println!("   {} No hardcoded API URLs found", "✅".bright_green());
    Ok(())
}

/// Verifies bundle consistency: index.html references match actual bundle files
/// Prevents stale bundles from being deployed (e.g., old bundles with wrong URLs)
fn verify_bundle_consistency(dist_dir: &Path) -> Result<()> {
    info!("🔍 Verifying bundle consistency...");

    let index_html_path = dist_dir.join("index.html");
    if !index_html_path.exists() {
        bail!("index.html not found: {}", index_html_path.display());
    }

    // Read index.html
    let mut index_html_content = String::new();
    fs::File::open(&index_html_path)
        .context("Failed to open index.html")?
        .read_to_string(&mut index_html_content)
        .context("Failed to read index.html")?;

    // Extract all .js file references from index.html
    let referenced_bundles: Vec<String> = index_html_content
        .lines()
        .filter(|line| line.contains(".js"))
        .flat_map(|line| {
            // Extract script src="..." or link href="..."
            let re = regex::Regex::new(r#"(?:src|href)="(/assets/[^"]+\.js[^"]*)""#).unwrap();
            re.captures_iter(line)
                .map(|cap| cap[1].to_string())
                .collect::<Vec<_>>()
        })
        .collect();

    if referenced_bundles.is_empty() {
        bail!("No JavaScript bundles referenced in index.html");
    }

    info!(
        "   Found {} bundle references in index.html",
        referenced_bundles.len()
    );

    // Check that all referenced bundles exist
    let mut missing_bundles = Vec::new();
    for bundle in &referenced_bundles {
        let bundle_path = dist_dir.join(bundle.trim_start_matches('/'));
        if !bundle_path.exists() {
            missing_bundles.push(bundle.clone());
        }
    }

    if !missing_bundles.is_empty() {
        bail!(
            "❌ Bundle consistency check FAILED!\n\
            index.html references bundles that don't exist:\n{}\n\
            This indicates a build caching issue.",
            missing_bundles.join("\n")
        );
    }

    // Note: We do NOT check for "stale" bundles because modern Vite builds use:
    // 1. Dynamic imports (lazy-loaded route chunks) - not in index.html
    // 2. Code splitting (vendor chunks loaded on demand)
    // 3. Worker scripts (separate entry points)
    // These are legitimate bundles that won't be directly referenced in index.html

    println!(
        "   {} Bundle references verified (index.html → assets)",
        "✅".bright_green()
    );
    Ok(())
}

/// Verifies cache policy configuration to prevent aggressive browser caching
/// Ensures env.js and version.json use cache-busting, no long-cache meta tags,
/// and assets use content hashing
fn verify_cache_policy(dist_dir: &Path) -> Result<()> {
    info!("🔍 Verifying cache policy configuration...");

    let index_html_path = dist_dir.join("index.html");
    if !index_html_path.exists() {
        bail!("index.html not found for cache policy verification");
    }

    // Read index.html
    let mut index_html_content = String::new();
    fs::File::open(&index_html_path)
        .context("Failed to open index.html")?
        .read_to_string(&mut index_html_content)
        .context("Failed to read index.html")?;

    // CHECK 1: Verify env.js uses cache-busting (dynamic loading with timestamp)
    // Accepts either pattern:
    // 1. Async: envScript.src = '/env.js?t=' + Date.now()
    // 2. Sync:  document.write('<script src="/env.js?t=' + Date.now()
    // Both single and double quotes are accepted for HTML attributes
    let has_cache_busting = index_html_content
        .contains("envScript.src = '/env.js?t=' + Date.now()")
        || index_html_content.contains("'/env.js?t=' + Date.now()")
        || index_html_content.contains("\"/env.js?t=' + Date.now()");

    if has_cache_busting {
        println!(
            "   {} env.js uses cache-busting query parameter",
            "✅".bright_green()
        );
    } else if index_html_content.contains("/env.js") {
        bail!(
            "❌ CACHE POLICY VIOLATION: env.js loaded without cache-busting!\n\
            Found: Static <script src=\"/env.js\"></script>\n\
            Required: Dynamic loading with timestamp query parameter\n\
            Expected (async):  envScript.src = '/env.js?t=' + Date.now()\n\
            Expected (sync):   document.write('<script src=\"/env.js?t=' + Date.now())\n\n\
            This causes browsers to cache env.js indefinitely, leading to:\n\
            - Wrong API URLs after deployment\n\
            - Stale feature flags\n\
            - Users stuck on old configuration\n\n\
            Fix: Update index.html to load env.js dynamically with cache-busting"
        );
    } else {
        warn!("⚠️  env.js not referenced in index.html (may be loaded differently)");
    }

    // CHECK 2: Verify version.json uses cache-busting
    if index_html_content.contains("fetch('/version.json?t=' + Date.now()") {
        println!(
            "   {} version.json uses cache-busting query parameter",
            "✅".bright_green()
        );
    } else if index_html_content.contains("/version.json") {
        bail!(
            "❌ CACHE POLICY VIOLATION: version.json fetched without cache-busting!\n\
            Expected: fetch('/version.json?t=' + Date.now())\n\
            version.json must be fetched fresh on every page load to detect new deployments"
        );
    } else {
        warn!("⚠️  version.json not referenced in index.html");
    }

    // CHECK 3: Verify no long-cache meta tags in HTML
    // Look for cache-control meta tags with max-age >= 30000 seconds (8+ hours)
    let cache_meta_regex =
        regex::Regex::new(r#"http-equiv=["']cache-control["'].*?max-age=(\d+)"#).unwrap();

    for line in index_html_content.lines() {
        if let Some(caps) = cache_meta_regex.captures(line) {
            if let Some(max_age_str) = caps.get(1) {
                if let Ok(max_age) = max_age_str.as_str().parse::<u32>() {
                    if max_age >= 30000 {
                        bail!(
                            "❌ CACHE POLICY VIOLATION: HTML contains long-cache meta tag!\n\
                            Found: max-age={} (>= 30000 seconds)\n\
                            Line: {}\n\n\
                            HTML files should rely on server-side Cache-Control headers,\n\
                            not inline meta tags. Server middleware enforces no-cache for HTML.",
                            max_age,
                            line.trim()
                        );
                    }
                }
            }
        }
    }
    println!(
        "   {} No problematic cache-control meta tags in HTML",
        "✅".bright_green()
    );

    // CHECK 4: Verify asset hashing strategy
    let assets_dir = dist_dir.join("assets");
    if assets_dir.exists() {
        let asset_files: Vec<PathBuf> = fs::read_dir(&assets_dir)
            .context("Failed to read assets directory")?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let path = entry.path();
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "js" || ext == "css")
                    .unwrap_or(false)
            })
            .map(|entry| entry.path())
            .collect();

        if asset_files.is_empty() {
            warn!("⚠️  No JavaScript or CSS assets found in distribution");
        } else {
            // Check if assets use content hashing (e.g., main-abc123.js)
            let hashed_pattern = regex::Regex::new(r"-[a-zA-Z0-9]{8,}\.(js|css)$").unwrap();
            let mut hashed_count = 0;
            let mut non_hashed_count = 0;

            for asset in &asset_files {
                let filename = asset.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if hashed_pattern.is_match(filename) {
                    hashed_count += 1;
                } else {
                    non_hashed_count += 1;
                    warn!("⚠️  Non-hashed asset: {} (will use short cache)", filename);
                }
            }

            if non_hashed_count == 0 {
                println!(
                    "   {} All {} asset files use content hashing (immutable cache safe)",
                    "✅".bright_green(),
                    hashed_count
                );
            } else {
                println!(
                    "   {} {} hashed assets (immutable cache), {} non-hashed (short cache)",
                    "✅".bright_green(),
                    hashed_count,
                    non_hashed_count
                );
            }
        }
    } else {
        warn!("⚠️  Assets directory not found");
    }

    println!(
        "   {} Cache policy verification passed",
        "✅".bright_green()
    );
    Ok(())
}

/// Copies env.js template and validates NO compressed versions exist
///
/// CRITICAL: env.js must NOT be pre-compressed because:
/// 1. File is tiny (~2KB) - compression overhead exceeds savings
/// 2. ConfigMap-mounted env.js updates don't update .gz/.br files
/// 3. Web server compression middleware serves stale .gz/.br instead of fresh ConfigMap
/// 4. Results in wrong API URLs and GraphQL 500 errors in production
fn copy_and_compress_env_template(dist_dir: &Path, template_path: &Path) -> Result<()> {
    info!("📄 Adding template env.js (will be replaced by ConfigMap)...");

    let env_js_path = dist_dir.join("env.js");

    // Copy template to dist/env.js
    fs::copy(template_path, &env_js_path).context(format!(
        "Failed to copy {} to {}",
        template_path.display(),
        env_js_path.display()
    ))?;

    // CRITICAL: Verify NO compressed versions of runtime config files exist
    // These files are too small to compress and cause caching bugs
    let prohibited_compressed_files = vec![
        dist_dir.join("env.js.gz"),
        dist_dir.join("env.js.br"),
        dist_dir.join("version.json.gz"),
        dist_dir.join("version.json.br"),
    ];

    let mut found_compressed = Vec::new();
    for compressed_file in &prohibited_compressed_files {
        if compressed_file.exists() {
            found_compressed.push(compressed_file.display().to_string());
        }
    }

    if !found_compressed.is_empty() {
        bail!(
            "❌ PRE-COMPRESSION VIOLATION: Found compressed runtime config files!\n\
            Files found: {}\n\n\
            Runtime config files (env.js, version.json) must NOT be pre-compressed because:\n\
            1. Files are tiny (~2KB) - compression overhead exceeds any savings\n\
            2. ConfigMap-mounted updates don't update compressed versions\n\
            3. Web server serves stale .gz/.br instead of fresh ConfigMap\n\
            4. Results in wrong API URLs and GraphQL 500 errors\n\n\
            Fix: Configure vite-plugin-compression to exclude these files\n\
            See: vite.config.ts filter option",
            found_compressed.join(", ")
        );
    }

    println!(
        "   {} Template env.js present (will be replaced by ConfigMap)",
        "✅".bright_green()
    );
    println!(
        "   {} No compressed runtime config files (prevents caching bugs)",
        "✅".bright_green()
    );

    Ok(())
}
