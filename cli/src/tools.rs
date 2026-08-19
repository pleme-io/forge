//! Runtime tool path resolution
//!
//! This module provides a centralized, generalized way to resolve paths to external tools
//! using the derivation-to-environment-variable pattern.
//!
//! ## Pattern
//!
//! For each tool (e.g., `skopeo`), we:
//! 1. Check for an environment variable `{TOOL}_BIN` (e.g., `SKOPEO_BIN`)
//! 2. Fall back to PATH-based invocation if the envvar is not set
//!
//! This allows Nix to provide explicit derivation paths via environment variables,
//! ensuring reproducible builds while maintaining flexibility for non-Nix environments.
//!
//! ## Benefits
//!
//! - **Explicit dependencies**: Nix flake apps export tool paths from derivations
//! - **Reproducible**: Always uses exact version specified in nixpkgs
//! - **Flexible**: Falls back to PATH for development/testing
//! - **Easy to add tools**: Just call `get_tool_path("toolname")`
//! - **Easy to mock**: Override envvar in tests
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::tools::get_tool_path;
//! use tokio::process::Command;
//!
//! // Get skopeo path (reads SKOPEO_BIN envvar, falls back to "skopeo")
//! let skopeo = get_tool_path("skopeo");
//! Command::new(&skopeo)
//!     .args(&["copy", source, dest])
//!     .status()
//!     .await?;
//!
//! // Get kubectl path (reads KUBECTL_BIN envvar, falls back to "kubectl")
//! let kubectl = get_tool_path("kubectl");
//! Command::new(&kubectl)
//!     .args(&["get", "pods"])
//!     .status()
//!     .await?;
//! ```
//!
//! ## Adding New Tools
//!
//! 1. Add tool to `runtimeTools` in substrate
//! 2. Call `get_tool_path("toolname")` in Rust code
//! 3. Nix apps automatically export the envvar via `mkRuntimeToolsEnv`
//!
//! No other changes needed - the pattern is fully generalized.

use std::env;

/// Get the path to an external tool
///
/// Checks for an environment variable `{TOOL}_BIN` (uppercase tool name with
/// any `-` canonicalized to `_`, then `_BIN` appended). Falls back to the
/// tool name itself if the envvar is not set, which relies on PATH.
///
/// # Arguments
///
/// * `tool` - The tool name (e.g., "skopeo", "kubectl", "attic", "git",
///   "postgres-bootstrap")
///
/// # Returns
///
/// The tool path as a String. Either:
/// - The value of the derived env var (e.g., `SKOPEO_BIN` for "skopeo",
///   `POSTGRES_BOOTSTRAP_BIN` for "postgres-bootstrap")
/// - The tool name itself if envvar not set
///
/// # Env-var name is shell-safe by construction
///
/// POSIX environment variable names are restricted to `[A-Z0-9_]` — a dash
/// is not legal. Tool names in forge follow the Nix derivation convention
/// of dash-separated kebab-case (`postgres-bootstrap`, `openbao-bootstrap`,
/// `kanidm-bootstrap`); the derivation that exports the bin path lifts to
/// `{POSTGRES_BOOTSTRAP_BIN, OPENBAO_BOOTSTRAP_BIN, KANIDM_BOOTSTRAP_BIN}`.
/// Without the `-` → `_` canonicalization, a dash-bearing tool name would
/// produce an env-var lookup (e.g. `POSTGRES-BOOTSTRAP_BIN`) that no
/// shell-emitted environment ever sets — silently downgrading every
/// Nix-derivation-provided path back to PATH-based invocation. The
/// canonicalization is the load-bearing bridge between the derivation
/// surface (dashes legal) and the env-var surface (underscores only).
///
/// # Examples
///
/// ```rust,ignore
/// // With SKOPEO_BIN="/nix/store/abc123-skopeo-1.14.0/bin/skopeo"
/// assert_eq!(get_tool_path("skopeo"), "/nix/store/abc123-skopeo-1.14.0/bin/skopeo");
///
/// // Dash-bearing tool name -> underscore env var
/// // With POSTGRES_BOOTSTRAP_BIN="/nix/store/.../bin/postgres-bootstrap"
/// assert_eq!(
///     get_tool_path("postgres-bootstrap"),
///     "/nix/store/.../bin/postgres-bootstrap",
/// );
///
/// // Without SKOPEO_BIN set
/// assert_eq!(get_tool_path("skopeo"), "skopeo");
/// ```
pub fn get_tool_path(tool: &str) -> String {
    let env_var = format!("{}_BIN", tool.to_uppercase().replace("-", "_"));
    env::var(&env_var).unwrap_or_else(|_| tool.to_string())
}

/// Get the path to a tool with a custom environment variable name
///
/// Like `get_tool_path`, but allows specifying a custom environment variable name
/// instead of deriving it from the tool name.
///
/// # Arguments
///
/// * `tool` - The tool name (fallback if envvar not set)
/// * `env_var` - The environment variable name to check
///
/// # Returns
///
/// The tool path as a String
///
/// # Examples
///
/// ```rust,ignore
/// // Check CUSTOM_SKOPEO_PATH, fall back to "skopeo"
/// let path = get_tool_path_custom("skopeo", "CUSTOM_SKOPEO_PATH");
/// ```
pub fn get_tool_path_custom(tool: &str, env_var: &str) -> String {
    env::var(env_var).unwrap_or_else(|_| tool.to_string())
}

/// Common tool names (for documentation and IDE autocomplete)
///
/// This module doesn't enforce these names - you can pass any string to `get_tool_path`.
/// These constants are provided for convenience and discoverability.
pub mod tools {
    /// doca — the one fleet container tool (substrate#oci-push). Replaces
    /// SKOPEO below. Resolved via `DOCA_BIN`, falling back to `oci-push` on
    /// PATH; the nix closure that ships forge bakes it in.
    pub const DOCA: &str = "oci-push";
    /// RETIRED in favour of [`DOCA`]. Kept per MODULARIZE-DON'T-DELETE — the
    /// constant still resolves so any out-of-tree caller keeps building — but
    /// no forge code path invokes skopeo any more.
    pub const SKOPEO: &str = "skopeo";
    pub const ATTIC: &str = "attic";
    pub const KUBECTL: &str = "kubectl";
    pub const GIT: &str = "git";
    pub const NIX: &str = "nix";
    pub const FLUX: &str = "flux";
    pub const DOCKER: &str = "docker";
    pub const CRATE2NIX: &str = "crate2nix";
    pub const HELM: &str = "helm";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_get_tool_path_from_env() {
        env::set_var("TEST_TOOL_BIN", "/custom/path/to/test-tool");
        assert_eq!(get_tool_path("test-tool"), "/custom/path/to/test-tool");
        env::remove_var("TEST_TOOL_BIN");
    }

    #[test]
    fn test_get_tool_path_fallback() {
        env::remove_var("MISSING_TOOL_BIN");
        assert_eq!(get_tool_path("missing-tool"), "missing-tool");
    }

    #[test]
    fn test_get_tool_path_custom() {
        env::set_var("CUSTOM_VAR", "/custom/path");
        assert_eq!(get_tool_path_custom("tool", "CUSTOM_VAR"), "/custom/path");
        env::remove_var("CUSTOM_VAR");
    }

    /// DOCA resolves from DOCA_BIN, and the DERIVING lookup cannot supply it.
    ///
    /// This pins a bug that shipped and stayed hidden for a release cycle.
    /// `tools::DOCA` is NAMED for doca but its VALUE is "oci-push", and
    /// `get_tool_path` derives its env var from the value — so it read
    /// `OCI_PUSH_BIN`, which nothing in the fleet has ever exported. substrate's
    /// mkImageReleaseApp exports `DOCA_BIN`; the sibling push path
    /// (commands/push.rs, via the two-argument repo::get_tool_path) reads
    /// `DOCA_BIN`. Only commands/image_release.rs used the deriving form, so the
    /// two push paths silently disagreed and only image-release was broken.
    ///
    /// It failed at a distance rather than loudly: unset, the lookup falls back
    /// to a bare `oci-push`, a pleme-io binary ambient NOWHERE, so all seven
    /// consumers of nix-image-auto-release.yml built clean and died at push.
    ///
    /// The comments on BOTH sides asserted DOCA_BIN, which is exactly why review
    /// never caught it — everyone reasoned about the constant's NAME while the
    /// code used its VALUE. So this test asserts the divergence itself, not just
    /// the happy path: if someone "tidies" image_release.rs back to the
    /// one-argument form, the second assertion is what fails.
    #[test]
    fn doca_resolves_from_doca_bin_and_the_deriving_lookup_does_not() {
        env::remove_var("OCI_PUSH_BIN");
        env::set_var("DOCA_BIN", "/nix/store/xyz/bin/oci-push");

        // What image_release.rs does — correct.
        assert_eq!(
            get_tool_path_custom(tools::DOCA, "DOCA_BIN"),
            "/nix/store/xyz/bin/oci-push",
            "DOCA must resolve from DOCA_BIN, the var substrate actually exports"
        );

        // What it used to do — silently falls through to a bare binary name.
        assert_eq!(
            get_tool_path(tools::DOCA),
            "oci-push",
            "the deriving lookup reads OCI_PUSH_BIN, which nothing exports; if this \
             ever returns a store path the derivation changed and image_release.rs \
             should be revisited"
        );

        env::remove_var("DOCA_BIN");
    }

    #[test]
    fn test_uppercase_conversion() {
        env::set_var("SKOPEO_BIN", "/nix/store/abc/bin/skopeo");
        assert_eq!(get_tool_path("skopeo"), "/nix/store/abc/bin/skopeo");
        env::remove_var("SKOPEO_BIN");
    }

    /// Pins the dash-to-underscore canonicalization: a tool name with one
    /// dash routes to the shell-safe underscore env var, not to the
    /// dash-bearing form (which POSIX shells cannot export).
    ///
    /// Regression coverage for the silent-PATH-fallback bug a single-`-`
    /// canonicalization regression would re-introduce: the derived env
    /// var `POSTGRES-BOOTSTRAP_BIN` is unsettable from shells, so a
    /// regression would always fall through to the PATH-based "tool name"
    /// fallback, defeating every Nix-derivation-provided absolute path
    /// at the bootstrap-binary surface (`commands/bootstrap.rs`).
    #[test]
    fn test_get_tool_path_canonicalizes_single_dash_to_underscore() {
        env::set_var(
            "POSTGRES_BOOTSTRAP_BIN",
            "/nix/store/abc/bin/postgres-bootstrap",
        );
        assert_eq!(
            get_tool_path("postgres-bootstrap"),
            "/nix/store/abc/bin/postgres-bootstrap"
        );
        // The dash-preserving form is NOT what gets looked up — a value
        // exported there must not leak through.
        assert!(env::var("POSTGRES-BOOTSTRAP_BIN").is_err());
        env::remove_var("POSTGRES_BOOTSTRAP_BIN");
    }

    /// Pins the dash-to-underscore canonicalization for multi-dash names:
    /// every `-` collapses, not just the first. A tool name with N dashes
    /// derives the same `[A-Z0-9_]+_BIN` env var the shell that wrapped
    /// the binary set.
    #[test]
    fn test_get_tool_path_canonicalizes_multiple_dashes_to_underscores() {
        env::set_var("FOO_BAR_BAZ_BIN", "/nix/store/abc/bin/foo-bar-baz");
        assert_eq!(
            get_tool_path("foo-bar-baz"),
            "/nix/store/abc/bin/foo-bar-baz"
        );
        env::remove_var("FOO_BAR_BAZ_BIN");
    }
}

/// Crate-wide shield: a bare-literal subprocess spawn may SHRINK, never grow.
///
/// Rung 0 of the controlled-subprocess ladder
/// (`pleme-io/docs/controlled-subprocess.md`): every spawn must resolve its
/// binary through a `_BIN` sigil, because `Command::new("kubectl")` runs
/// whatever `PATH` resolved first and attributes the verdict to a binary nobody
/// declared — the silent-PATH-fallback class the sibling per-module shields in
/// `commands/gem.rs` were written to close.
///
/// This generalizes those shields from one module to the crate, with a
/// PER-TOOL baseline rather than a single total: a shrinking total would
/// otherwise let a NEW uncontrolled tool hide behind someone else's cleanup.
/// An unlisted tool name is a hard failure, so adding a spawn of a tool that
/// has never been spawned bare is refused outright.
///
/// # Three shapes, one tally
///
/// The scanner sees every shape a bare literal can reach `Command::new`
/// through. Pre-extension the tally counted only the DIRECT shape
/// (`Command::new("<literal>")`), so a literal flowing through a
/// program-first helper's tail — `run_cmd(dir, "<literal>", …)` on
/// `commands/tool.rs`, `run_program_timed("<literal>", …)` on
/// `commands/helm.rs` — was invisible to the crate-wide tally and only
/// caught by that module's own per-tool shield. The three pre-lift `zig`
/// sites at `commands/tool.rs::{check,lock}` (routed at 5f898d1) were the
/// live evidence: `zig` never appeared in this baseline yet three helper-
/// wrapped bare spawns ran under every `forge tool check` / `forge tool
/// lock` invocation. Extending the tally to also match the two
/// program-first helper shapes closes that substrate hole, so a helper-
/// wrapped literal is now caught at the crate-wide surface — a future new
/// helper-wrapped spawn of any tool without a sigil is refused as
/// UNLISTED even in the module that first adds the helper.
///
/// # Comment-blind, code-truthful
///
/// The scanner filters `//` / `///` / `//!` lines before applying the
/// regexes, so a doc comment that MENTIONS the forbidden shape verbatim
/// (`/// like `Command::new("kubectl")` — DON'T`) does not inflate the
/// tally. Pre-extension the tally counted the shape in every prose
/// mention: 43 for kubectl, 41 for git, 24 for nix — almost entirely doc-
/// comment text describing the shield's own rules. After filtering, the
/// tally reflects ACTUAL code-line spawns: 5 sites in 3 files, every one
/// terminal by nature (`/bin/*` absolute paths, `false`/`true`/`sleep`
/// test fixtures). A new real spawn of `kubectl` / `git` / `nix` now
/// counts as `1` against a nonexistent baseline entry and fires
/// UNLISTED, not `44` against a 43-slot budget hidden behind decades of
/// prose.
#[cfg(test)]
mod spawn_shield {
    /// Measured 2026-08-19. Every entry is a REAL code-line site the
    /// tally sees after comment filtering — a `Command::new(<literal>)`,
    /// `run_cmd(<dir>, <literal>, …)`, or `run_program_timed(<literal>,
    /// …)` site NOT inside a `//` / `///` / `//!` line. Every one is
    /// TERMINAL BY NATURE: absolute `/bin/*` paths are already
    /// unambiguous, `false`/`true`/`sleep` are exit-code and timeout
    /// fixtures in test bodies. No sigil candidate remains under the
    /// crate-wide surface post-comment-filter — every real tool spawn
    /// already routes through `get_tool_path` or a `<tool>_bin()` sigil.
    /// SHRINK-ONLY: lower a number when you route a call site through a
    /// sigil; never raise one.
    const BASELINE: &[(&str, usize)] = &[
        // Direct `Command::new("<literal>")` code-line sites.
        ("/bin/sh", 3),   // retry.rs — subprocess-error primitive fixtures
        ("/bin/true", 1), // store_path.rs — success-exit fixture
        // `false`: 1 direct site (commands/rollout.rs) + 1 helper-wrapped
        // (helm.rs `run_program_timed("false", …)` test fixture).
        ("false", 2),
        // Helper-wrapped `run_program_timed(<literal>, …)` code-line
        // sites in the `commands/helm.rs` test module — `true` and
        // `sleep` are exit-code and timeout fixtures the tests use to
        // exercise `run_program_timed`'s own wall-clock behavior.
        ("true", 1),
        ("sleep", 1),
    ];

    /// Scan `source` for every bare-literal-spawn shape and tally the
    /// captured tool names. Three regexes, one map:
    ///
    /// - `Command::new\("([^"]+)"\)` — the direct shape.
    /// - `run_cmd\([^,()]+,\s*"([^"]+)"` — the two-arg helper-wrapped
    ///   shape (first arg is a non-comma-non-paren token like `dir`,
    ///   second arg is a bare quoted literal).
    /// - `run_program_timed\(\s*"([^"]+)"` — the first-arg helper-
    ///   wrapped shape.
    ///
    /// Every needle is regex-escaped (`new\(`, `run_cmd\(`,
    /// `run_program_timed\(`), so this module's own regex-source literals
    /// cannot match themselves. Lines whose trimmed prefix is `//`,
    /// `///`, or `//!` are filtered before scanning — a doc-comment
    /// mention of the shape is not a spawn.
    fn tally_spawn_shapes(source: &str) -> std::collections::BTreeMap<String, usize> {
        let direct = regex::Regex::new(r#"Command::new\("([^"]+)"\)"#).expect("static direct");
        let run_cmd =
            regex::Regex::new(r#"run_cmd\([^,()]+,\s*"([^"]+)""#).expect("static run_cmd");
        let run_timed = regex::Regex::new(r#"run_program_timed\(\s*"([^"]+)""#)
            .expect("static run_program_timed");
        let mut tally: std::collections::BTreeMap<String, usize> = Default::default();
        for line in source.lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            for re in [&direct, &run_cmd, &run_timed] {
                for c in re.captures_iter(line) {
                    *tally.entry(c[1].to_string()).or_default() += 1;
                }
            }
        }
        tally
    }

    fn bare_literal_spawns() -> Vec<(String, usize)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut tally: std::collections::BTreeMap<String, usize> = Default::default();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).expect("read src dir").flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    for (k, v) in tally_spawn_shapes(&text) {
                        *tally.entry(k).or_default() += v;
                    }
                }
            }
        }
        tally.into_iter().collect()
    }

    #[test]
    fn bare_literal_spawns_may_shrink_never_grow() {
        let found = bare_literal_spawns();
        // Anti-vacuity: a walk that finds nothing is a broken walk, not a clean
        // crate — five terminal fixtures live in the tree by design (see
        // BASELINE above), so an empty tally means the walker or the regexes
        // are broken and the shield is silently vacuous.
        assert!(
            !found.is_empty(),
            "found zero spawn sites — the source walk is broken, which would \
             make this shield silently vacuous"
        );

        let base: std::collections::BTreeMap<&str, usize> = BASELINE.iter().copied().collect();
        let mut grew = Vec::new();
        let mut unlisted = Vec::new();
        for (tool, n) in &found {
            match base.get(tool.as_str()) {
                Some(allowed) if n <= allowed => {}
                Some(allowed) => grew.push(format!("{tool}: {n} > baseline {allowed}")),
                None => unlisted.push(format!("{tool}: {n}")),
            }
        }
        assert!(
            grew.is_empty() && unlisted.is_empty(),
            "bare-literal spawns must shrink, never grow.\n  GREW: {:?}\n  \
             UNLISTED (a tool that has never been spawned bare — route it \
             through get_tool_path instead): {:?}\n  ACTUAL TALLY: {:?}",
            grew,
            unlisted,
            found
        );
    }

    /// Pins the helper-wrapped extension: the tally MUST see a bare
    /// literal that reaches `Command::new` through the program-first
    /// helpers `run_cmd(dir, "<lit>", …)` and `run_program_timed("<lit>",
    /// …)`, not only the direct `Command::new("<lit>")` shape.
    ///
    /// Fail-before-pass-after: with only the direct-shape regex active
    /// (the pre-extension state at 5f898d1's substrate-hole note),
    /// `tally_spawn_shapes` on the fixture below returned
    /// `{"synth-direct": 1}` and both helper-wrapped keys were
    /// absent. Post-extension all three keys appear with count 1.
    ///
    /// The three fixture lines are assembled via `concat!` from split
    /// string fragments so this test's OWN source text never contains
    /// the fused shapes — the crate-wide walker scanning
    /// `include_str!("tools.rs")` therefore does not false-match this
    /// fixture and inflate the real baseline.
    #[test]
    fn helper_wrapped_bare_literal_is_counted_toward_the_baseline() {
        let synth_direct = concat!("    let c = Command::", "new(\"synth-direct\");\n");
        let synth_helper_cmd =
            concat!("    let _ = run_", "cmd(dir, \"synth-helper-cmd\", &[]);\n");
        let synth_helper_timed = concat!(
            "    let _ = run_",
            "program_timed(\"synth-helper-timed\", &[], Duration::from_secs(1));\n"
        );
        let source = format!("{synth_direct}{synth_helper_cmd}{synth_helper_timed}");

        let tally = tally_spawn_shapes(&source);
        assert_eq!(
            tally.get("synth-direct"),
            Some(&1),
            "direct `Command::new(<literal>)` shape must count. Tally: {tally:?}"
        );
        assert_eq!(
            tally.get("synth-helper-cmd"),
            Some(&1),
            "helper-wrapped `run_cmd(<dir>, <literal>, …)` shape must count — \
             this is the substrate hole 5f898d1's body flagged (the crate-wide \
             regex was helper-blind, so a literal through `run_cmd`'s tail \
             slipped past the tally). Tally: {tally:?}"
        );
        assert_eq!(
            tally.get("synth-helper-timed"),
            Some(&1),
            "helper-wrapped `run_program_timed(<literal>, …)` shape must count — \
             sibling of the run_cmd hole above, on the bounded-spawn helper \
             `commands/helm.rs` exposes. Tally: {tally:?}"
        );
    }

    /// Pins the comment-blind filter: a `//` / `///` / `//!` line
    /// mentioning the forbidden shape verbatim (as this shield's own
    /// docstring and the sibling per-module shields' docstrings do) must
    /// NOT inflate the tally. Pre-extension the tally counted every doc-
    /// comment mention as a spawn — 43 "kubectl" hits, 41 "git" hits, 24
    /// "nix" hits — none of them real code sites, all of them prose
    /// describing the shield's own rules. After filtering, only real
    /// code-line spawns count.
    ///
    /// Fixture fragments are split via `concat!` so this test's OWN
    /// source text never fuses the shape the regex looks for.
    #[test]
    fn comment_lines_do_not_inflate_the_tally() {
        let commented = concat!(
            "/// docstring naming Command::",
            "new(\"comment-ghost\") — must not count\n",
            "    // inline comment naming run_",
            "cmd(dir, \"comment-ghost\", &[]) — must not count\n",
            "//! module doc naming run_",
            "program_timed(\"comment-ghost\", &[], t) — must not count\n",
        );
        let tally = tally_spawn_shapes(commented);
        assert!(
            tally.get("comment-ghost").is_none(),
            "doc-comment mentions of any of the three spawn shapes must be \
             filtered before scanning — a `///` / `//!` / `//` line is prose, \
             not a spawn. Tally: {tally:?}"
        );
    }
}
