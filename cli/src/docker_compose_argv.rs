//! Fixed 3-element `["compose", "-f", <compose_file>]` argv prefix used
//! at every `docker compose` spawn site across the crate.
//!
//! # Pre-lift census — five sibling stanzas, one argv prefix
//!
//! Five consumer sites across two modules each spelled the same 3-element
//! `["compose", "-f", <compose_file>]` argv opening on their `docker`
//! builder / spawn helper, diverging only on the `<compose_file>`
//! interpolation and on the trailing verb-specific suffix
//! (`up -d [services…]` / `down` / `down -v --remove-orphans`):
//!
//! 1. `commands/infra.rs::up` (infrastructure services bring-up,
//!    `.args(&argv).current_dir(&repo_root)` chained onto a
//!    [`std::process::Command`] built from
//!    [`super::commands::infra::docker_bin`], routed through
//!    [`crate::retry::run_inherited_status_sync`] with op label
//!    `"docker compose up"`; suffix `["up", "-d", <services…>]`).
//! 2. `commands/infra.rs::down` (services take-down; suffix `["down"]`).
//! 3. `commands/infra.rs::clean` (services take-down + volume/orphan
//!    pruning; suffix `["down", "-v", "--remove-orphans"]`).
//! 4. `commands/local.rs::up`'s compose branch (per-name compose-driven
//!    bring-up; routed through
//!    [`crate::retry::run_bin_args_inherited_status_sync`] with op label
//!    `"docker compose up"`; suffix `["up", "-d", <name>]`).
//! 5. `commands/local.rs::down`'s compose branch (per-name compose-driven
//!    take-down; suffix `["down"]`).
//!
//! All five pre-lift call sites spelled the leading three positional
//! slots `["compose", "-f", <compose_file>]` byte-for-byte. A drift in
//! the prefix — a future Docker CLI dropping `compose` for `deploy`, an
//! argv-order swap between `"-f"` and the file path, adding a global
//! `--project-name <p>` companion, or replacing `-f <file>` with the
//! `COMPOSE_FILE` env-var contract — pre-lift had to hit five sites in
//! lockstep or diverge; post-lift it lands at ONE typed body and every
//! consumer inherits the change from `.args(&docker_compose_argv(
//! compose_file, suffix))` / `run_bin_args_inherited_status_sync(bin,
//! &docker_compose_argv(compose_file, suffix), op)`.
//!
//! # Why an argv slice, not a spawn primitive
//!
//! The five consumers differ AFTER the argv slice on three axes that
//! don't fit under a single spawn wrapper:
//!
//! - **Working directory.** `commands/infra.rs`'s three sites chain
//!   `.current_dir(&repo_root)` onto the [`std::process::Command`]
//!   builder so relative build contexts inside the compose file resolve
//!   against the repo root; `commands/local.rs`'s two sites inherit the
//!   caller's cwd.
//! - **Spawn helper.** `commands/infra.rs` reaches for the
//!   [`std::process::Command`]-based
//!   [`crate::retry::run_inherited_status_sync`] because it also needs
//!   `.current_dir(...)`; `commands/local.rs` reaches for the argv-slice-
//!   based [`crate::retry::run_bin_args_inherited_status_sync`] because
//!   it does not.
//! - **Suffix arity.** `up -d [services…]` is dynamic on
//!   `commands/infra.rs::up` (`services: &[String]`) and monomorphic on
//!   every other site; `["down", "-v", "--remove-orphans"]` is only
//!   present in `commands/infra.rs::clean`.
//!
//! An argv-slice primitive owns the invariant prefix; every legitimate
//! downstream variance stays at the caller. Modeled on
//! [`crate::docker_tag_argv::docker_tag_argv`],
//! [`crate::kubectl_annotate_overwrite_argv::kubectl_annotate_overwrite_argv`],
//! and [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`].
//!
//! # Distinct from the sibling docker-run argv shape
//!
//! `commands/local.rs::up`'s Nix-image branch spawns `docker run -d -p
//! <port>:80 --name <name> <name>` and `docker load -i <image>`; those
//! are on the `docker` binary but do NOT open with the `compose`
//! subcommand and do NOT carry a `-f <compose_file>` argument. This
//! primitive owns ONLY the compose-subcommand 3-element opening; the
//! plain-docker shapes stay outside its remit.

/// The pre-lift 3-element `["compose", "-f", <compose_file>]` argv
/// prefix, followed by every caller-supplied `suffix` element in order.
///
/// Callers assemble the surrounding builder chain themselves —
/// `Command::new(&docker_bin())` on `commands/infra.rs` (paired with
/// `.current_dir(&repo_root)` and
/// [`crate::retry::run_inherited_status_sync`]),
/// [`crate::retry::run_bin_args_inherited_status_sync`] on
/// `commands/local.rs`, and the operator-facing op-label spelling.
/// Those axes vary across the five consumers; this primitive owns only
/// the 3-element opening.
///
/// # Element layout
///
/// - `argv[0] = "compose"` — docker top-level subcommand.
/// - `argv[1] = "-f"` — file-selector flag (short form; every consumer
///   spelled the short form pre-lift).
/// - `argv[2] = <compose_file>` — caller-supplied compose-file path
///   (an absolute path via [`crate::repo::path_to_string_lossy`] on
///   `commands/infra.rs`; a relative or absolute string via the
///   `--compose-file` CLI argument on `commands/local.rs`).
/// - `argv[3..] = <suffix>` — caller-supplied verb-and-args suffix
///   (`["up", "-d", <services…>]` / `["down"]` / `["down", "-v",
///   "--remove-orphans"]` / `["up", "-d", <name>]`).
///
/// # Return type
///
/// Returns [`Vec<&'a str>`] (not `Vec<String>`) so both a
/// [`std::process::Command`]'s `.args(&argv)` invocation and a
/// `&[&str]`-taking spawn helper such as
/// [`crate::retry::run_bin_args_inherited_status_sync`] can consume the
/// returned buffer without a per-caller `String::as_str` re-collection.
/// The lifetime `'a` couples the borrowed elements to both
/// `compose_file` and every suffix entry, so the returned buffer cannot
/// silently outlive its inputs.
pub fn docker_compose_argv<'a>(compose_file: &'a str, suffix: &[&'a str]) -> Vec<&'a str> {
    let mut argv = Vec::with_capacity(3 + suffix.len());
    argv.push("compose");
    argv.push("-f");
    argv.push(compose_file);
    argv.extend_from_slice(suffix);
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`docker_compose_argv`] emits the pre-lift 3-element
    /// prefix element-for-element (`"compose"`, `"-f"`,
    /// `<compose_file>`) in the pre-lift order, then the caller's
    /// suffix element-for-element. A future refactor that (a)
    /// reordered the prefix, (b) inserted a global companion (e.g.
    /// `--project-name <p>`) between the prefix and the suffix, (c)
    /// renamed `"compose"` to `"deploy"` for a hypothetical Docker CLI
    /// alias, (d) swapped `"-f"` for `"--file"`, or (e) collapsed any
    /// element regresses this assertion.
    #[test]
    fn test_docker_compose_argv_emits_pre_lift_prefix_then_suffix() {
        let argv = docker_compose_argv(
            "/repo/docker-compose.yml",
            &["up", "-d", "postgres", "redis"],
        );
        assert_eq!(argv[0], "compose");
        assert_eq!(argv[1], "-f");
        assert_eq!(argv[2], "/repo/docker-compose.yml");
        assert_eq!(argv[3], "up");
        assert_eq!(argv[4], "-d");
        assert_eq!(argv[5], "postgres");
        assert_eq!(argv[6], "redis");
        assert_eq!(argv.len(), 7);
    }

    /// Empty-suffix boundary: the 3-element prefix is emitted verbatim
    /// with no trailing elements when the caller supplies no suffix.
    /// Pins that the primitive does not silently append a
    /// `--help` / `--version` / synthetic verb fallback when the
    /// caller passes `&[]`.
    #[test]
    fn test_docker_compose_argv_empty_suffix_yields_only_three_element_prefix() {
        let argv = docker_compose_argv("compose.yaml", &[]);
        assert_eq!(argv, vec!["compose", "-f", "compose.yaml"]);
        assert_eq!(argv.len(), 3);
    }

    /// Interpolation-position pin: the compose-file path lands at
    /// index 2 (immediately after `"-f"`), NEVER at index 0 or index 1
    /// (a swap that would ask Docker to run the CLI subcommand named
    /// after the compose file, or hand the file path to a
    /// non-existent `-f` alias). A distinct pair of strings makes an
    /// argv-order swap observable at the assertion level.
    #[test]
    fn test_docker_compose_argv_places_compose_file_at_index_2() {
        let argv = docker_compose_argv("path-alpha.yml", &["down"]);
        assert_eq!(argv[0], "compose", "index 0 must be the `compose` verb");
        assert_eq!(argv[1], "-f", "index 1 must be the `-f` selector");
        assert_eq!(
            argv[2], "path-alpha.yml",
            "index 2 must carry the compose-file path"
        );
    }

    /// Suffix-appending discipline: every element the caller passes in
    /// `suffix` appears at the tail in the caller's order (index 3, 4,
    /// 5, …), never reordered or deduplicated. Pre-lift
    /// `commands/infra.rs::clean` spelled `["down", "-v",
    /// "--remove-orphans"]` in exactly that order; a silent
    /// reordering that placed `--remove-orphans` ahead of `-v` would
    /// still be a valid Docker CLI invocation but would drift from the
    /// pre-lift byte shape.
    #[test]
    fn test_docker_compose_argv_preserves_suffix_order() {
        let argv = docker_compose_argv("f.yml", &["down", "-v", "--remove-orphans"]);
        assert_eq!(&argv[3..], &["down", "-v", "--remove-orphans"]);
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `"compose", "-f",` argv opening inline any more. The five
    /// pre-lift sites migrated; any future consumer that wants the
    /// same `docker compose -f <file> …` shape reaches for
    /// [`docker_compose_argv`] on first grep, not by copy-pasting the
    /// raw literal from an existing command module.
    ///
    /// Anchored on the two-token opening `"compose", "-f",` (the
    /// prefix's first two positional slots, both `'static` string
    /// literals in every pre-lift site). Scans skip line-comment and
    /// block-comment lines so this shield's own docstring mentions of
    /// the forbidden shape do not self-match, and skip the whole
    /// `#[cfg(test)]` region on every module (so a downstream sibling
    /// test that composes the same tokens for coverage doesn't trip
    /// the shield).
    #[test]
    fn no_command_module_still_spells_raw_docker_compose_prefix() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        // Reconstruct the needle from two literals so this test's own
        // source does not carry the fused token pair — the whole-
        // module scan below would otherwise false-match itself when a
        // future edit widened the scan to include `cli/src/`.
        let needle = format!("\"{}\", \"{}\",", "compose", "-f");
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            let mut in_test_region = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("#[cfg(test)]") {
                    in_test_region = true;
                }
                if in_test_region {
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if line.contains(&needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"compose\", \"-f\",` argv opening(s) survive under \
             `commands/` — route each through \
             `crate::docker_compose_argv::docker_compose_argv()` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the five sites MUST each forward through
    /// [`docker_compose_argv`] at least once (three on `infra.rs`, two
    /// on `local.rs`), so a migration that dropped a call site
    /// outright leaves the negative "no raw prefix" scan trivially
    /// satisfied by absence but the positive count still fails.
    /// Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields on
    /// [`crate::docker_tag_argv::docker_tag_argv`] and every other
    /// typed argv primitive the crate carries.
    #[test]
    fn every_prelift_module_forwards_through_docker_compose_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("infra.rs", 3), ("local.rs", 2)];
        let needle = "docker_compose_argv(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} `docker compose` \
                 spawn site(s) through `{needle}`; found {forwards}. \
                 A dropped call would leave the negative raw-prefix scan \
                 satisfied by absence.",
            );
        }
    }
}
