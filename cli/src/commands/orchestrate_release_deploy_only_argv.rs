//! Fixed-shape argv builder for the deploy-only, single-environment
//! `forge orchestrate-release` self-re-invocation.
//!
//! # Pre-lift census — two sibling 15-slot argv literals
//!
//! Two consumer sites in `commands/{rollback,product_release}.rs` each
//! spelled the same 15-slot argv literal verbatim through
//! [`crate::commands::product_release::run_forge_subcommand`],
//! diverging only in the three per-caller value slots (service name,
//! registry URL, image tag) and the receiver bindings for
//! `service_dir` / `repo_root` / `env_name`:
//!
//! ```ignore
//! run_forge_subcommand(&[
//!     "orchestrate-release",
//!     "--service",
//!     &<service>,
//!     "--service-dir",
//!     &<service_dir>,
//!     "--repo-root",
//!     &<repo_root>,
//!     "--registry",
//!     &<registry>,
//!     "--deploy-only",
//!     "--image-tag",
//!     &<image_tag>,
//!     "--single-environment",
//!     "--environment",
//!     env_name,
//! ])
//! .await?;
//! ```
//!
//! 1. `commands/rollback.rs::execute` (Deploy-previous-tags loop
//!    ~L232-249): `<service>` = `entry.name`, `<registry>` =
//!    `entry.registry_url`, `<image_tag>` = `entry.previous_tag`.
//! 2. `commands/product_release.rs::execute` (Phase-2 deploy loop
//!    ~L727-744): `<service>` = `svc.name`, `<registry>` =
//!    `registry_url`, `<image_tag>` = `image_tag`.
//!
//! Both callers hand the fixed 8 flag literals + 6 caller-provided
//! value slots + 1 fixed subcommand slot to the same
//! [`crate::commands::product_release::run_forge_subcommand`]
//! adapter; both target the exact same self-re-invocation contract
//! (deploy an already-pushed image tag to one environment, skip the
//! build phase). Two occurrences past the PRIME DIRECTIVE's
//! duplication-is-a-bug threshold — a flag rename (say
//! `--single-environment` → `--one-env`), a slot reorder, an added
//! sentinel (`--`), or a swap of `--deploy-only` for the equivalent
//! `--skip-build` flag alias had to hit both sites in lockstep
//! pre-lift; post-lift it hits one typed body and both consumers
//! inherit the shape from the primitive.
//!
//! # Why an array builder, not an argv-plus-spawn fuser
//!
//! The two call sites already route through
//! [`crate::commands::product_release::run_forge_subcommand`] for the
//! spawn half (the current-exe self-re-invoke, the
//! subcommand-invocation announce, the retry-adapted status await).
//! Fusing the spawn into this primitive would duplicate that
//! adapter's concerns (each site would need its own re-invoke
//! wrapper) and drift from the sibling
//! `product_working_dir_forge_argv` (:47-52) which owns its argv
//! shape at one function and hands the array to the shared
//! `run_forge_subcommand`. This primitive follows the same argv-only
//! discipline so the spawn adapter stays the sole owner of the
//! spawn-time behaviour and this primitive stays the sole owner of
//! the argv layout.
//!
//! # THEORY grounding
//!
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the returned `[&'a str; 15]` array
//!   pins the argv arity at the type level — a caller cannot
//!   accidentally omit a flag or a value slot and still compile.
//! - THEORY.md §VI.1 (three-times rule): two sibling occurrences at
//!   the "two is a coincidence, three is a law" threshold — this
//!   lift closes the class before a third caller re-inlines it.

/// The `orchestrate-release` subcommand token every deploy-only
/// self-re-invocation hands as the first argv slot. Named as a
/// `pub const` so a future rename (`orchestrate-release` →
/// `release-orchestrate`) reaches one edit rather than through two
/// lockstep argv literals in `commands/{rollback,product_release}.rs`.
pub const ORCHESTRATE_RELEASE_SUBCOMMAND: &str = "orchestrate-release";

/// The eight fixed flag tokens spliced into the argv layout in slot
/// order. Encoded as a `pub const` so a byte-oracle test can pin the
/// exact spelling of `--deploy-only` and `--single-environment`
/// (both boolean flags — no value follows), and so a fleet-wide
/// audit or a downstream shell renderer can round-trip the layout
/// without re-typing the literals.
pub const ORCHESTRATE_RELEASE_DEPLOY_ONLY_SINGLE_ENV_FLAGS: [&str; 8] = [
    "--service",
    "--service-dir",
    "--repo-root",
    "--registry",
    "--deploy-only",
    "--image-tag",
    "--single-environment",
    "--environment",
];

/// Build the canonical 15-slot argv both pre-lift sites in
/// `commands/{rollback,product_release}.rs::execute` handed to
/// [`crate::commands::product_release::run_forge_subcommand`] — the
/// fixed
/// `[orchestrate-release, --service, <service>, --service-dir,
/// <service_dir>, --repo-root, <repo_root>, --registry, <registry>,
/// --deploy-only, --image-tag, <image_tag>, --single-environment,
/// --environment, <env_name>]` layout.
///
/// The two boolean flags (`--deploy-only`, `--single-environment`)
/// appear as bare tokens (no adjacent value slot); the six
/// caller-provided string slots occupy the six positional argv slots
/// immediately following their corresponding flag.
///
/// Returns a fixed-arity `[&'a str; 15]` so the argv layout is
/// pinned at the type level — a caller cannot drop a flag / value
/// slot and still compile. Callers hand the returned array by
/// reference to
/// [`crate::commands::product_release::run_forge_subcommand`]
/// (`run_forge_subcommand(&argv).await`), which is what both pre-lift
/// sites did with the inline literal.
pub fn orchestrate_release_deploy_only_single_env_argv<'a>(
    service: &'a str,
    service_dir: &'a str,
    repo_root: &'a str,
    registry: &'a str,
    image_tag: &'a str,
    env_name: &'a str,
) -> [&'a str; 15] {
    [
        ORCHESTRATE_RELEASE_SUBCOMMAND,
        "--service",
        service,
        "--service-dir",
        service_dir,
        "--repo-root",
        repo_root,
        "--registry",
        registry,
        "--deploy-only",
        "--image-tag",
        image_tag,
        "--single-environment",
        "--environment",
        env_name,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signature pin: the primitive accepts six `&str` slots (in the
    /// pre-lift argument order the two call sites already spelled) and
    /// returns a 15-slot `[&str; 15]` array. A future edit that widened
    /// the signature (e.g. took a `Vec<&str>` for extra passthrough
    /// args, or returned a `Vec<&str>` to admit variable arity)
    /// ripples to every caller and trips this pin.
    #[test]
    fn signature_is_six_slot_str_in_fifteen_slot_out() {
        let _: for<'a> fn(&'a str, &'a str, &'a str, &'a str, &'a str, &'a str) -> [&'a str; 15] =
            orchestrate_release_deploy_only_single_env_argv;
    }

    /// Byte-oracle: the returned argv layout matches the pre-lift
    /// 15-slot literal exactly. Pins the subcommand token, every
    /// flag literal, every value-slot position, and the boolean-flag
    /// bare-token discipline (`--deploy-only` and
    /// `--single-environment` appear alone, no adjacent value slot).
    /// A drift (a reorder, a flag rename, a swapped value / flag
    /// position, an added or dropped slot) flips this assertion
    /// rather than compiling and silently diverging the two consumer
    /// sites' self-re-invocation contracts.
    #[test]
    fn argv_layout_is_pre_lift_fifteen_slot_literal() {
        let argv = orchestrate_release_deploy_only_single_env_argv(
            "kenshi",
            "/repo/pkgs/products/foo/kenshi",
            "/repo",
            "ghcr.io/pleme-io/kenshi",
            "20260101-abcdef",
            "staging",
        );
        assert_eq!(
            argv,
            [
                "orchestrate-release",
                "--service",
                "kenshi",
                "--service-dir",
                "/repo/pkgs/products/foo/kenshi",
                "--repo-root",
                "/repo",
                "--registry",
                "ghcr.io/pleme-io/kenshi",
                "--deploy-only",
                "--image-tag",
                "20260101-abcdef",
                "--single-environment",
                "--environment",
                "staging",
            ],
            "argv layout must render as the exact pre-lift 15-slot \
             literal both `commands/rollback.rs::execute` and \
             `commands/product_release.rs::execute` handed to \
             `run_forge_subcommand`. Got {argv:?}"
        );
    }

    /// Constant pin: the `orchestrate-release` subcommand token is the
    /// pre-lift literal both sites spelled as the first argv slot.
    /// A rename reaches one edit through the constant.
    #[test]
    fn subcommand_constant_is_pre_lift_literal() {
        assert_eq!(
            ORCHESTRATE_RELEASE_SUBCOMMAND, "orchestrate-release",
            "ORCHESTRATE_RELEASE_SUBCOMMAND must project the \
             pre-lift subcommand literal both call sites handed as \
             the first slot to `run_forge_subcommand`. Got {:?}",
            ORCHESTRATE_RELEASE_SUBCOMMAND
        );
    }

    /// Constant pin: the fixed 8-flag ordering matches the pre-lift
    /// argv layout. Pins both boolean flags (`--deploy-only`,
    /// `--single-environment`) at their exact positions relative to
    /// the value-carrying flags. A drift (a rename, a reorder, a
    /// splice of a new flag) reaches one edit through the constant.
    #[test]
    fn flag_slot_constant_is_pre_lift_ordering() {
        assert_eq!(
            ORCHESTRATE_RELEASE_DEPLOY_ONLY_SINGLE_ENV_FLAGS,
            [
                "--service",
                "--service-dir",
                "--repo-root",
                "--registry",
                "--deploy-only",
                "--image-tag",
                "--single-environment",
                "--environment",
            ],
            "ORCHESTRATE_RELEASE_DEPLOY_ONLY_SINGLE_ENV_FLAGS must \
             project the pre-lift 8-flag ordering both call sites \
             spelled inline in their 15-slot argv literals. Got {:?}",
            ORCHESTRATE_RELEASE_DEPLOY_ONLY_SINGLE_ENV_FLAGS
        );
    }

    /// Sanity-check: every value slot the caller passes surfaces in
    /// the returned argv at its designated position, and every
    /// caller-provided value slot appears immediately after its
    /// flag. A future edit that dropped a value slot, doubled one,
    /// or paired a value with the wrong flag would flip this
    /// assertion.
    #[test]
    fn caller_value_slots_land_after_their_flag() {
        let argv = orchestrate_release_deploy_only_single_env_argv(
            "SERVICE", "SVC_DIR", "REPO", "REGISTRY", "IMG", "ENV",
        );
        // Slot pairs: (flag_position, value_position, flag, value)
        for (flag_pos, value_pos, flag, value) in [
            (1usize, 2usize, "--service", "SERVICE"),
            (3, 4, "--service-dir", "SVC_DIR"),
            (5, 6, "--repo-root", "REPO"),
            (7, 8, "--registry", "REGISTRY"),
            (10, 11, "--image-tag", "IMG"),
            (13, 14, "--environment", "ENV"),
        ] {
            assert_eq!(
                argv[flag_pos], flag,
                "slot {flag_pos} must spell {flag:?}, got {:?}",
                argv[flag_pos]
            );
            assert_eq!(
                argv[value_pos], value,
                "slot {value_pos} must carry the caller's {flag} value \
                 ({value:?}), got {:?}",
                argv[value_pos]
            );
        }
        // Boolean-flag positions carry no value slot; assert them.
        assert_eq!(
            argv[9], "--deploy-only",
            "slot 9 must spell the bare `--deploy-only` boolean flag"
        );
        assert_eq!(
            argv[12], "--single-environment",
            "slot 12 must spell the bare `--single-environment` \
             boolean flag"
        );
    }

    /// Positive delegation shield: each pre-lift command module MUST
    /// forward through
    /// [`orchestrate_release_deploy_only_single_env_argv`] at least
    /// once, so a migration that dropped a call site outright leaves
    /// the negative "no raw 15-slot argv literal" scan (below)
    /// trivially satisfied by absence but the positive count still
    /// fails.
    ///
    /// Rollback.rs (×1: deploy-previous-tags loop in `execute` at
    /// :232-249). Product-release.rs (×1: Phase-2 deploy loop in
    /// `execute` at :727-744).
    #[test]
    fn every_prelift_module_forwards_through_argv_builder() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("rollback.rs", 1), ("product_release.rs", 1)];
        // Reconstruct the delegation needle via `format!` so this
        // shield's own source text does not false-match itself.
        let needle = format!("{}(", "orchestrate_release_deploy_only_single_env_argv");
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = crate::test_support::code_line_hits(&source, &needle).len();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 deploy-only single-environment `orchestrate-release` \
                 argv stanza(s) through \
                 `crate::commands::orchestrate_release_deploy_only_argv::\
                 orchestrate_release_deploy_only_single_env_argv(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-literal scan satisfied by absence."
            );
        }
    }

    /// Negative caller shield: no source file under
    /// `cli/src/commands/` may spell the pre-lift raw 15-slot argv
    /// literal — a `run_forge_subcommand(&[...])` call whose first
    /// slot is `"orchestrate-release"` and whose middle slot carries
    /// both `"--deploy-only"` and `"--single-environment"` — inline
    /// any more. The two pre-lift sites migrated; any future
    /// consumer that wants the same self-re-invocation reaches for
    /// [`orchestrate_release_deploy_only_single_env_argv`] on first
    /// grep, not by copy-pasting the 15-line argv shape from an
    /// existing site.
    ///
    /// The scan looks for a `run_forge_subcommand(&[` opener followed
    /// (within a 40-line window so the multi-line array literal
    /// fits) by the four fingerprint tokens (subcommand,
    /// `--deploy-only`, `--single-environment`, `--environment`) as
    /// quoted string literals. Reconstruct the needles via `format!`
    /// so this shield's own source text does not false-match itself.
    #[test]
    fn no_command_module_still_spells_raw_orchestrate_release_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstructed via `format!` so this test module's own body
        // does not match itself.
        let subcommand_literal = format!("{}{}{}", "\"", "orchestrate-release", "\"");
        let deploy_only_literal = format!("{}{}{}", "\"", "--deploy-only", "\"");
        let single_env_literal = format!("{}{}{}", "\"", "--single-environment", "\"");
        let mut offenders: Vec<(PathBuf, usize)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip this module's own file so its `format!`-reconstructed
            // needles and the byte-oracle assertion above do not
            // false-match themselves.
            if path.file_name().and_then(|n| n.to_str())
                == Some("orchestrate_release_deploy_only_argv.rs")
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let executable_lines: Vec<(usize, String)> = source
                .lines()
                .enumerate()
                .filter(|(_, l)| {
                    let t = l.trim_start();
                    !t.starts_with("//!") && !t.starts_with("///") && !t.starts_with("//")
                })
                .map(|(i, l)| (i, l.to_string()))
                .collect();
            for i in 0..executable_lines.len() {
                let (idx0, first) = &executable_lines[i];
                if !first.contains(&subcommand_literal) {
                    continue;
                }
                // Look for the sibling flag literals within a
                // 40-executable-line window so unrelated
                // `"orchestrate-release"` mentions (e.g. inside a
                // help-text string) are not caught.
                let window = &executable_lines[i + 1..(i + 40).min(executable_lines.len())];
                let has_deploy_only = window.iter().any(|(_, l)| l.contains(&deploy_only_literal));
                let has_single_env = window.iter().any(|(_, l)| l.contains(&single_env_literal));
                if has_deploy_only && has_single_env {
                    offenders.push((path.clone(), idx0 + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw 15-slot `[\"orchestrate-release\", ..., \
             \"--deploy-only\", ..., \"--single-environment\", ...]` \
             argv literal(s) survive under `commands/` — route each \
             stanza through \
             `crate::commands::orchestrate_release_deploy_only_argv::\
             orchestrate_release_deploy_only_single_env_argv(...)` \
             and hand the returned array to \
             `run_forge_subcommand`:\n{offenders:#?}"
        );
    }
}
