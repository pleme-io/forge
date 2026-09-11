//! Fixed-arity `docker tag <source> <target>` argv slice used at every
//! `docker tag` spawn site across the crate.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites each spelled the same 3-element argv literal on
//! their `docker` builder, diverging only on the `<source>` /
//! `<target>` interpolations and on the surrounding spawn / classify
//! wiring:
//!
//! 1. `commands/product_release.rs::push_prebuilt_image` (Phase-1
//!    registry-push retag of a locally-loaded E2E image onto the
//!    `<registry>:<tag>` composed via
//!    [`crate::oci_manifest::image_reference`], routed through
//!    [`crate::retry::run_inherited_status`] with op label
//!    `"docker tag <image_id> <full_tag>"`).
//! 2. `commands/comprehensive_release.rs::execute` (Phase-1 in-memory
//!    Docker-loaded image retag onto `<registry>:latest` ahead of the
//!    `docker-compose up` bring-up, routed through
//!    [`crate::retry::run_inherited_status`] with op label
//!    `"docker tag <image_name> -> <compose_tag>"`).
//!
//! Both consumers pass `.args(["tag", <src>, <dst>])` byte-for-byte;
//! the only pre-lift divergence is in the operator-facing op-label
//! (space-joined vs `-> `-joined pair) which lives outside the argv
//! slice and belongs to the caller. A drift in the argv shape — a
//! `--force` companion, a rename by a future Docker CLI release, an
//! argv-order swap between `<src>` and `<dst>`, or a swap of the
//! positional pair for a `-t <dst>` flag pair — pre-lift had to hit
//! two sites in lockstep or diverge; post-lift it hits ONE typed body
//! and every consumer inherits the change from
//! `.args(crate::docker_tag_argv::docker_tag_argv(source, target))`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on two axes:
//!
//! - **Op-label composition.** Site 1 assembles `format!("docker tag
//!   {} {}", image_id, full_tag)` inline at the
//!   [`crate::retry::run_inherited_status`] call; site 2 hoists the
//!   label into a `tag_op` binding with the divergent `-> `-joined
//!   pair. The argv-slice primitive owns the argv; the op-label
//!   spelling stays at the caller.
//! - **Source-of-image discipline.** Site 1's `<src>` is a Docker
//!   image ID (from
//!   [`crate::infrastructure::docker::find_first_image_id_by_name_async`]);
//!   site 2's `<src>` is a `<repository>[:tag]` reference parsed out
//!   of `docker load`'s stdout via
//!   [`crate::oci_manifest::docker_load_image_reference`]. Docker's
//!   `tag` subcommand accepts either shape at position 1, so the
//!   argv slice's shape is invariant across the two — the divergence
//!   is at the caller.
//!
//! A `Command`-builder primitive would have to expose all these axes
//! as parameters; the argv slice owns only the shape both
//! `tokio::process::Command`'s `.args()` and any `&[&str]`-taking
//! helper consume identically. Modeled on
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::kubectl_annotate_overwrite_argv::kubectl_annotate_overwrite_argv`],
//! and [`crate::bun_argv::bun_install_frozen_lockfile_argv`] —
//! argv-slice primitives that partition their tool's duplication
//! budget without collapsing the spawn / classify / op-label layers
//! that legitimately diverge downstream.
//!
//! # Distinct from the sibling git-tag argv shape
//!
//! `commands/helm.rs::bump` at ~line 1668 spells
//! `git_command_sync().args(["tag", &tag])` — a 2-element argv on the
//! `git` binary that shares the leading `"tag"` verb but stops there:
//! git's `tag` subcommand takes ONE positional (the tag name) whereas
//! docker's `tag` subcommand takes TWO (source and target references).
//! The two argv shapes are distinct by arity, distinct by target
//! binary, and distinct in downstream classification (git's `tag`
//! bounces on tag-already-exists with a warn; docker's `tag` bails on
//! any non-zero exit through the shared
//! [`crate::retry::run_inherited_status`] envelope). This primitive
//! owns only the 3-element docker shape; the git-tag shape does not
//! collapse onto it.

/// The pre-lift 3-element `tag <source> <target>` argv slice used at
/// every `docker tag` spawn site.
///
/// Callers assemble the surrounding builder chain
/// (`Command::new(&docker)`, the [`crate::retry::run_inherited_status`]
/// dispatch, and the operator-facing op-label spelling) themselves —
/// those axes vary across the two consumers. This primitive owns
/// ONLY the 3-element argv shape.
///
/// # Element layout
///
/// - `argv[0] = "tag"` — docker subcommand.
/// - `argv[1] = <source>` — caller-supplied source image reference
///   (image ID from `docker images` or `<repository>[:tag]` from a
///   `docker load` output line — Docker's `tag` accepts either).
/// - `argv[2] = <target>` — caller-supplied target reference in
///   `<registry>[/<repository>]:<tag>` shape (composed via
///   [`crate::oci_manifest::image_reference`] at site 1, via
///   `format!("{}:latest", registry)` at site 2).
///
/// # Lifetime discipline
///
/// The returned array borrows `source` and `target` under a single
/// `'a` bound. Every current caller binds both strings ahead of the
/// spawn and holds them alive across the `.args(...)` call; the
/// `[&'a str; 3]` return type pins that requirement at the type
/// level (a caller cannot silently extend the array past either
/// input's scope).
pub fn docker_tag_argv<'a>(source: &'a str, target: &'a str) -> [&'a str; 3] {
    ["tag", source, target]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`docker_tag_argv`] returns the pre-lift 3-element
    /// slice element-for-element (`"tag"`, `<source>`, `<target>`) in
    /// the pre-lift order, with no extra element and no rewritten
    /// value. A future refactor that (a) reordered the slice, (b) added
    /// a `--force` / `-f` companion, (c) renamed `"tag"` to a
    /// hypothetical `"retag"` alias, (d) swapped the positional pair
    /// for a `-t <target>` flag pair, or (e) collapsed any element
    /// regresses this assertion.
    #[test]
    fn test_docker_tag_argv_emits_pre_lift_three_element_slice() {
        let argv = docker_tag_argv("sha256:abcdef", "ghcr.io/pleme-io/cart:amd64-bb90b44");
        assert_eq!(argv[0], "tag");
        assert_eq!(argv[1], "sha256:abcdef");
        assert_eq!(argv[2], "ghcr.io/pleme-io/cart:amd64-bb90b44");
        assert_eq!(argv.len(), 3);
    }

    /// The return type is a fixed-arity `[&str; 3]`, NOT a
    /// `Vec<&str>` or a `&[&str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without
    /// touching this module; a change to a slice reference would allow
    /// an unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 3]` shape, this line fails to type-check.
    #[test]
    fn test_docker_tag_argv_returns_fixed_arity_three() {
        let argv: [&str; 3] = docker_tag_argv("src", "dst");
        let [a0, a1, a2] = argv;
        assert_eq!(a0, "tag");
        assert_eq!(a1, "src");
        assert_eq!(a2, "dst");
    }

    /// Interpolation-position pin: `source` lands at index 1,
    /// `target` at index 2. A future refactor that swapped them (e.g.
    /// an argv-order shuffle placing target before source) would
    /// silently RETAG the target reference away from an already-
    /// deployed image and onto the source ID — a destructive-in-
    /// production reordering that a mere length check would not
    /// catch. Two distinct string arguments make the swap observable
    /// at the assertion level.
    #[test]
    fn test_docker_tag_argv_places_source_at_index_1_and_target_at_index_2() {
        let argv = docker_tag_argv("src-alpha", "dst-beta");
        assert_eq!(
            argv[1], "src-alpha",
            "index 1 must carry the source reference"
        );
        assert_eq!(
            argv[2], "dst-beta",
            "index 2 must carry the target reference"
        );
        assert_ne!(argv[1], argv[2], "source and target must not collide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw 3-element
    /// `["tag", <src>, <dst>]` argv literal inline any more. The two
    /// pre-lift sites migrated; any future consumer that wants the
    /// same `docker tag <src> <dst>` shape reaches for
    /// [`docker_tag_argv`] on first grep, not by copy-pasting the raw
    /// literal from an existing command module.
    ///
    /// Anchored on `.args(["tag", ` opening the argv literal, then a
    /// same-line check that the args-slice section carries a comma
    /// AFTER the `"tag", ` opening (i.e., 3+ elements). The sibling
    /// 2-element `git_command_sync().args(["tag", &tag])` shape at
    /// `commands/helm.rs` — one positional, no comma between `"tag", `
    /// and `])` — does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_docker_tag_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let open_needle = ".args([\"tag\", ";
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
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
                let Some(open_pos) = line.find(open_needle) else {
                    continue;
                };
                let rest = &line[open_pos + open_needle.len()..];
                let Some(close_pos) = rest.find("])") else {
                    continue;
                };
                let inner = &rest[..close_pos];
                // A 3-element `.args(["tag", <src>, <dst>])` shape has
                // at least one `, ` between the source and target
                // slots. The 2-element `.args(["tag", &tag])` shape
                // (git-tag at `commands/helm.rs`) has none.
                if inner.contains(", ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"tag\", <src>, <dst>]` argv literal(s) survive under \
             `commands/` — route each through \
             `crate::docker_tag_argv::docker_tag_argv()` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the two sites MUST each forward through
    /// [`docker_tag_argv`] at least once, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count
    /// still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_docker_tag_argv() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] =
            &[("product_release.rs", 1), ("comprehensive_release.rs", 1)];
        let needle = "docker_tag_argv(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} `docker tag` \
                 spawn site(s) through `{needle}`; found {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
