//! `<working_dir>/<out-link-name>` composition — the resolved
//! filesystem path of a Nix `--out-link` under a build's working
//! directory.
//!
//! # Pre-lift census — six sibling stanzas, one composition shape
//!
//! Every consumer that spawns `nix build` inside a caller-owned
//! `working_dir` and then reaches back for the resulting `result*`
//! symlink composes the same `format!("{}/{}", working_dir, <name>)`
//! byte shape. Six stanzas across two consumer modules:
//!
//! 1. `commands/build.rs::execute` (custom-out-link branch, ~L208) —
//!    the CANONICAL nix-default `<working_dir>/result` symlink used as
//!    the `replace_symlink_async` target when the caller-specified
//!    `output` differs from `"result"`; pre-lift
//!    `format!("{}/result", working_dir)`.
//! 2. `commands/build.rs::execute` (custom-out-link branch, ~L209) —
//!    the caller-specified `<working_dir>/<output>` link name used as
//!    the `replace_symlink_async` link_name argument; pre-lift
//!    `format!("{}/{}", working_dir, output)`.
//! 3. `commands/build.rs::execute` (Attic-push branch, ~L229) — the
//!    caller-specified `<working_dir>/<output>` link name passed to
//!    [`crate::nix::path_info_recursive`] to enumerate the built
//!    closure for per-derivation Attic caching; pre-lift
//!    `format!("{}/{}", working_dir, output)`.
//! 4. `commands/build.rs::execute` (image-size read, ~L290) — the
//!    caller-specified `<working_dir>/<output>` link name passed to
//!    [`tokio::fs::metadata`] to read the built image's on-disk size
//!    for the operator-facing `📦 Image size` info line; pre-lift
//!    `format!("{}/{}", working_dir, output)`.
//! 5. `commands/github_runner_ci.rs::execute` (build-output binding,
//!    ~L158) — the fixed `<working_dir>/result-runner` link name the
//!    later `replace_symlink_async` call installs as an alias of the
//!    nix-default `result` link; pre-lift
//!    `format!("{}/result-runner", working_dir)`.
//! 6. `commands/github_runner_ci.rs::execute` (nix-default read,
//!    ~L357) — the CANONICAL nix-default `<working_dir>/result`
//!    symlink read via [`tokio::fs::read_link`] to recover the nix-
//!    store target the runner build produced; pre-lift
//!    `format!("{}/result", working_dir)`.
//!
//! All six compose the same two-segment shape: the caller-owned
//! `working_dir` on the left, a `--out-link` name (`"result"` by
//! default, `"result-runner"` for the runner-image build, or a
//! caller-specified custom name) on the right. Post-lift the six
//! stanzas route through one primitive body; a drift in the
//! composition shape (a `Path::join` swap, a trailing-slash normalize,
//! a switch to `PathBuf`) lands at ONE typed body and reaches every
//! consumer by construction.
//!
//! # Why a `String`, not a `PathBuf`
//!
//! The six pre-lift stanzas each produce a `String`, and every
//! downstream consumer (`std::path::Path::new(&…)`, `tokio::fs::
//! metadata(&…)`, `tokio::fs::read_link(&…)`,
//! [`crate::nix::path_info_recursive`]) accepts an `AsRef<Path>` or
//! `AsRef<str>` from a `String`. Preserving the `String` return
//! keeps the primitive byte-identical to the pre-lift `format!`
//! output — a `PathBuf` return would round-trip through
//! [`std::path::PathBuf::display`] at the operator-facing sites
//! (site 4's `📦 Image size` line binds `result_path` before the
//! `metadata()` await, and a `PathBuf` would force a `.display()`
//! coercion nowhere present today). The primitive owns the
//! composition shape; the choice of downstream `AsRef` conversion
//! stays at the caller.
//!
//! # Distinct from the sibling `<registry>:<tag>` composition shape
//!
//! [`crate::oci_manifest::image_reference`] composes a
//! `<registry>:<tag>` OCI reference on the `":"` separator; this
//! primitive composes a `<working_dir>/<name>` filesystem path on the
//! `"/"` separator. The two shapes share the "two-string
//! composition" pattern but are distinct by separator, distinct by
//! semantics (registry-and-tag vs directory-and-file), and distinct
//! in downstream classification (OCI manifest push vs filesystem
//! read). This primitive owns ONLY the `<working_dir>/<name>`
//! filesystem-path shape.
//!
//! # THEORY grounding
//!
//! §VI.1 three-is-a-law: six stanzas across two modules materially
//! exceed the three-is-a-law threshold. §V solve-once-at-the-
//! primitive: the composition shape lives at ONE construction
//! surface so a future refinement (e.g. a trailing-slash normalize
//! for a `working_dir` that operators pass with a trailing `/`, a
//! swap to `Path::join` for platform-portable path composition, a
//! guard rejecting an empty `working_dir` that would fabricate a
//! root-relative `/<name>` path) lands in one place.

/// Compose the resolved filesystem path of a Nix `--out-link` under
/// a build's working directory: `<working_dir>/<out_link_name>`.
///
/// Callers pass the working directory the `nix build` command ran
/// inside (`Command::current_dir(&working_dir)`) and the `--out-link`
/// name Nix produced under it (default `"result"`, or the caller-
/// specified custom name from `--out-link <name>` — this argument is
/// NOT passed to `nix build` at the current build-site call chain, so
/// callers relying on the custom-name arm additionally install a
/// symlink at `<working_dir>/<out_link_name>` themselves).
///
/// # Byte shape
///
/// Returns `format!("{}/{}", working_dir, out_link_name)`
/// byte-for-byte. No trailing-slash normalization is performed
/// (`working_dir = "/tmp/build/"` composes `"/tmp/build//result"`,
/// which every downstream `Path`-consumer at the six lifted sites
/// tolerates identically — POSIX collapses consecutive slashes at
/// the resolution layer). No empty-argument check is performed
/// (`working_dir = ""` composes `"/result"`; `out_link_name = ""`
/// composes `"/tmp/build/"` — both are downstream errors, not
/// composition errors, and the six pre-lift sites did not guard
/// them either).
///
/// # Lifetime discipline
///
/// The returned `String` is heap-allocated and independent of the
/// input `&str` lifetimes — a caller can drop `working_dir` /
/// `out_link_name` immediately after the call. Matches the pre-lift
/// `format!` behavior at every consumer.
pub fn nix_result_link_path(working_dir: &str, out_link_name: &str) -> String {
    format!("{}/{}", working_dir, out_link_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`nix_result_link_path`] returns the pre-lift
    /// `format!("{}/{}", working_dir, out_link_name)` byte sequence
    /// element-for-element. Pins the two-segment `/`-separator
    /// composition against a future drift that (a) swapped `/` for a
    /// platform-native separator (`Path::join` on Windows renders
    /// `\`), (b) inserted a normalize step that collapsed trailing
    /// slashes (changing `<wd>//result` to `<wd>/result`), or (c)
    /// reordered the two segments.
    #[test]
    fn test_nix_result_link_path_emits_pre_lift_composition() {
        assert_eq!(
            nix_result_link_path("/tmp/build", "result"),
            "/tmp/build/result"
        );
        assert_eq!(
            nix_result_link_path("/home/user/forge", "result-runner"),
            "/home/user/forge/result-runner"
        );
        assert_eq!(
            nix_result_link_path("/nix/workspace", "result-amd64"),
            "/nix/workspace/result-amd64"
        );
    }

    /// Interpolation-position pin: `working_dir` lands on the left of
    /// the `/`, `out_link_name` on the right. A future refactor that
    /// swapped them (rendering `<name>/<working_dir>` — e.g.
    /// `result/tmp/build`) would fabricate a nonsense filesystem path
    /// that every downstream `metadata()` / `read_link()` would then
    /// fail on with an obscure `NotFound`; two distinct strings make
    /// the swap observable at the assertion level.
    #[test]
    fn test_nix_result_link_path_places_working_dir_left_and_name_right() {
        let composed = nix_result_link_path("dir-alpha", "link-beta");
        assert_eq!(
            composed, "dir-alpha/link-beta",
            "working_dir must land on the left of `/`, name on the right"
        );
        assert_ne!(
            composed, "link-beta/dir-alpha",
            "positional swap must be observable at the byte level"
        );
    }

    /// Separator pin: the composition uses exactly ONE `/` byte
    /// between the two segments. A future drift that (a) doubled it
    /// (`{}//{}`), (b) swapped it for `::` (OCI-reference style),
    /// (c) swapped it for the platform-native separator, or
    /// (d) added a leading `/` (rendering `/<wd>/<name>`) regresses
    /// this assertion. Sibling of the `":"`-separator pin at
    /// [`crate::oci_manifest`]'s `<registry>:<tag>` primitive.
    #[test]
    fn test_nix_result_link_path_uses_single_slash_separator() {
        let composed = nix_result_link_path("a", "b");
        assert_eq!(composed, "a/b");
        assert_eq!(composed.matches('/').count(), 1);
        assert!(!composed.starts_with('/'));
        assert!(!composed.ends_with('/'));
    }

    /// Return-type pin: the primitive returns an owned `String`, not
    /// a `PathBuf` and not a borrowed `&str`. A `PathBuf` return
    /// would force a `.display()` coercion at the operator-facing
    /// `📦 Image size` info line in `commands/build.rs` (site 4) that
    /// no pre-lift call spelled; a `&str` return would need a
    /// lifetime bound the six pre-lift sites do not carry (each
    /// binds the composed path into a local before the downstream
    /// consumer's `&`-borrow, matching the `String` owning-shape
    /// exactly). The destructuring assignment below fails to type-
    /// check if the return type ever loses its `String` shape.
    #[test]
    fn test_nix_result_link_path_returns_owned_string() {
        let composed: String = nix_result_link_path("wd", "name");
        assert_eq!(composed, "wd/name");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `format!("{}/{}", <ident_with_working_dir>, <output_ident>)`
    /// or `format!("{}/<literal>", <ident_with_working_dir>)`
    /// composition shape inline any more. The six pre-lift sites in
    /// `commands/build.rs` and `commands/github_runner_ci.rs`
    /// migrated; any future consumer that wants the same
    /// `<working_dir>/<name>` shape reaches for
    /// [`nix_result_link_path`] on first grep, not by copy-pasting a
    /// raw `format!` literal from an existing command module.
    ///
    /// The scan looks for `format!(` opening at column N, then a
    /// same-line `working_dir` substring appearing AFTER a
    /// `"{}/`-style template head (a `/`-separator two-segment
    /// composition with `working_dir` on the right of the `/`).
    /// Unrelated `format!("{}/{}", <other>, <other>)` sites (e.g.
    /// `<upstream>/<name>` in `commands/helm.rs`, `<repo>/<name>` in
    /// `commands/status.rs`) that do not mention `working_dir` on the
    /// same line are not flagged.
    #[test]
    fn no_command_module_still_spells_raw_working_dir_result_link_composition() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
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
                // Look for `format!("{}/` (a `/`-separator two-segment
                // composition head) with `working_dir` mentioned as
                // one of the substitution operands on the same line.
                let has_template_head = line.contains("format!(\"{}/");
                let has_working_dir = line.contains("working_dir");
                let forwards_through_primitive = line.contains("nix_result_link_path(");
                if has_template_head && has_working_dir && !forwards_through_primitive {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"{{}}/…\", working_dir, …)` composition(s) survive under \
             `commands/` — route each through \
             `crate::nix_result_link_path::nix_result_link_path()` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the six sites MUST each forward through
    /// [`nix_result_link_path`] at least the pre-lift count of times,
    /// so a migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed primitive.
    ///
    /// `commands/build.rs` housed FOUR pre-lift sites (one
    /// `<wd>/result` literal + three `<wd>/<output>` runtime); a
    /// migration that fused two of them into a single `let` binding
    /// (say, hoisting the Attic-push and image-size sites to share
    /// one bind above the `if push_cache` guard) would drop the
    /// forward count below four, which is the correct signal — the
    /// shield reports the drift rather than silently accepting a
    /// narrower forwards count.
    ///
    /// `commands/github_runner_ci.rs` housed TWO pre-lift sites (one
    /// `<wd>/result-runner` literal + one `<wd>/result` literal), so
    /// the minimum forward count is two.
    #[test]
    fn every_prelift_module_forwards_through_nix_result_link_path() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("build.rs", 4), ("github_runner_ci.rs", 2)];
        let needle = "nix_result_link_path(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `<working_dir>/<out-link>` composition site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
