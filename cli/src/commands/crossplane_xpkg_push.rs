//! Announce-run-report `crossplane xpkg push` fusion primitive.
//!
//! Two pre-lift sibling stanzas in `commands/crossplane.rs`
//! (`function_release` at 149-160 + `configuration_release` at
//! 193-200) each spelled the same open-run-close visual grammar
//! around the `crossplane xpkg push` spawn, differing only in the
//! `Function|Configuration` adjective the trailing
//! `info!("<Kind> package published: {}", dest);` line spliced:
//!
//! ```ignore
//! let dest = crate::oci_manifest::image_reference(package_ref.trim_end_matches('/'), tag);
//! info!("crossplane xpkg push \u{2192} {}", dest);
//! let mut push = Command::new(&crossplane);
//! push.args(["xpkg", "push", "--package-files"]).arg(&out).arg(&dest);
//! run_inherited_status_sync(push, &format!("crossplane xpkg push {}", dest))?;
//! info!("<Function|Configuration> package published: {}", dest);
//! ```
//!
//! Encoding that correlated pair as [`CrossplanePackageKind`] closes
//! two drift risks at ONE typed boundary. First, a caller cannot
//! silently pass the Function-shaped push above the Configuration-
//! shaped report (or vice versa) because the kind-enum owns the
//! published-message adjective. Second, a future re-branding of the
//! `crossplane xpkg push \u{2192}` announcement, the fixed
//! `["xpkg", "push", "--package-files"]` argv, the
//! `"crossplane xpkg push <dest>"` op label, or the
//! `"<Kind> package published"` postamble lands at exactly one
//! module rather than through two inline literal edits.
//!
//! Same visual-grammar-fusion pattern as
//! [`crate::commands::supergraph_composition_phase`] (correlated
//! `{Pre, Post}` pair over the composition-validation stanza) and
//! [`crate::rebac_keys_probe`] (correlated `{Relation, Permission}`
//! pair over the ReBAC KEYS-probe stanza): a closed enum whose two
//! arms each carry the exact adjective the pre-lift stanza spelled
//! inline.
//!
//! # Scope boundary
//!
//! The primitive owns the announce + push + report grammar around
//! ONE `crossplane xpkg push` invocation. The prior `crossplane xpkg
//! build` phase — which differs meaningfully between Function
//! (`--embed-runtime-image-tarball <runtime>`) and Configuration
//! (no runtime image) — stays at the call site because its shape
//! varies between the two release fns. The output-path setup
//! (`xpkg_output_file()`) also stays at the caller since its
//! `TempDir` guard must be bound to a local so `Drop` fires at end
//! of scope. Sibling of the
//! `commands/supergraph_composition_phase` carve-out that owns
//! open+close around a body that varies per phase.

use std::io;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use tracing::info;

use crate::retry::run_inherited_status_sync;

/// The invariant argv slice the pre-lift two sibling
/// `push.args([...])` calls both spelled inline —
/// `["xpkg", "push", "--package-files"]`. Named as a `const` so a
/// future re-tuning of the flag (e.g. a switch to a positional
/// `<package>` form the crossplane CLI eventually stabilizes on)
/// flows through one edit rather than through two inline literal
/// edits.
///
/// The `--package-files` (plural) flag is the intentional spelling
/// per the crossplane CLI — verified against the CLI, NOT the
/// singular `--package-file` that the sibling `xpkg build` uses.
pub const XPKG_PUSH_ARGV: [&str; 3] = ["xpkg", "push", "--package-files"];

/// The invariant prefix the pre-lift two sibling
/// `info!("crossplane xpkg push \u{2192} {}", dest)` announcement
/// lines spliced before the `dest` field —
/// `"crossplane xpkg push \u{2192} "` (verb + right-arrow glyph
/// U+2192 + ASCII space). Named as a `const` so a future
/// re-branding of the verb or the arrow glyph flows through one
/// edit alongside its sibling constants.
const PUSH_ANNOUNCEMENT_PREFIX: &str = "crossplane xpkg push \u{2192} ";

/// The invariant prefix the pre-lift two sibling
/// `run_inherited_status_sync(_, &format!("crossplane xpkg push {}",
/// dest))` op-label formatters spliced before the `dest` field —
/// `"crossplane xpkg push "` (verb + trailing ASCII space, NO
/// arrow). Named as a `const` so a future re-tuning of the op label
/// (which the retry primitive stamps into the operator-facing
/// `"{op} failed (exit {code})"` envelope on non-zero exit) flows
/// through one edit.
const PUSH_OP_LABEL_PREFIX: &str = "crossplane xpkg push ";

/// The invariant suffix the pre-lift two sibling
/// `info!("<Kind> package published: {}", dest)` postamble lines
/// spliced between the `<Kind>` adjective and the `dest` field —
/// `" package published: "` (leading space + noun + colon + trailing
/// space). Named as a `const` so a future re-branding of the
/// postamble verb flows through one edit alongside its
/// [`CrossplanePackageKind`]-driven adjective.
const PACKAGE_PUBLISHED_INFIX: &str = " package published: ";

/// The two typed variants of the `crossplane xpkg push` release
/// stanza the fusion primitive supports.
///
/// The pre-lift two sites each picked their postamble adjective
/// (`Function` / `Configuration`, capitalized) INDEPENDENTLY, at
/// inline literal call sites — a silent drift that shipped the
/// Function-shaped push above the Configuration-shaped report (or
/// vice versa) would have flowed through review with nothing
/// catching it. Encoding the correlated pair as a kind enum with
/// [`Self::label`] mirroring the pre-lift wording makes the
/// pairing structurally impossible to break: a future re-tuning
/// of the adjective touches this enum, and every caller inherits
/// the invariant by construction.
///
/// Same closed-enum discipline as
/// [`crate::commands::supergraph_composition_phase::SupergraphCompositionPhase`]
/// ({`Pre`, `Post`}) and [`crate::rebac_keys_probe::RebacKeyKind`]
/// ({`Relation`, `Permission`}) — each arm carries the exact
/// adjective the pre-lift stanza spliced inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossplanePackageKind {
    /// A Crossplane composition **Function** package (an xpkg
    /// bundling a Nix-built runtime image + a `crossplane.yaml`
    /// Function meta). Consumed by
    /// `commands/crossplane.rs::function_release`; the pre-lift
    /// postamble spelled `"Function"`.
    Function,
    /// A Crossplane **Configuration** package (an xpkg bundling
    /// XRDs + Compositions from a `crossplane.yaml`
    /// Configuration meta, with no runtime image). Consumed by
    /// `commands/crossplane.rs::configuration_release`; the
    /// pre-lift postamble spelled `"Configuration"`.
    Configuration,
}

impl CrossplanePackageKind {
    /// The capitalized adjective the pre-lift `info!("<Kind>
    /// package published: {}", dest)` postamble spliced inline for
    /// this kind: `Function` → `"Function"`, `Configuration` →
    /// `"Configuration"`. Byte-identical to the wording each
    /// pre-lift call site carried.
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CrossplanePackageKind::Function => "Function",
            CrossplanePackageKind::Configuration => "Configuration",
        }
    }
}

/// Compose the `dest` reference string the pre-lift two sites each
/// derived — `<package_ref stripped of a trailing '/'>:<tag>` via
/// [`crate::oci_manifest::image_reference`]. Named as its own
/// primitive so a future tweak to the `trim_end_matches('/')`
/// discipline (a switch to normalize both leading and trailing
/// slashes, say) lands in one place instead of two inline
/// restatements.
#[must_use]
pub fn compose_xpkg_push_dest(package_ref: &str, tag: &str) -> String {
    crate::oci_manifest::image_reference(package_ref.trim_end_matches('/'), tag)
}

/// The full announcement line for a push against `dest` — the
/// `"crossplane xpkg push \u{2192} <dest>"` composition of
/// [`PUSH_ANNOUNCEMENT_PREFIX`] and the `dest` field.
/// Byte-identical to the string each pre-lift call site passed to
/// [`info!`] as its format-string+argument pair.
#[must_use]
pub fn format_xpkg_push_announcement(dest: &str) -> String {
    format!("{PUSH_ANNOUNCEMENT_PREFIX}{dest}")
}

/// The full op-label the retry primitive receives for a push
/// against `dest` — the `"crossplane xpkg push <dest>"` composition
/// of [`PUSH_OP_LABEL_PREFIX`] and the `dest` field.
/// Byte-identical to the string each pre-lift call site built with
/// `format!("crossplane xpkg push {}", dest)`. Distinct from
/// [`format_xpkg_push_announcement`] by exactly one glyph: the
/// arrow (`\u{2192}`) is present in the operator-facing
/// announcement but NOT in the retry primitive's op-label, since
/// the op-label is spliced back into the
/// `"{op} failed (exit {code})"` envelope and a stray arrow there
/// would read as noise.
#[must_use]
pub fn format_xpkg_push_op_label(dest: &str) -> String {
    format!("{PUSH_OP_LABEL_PREFIX}{dest}")
}

/// The full postamble line for a completed push of a package of
/// `kind` against `dest` — the `"<Kind> package published: <dest>"`
/// composition of [`CrossplanePackageKind::label`],
/// [`PACKAGE_PUBLISHED_INFIX`], and the `dest` field.
/// Byte-identical to the string each pre-lift call site passed to
/// [`info!`] as its format-string+argument pair.
#[must_use]
pub fn format_package_published_message(kind: CrossplanePackageKind, dest: &str) -> String {
    format!("{}{PACKAGE_PUBLISHED_INFIX}{dest}", kind.label())
}

/// Writer-taking sibling to [`format_xpkg_push_announcement`].
/// Emits the single announcement line via [`writeln!`] against the
/// supplied writer, byte-for-byte identical to the pre-lift inline
/// literal. Same writer/print split every prior sibling-writer
/// refactor honors (see
/// [`crate::commands::supergraph_composition_phase::write_composition_phase_start`]
/// for the canonical split rationale).
pub fn write_xpkg_push_announcement<W: io::Write>(w: &mut W, dest: &str) -> io::Result<()> {
    writeln!(w, "{}", format_xpkg_push_announcement(dest))
}

/// Writer-taking sibling to [`format_package_published_message`].
/// Emits the single postamble line via [`writeln!`] against the
/// supplied writer, byte-for-byte identical to the pre-lift inline
/// literal.
pub fn write_package_published_message<W: io::Write>(
    w: &mut W,
    kind: CrossplanePackageKind,
    dest: &str,
) -> io::Result<()> {
    writeln!(w, "{}", format_package_published_message(kind, dest))
}

/// Announce, spawn `crossplane xpkg push --package-files <out>
/// <dest>`, and report the completion — the full open-run-close
/// stanza both pre-lift release fns carried verbatim, fused into
/// one entry point driven by the [`CrossplanePackageKind`]
/// correlated-adjective enum.
///
/// The `crossplane` binary is resolved at the caller via the
/// module-local `crossplane_bin()` sigil (which routes through
/// `CROSSPLANE_BIN` per the hermetic-runner contract) and passed in
/// as `&str` so this primitive stays free of the `commands/`-scoped
/// sigil layer. `out` is the on-disk xpkg the sibling `xpkg build`
/// step wrote, kept alive by the caller's `TempDir` guard for the
/// duration of this call.
///
/// Every status-only spawn in `commands/crossplane.rs` routes
/// through [`run_inherited_status_sync`] — this primitive preserves
/// that discipline, so the whole-module status-spawn shield stays
/// intact.
pub fn xpkg_push_and_report(
    crossplane: &str,
    out: &Path,
    package_ref: &str,
    tag: &str,
    kind: CrossplanePackageKind,
) -> Result<()> {
    let dest = compose_xpkg_push_dest(package_ref, tag);
    info!("{}", format_xpkg_push_announcement(&dest));
    let mut push = Command::new(crossplane);
    push.args(XPKG_PUSH_ARGV).arg(out).arg(&dest);
    run_inherited_status_sync(push, &format_xpkg_push_op_label(&dest))?;
    info!("{}", format_package_published_message(kind, &dest));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Argv-slice pin: the pre-lift two sites each spelled the
    /// 3-element `["xpkg", "push", "--package-files"]` argv inline.
    /// A drift onto the singular `--package-file` (which the
    /// sibling `xpkg build` uses) would silently accept the flag
    /// but fail to publish the artifact.
    #[test]
    fn xpkg_push_argv_matches_pre_lift_slice() {
        assert_eq!(XPKG_PUSH_ARGV, ["xpkg", "push", "--package-files"]);
    }

    /// Adjective-axis pin: `Function` splices `"Function"` and
    /// `Configuration` splices `"Configuration"` — the two verbatim
    /// adjectives the pre-lift postamble sites each spelled inline.
    #[test]
    fn label_maps_to_pre_lift_wording() {
        assert_eq!(CrossplanePackageKind::Function.label(), "Function");
        assert_eq!(
            CrossplanePackageKind::Configuration.label(),
            "Configuration"
        );
    }

    /// Correlated-pair divergence guard: the two arms must produce
    /// distinct labels. A future edit collapsing both onto the same
    /// spelling would fuse the two published-message narratives
    /// into a single indistinguishable line.
    #[test]
    fn function_and_configuration_labels_are_distinct() {
        assert_ne!(
            CrossplanePackageKind::Function.label(),
            CrossplanePackageKind::Configuration.label()
        );
    }

    /// Pin the exact dest composition: a bare `<repo>:<tag>` when
    /// `package_ref` carries no trailing slash. Byte-identical to
    /// the string each pre-lift `let dest = ...` line derived.
    #[test]
    fn compose_dest_bare_ref_matches_pre_lift() {
        assert_eq!(
            compose_xpkg_push_dest("ghcr.io/pleme-io/function-pitr-drill", "v0.1.0"),
            "ghcr.io/pleme-io/function-pitr-drill:v0.1.0"
        );
    }

    /// Pin the trailing-slash trim: a `package_ref` ending in `/`
    /// composes the same `<repo>:<tag>` as its trimmed counterpart.
    /// Byte-identical to the `.trim_end_matches('/')` discipline
    /// each pre-lift call site carried inline.
    #[test]
    fn compose_dest_trims_trailing_slash() {
        assert_eq!(
            compose_xpkg_push_dest("ghcr.io/pleme-io/config-drill/", "v0.2.0"),
            "ghcr.io/pleme-io/config-drill:v0.2.0"
        );
    }

    /// Pin the announcement composition: the
    /// `"crossplane xpkg push \u{2192} <dest>"` line each pre-lift
    /// call site passed to [`info!`]. A drift on the verb, on the
    /// arrow glyph, or on the surrounding spaces flips this
    /// assertion at ONE site rather than silently forking the
    /// grammar across two call sites.
    #[test]
    fn announcement_matches_pre_lift_wording() {
        assert_eq!(
            format_xpkg_push_announcement("ghcr.io/pleme-io/x:v1"),
            "crossplane xpkg push \u{2192} ghcr.io/pleme-io/x:v1"
        );
    }

    /// Pin the op-label composition: the `"crossplane xpkg push
    /// <dest>"` label each pre-lift call site built with
    /// `format!` and passed to [`run_inherited_status_sync`].
    /// Distinct from the announcement by exactly one glyph — no
    /// arrow — so the retry primitive's
    /// `"{op} failed (exit {code})"` envelope stays readable.
    #[test]
    fn op_label_matches_pre_lift_wording() {
        assert_eq!(
            format_xpkg_push_op_label("ghcr.io/pleme-io/x:v1"),
            "crossplane xpkg push ghcr.io/pleme-io/x:v1"
        );
    }

    /// Divergence guard: the announcement carries the arrow glyph
    /// `\u{2192}` and the op-label does NOT. A future edit that
    /// silently unified the two shapes would push the arrow into
    /// the retry primitive's failure envelope (unreadable) or drop
    /// the arrow from the operator-facing announcement
    /// (regression). Pinning the exact character sets on each side
    /// makes either drift a test failure at THIS site.
    #[test]
    fn announcement_and_op_label_diverge_on_arrow_glyph() {
        let dest = "ghcr.io/pleme-io/x:v1";
        assert!(format_xpkg_push_announcement(dest).contains('\u{2192}'));
        assert!(!format_xpkg_push_op_label(dest).contains('\u{2192}'));
    }

    /// Pin the postamble composition for both kinds:
    /// `Function` → `"Function package published: <dest>"`,
    /// `Configuration` → `"Configuration package published: <dest>"`
    /// — byte-identical to the string each pre-lift call site
    /// passed to [`info!`].
    #[test]
    fn published_message_matches_pre_lift_wording() {
        assert_eq!(
            format_package_published_message(
                CrossplanePackageKind::Function,
                "ghcr.io/pleme-io/x:v1"
            ),
            "Function package published: ghcr.io/pleme-io/x:v1"
        );
        assert_eq!(
            format_package_published_message(
                CrossplanePackageKind::Configuration,
                "ghcr.io/pleme-io/x:v1"
            ),
            "Configuration package published: ghcr.io/pleme-io/x:v1"
        );
    }

    /// Byte-oracle pin for the announcement writer sibling:
    /// `writeln!` of `format_xpkg_push_announcement(dest)` produces
    /// exactly `"crossplane xpkg push \u{2192} <dest>\n"`. A drift
    /// on the verb, arrow, spacing, or newline discipline flips
    /// this test.
    #[test]
    fn write_announcement_emits_pre_lift_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_xpkg_push_announcement(&mut buf, "ghcr.io/pleme-io/x:v1").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "crossplane xpkg push \u{2192} ghcr.io/pleme-io/x:v1\n"
        );
    }

    /// Byte-oracle pin for the postamble writer sibling on the
    /// Function arm: `writeln!` of
    /// `format_package_published_message(Function, dest)` produces
    /// exactly `"Function package published: <dest>\n"`.
    #[test]
    fn write_published_emits_function_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_published_message(
            &mut buf,
            CrossplanePackageKind::Function,
            "ghcr.io/pleme-io/x:v1",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Function package published: ghcr.io/pleme-io/x:v1\n"
        );
    }

    /// Byte-oracle pin for the postamble writer sibling on the
    /// Configuration arm: sibling of the Function pin above,
    /// verifies the correlated adjective splices unchanged.
    #[test]
    fn write_published_emits_configuration_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_package_published_message(
            &mut buf,
            CrossplanePackageKind::Configuration,
            "ghcr.io/pleme-io/x:v1",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Configuration package published: ghcr.io/pleme-io/x:v1\n"
        );
    }

    /// Const-anchor pin: the three canonical strings the primitive
    /// owns each carry their exact pre-lift byte sequence.
    #[test]
    fn canonical_constants_carry_pre_lift_byte_sequences() {
        assert_eq!(PUSH_ANNOUNCEMENT_PREFIX, "crossplane xpkg push \u{2192} ");
        assert_eq!(PUSH_OP_LABEL_PREFIX, "crossplane xpkg push ");
        assert_eq!(PACKAGE_PUBLISHED_INFIX, " package published: ");
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift announcement literal
    /// `info!("crossplane xpkg push \u{2192} {}", dest)` inline any
    /// more. Every push-announce narrative in a crossplane release
    /// flow must resolve through [`xpkg_push_and_report`] so a
    /// future drift on the verb or the arrow glyph flows to both
    /// kinds from one edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from bare fragments so this shield's own source
    /// text does not false-match itself. Every hit routes through
    /// [`crate::test_support::code_line_hits`] for anti-comment-
    /// line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_xpkg_push_announcement() {
        let forbidden = format!("info!(\"crossplane xpkg push {} {{}}\", dest)", "\u{2192}");
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip THIS module — its own byte-oracle test strings
            // mention the pre-lift shape verbatim by design.
            if path.file_name().and_then(|n| n.to_str()) == Some("crossplane_xpkg_push.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `{forbidden}` announcement stanza(s) survive under \
             `commands/` — route each through \
             `crate::commands::crossplane_xpkg_push::xpkg_push_and_report(...)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift postamble literal `info!("<Kind> package
    /// published: {}", dest)` inline any more. Every published
    /// narrative in a crossplane release flow must resolve through
    /// [`xpkg_push_and_report`] so a future re-phrasing of the
    /// postamble suffix flows to both kinds from one edit.
    #[test]
    fn no_command_module_still_spells_raw_package_published_postamble() {
        for kind_word in ["Function", "Configuration"] {
            let forbidden = format!("info!(\"{kind_word} package published: {{}}\", dest)");
            let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands");
            let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str()) == Some("crossplane_xpkg_push.rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let hits = crate::test_support::code_line_hits(&source, &forbidden);
                if !hits.is_empty() {
                    offenders.push((path, hits));
                }
            }
            assert!(
                offenders.is_empty(),
                "pre-lift `{forbidden}` postamble stanza(s) survive under \
                 `commands/` — route each through \
                 `crate::commands::crossplane_xpkg_push::xpkg_push_and_report(...)` \
                 instead:\n{offenders:#?}",
            );
        }
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift 3-element push argv literal
    /// `push.args(["xpkg", "push", "--package-files"])` inline any
    /// more. Every crossplane xpkg push spawn must resolve through
    /// [`XPKG_PUSH_ARGV`] via [`xpkg_push_and_report`] so a future
    /// re-tuning of the flag (e.g. the singular `--package-file`
    /// which the sibling `xpkg build` uses) flows through one edit.
    #[test]
    fn no_command_module_still_spells_raw_xpkg_push_argv() {
        let forbidden = "args([\"xpkg\", \"push\", \"--package-files\"])";
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("crossplane_xpkg_push.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `{forbidden}` argv stanza(s) survive under \
             `commands/` — route each through \
             `crate::commands::crossplane_xpkg_push::xpkg_push_and_report(...)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Positive-half delegation shield: the sole consumer module
    /// `commands/crossplane.rs` MUST carry exactly two calls to
    /// [`xpkg_push_and_report`] — one from `function_release`, one
    /// from `configuration_release`. Guards against a silent removal
    /// of the push+report fusion from either release flow.
    #[test]
    fn every_crossplane_release_delegates_through_fusion() {
        let source = include_str!("crossplane.rs");
        let count = source.matches("xpkg_push_and_report(").count();
        assert_eq!(
            count, 2,
            "`commands/crossplane.rs` must invoke \
             `crate::commands::crossplane_xpkg_push::xpkg_push_and_report(` \
             exactly twice (one per release fn); found {count}. A flow \
             that runs to completion without emitting the push+report \
             stanza breaks the operator-facing crossplane release \
             narrative.",
        );
    }
}
