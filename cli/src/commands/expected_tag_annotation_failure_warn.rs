//! `warn_expected_tag_annotation_failed_nonfatal` — two sibling
//! `crate::ui::print_plain_step_warn(&format!("Failed to set expected-tag
//! annotation (non-fatal): {}", <detail>))` post-annotate warn stanzas in
//! `commands/migrations.rs::set_expected_tag_annotation` collapsed onto
//! one typed primitive.
//!
//! # Pre-lift census — two sibling stanzas, one warn line
//!
//! [`crate::commands::migrations::set_expected_tag_annotation`] spawns a
//! `kubectl annotate databasemigration <name> -n <ns>
//! release.shinka.pleme.io/expected-tag=<tag> --overwrite` and dispatches
//! on the resulting [`std::io::Result<std::process::Output>`]:
//!
//! - `Ok(output)` with `!output.status.success()` — kubectl ran but its
//!   exit status is non-zero; the stderr is decoded via
//!   [`crate::repo::utf8_lossy_borrow`] and `.trim()`d, then routed
//!   through [`crate::ui::print_plain_step_warn`] with the format literal
//!   `"Failed to set expected-tag annotation (non-fatal): {}"`.
//! - `Err(e)` — the spawn itself failed (kubectl absent, `PATH`
//!   misresolved, `Command::output` I/O error). The [`std::io::Error`]'s
//!   [`std::fmt::Display`] impl is routed through the identical warn
//!   grammar with the same format literal.
//!
//! Both arms restate the same label + `(non-fatal): ` marker + `{}`
//! detail-slot verbatim, differing only in whether `<detail>` is the
//! trimmed stderr `&str` or the borrowed [`std::io::Error`]. The
//! surrounding function is deliberately non-fatal because the
//! expected-tag annotation is a *hint* to Shinka's cache-invalidation
//! path — the enclosing migration proceeds either way and just falls
//! back to the ordinary 60s reconcile cadence rather than the
//! Shinka-hinted 1s fast-requeue.
//!
//! Two occurrences of a byte-identical label + marker + slot shape past
//! THEORY §VI.1's three-is-a-law-in-waiting threshold. A single-site
//! drift — a rephrase of `"Failed to set"` to `"Could not set"`, a swap
//! of the `(non-fatal)` marker to `(warning)`, a rearrangement of the
//! marker after the colon (`"…annotation: (non-fatal) {}"`) — pre-lift
//! had to hit two sites in lockstep or diverge across the two error
//! flavors. Post-lift a future adjustment (a promotion of the marker to
//! the fleet-standard `warn_nonfatal!` grammar over on
//! [`crate::warn_nonfatal!`], wiring an OTLP
//! `shinka_annotation_set_failed` span alongside the warn, promoting the
//! render to a structured [`crate::error::ForgeError`] variant, or
//! adding the offending `expected-tag` value back into the message)
//! reaches ONE typed body and every consumer inherits the change.
//!
//! # Distinct from every peer `warn_*_nonfatal` sibling
//!
//! [`crate::warn_nonfatal!`] carries the fleet-standard
//! `warn!("⚠️  <label> (non-fatal): <err>")` grammar routed through
//! [`tracing::warn`] — a `WARN`-level tracing event whose renderer paints
//! the timestamp, target module, and log level around the message. The
//! two pre-lift `set_expected_tag_annotation` sites deliberately spelled
//! the marker as a bare-stdout [`println!`]-adjacent
//! [`crate::ui::print_plain_step_warn`] call so the warn line reads
//! inline with the surrounding `📌 Setting expected-tag annotation: …`
//! stdout announcement rather than as a stderr-routed structured log
//! event. Preserving that dialect is load-bearing — the enclosing
//! command's operator surface is a sequential stdout narrative, and a
//! silent promotion to [`crate::warn_nonfatal!`] would fragment the
//! narrative across stdout and stderr.
//!
//! # Byte-oracle
//!
//! [`write_warn_expected_tag_annotation_failed_nonfatal`] is the
//! writer-taking sibling — a [`Vec<u8>`] sink lets tests pin the exact
//! rendered bytes (the three-space indent + UNCOLORED `⚠️` glyph +
//! two-space post-glyph gap + the fixed `"Failed to set expected-tag
//! annotation (non-fatal): "` label + `(non-fatal): ` marker + the
//! caller's detail + trailing `\n`, with NO ANSI escape) at one site
//! rather than as two lockstep format literals across
//! `migrations.rs::set_expected_tag_annotation`'s two error arms.

use std::fmt::Display;
use std::io;

/// The invariant label + marker every pre-lift warn stanza spelled — a
/// fixed `"Failed to set expected-tag annotation"` verb phrase, one
/// ASCII space, the load-bearing `"(non-fatal)"` marker in
/// parentheses, then `": "` and the caller-supplied detail. Named as a
/// `const` so a future rebranding of the marker or the verb reaches one
/// site rather than two inline format literals.
pub const EXPECTED_TAG_ANNOTATION_FAILURE_LABEL: &str =
    "Failed to set expected-tag annotation (non-fatal)";

/// Emit the canonical
/// `"   ⚠️  Failed to set expected-tag annotation (non-fatal): <detail>"`
/// warn line to stdout via [`crate::ui::print_plain_step_warn`]. Called
/// on both non-fatal error arms of
/// [`crate::commands::migrations::set_expected_tag_annotation`] — the
/// `Ok(output)` non-success stderr-decode branch and the `Err(e)`
/// spawn-failure branch — with the pre-computed `detail` being either
/// the trimmed stderr `&str` or the borrowed [`std::io::Error`].
///
/// Delegates to
/// [`write_warn_expected_tag_annotation_failed_nonfatal`] against
/// [`std::io::stdout`]; the writer split exists so the fail-before-pass
/// byte-oracle test pins the exact rendered bytes without capturing
/// stdout.
pub fn warn_expected_tag_annotation_failed_nonfatal(detail: &dyn Display) {
    let _ = write_warn_expected_tag_annotation_failed_nonfatal(&mut io::stdout().lock(), detail);
}

/// Writer-taking sibling to
/// [`warn_expected_tag_annotation_failed_nonfatal`]. Emits the single
/// `   ⚠️  Failed to set expected-tag annotation (non-fatal): <detail>\n`
/// line via [`crate::ui::write_plain_step_warn`] against the supplied
/// writer.
///
/// [`warn_expected_tag_annotation_failed_nonfatal`] is the stdout
/// adapter; this variant exists so tests can pin the exact indent
/// (three ASCII spaces), the UNCOLORED `⚠️` glyph, the two-space
/// post-glyph gap, the fixed label + marker, the `": "` connective,
/// the caller-supplied detail, the trailing `\n`, and the absence of
/// every ANSI palette sequence without capturing stdout.
pub fn write_warn_expected_tag_annotation_failed_nonfatal<W: io::Write>(
    w: &mut W,
    detail: &dyn Display,
) -> io::Result<()> {
    crate::ui::write_plain_step_warn(
        w,
        &format!("{}: {}", EXPECTED_TAG_ANNOTATION_FAILURE_LABEL, detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: [`EXPECTED_TAG_ANNOTATION_FAILURE_LABEL`] carries
    /// the exact pre-lift verb + `(non-fatal)` marker byte sequence.
    /// A drift to `"Could not"`, `"(warning)"`, or a comma before the
    /// marker flips this assertion.
    #[test]
    fn expected_tag_annotation_failure_label_matches_pre_lift_bytes() {
        assert_eq!(
            EXPECTED_TAG_ANNOTATION_FAILURE_LABEL,
            "Failed to set expected-tag annotation (non-fatal)"
        );
    }

    /// Byte-oracle (stderr-decode branch): the primitive renders the
    /// pre-lift `   ⚠️  Failed to set expected-tag annotation
    /// (non-fatal): <trimmed stderr>\n` line byte-for-byte when the
    /// caller passes a plain `&str` `detail`.
    #[test]
    fn write_warn_expected_tag_annotation_failed_nonfatal_emits_stderr_branch_bytes_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let stderr_detail = "annotate.batch/v1 forbidden";
        write_warn_expected_tag_annotation_failed_nonfatal(&mut buf, &stderr_detail)
            .expect("write against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf)
            .expect("write must emit valid UTF-8 (the pre-lift `print_plain_step_warn` calls did)");
        assert_eq!(
            out,
            "   \u{26A0}\u{FE0F}  Failed to set expected-tag annotation (non-fatal): \
             annotate.batch/v1 forbidden\n",
            "byte-oracle: the primitive must render the three-space \
             indent + UNCOLORED U+26A0 U+FE0F glyph + two-space gap + \
             fixed label + `(non-fatal): ` marker + trimmed stderr + \
             `\\n`, no ANSI escape, no other glyph"
        );
    }

    /// Byte-oracle (spawn-failure branch): the same rendered line
    /// modulo the caller-supplied detail, this time passed as a
    /// [`std::io::Error`] whose [`Display`] impl the primitive
    /// interpolates through the shared `{}` slot. Pins the `Err(e)`
    /// arm's pre-lift shape so a future refactor that pre-decoded the
    /// error via a debug-format (`{:?}`) or an intermediate string
    /// allocation regresses this assertion.
    #[test]
    fn write_warn_expected_tag_annotation_failed_nonfatal_emits_spawn_error_branch_bytes_verbatim()
    {
        let mut buf: Vec<u8> = Vec::new();
        let io_err = io::Error::new(io::ErrorKind::NotFound, "kubectl: not found");
        write_warn_expected_tag_annotation_failed_nonfatal(&mut buf, &io_err)
            .expect("write against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "   \u{26A0}\u{FE0F}  Failed to set expected-tag annotation (non-fatal): \
             kubectl: not found\n",
            "byte-oracle: the spawn-failure arm must render the io::Error \
             through the same primitive with the same three-space indent + \
             UNCOLORED U+26A0 U+FE0F glyph + label + marker + `\\n`"
        );
    }

    /// A silent promotion of the primitive to `.bold()` / `.dimmed()` /
    /// any `.<color>()` chain would flatten the pre-lift plain-stdout
    /// grammar the two consumer sites deliberately spelled uncolored
    /// so the warn line reads inline with the surrounding
    /// `📌 Setting expected-tag annotation: <tag>` stdout announcement.
    /// This shield pins the absence of every ANSI escape byte so a
    /// color-chain promotion surfaces here rather than silently
    /// coloring both error flows.
    #[test]
    fn write_warn_expected_tag_annotation_failed_nonfatal_carries_no_ansi_escape_byte() {
        let mut buf: Vec<u8> = Vec::new();
        let detail = "any detail";
        write_warn_expected_tag_annotation_failed_nonfatal(&mut buf, &detail).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains('\x1b'),
            "primitive must carry NO ANSI escape byte (`\\x1b`) — \
             the pre-lift `print_plain_step_warn` sites reach stdout \
             uncolored; a `.bold()` / `.dimmed()` / `.<color>()` \
             promotion would flatten the warn grammar. Got {out:?}"
        );
    }

    /// The load-bearing `(non-fatal)` marker MUST appear exactly once
    /// inside the parenthesized suffix of the label and MUST come
    /// BEFORE the `": "` connective and the caller-supplied detail. A
    /// future refactor that moved the marker after the detail
    /// (`"…annotation: <detail> (non-fatal)"`), doubled it, or dropped
    /// it entirely would break the operator's expectation that the
    /// bracketed marker signals fault severity ahead of the noisy
    /// stderr/error text.
    #[test]
    fn write_warn_expected_tag_annotation_failed_nonfatal_places_marker_before_colon_and_detail() {
        let mut buf: Vec<u8> = Vec::new();
        let detail = "SENTINEL_DETAIL";
        write_warn_expected_tag_annotation_failed_nonfatal(&mut buf, &detail).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out.matches("(non-fatal)").count(),
            1,
            "(non-fatal) marker must appear exactly once; got {out:?}"
        );
        let marker_idx = out.find("(non-fatal)").expect("marker must be present");
        let colon_idx = out
            .find("): ")
            .expect("marker's closing paren + `: ` connective must be present");
        let detail_idx = out
            .find("SENTINEL_DETAIL")
            .expect("caller-supplied detail must be interpolated");
        assert!(
            marker_idx < colon_idx && colon_idx < detail_idx,
            "marker must precede the `: ` connective which must precede \
             the detail; got marker@{marker_idx} colon@{colon_idx} \
             detail@{detail_idx} in {out:?}"
        );
    }

    /// The caller-supplied detail lands after the label + `(non-fatal)`
    /// marker + `": "` connective EXACTLY once. A future refactor that
    /// dropped the interpolation slot (a bare label warn with no
    /// operator-visible cause) or doubled it (a detail echoed twice
    /// for emphasis) flips this assertion.
    #[test]
    fn write_warn_expected_tag_annotation_failed_nonfatal_interpolates_detail_slot_once() {
        let mut buf: Vec<u8> = Vec::new();
        let detail = "SENTINEL_XYZ";
        write_warn_expected_tag_annotation_failed_nonfatal(&mut buf, &detail).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out.matches("SENTINEL_XYZ").count(),
            1,
            "detail must appear exactly once in the warn line; got {out:?}"
        );
    }

    /// Whole-file negative caller shield: no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `"Failed to set expected-tag annotation (non-fatal): "` label
    /// literal inline any more. The two pre-lift sites migrated; any
    /// future consumer that wants the same warn reaches for
    /// [`warn_expected_tag_annotation_failed_nonfatal`] on first grep,
    /// not by copy-pasting the raw format literal from an existing
    /// module.
    ///
    /// Reconstructed at test time via [`format!`] against the module's
    /// own [`EXPECTED_TAG_ANNOTATION_FAILURE_LABEL`] const so this
    /// shield's own source text does not false-match itself when the
    /// scan visits its own path (which is additionally excluded by
    /// name). Docstring `///` lines and block-comment ranges are
    /// skipped so a future module that quotes the pre-lift shape as
    /// historical prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_expected_tag_annotation_failure_label() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");
        let this_file = scan_dir.join("expected_tag_annotation_failure_warn.rs");

        // Reconstruct the forbidden literal via `format!` so this
        // shield's own docstring / prose mentions of the label do not
        // false-match themselves.
        let forbidden = format!("{}: ", EXPECTED_TAG_ANNOTATION_FAILURE_LABEL);

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
            let path = entry.path();
            if path == this_file {
                continue;
            }
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
                if line.contains(&forbidden) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"Failed to set expected-tag annotation (non-fatal): …\"` \
             literal(s) survive under `commands/` — route each through \
             `crate::commands::expected_tag_annotation_failure_warn::\
             warn_expected_tag_annotation_failed_nonfatal(...)` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the two sites (`commands/migrations.rs`) MUST forward
    /// through [`warn_expected_tag_annotation_failed_nonfatal`] at
    /// least twice, so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    /// Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields the crate carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_warn_expected_tag_annotation_failed_nonfatal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("migrations.rs"), 2)];
        let needle = "warn_expected_tag_annotation_failed_nonfatal(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} expected-tag-annotation warn site(s) through \
                 `{}`; found {}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
