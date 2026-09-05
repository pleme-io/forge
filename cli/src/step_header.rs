//! Info-routed release-workflow step-header grammar.
//!
//! Thirty-one pre-lift sibling sites — `commands/comprehensive_release`
//! (six: `Pre-Build Validation`, `Build Docker Image`, two
//! `Integration Testing`, `Push to Registry`, `Deploy to Kubernetes`),
//! `commands/deploy` (four: `Build`, `Push`, `GitOps Deploy`,
//! `Purge Cloudflare Cache`), `commands/github_runner_ci` (three:
//! `Build`, `Push to GHCR`, `GitOps Deployment`), `commands/kenshi`
//! (four: `Push Image`, `Update primary cluster kustomization`,
//! `Update secondary cluster kustomization`, `Commit and Push`),
//! `commands/kenshi_agent` (six: `Push Image`, `Update primary cluster
//! kustomization`, `Update secondary cluster kustomization`, `Update
//! primary cluster builder-pool`, `Update secondary cluster
//! builder-pool`, `Commit and Push`), `commands/nix_builder` (eight:
//! `Push Image`, `Update primary cluster nix-builder kustomization`,
//! the sibling `Skip primary cluster nix-builder kustomization` arm,
//! `Update primary cluster kenshi BUILDER_IMAGE`, `Update primary
//! cluster builder-pool`, `Update secondary cluster kenshi
//! BUILDER_IMAGE`, `Update secondary cluster builder-pool`,
//! `Commit and Push`) — each restated the
//! `info!("━━━ Step {N}/{M}: <TITLE> ━━━")` step-header stanza verbatim
//! — three `━` (U+2501, BOX DRAWINGS HEAVY HORIZONTAL, no variation
//! selector) heavy horizontals, one ASCII space, the literal `Step `,
//! a 1-based step index, an ASCII `/`, the workflow's step total,
//! `": "`, a per-site title, one ASCII space, then three more `━` —
//! and an `info!`-routed emission via the tracing subscriber. Post-lift
//! the sites call [`announce_step_header`] and the glyph-count +
//! separator + step/total grammar + tracing verbosity + the
//! `1 <= step <= total` invariant are decided once here.
//!
//! # Types-as-theorems: the step-index invariant
//!
//! Every pre-lift site spells the `{step}/{total}` pair as two literal
//! integer tokens; a typo that walks a `Step 4/3:` heading past the
//! workflow's step total (or a `Step 0/5:` heading with a zero-based
//! index) would print an off-by-one label the operator reads as truth,
//! and a downstream OTLP consumer indexing on the numeric pair would
//! silently accept the impossible record. The primitive lifts the pair
//! from unchecked literal text into a typed `(usize, usize)` triple
//! with `1 <= step <= total` and `total >= 1` asserted at each call —
//! a debug-build failure that catches the off-by-one on the first test
//! run rather than after a live release surface. The invariant is
//! stated once here and enforced everywhere the primitive is called,
//! which is the compounding win: a future orchestrator that reaches for
//! [`announce_step_header`] inherits the check without restating it.
//!
//! # Distinct from the sibling release-narration primitives
//!
//! The crate carries several banner-shaped release-narration
//! primitives, each the sole home for its distinct semantic layer:
//!
//! - [`crate::commands::cluster_overlay_release_preamble::announce_release_start_and_compute_tag`]
//!   narrates a release's OPENING banner (a `🚀 Starting` line, image /
//!   registry / release-tag lines) via `tracing::info!` + `println!`.
//! - [`crate::commands::cluster_overlay_release_postamble::announce_release_complete`]
//!   narrates a release's CLOSING banner (a `╔═══╗` box, a "release
//!   complete!" middle row, a trailing image + reconcile-notice
//!   trailer) via `tracing::info!` + `println!`.
//! - [`announce_step_header`] (this module) narrates a MID-workflow
//!   step heading via `tracing::info!` — one
//!   `━━━ Step N/M: TITLE ━━━` line between workflow steps.
//!
//! The three primitives share the `tracing::info!`-routed emission
//! path so the crate's `tracing_subscriber` initialization in `main.rs`
//! (deliberately `with_ansi(false)`) processes each record uniformly;
//! they differ only in the rendered body and the workflow position.
//!
//! # Byte-oracle writer split
//!
//! The [`announce_step_header`] entry point routes through
//! [`tracing::info!`] — the subscriber pipeline (structured logging,
//! filter, OTLP export) processes the record. The direct-writer
//! [`write_step_header`] variant captures the exact rendered body for
//! the tests (the three `━` opener + closer, the one-space gaps around
//! the title, the trailing newline) without capturing a tracing
//! subscriber and without racing an ambient logger — the same split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`],
//! [`crate::success_step::write_success_step`] carries against
//! [`crate::info_success!`], and
//! [`crate::skipping_step::write_skipping_step`] carries against
//! [`crate::info_skipping!`].

use std::fmt;
use std::io;

/// Assert the `1 <= step <= total` and `total >= 1` step-index
/// invariant. Debug-only: release builds pay no runtime cost, and the
/// crate's `cargo test` gate exercises every call site through the
/// caller-shield tests below.
#[inline]
fn debug_assert_step_in_workflow(step: usize, total: usize) {
    debug_assert!(total >= 1, "workflow step total must be >= 1 (got 0)");
    debug_assert!(step >= 1, "workflow step index must be 1-based (got 0)");
    debug_assert!(
        step <= total,
        "workflow step index {} exceeds total {}",
        step,
        total,
    );
}

/// Emits a single `"━━━ Step {step}/{total}: {title} ━━━"` line via
/// [`writeln!`] against the supplied writer, wrapping the arguments
/// with the pre-lift three-`━` opener + one-space + `Step ` label +
/// step/total pair + `": "` + title + one-space + three-`━` closer
/// that thirty-one sibling sites spelled inline.
///
/// The [`announce_step_header`] entry point is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the three `━` at each end, the single-space gaps around the title,
/// the trailing newline) without capturing a tracing subscriber and
/// without racing an ambient logger — the same split
/// [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`].
///
/// The `title` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare literal (used by every pre-lift call site
/// today), a `String` / `Cow<str>`, and a future step-descriptor type
/// carrying structured fields all flow through the same writer without
/// a per-caller `.to_string()` intermediate.
///
/// Panics in debug builds when the step-index invariant
/// `1 <= step <= total` (or `total >= 1`) is violated; release builds
/// pay no runtime cost. See the module docs for the compounding
/// rationale.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `announce_step_header`, and a future
                    // `collect_step_headers` summary sibling will
                    // consume it directly.
pub fn write_step_header<W: io::Write>(
    w: &mut W,
    step: usize,
    total: usize,
    title: &dyn fmt::Display,
) -> io::Result<()> {
    debug_assert_step_in_workflow(step, total);
    writeln!(
        w,
        "\u{2501}\u{2501}\u{2501} Step {}/{}: {} \u{2501}\u{2501}\u{2501}",
        step, total, title,
    )
}

/// Emit a mid-workflow step heading via [`tracing::info!`] on the
/// fleet-standard `"━━━ Step {step}/{total}: {title} ━━━"` grammar.
///
/// See the [module docs](self) for the sibling site census, the split
/// against
/// [`crate::commands::cluster_overlay_release_preamble::announce_release_start_and_compute_tag`]
/// / [`crate::commands::cluster_overlay_release_postamble::announce_release_complete`],
/// and the compounding rationale for the load-bearing three-`━` opener
/// + closer plus the `1 <= step <= total` step-index invariant.
///
/// Panics in debug builds when `step` is 0, `total` is 0, or `step`
/// exceeds `total`; release builds pay no runtime cost.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("━━━ Step 1/3: Build ━━━");
/// info!("━━━ Step 2/3: Push ━━━");
///
/// // Post-lift
/// crate::step_header::announce_step_header(1, 3, "Build");
/// crate::step_header::announce_step_header(2, 3, "Push");
/// ```
pub fn announce_step_header(step: usize, total: usize, title: &str) {
    debug_assert_step_in_workflow(step, total);
    tracing::info!(
        "\u{2501}\u{2501}\u{2501} Step {}/{}: {} \u{2501}\u{2501}\u{2501}",
        step,
        total,
        title,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three `━` (U+2501, 3 bytes E2 94 81
    // each, no variation selector), one ASCII space, `Step `, the
    // interpolated step index, `/`, the interpolated total, `: `, the
    // interpolated title Display, one ASCII space, three more `━`, then
    // `\n`. A future refactor that widens the horizontal glyph count,
    // drops a space around the title, or adds a variation selector to
    // the `━` regresses this assertion.
    #[test]
    fn write_step_header_emits_three_heavy_horizontals_and_step_pair() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header(&mut buf, 1, 3, &"Build").unwrap();
        assert_eq!(
            buf,
            b"\xe2\x94\x81\xe2\x94\x81\xe2\x94\x81 Step 1/3: Build \
              \xe2\x94\x81\xe2\x94\x81\xe2\x94\x81\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes. Doubles as a Display-
    // forwarding pin: the `&dyn Display` slot receives a title whose
    // rendered form contains a hyphen and interpolated substrings; the
    // interior punctuation MUST survive verbatim without the writer
    // re-quoting or re-escaping the inner text.
    #[test]
    fn write_step_header_forwards_multi_word_title_display() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header(&mut buf, 4, 6, &"Update primary cluster builder-pool").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2501}\u{2501}\u{2501} Step 4/6: Update primary cluster \
             builder-pool \u{2501}\u{2501}\u{2501}\n"
        );
    }

    // Guard against the glyph-count drift: two `━` (or four) would
    // slip past a `contains("━")` check but produce a visually different
    // heading than the thirty-one pre-lift sites share. Pin the exact
    // three-glyph opener + closer explicitly so a future reader who
    // reaches for a different width hits this test.
    #[test]
    fn write_step_header_uses_exactly_three_heavy_horizontals_each_side() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header(&mut buf, 1, 1, &"Only step").unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(
            rendered.starts_with("\u{2501}\u{2501}\u{2501} "),
            "step header must open with exactly three `━` + one space; \
             got: {:?}",
            rendered
        );
        assert!(
            rendered.trim_end().ends_with(" \u{2501}\u{2501}\u{2501}"),
            "step header must close with one space + exactly three `━`; \
             got: {:?}",
            rendered
        );
        // Reject the four-glyph shape: no run of four consecutive `━`
        // may appear anywhere in the rendered body.
        assert!(
            !rendered.contains("\u{2501}\u{2501}\u{2501}\u{2501}"),
            "step header must NOT widen to four `━`; got: {:?}",
            rendered
        );
    }

    // Types-as-theorems: the debug-only step-index invariant. The
    // pre-lift sites all spell `{step}/{total}` as integer literals; a
    // typo that walks a `Step 0/5:` (zero-based), `Step 4/3:`
    // (out-of-range), or `Step 1/0:` (empty workflow) heading would
    // print an off-by-one label an operator reads as truth. The
    // debug-build assertion catches the impossible record on the first
    // test run rather than in production.
    #[test]
    #[should_panic(expected = "workflow step index must be 1-based")]
    fn announce_step_header_rejects_zero_based_step_index() {
        announce_step_header(0, 5, "Zero step");
    }

    #[test]
    #[should_panic(expected = "exceeds total")]
    fn announce_step_header_rejects_step_index_past_total() {
        announce_step_header(6, 5, "Past total");
    }

    #[test]
    #[should_panic(expected = "workflow step total must be >= 1")]
    fn announce_step_header_rejects_zero_step_total() {
        announce_step_header(1, 0, "Empty workflow");
    }

    // Same invariant on the byte-oracle writer entry point.
    #[test]
    #[should_panic(expected = "exceeds total")]
    fn write_step_header_rejects_step_index_past_total() {
        let mut buf: Vec<u8> = Vec::new();
        let _ = write_step_header(&mut buf, 6, 5, &"Past total");
    }

    // Boundary case: the `step == total` heading is legal (a workflow
    // ends with `Step N/N: ...`) and must NOT trip the assertion. Pin
    // the positive boundary explicitly so a future off-by-one in the
    // assertion (`<` instead of `<=`) surfaces as a compile-run failure
    // here rather than through a live cluster-overlay release breaking
    // on its final step heading.
    #[test]
    fn write_step_header_accepts_step_equal_to_total() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header(&mut buf, 7, 7, &"Commit and Push").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2501}\u{2501}\u{2501} Step 7/7: Commit and Push \
             \u{2501}\u{2501}\u{2501}\n"
        );
    }

    // The `announce_step_header` fn forwards to `::tracing::info!` and
    // its emission source-location is this module (a deliberate trade
    // — see module docs — versus the macro-based
    // `info_success!`/`info_skipping!` primitives, which preserve the
    // caller's site so per-module `RUST_LOG` filters keep routing).
    // The subscriber cannot be captured in-process without racing
    // whatever subscriber `main` installs. Instead, pin that
    // `announce_step_header` accepts the supported call shapes by
    // driving it at test time — a compile-fail here would fail the
    // crate's `cargo test` build gate.
    #[test]
    fn announce_step_header_compiles_with_supported_arg_shapes() {
        // Bare literal title (every pre-lift call site today).
        announce_step_header(1, 3, "Build");
        // Multi-word title with punctuation.
        announce_step_header(2, 3, "Update primary cluster kustomization");
        // Runtime `&str` interpolated at the call site.
        let title = String::from("runtime title");
        announce_step_header(3, 3, &title);
    }

    // Caller shield: no source line under `cli/src/commands/` may spell
    // the pre-lift `info!("━━━ Step ` stanza inline any more. Every
    // release-workflow step heading must route through
    // `crate::step_header::announce_step_header`, which centralises the
    // glyph-count + step-index invariant + tracing routing.
    //
    // The shield scans EVERY `commands/*.rs` module rather than only
    // the six pre-lift files so a future workflow orchestrator that
    // surfaces a new step heading (a new sub-step in a new command
    // module) reaches for `announce_step_header` on first grep, not by
    // copy-pasting a raw `info!("━━━ Step ...")` stanza from deploy.rs.
    #[test]
    fn no_command_module_still_spells_raw_info_step_header() {
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
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"\u{2501}\u{2501}\u{2501} Step ") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"\u{2501}\u{2501}\u{2501} Step ...\")` \
             stanza(s) survive under `commands/` — route each through \
             `crate::step_header::announce_step_header(step, total, title)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the six pre-lift files MUST each
    // forward through `crate::step_header::announce_step_header(` at
    // least the pre-lift count of times, so a migration that dropped a
    // call site outright leaves the negative "no raw inline shape" scan
    // trivially satisfied by absence but the positive count still
    // fails.
    #[test]
    fn every_prelift_module_forwards_through_announce_step_header() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("comprehensive_release.rs", 6),
            ("deploy.rs", 4),
            ("github_runner_ci.rs", 3),
            ("kenshi.rs", 4),
            ("kenshi_agent.rs", 6),
            ("nix_builder.rs", 8),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::step_header::announce_step_header(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 step-header site(s) through \
                 `crate::step_header::announce_step_header(`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
