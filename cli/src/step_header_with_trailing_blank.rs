//! Fused `announce_step_header(step, total, title); println!();`
//! two-line stanza — a `tracing::info!`-routed step heading
//! immediately followed by a raw-stdout framing blank.
//!
//! # Pre-lift census — twelve sibling two-line stanzas
//!
//! Twelve consumer sites across four release-workflow command
//! modules spelled the same two-line body verbatim, diverging only
//! on the caller-owned `(step, total, title)` triple:
//!
//! 1. `commands/deploy.rs::execute` — Step 3/3 `"GitOps Deploy"`
//!    (~L64) and Step 4/4 `"Purge Cloudflare Cache"` (~L144).
//! 2. `commands/comprehensive_release.rs::execute` — Steps
//!    1/5 `"Pre-Build Validation"` (~L296), 2/5 `"Build Docker
//!    Image"` (~L371), the `run_integration_tests`-branch 3/5
//!    `"Integration Testing"` (~L400), the fall-through 3/5
//!    `"Integration Testing"` (~L725), 4/5 `"Push to Registry"`
//!    (~L739), and 5/5 `"Deploy to Kubernetes"` (~L771).
//! 3. `commands/github_runner_ci.rs::execute` — Steps 1/3
//!    `"Build"` (~L168), 2/3 `"Push to GHCR"` (~L425), and 3/3
//!    `"GitOps Deployment"` (~L462).
//! 4. `commands/nix_builder.rs::execute` — the `else`-branch Step
//!    2/7 `"Skip primary cluster nix-builder kustomization (not
//!    provided)"` (~L285), the only pre-lift site whose
//!    `announce_step_header` call spans four lines (arg-per-line
//!    formatting) yet whose trailing `println!()` still lands
//!    immediately after the `);` — the same fused pair the
//!    other eleven sites spelled on two lines.
//!
//! Each pre-lift stanza was:
//!
//! ```ignore
//! crate::step_header::announce_step_header(<step>, <total>, "<title>");
//! println!();
//! ```
//!
//! The `tracing::info!` emission renders the heavy-horizontal
//! `"━━━ Step N/M: <title> ━━━"` line through the crate's
//! `tracing_subscriber` (initialized in `main.rs` with
//! `.with_ansi(false)`, defaulting to stdout); the immediately-following
//! `println!()` writes a single `\n` framing blank on stdout that
//! separates the step-heading from the step body that follows.
//!
//! # Duplication signal past the PRIME DIRECTIVE threshold
//!
//! Twelve identically-shaped bodies well past the THEORY §VI.1
//! recurring-shape-to-helper cut. Pre-lift, a drift to the framing
//! blank (a swap for `println!("\n")`, a demotion to an unframed
//! step-body opener, a promotion to a doubled `println!(); println!();`
//! wide-frame variant) had to hit up to twelve sites in lockstep to
//! stay coherent; post-lift the framing decision lives at one call
//! site — a future switch to a `writeln!(io::stdout(), "")` explicit
//! sink, or an inserted `otlp_workflow_step_advanced` span, or a
//! promotion of the heading-plus-frame pair to a structured
//! [`tracing::Span`] enter/exit envelope, lands at ONE body.
//!
//! # Delegation, not re-implementation
//!
//! The step-heading line is delegated to
//! [`crate::step_header::announce_step_header`], which itself
//! terminates in the `tracing::info!` macro and enforces the
//! `1 <= step <= total` debug-only invariant. The trailing blank
//! is a raw [`println!`] with no arguments — the exact bytes the
//! eleven pre-lift sites wrote. Neither the heavy-horizontal glyphs
//! nor the step-index assertion is restated here; a future swap of
//! either lands on the peer primitive and this fusion inherits by
//! composition.
//!
//! # Byte-oracle
//!
//! [`write_step_header_with_trailing_blank`] is the writer-taking
//! sibling for the two-line stanza. It composes
//! [`crate::step_header::write_step_header`] followed by a bare
//! [`writeln!`], so a byte-for-byte match against the peer primitive
//! plus an explicit trailing-`\n` framing blank pins the exact
//! rendered shape without capturing a tracing subscriber and without
//! racing an ambient logger.
//!
//! # THEORY grounding
//!
//! - §V solve-once-at-the-primitive: the "step heading + framing
//!   blank" pair lives at ONE construction surface. A future
//!   refinement (an OTLP `workflow_step_started` span emitted
//!   alongside the print, a demotion of the framing blank under a
//!   compact-log environment variable, a promotion of the pair to a
//!   [`tracing::Span`] `.entered()` guard) lands in one place.
//! - §VI.1 three-is-a-law is exceeded fourfold here at N=12.
//!   Lifting at N=12 closes a twelve-way lockstep-drift surface.
//! - §VII types-as-theorems: the `announce_step_header` peer already
//!   enforces `1 <= step <= total` in debug builds; this fusion
//!   inherits the invariant by delegation rather than by copy.

/// Emit the fused two-line stanza — a `tracing::info!`-routed
/// `"━━━ Step N/M: <title> ━━━"` heading followed by a raw-stdout
/// `println!()` framing blank — sharing the exact bytes the twelve
/// pre-lift sibling sites wrote across `commands/deploy.rs`,
/// `commands/comprehensive_release.rs`,
/// `commands/github_runner_ci.rs`, and `commands/nix_builder.rs`.
///
/// Delegates through the peer primitive
/// [`crate::step_header::announce_step_header`] for the heading
/// line — the heavy-horizontal glyphs, the `Step N/M: ` label
/// grammar, and the `1 <= step <= total` debug-only invariant all
/// live on that peer and are inherited here by construction.
///
/// Panics in debug builds when the peer invariant
/// `1 <= step <= total` (or `total >= 1`) is violated; release
/// builds pay no runtime cost. See
/// [`crate::step_header::announce_step_header`] for the rationale.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// crate::step_header::announce_step_header(3, 3, "GitOps Deploy");
/// println!();
///
/// // Post-lift
/// crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(
///     3, 3, "GitOps Deploy",
/// );
/// ```
pub fn announce_step_header_with_trailing_blank(step: usize, total: usize, title: &str) {
    crate::step_header::announce_step_header(step, total, title);
    println!();
}

/// Writer-taking sibling to
/// [`announce_step_header_with_trailing_blank`] — emits the same
/// byte sequence the runtime primitive writes: the peer
/// [`crate::step_header::write_step_header`] rendering of the
/// `"━━━ Step N/M: <title> ━━━\n"` line followed by a single `\n`
/// framing blank. The byte-oracle surface for tests that pin the
/// two-line shape without capturing stdout or a tracing subscriber.
///
/// Gated `#[cfg(test)]` because the runtime primitive delegates
/// through the peer print + `tracing::info!` primitives and does
/// not need a public writer sibling at runtime.
#[cfg(test)]
fn write_step_header_with_trailing_blank<W: std::io::Write>(
    w: &mut W,
    step: usize,
    total: usize,
    title: &dyn std::fmt::Display,
) -> std::io::Result<()> {
    crate::step_header::write_step_header(w, step, total, title)?;
    writeln!(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step_header::write_step_header;

    /// Byte-oracle #1: the two-line stanza emits exactly two lines
    /// — the heavy-horizontal step-header line and a single `\n`
    /// framing blank. A fusion that dropped the trailing blank OR
    /// doubled it up regresses this.
    #[test]
    fn write_step_header_with_trailing_blank_emits_exactly_two_lines() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header_with_trailing_blank(&mut buf, 1, 3, &"Build").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            2,
            "write_step_header_with_trailing_blank must emit exactly two lines \
             (step-header + trailing framing blank); got {}:\n{:?}",
            lines.len(),
            out
        );
    }

    /// Byte-oracle #2: line 0 matches the peer primitive
    /// `write_step_header` byte-for-byte. The delegation shield —
    /// a future swap of the heavy-horizontal glyph count or the
    /// `Step N/M: ` grammar over on the peer reaches this fusion
    /// by construction.
    #[test]
    fn write_step_header_with_trailing_blank_first_line_matches_peer_primitive() {
        let mut fused_buf: Vec<u8> = Vec::new();
        write_step_header_with_trailing_blank(&mut fused_buf, 2, 5, &"Build Docker Image").unwrap();
        let fused = String::from_utf8(fused_buf).unwrap();
        let fused_lines: Vec<&str> = fused.split_inclusive('\n').collect();

        let mut peer_buf: Vec<u8> = Vec::new();
        write_step_header(&mut peer_buf, 2, 5, &"Build Docker Image").unwrap();
        let peer = String::from_utf8(peer_buf).unwrap();

        assert_eq!(
            fused_lines[0], peer,
            "line 0 must match the peer `write_step_header` byte-for-byte"
        );
    }

    /// Byte-oracle #3: line 1 is exactly the trailing framing
    /// blank (`\n` only). A drift that widened the frame to two
    /// blanks or swapped the trailing `\n` for a `\r\n` regresses.
    #[test]
    fn write_step_header_with_trailing_blank_second_line_is_bare_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header_with_trailing_blank(&mut buf, 3, 3, &"GitOps Deploy").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines[1], "\n",
            "line 1 must be exactly the trailing framing blank (single `\\n`)"
        );
    }

    /// Byte-oracle #4: the header precedes the framing blank, not
    /// the reverse. A silent swap that emitted a leading blank and
    /// then the header would still satisfy line-count and per-line
    /// pins, so pin the sequence explicitly.
    #[test]
    fn write_step_header_with_trailing_blank_orders_header_before_frame() {
        let mut buf: Vec<u8> = Vec::new();
        write_step_header_with_trailing_blank(&mut buf, 5, 5, &"Deploy to Kubernetes").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let header_pos = out
            .find("Deploy to Kubernetes")
            .expect("step-header title must appear");
        // The last byte of the buffer is the trailing framing blank's `\n`.
        assert!(out.ends_with('\n'), "output must end with `\\n`");
        assert!(
            header_pos < out.len() - 1,
            "header title must precede the trailing framing blank; got \
             header_pos={header_pos} out_len={} out={out:?}",
            out.len()
        );
    }

    /// Types-as-theorems: the debug-only step-index invariant is
    /// inherited from the peer primitive. A future consumer that
    /// walks a `Step 0/5:` (zero-based) or `Step 6/5:` (past total)
    /// heading through this fusion trips the peer's invariant
    /// exactly as it would trip a direct call to
    /// `announce_step_header`.
    #[test]
    #[should_panic(expected = "workflow step index must be 1-based")]
    fn announce_step_header_with_trailing_blank_inherits_zero_step_invariant() {
        announce_step_header_with_trailing_blank(0, 5, "Zero step");
    }

    #[test]
    #[should_panic(expected = "exceeds total")]
    fn announce_step_header_with_trailing_blank_inherits_past_total_invariant() {
        announce_step_header_with_trailing_blank(6, 5, "Past total");
    }

    /// The `announce_step_header_with_trailing_blank` fn forwards
    /// to `tracing::info!` and a raw `println!()`; neither can be
    /// captured in-process without racing whatever subscriber /
    /// stdout writer `main` installs. Instead, pin that the entry
    /// point accepts the supported call shapes by driving it at
    /// test time — a compile-fail here would fail the crate's
    /// `cargo test` build gate.
    #[test]
    fn announce_step_header_with_trailing_blank_compiles_with_supported_arg_shapes() {
        // Bare literal title (every pre-lift call site today).
        announce_step_header_with_trailing_blank(1, 3, "Build");
        // Multi-word title with punctuation.
        announce_step_header_with_trailing_blank(2, 5, "Build Docker Image");
        // Runtime `&str` interpolated at the call site.
        let title = String::from("runtime title");
        announce_step_header_with_trailing_blank(3, 3, &title);
    }

    /// Caller shield (negative): no source line under
    /// `cli/src/commands/{deploy,comprehensive_release,github_runner_ci}.rs`
    /// may still spell the pre-lift fused stanza — a
    /// `crate::step_header::announce_step_header(<...>);` line
    /// immediately followed by a `println!();` on the next
    /// non-comment line. Every fused site migrated; any future
    /// consumer that wants the two-line stanza reaches for
    /// [`announce_step_header_with_trailing_blank`] on first grep,
    /// not by copy-pasting the pair from a peer.
    #[test]
    fn no_command_module_still_spells_raw_step_header_plus_framing_blank_pair() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands = src_dir.join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();

        for entry in std::fs::read_dir(&commands).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let raw_lines: Vec<&str> = source.lines().collect();
            // Slide a window across NON-COMMENT lines: if line N carries
            // `crate::step_header::announce_step_header(` (allowing the
            // trailing `;` to land on the same or a later line — one
            // pre-lift site spelled the call across multiple lines) and
            // the NEXT non-blank, non-comment source line is exactly
            // `println!();`, that pair is the raw pre-lift stanza.
            for (idx, line) in raw_lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if !line.contains("crate::step_header::announce_step_header(") {
                    continue;
                }
                // Walk forward to find the next non-comment, non-blank line.
                let mut j = idx + 1;
                // Skip until we pass the closing `);` of the announce call
                // (the call may span multiple lines in some modules).
                let mut saw_semicolon = line.contains(");");
                while j < raw_lines.len() && !saw_semicolon {
                    let peek = raw_lines[j].trim();
                    if peek.contains(");") {
                        saw_semicolon = true;
                        j += 1;
                        break;
                    }
                    if peek.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    j += 1;
                }
                while j < raw_lines.len() {
                    let peek = raw_lines[j].trim();
                    if peek.is_empty() || peek.starts_with("//") {
                        j += 1;
                        continue;
                    }
                    // Match ONLY the bare-blank `println!();` (no args).
                    if peek == "println!();" {
                        offenders.push((
                            path.clone(),
                            idx + 1,
                            format!("{}\n{}", raw_lines[idx], raw_lines[j]),
                        ));
                    }
                    break;
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "raw `crate::step_header::announce_step_header(...); println!();` \
             two-line stanza(s) survive under `commands/` — route each through \
             `crate::step_header_with_trailing_blank::\
             announce_step_header_with_trailing_blank(step, total, title)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive): each of the three pre-lift
    /// command modules MUST forward through
    /// `crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(`
    /// at least the pre-lift fused-stanza count. A migration that
    /// dropped a call site outright would leave the negative
    /// "no raw pair" scan satisfied by absence; the positive count
    /// catches the drop.
    #[test]
    fn every_prelift_module_forwards_through_announce_step_header_with_trailing_blank() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        // (module basename, minimum forward count).
        // Post-lift: 5 of the 6 pre-lift `comprehensive_release.rs`
        // fused-stanza sites migrated onto
        // `commands/comprehensive_release_step_header_timed_start::
        // announce_step_header_and_start_timer`, which itself forwards
        // through `announce_step_header_with_trailing_blank` at ONE
        // primitive body — so the caller-side floor shifts from
        // ≥6-at-`comprehensive_release.rs` to ≥1-at-
        // `comprehensive_release.rs` (the only remaining direct call
        // is the Step 3/5 `else`-branch that fires when
        // `compose_file` is `None` and never composes a timed
        // completion) plus ≥1 inside the timed-start fusion module.
        let expectations: &[(&str, usize)] = &[
            ("commands/deploy.rs", 2),
            ("commands/comprehensive_release.rs", 1),
            (
                "commands/comprehensive_release_step_header_timed_start.rs",
                1,
            ),
            ("commands/github_runner_ci.rs", 3),
            ("commands/nix_builder.rs", 1),
        ];
        for (relpath, min_count) in expectations {
            let path = src_dir.join(relpath);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches(
                    "crate::step_header_with_trailing_blank::\
                     announce_step_header_with_trailing_blank(",
                )
                .count();
            assert!(
                forwards >= *min_count,
                "{relpath} must forward at least {min_count} fused-stanza \
                 site(s) through \
                 `crate::step_header_with_trailing_blank::\
                 announce_step_header_with_trailing_blank(`; found {forwards}. \
                 A dropped call would leave the negative raw-pair shield \
                 satisfied by absence.",
            );
        }
    }
}
