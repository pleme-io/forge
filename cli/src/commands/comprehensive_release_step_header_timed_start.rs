//! Fused `let step_start = Instant::now(); crate::step_header_
//! with_trailing_blank::announce_step_header_with_trailing_blank(
//! step, total, title);` release-workflow step-header timed-start
//! stanza.
//!
//! # Pre-lift census — five sibling two-line stanzas
//!
//! Five consumer sites at the head of each top-level release-phase
//! branch in [`crate::commands::comprehensive_release::execute`]
//! opened their step body with the same two-line pair — an
//! [`Instant::now`] capture bound to a `step_start` local followed
//! immediately by the fused two-line step-heading + trailing-
//! framing-blank stanza owned by
//! [`crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank`]:
//!
//! 1. Step 1/5 `"Pre-Build Validation"` (`if !skip_unit_tests`).
//! 2. Step 2/5 `"Build Docker Image"` (`if !skip_build`).
//! 3. Step 3/5 `"Integration Testing"` (`if !skip_integration_tests`
//!    → `if let Some(compose_path) = &compose_file`).
//! 4. Step 4/5 `"Push to Registry"` (`if !skip_push`).
//! 5. Step 5/5 `"Deploy to Kubernetes"` (`if !skip_deploy`).
//!
//! Each pre-lift stanza was:
//!
//! ```ignore
//! let step_start = Instant::now();
//! crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(
//!     <step>, <total>, "<title>",
//! );
//! ```
//!
//! The `step_start` local is then read at the step's completion arm
//! and handed to
//! [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
//! for the ` (took N.Ns)`-tailed step-pass banner.
//!
//! The single `announce_step_header_with_trailing_blank` call
//! WITHOUT a preceding `Instant::now()` capture in this module (the
//! Step 3/5 `else`-branch at ~line 734 that fires when
//! `compose_file` is `None`) is deliberately out of scope: its
//! branch runs `warn_advisory!` + `println!()` and never composes an
//! elapsed-time completion banner, so the pre-lift pair — timer-
//! start + announce — is not the shape at that site.
//!
//! # Timer semantics — capture BEFORE announce
//!
//! Every pre-lift site captured [`Instant::now`] on the line BEFORE
//! the announce call, so the elapsed-time interval subsequently
//! reported by
//! [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
//! includes the microseconds spent rendering the step-heading
//! banner. The primitive preserves that ordering — a swap to
//! announce-then-capture would silently shave that heading-render
//! interval off every one of the 5 release phases' reported
//! durations. The order is pinned in tests through the
//! [`Instant`]-return-first byte-oracle sibling; a future
//! contributor who reaches for a wrapper that flipped the ordering
//! reads the doc + trips the shield.
//!
//! # Duplication signal past the PRIME DIRECTIVE threshold
//!
//! Five identically-shaped two-line bodies well past the THEORY
//! §VI.1 recurring-shape-to-helper cut. Pre-lift a drift to the
//! ordering (a capture-after-announce swap), a promotion of the
//! `Instant::now()` receiver to a
//! [`crate::deployment_poll_clock`]-style typed clock, or a swap of
//! the raw [`std::time::Instant`] for a [`tokio::time::Instant`]
//! monotonic-clock variant had to hit all 5 sites in lockstep to
//! stay coherent; post-lift each of those axes lives at ONE call.
//!
//! # Delegation, not re-implementation
//!
//! The step-heading + trailing-framing-blank pair is delegated to
//! [`crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank`],
//! itself already the fused primitive for the announce + framing-
//! blank pair. Neither the heavy-horizontal glyphs nor the step-
//! index invariant nor the trailing `\n` framing blank is restated
//! here; a future swap of any of those axes on either peer flows
//! through by composition.
//!
//! # Distinct from
//! [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
//!
//! The step-pass-timed primitive owns the DOWNSTREAM completion
//! banner (`✅ <MSG> (took N.Ns)`); this primitive owns the
//! UPSTREAM opening pair (timer-start + step-header). The two share
//! the `step_start`/`step_duration` local as their handoff — the
//! caller binds the [`Instant`] this primitive returns and hands
//! its [`Instant::elapsed`] value to the completion primitive.
//!
//! # THEORY grounding
//!
//! - §V solve-once-at-the-primitive: the timer-start + step-header
//!   pair lives at ONE construction surface. A future refinement
//!   (an OTLP `release_step_started` span emitted alongside the
//!   header, a promotion of the raw [`Instant`] to a typed
//!   `ReleaseStepClock` wrapper, a swap of the timer clock source)
//!   lands in one place.
//! - §VI.1 three-is-a-law is exceeded here at N=5.
//! - §VII types-as-theorems: the returned [`Instant`] carries the
//!   step-start invariant by construction. A caller that forgot to
//!   bind the return trips a `#[must_use]` warning; a caller that
//!   discarded it and re-called [`Instant::now`] would land on the
//!   [`Instant`] value AFTER the announce render — the exact drift
//!   this primitive exists to prevent.

use std::time::Instant;

/// Capture [`Instant::now`] as the step-start moment and emit the
/// fused two-line step-heading + trailing-framing-blank stanza the
/// pre-lift 5 sibling sites in
/// [`crate::commands::comprehensive_release::execute`] each spelled
/// verbatim — the same bytes
/// [`crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank`]
/// renders — then return the captured [`Instant`] for the caller
/// to hand to
/// [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
/// at the step's completion arm.
///
/// Delegates through the peer primitive
/// [`crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank`]
/// for the header + framing-blank pair — the heavy-horizontal
/// glyphs, the `Step N/M: ` label grammar, and the debug-only
/// `1 <= step <= total` invariant all live on that peer and are
/// inherited here by construction.
///
/// The [`Instant`] capture happens BEFORE the announce call, so the
/// elapsed-time interval reported by
/// [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
/// at the step's completion arm includes the microseconds spent
/// rendering the step-heading banner — matching the pre-lift
/// ordering across all 5 sites verbatim. A swap to announce-then-
/// capture would silently shave that heading-render interval off
/// every reported step duration; the ordering is pinned by
/// [`tests::returned_instant_captures_before_announce_render`].
///
/// # Examples
///
/// ```ignore
/// // Pre-lift:
/// let step_start = Instant::now();
/// crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(
///     1, 5, "Pre-Build Validation",
/// );
/// // ... run step body ...
/// let step_duration = step_start.elapsed();
/// crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed(
///     "Unit tests passed", step_duration,
/// );
///
/// // Post-lift:
/// let step_start = crate::commands::comprehensive_release_step_header_timed_start
///     ::announce_step_header_and_start_timer(1, 5, "Pre-Build Validation");
/// // ... run step body ...
/// let step_duration = step_start.elapsed();
/// crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed(
///     "Unit tests passed", step_duration,
/// );
/// ```
#[must_use = "the returned Instant is the step-start moment the caller \
              must hand to info_step_pass_timed at the step's completion \
              arm; discarding it defeats the fused primitive"]
pub fn announce_step_header_and_start_timer(step: usize, total: usize, title: &str) -> Instant {
    let start = Instant::now();
    crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(
        step, total, title,
    );
    start
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `announce_step_header_and_start_timer` fn forwards to
    /// [`Instant::now`] and to the peer
    /// `announce_step_header_with_trailing_blank`, whose print
    /// side cannot be captured in-process without racing whatever
    /// subscriber / stdout writer `main` installs. Instead, pin
    /// that the entry point accepts the supported call shapes by
    /// driving it at test time — a compile-fail here would fail
    /// the crate's `cargo test` build gate — and that it returns
    /// an [`Instant`] whose value is `<= Instant::now()` measured
    /// AFTER the call. The `<= now_after` bound doubles as the
    /// pin that the primitive does NOT return a future [`Instant`]
    /// via some monotonic-clock oddity.
    #[test]
    fn announce_step_header_and_start_timer_returns_valid_instant() {
        let before = Instant::now();
        let returned = announce_step_header_and_start_timer(1, 5, "Pre-Build Validation");
        let after = Instant::now();
        assert!(
            before <= returned,
            "returned Instant must be >= Instant::now() captured BEFORE the \
             call — a monotonic-clock regression that returned an earlier \
             timestamp would land here",
        );
        assert!(
            returned <= after,
            "returned Instant must be <= Instant::now() captured AFTER the \
             call — a future-Instant regression would land here",
        );
    }

    /// Types-as-theorems: the debug-only step-index invariant is
    /// inherited from the peer primitive through the
    /// `announce_step_header_with_trailing_blank` delegation. A
    /// future consumer that walks a `Step 0/5:` (zero-based) or
    /// `Step 6/5:` (past total) heading through this fusion trips
    /// the peer's invariant exactly as it would trip a direct
    /// call to the peer.
    #[test]
    #[should_panic(expected = "workflow step index must be 1-based")]
    fn announce_step_header_and_start_timer_inherits_zero_step_invariant() {
        let _ = announce_step_header_and_start_timer(0, 5, "Zero step");
    }

    #[test]
    #[should_panic(expected = "exceeds total")]
    fn announce_step_header_and_start_timer_inherits_past_total_invariant() {
        let _ = announce_step_header_and_start_timer(6, 5, "Past total");
    }

    /// Pin the timer-capture-BEFORE-announce ordering: the
    /// [`Instant`] the primitive returns must be captured on a
    /// line strictly BEFORE the announce call in the primitive
    /// body, so a swap to announce-then-capture that would silently
    /// shave the heading-render interval off every reported step
    /// duration lands here. Anchors on the body source ordering
    /// (the `Instant::now()` line's byte offset must be less than
    /// the `announce_step_header_with_trailing_blank(` byte offset).
    #[test]
    fn returned_instant_captures_before_announce_render() {
        let source = include_str!("comprehensive_release_step_header_timed_start.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "comprehensive_release_step_header_timed_start.rs",
        );
        let now_offset = body
            .find("Instant::now()")
            .expect("primitive body must call Instant::now()");
        let announce_offset = body
            .find("announce_step_header_with_trailing_blank(")
            .expect(
                "primitive body must delegate through \
                 announce_step_header_with_trailing_blank",
            );
        assert!(
            now_offset < announce_offset,
            "the primitive body must capture Instant::now() BEFORE the \
             announce_step_header_with_trailing_blank call — a swap to \
             announce-then-capture would silently shave the heading-render \
             interval off every reported step duration. Got \
             now_offset={now_offset} announce_offset={announce_offset}.",
        );
    }

    /// Solve-once-at-the-primitive: the primitive body must
    /// delegate the announce through the peer primitive
    /// [`crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank`]
    /// rather than re-inlining the heading + framing-blank pair.
    /// A future refinement of that pair (e.g. an OTLP
    /// `workflow_step_advanced` span emitted alongside the header,
    /// or a demotion of the framing blank under a compact-log
    /// environment variable) reaches this fusion by composition.
    #[test]
    fn primitive_body_delegates_through_announce_step_header_with_trailing_blank() {
        let source = include_str!("comprehensive_release_step_header_timed_start.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "comprehensive_release_step_header_timed_start.rs",
        );
        assert!(
            body.contains(
                "crate::step_header_with_trailing_blank::\
                 announce_step_header_with_trailing_blank(",
            ),
            "primitive body must delegate through \
             `crate::step_header_with_trailing_blank::\
             announce_step_header_with_trailing_blank(` rather than \
             re-inlining the heading + framing-blank pair.",
        );
    }

    /// Solve-once-at-the-primitive: the primitive body must NOT
    /// call the pre-fusion peer
    /// [`crate::step_header::announce_step_header`] directly —
    /// a bypass of the trailing-framing-blank sibling would drop
    /// the framing blank on all 5 release-phase step-opens. The
    /// only supported delegation is through the fused
    /// `announce_step_header_with_trailing_blank` sibling.
    #[test]
    fn primitive_body_does_not_bypass_the_trailing_blank_sibling() {
        let source = include_str!("comprehensive_release_step_header_timed_start.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "comprehensive_release_step_header_timed_start.rs",
        );
        assert!(
            !body.contains("crate::step_header::announce_step_header("),
            "primitive body must NOT bypass the fused sibling — a direct \
             call to `crate::step_header::announce_step_header(` would drop \
             the trailing framing blank on all 5 release-phase step-opens.",
        );
    }

    /// Caller shield (negative): no source line in
    /// `commands/comprehensive_release.rs` may still spell the
    /// pre-lift fused stanza — a `let <name>_start = Instant::now();`
    /// line immediately followed (allowing rustfmt to split the
    /// multi-arg call across lines) by a
    /// `crate::step_header_with_trailing_blank::announce_step_header_with_trailing_blank(`
    /// invocation. Every pre-lift site migrated; any future
    /// consumer that wants the two-line stanza reaches for
    /// [`announce_step_header_and_start_timer`] on first grep,
    /// not by copy-pasting the pair from a peer.
    ///
    /// The needle scans a 3-line rolling window so a rustfmt split
    /// that put `Instant::now();` and the announce call on
    /// non-consecutive physical lines still trips — the two markers
    /// must live within the recent window.
    #[test]
    fn no_raw_instant_now_plus_announce_pair_survives_in_consumer() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let raw_lines: Vec<&str> = source.lines().collect();
        let mut offenders: Vec<(usize, String)> = Vec::new();
        for (idx, line) in raw_lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // Anchor on the pre-lift opener: a `let <name>_start =
            // Instant::now();` binding. The `_start` suffix is
            // load-bearing — a bare `let now = Instant::now();`
            // one-off (e.g. a poll-loop probe) is deliberately out
            // of scope; only the pre-lift step-open binding shape
            // is matched.
            if !(trimmed.starts_with("let step_start = Instant::now();")
                || trimmed.starts_with("let health_start = Instant::now();"))
            {
                continue;
            }
            // Walk forward up to 5 lines skipping blanks + comments,
            // and check whether the next code line calls the peer
            // primitive.
            let mut j = idx + 1;
            let mut steps = 0;
            while j < raw_lines.len() && steps < 5 {
                let peek = raw_lines[j].trim();
                if peek.is_empty() || peek.starts_with("//") {
                    j += 1;
                    steps += 1;
                    continue;
                }
                if peek.contains(
                    "crate::step_header_with_trailing_blank::\
                     announce_step_header_with_trailing_blank(",
                ) {
                    offenders.push((idx + 1, format!("{}\n{}", raw_lines[idx], raw_lines[j])));
                }
                break;
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `let <name>_start = Instant::now(); \
             crate::step_header_with_trailing_blank::\
             announce_step_header_with_trailing_blank(...)` two-line \
             stanza(s) survive under `commands/comprehensive_release.rs` \
             — route each through \
             `crate::commands::comprehensive_release_step_header_timed_start\
             ::announce_step_header_and_start_timer(step, total, title)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Caller shield (positive): `commands/comprehensive_release.rs`
    /// MUST forward through
    /// [`announce_step_header_and_start_timer`] at least 5 times —
    /// the pre-lift fused-stanza count. Pairs with the negative
    /// caller shield above: the negative shield forbids the raw
    /// `Instant::now(); announce_step_header_with_trailing_blank(...)`
    /// pair from surviving, and this shield forbids a "just drop
    /// the announce, we log elsewhere" cleanup that quietly drops
    /// a step's operator-visible heading without regressing the
    /// negative-shield assertion.
    #[test]
    fn comprehensive_release_module_delegates_through_primitive_at_least_five_times() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let forwards = source
            .matches("announce_step_header_and_start_timer(")
            .count();
        assert!(
            forwards >= 5,
            "pre-lift 5 sibling release-phase step-open sites in \
             `commands/comprehensive_release.rs` must each resolve through \
             `comprehensive_release_step_header_timed_start::\
             announce_step_header_and_start_timer(...)`; found only {} \
             forwarding call(s). A cleanup that dropped any of the 5 \
             top-level release-phase step-opens regresses the operator's \
             visual anchor without tripping the negative caller shield.",
            forwards,
        );
    }

    /// Sibling-pairing shield: every call site that opens a
    /// timed release-step through
    /// [`announce_step_header_and_start_timer`] should ALSO close
    /// it through
    /// [`crate::commands::comprehensive_release_step_pass_timed::info_step_pass_timed`]
    /// — the two primitives are a matched open/close pair. The
    /// shield asserts the closes are at least as numerous as the
    /// opens; a caller may legitimately close a step through a
    /// non-`info_step_pass_timed` arm on failure paths, but every
    /// successful step-open expects a matching timed close.
    ///
    /// The specific inequality is `closes >= opens`: the fused
    /// pattern in the pre-lift call sites is one open + one close
    /// per phase, so post-lift `commands/comprehensive_release.rs`
    /// carries at least 5 of each. A future refinement that
    /// promoted a close through a wrapper module still counts as
    /// long as the wrapper module ultimately forwards through
    /// `info_step_pass_timed`.
    #[test]
    fn every_open_matches_at_least_one_close() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("comprehensive_release.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let opens = source
            .matches("announce_step_header_and_start_timer(")
            .count();
        let closes = source.matches("info_step_pass_timed(").count();
        assert!(
            closes >= opens,
            "each release-phase step-open through \
             `announce_step_header_and_start_timer` expects a matching \
             timed close through `info_step_pass_timed`; got opens={opens} \
             closes={closes}. A caller that opened a timed step but never \
             closed it drops the operator's step-completion banner.",
        );
    }
}
