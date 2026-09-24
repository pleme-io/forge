//! Attestation-compute outcome ack primitive: match a
//! `Result<T, anyhow::Error>` returned by a `compute_<kind>_attestation`
//! async, and either push the accepted attestation into the caller's
//! per-kind accumulator + emit a `"<Kind> attestation: <name>.cyan()"`
//! step-ok ack, OR emit a `"<Kind> attestation for <name>"` nonfatal
//! warn labeled against the error.
//!
//! # Pre-lift census — two sibling stanzas
//!
//! Two consumer sites inside
//! `commands/product_release.rs`'s Phase 1.5 attestation loop
//! (`for svc in &product_config.services`) each restated the same fused
//! 12-line `match … { Ok(att) => { <sink>.push(att);
//! print_step_ok(&format!("<Kind> attestation: {}", svc.name.cyan())); }
//! Err(e) => { print_nonfatal_warn(&format!("<Kind> attestation for {}",
//! svc.name), &e); } }` shape:
//!
//! 1. **Build attestation** (~L559-570). `<Kind>` = `"Build"`,
//!    `attestation::compute_build_attestation(&svc.name, repo_path)`
//!    async, `build_atts: Vec<BuildAttestation>` accumulator.
//! 2. **Image attestation** (~L575-586). `<Kind>` = `"Image"`,
//!    `attestation::compute_image_attestation(&registry_url, &image_tag)`
//!    async, `image_atts: Vec<ImageAttestation>` accumulator.
//!
//! Post-lift both sites reach for [`record_attestation_compute_outcome`];
//! the closed [`AttestationComputeKind`] enum owns the `"Build"` /
//! `"Image"` prefix that threads into BOTH the ok-ack format string
//! (`"<Kind> attestation: {}"` with a `.cyan()`-painted service-name
//! interpolant) AND the failure-warn label (`"<Kind> attestation for
//! {}"` with the same service-name plain — no color, since
//! [`crate::ui::print_nonfatal_warn`]'s writer already paints the `WARN`
//! prefix yellow).
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the "record one attestation-compute
//! outcome" composition (push-on-Ok + ack, warn-on-Err) lives at ONE
//! surface, so a future refinement — an OTLP
//! `attestation_compute_outcome` counter wired alongside the print, a
//! promotion of the `.cyan()` service-name paint to a themed
//! [`crate::ui`] adapter, a swap of `print_step_ok` for
//! `print_step_pass_timed` once a `Duration` gets threaded through, a
//! hand-off to a per-kind newtype accumulator that owns the
//! `Vec<Attestation>` push intrinsically — lands here and reaches both
//! consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: two sibling stanzas across one
//! function body meet the recurring-shape criterion. The push-side and
//! print-side share a load-bearing invariant — a successful
//! `compute_*_attestation` MUST both accumulate the returned
//! [`Vec<T>`] entry AND emit the operator ack, and a failure MUST NOT
//! accumulate — that the pre-lift split-stanza shape let drift silently
//! (a hand edit that forgot the `push` while keeping the ack would
//! silently drop the attestation from the composed certification while
//! reporting success to the operator). The fused body forecloses that
//! drift class.

use anyhow::Result;
use colored::Colorize;

/// The `<Kind>` byte-shape half of the pre-lift stanza's `"<Kind>
/// attestation: <name>.cyan()"` step-ok text and `"<Kind> attestation
/// for <name>"` nonfatal-warn label. Closed enum with two arms — one
/// per pre-lift compute site — so a future addition (a `Chart` /
/// `Deployment` / `Compliance` compute-outcome site) surfaces as an
/// added arm at this closed surface rather than as a divergent
/// `&'static str` literal at a new consumer.
#[cfg_attr(not(feature = "attestation"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationComputeKind {
    /// The `attestation::compute_build_attestation` site — pre-lift
    /// stanza spelled `"Build attestation: {}"` / `"Build attestation
    /// for {}"`.
    Build,
    /// The `attestation::compute_image_attestation` site — pre-lift
    /// stanza spelled `"Image attestation: {}"` / `"Image attestation
    /// for {}"`.
    Image,
}

impl AttestationComputeKind {
    /// The `"Build"` / `"Image"` prefix threaded verbatim into both
    /// the ok-ack (`"<prefix> attestation: <name>"`) and the
    /// failure-warn label (`"<prefix> attestation for <name>"`).
    ///
    /// `const` because the enum's two arms have compile-time literal
    /// tails; coerces into any lifetime a caller needs.
    #[cfg_attr(not(feature = "attestation"), allow(dead_code))]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Image => "Image",
        }
    }
}

/// Record the outcome of a `compute_<kind>_attestation` call: on
/// [`Ok`], push the returned attestation into `sink` AND print `"<Kind>
/// attestation: <service_name>.cyan()"` via
/// [`crate::ui::print_step_ok`]; on [`Err`], print `"<Kind> attestation
/// for <service_name>"` labeled against the error via
/// [`crate::ui::print_nonfatal_warn`].
///
/// The push happens BEFORE the ack, matching the pre-lift stanza
/// ordering — a caller that later reads `sink.len()` in a
/// success-observer body between the two lines would see the accepted
/// entry AT LATEST when the ack fires, never later.
///
/// # Generic over `T`
///
/// The two pre-lift sites accumulated `Vec<BuildAttestation>` and
/// `Vec<ImageAttestation>` — two distinct types from the `tameshi`
/// attestation crate. A common receiver monomorphizes per call site,
/// so no `dyn Attestation` trait object or attestation-crate-side
/// enum widening is needed to share the shape.
///
/// # Failure arm carries the error verbatim
///
/// The [`Err`] arm takes `&e` through
/// [`crate::ui::print_nonfatal_warn`], which threads it through its
/// `err: &dyn std::fmt::Display` receiver — the pre-lift stanza's
/// `&e` byte-shape is preserved. `anyhow::Error` implements
/// [`std::fmt::Display`] transparently, so the operator readout
/// carries the full error chain the pre-lift stanza did.
#[cfg_attr(not(feature = "attestation"), allow(dead_code))]
pub fn record_attestation_compute_outcome<T>(
    kind: AttestationComputeKind,
    service_name: &str,
    outcome: Result<T>,
    sink: &mut Vec<T>,
) {
    match outcome {
        Ok(att) => {
            sink.push(att);
            crate::ui::print_step_ok(&format!(
                "{} attestation: {}",
                kind.prefix(),
                service_name.cyan()
            ));
        }
        Err(e) => {
            crate::ui::print_nonfatal_warn(
                &format!("{} attestation for {}", kind.prefix(), service_name),
                &e,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::path::PathBuf;

    /// Pin the `prefix()` projection: [`AttestationComputeKind::Build`]
    /// renders as `"Build"`, [`AttestationComputeKind::Image`] as
    /// `"Image"`. A drift in either arm walks the pre-lift byte-shape
    /// of BOTH the ok-ack (`"<prefix> attestation: <name>"`) and the
    /// failure-warn label (`"<prefix> attestation for <name>"`) at
    /// once — the enum owns both surfaces, so re-spelling `"Build"` as
    /// `"BuildAttestation"` or `"build"` would flip the operator log-
    /// scraper matching pre-lift shapes on both surfaces
    /// simultaneously.
    #[test]
    fn attestation_compute_kind_prefix_pins_both_arms() {
        assert_eq!(AttestationComputeKind::Build.prefix(), "Build");
        assert_eq!(AttestationComputeKind::Image.prefix(), "Image");
    }

    /// Pin the push-then-ack contract on the [`Ok`] arm: the accepted
    /// attestation lands in `sink` verbatim. The primitive's `T` is
    /// generic — use `String` here so the test avoids depending on
    /// the `tameshi` attestation-feature crate (the two production
    /// call sites monomorphize to `BuildAttestation` and
    /// `ImageAttestation` respectively, but the invariant this test
    /// checks — a successful `Result` pushes its payload into the
    /// accumulator — is generic).
    #[test]
    fn record_attestation_compute_outcome_pushes_on_ok() {
        let mut sink: Vec<String> = Vec::new();
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "auth",
            Ok::<String, anyhow::Error>("build-att-payload".to_string()),
            &mut sink,
        );
        assert_eq!(sink.len(), 1);
        assert_eq!(sink[0], "build-att-payload");
    }

    /// Pin the no-push contract on the [`Err`] arm: a failure leaves
    /// `sink` untouched. The pre-lift stanzas each guarded the `push`
    /// under the `Ok(att) =>` arm exclusively; a drift that hoisted
    /// the `push` out of the arm would silently accumulate a fake
    /// entry against a failed compute — the composed
    /// `attestation::compose_product_certification` downstream would
    /// then walk a `Vec<T>` whose length inflated the count of
    /// legitimately-computed attestations. This test compile-flips
    /// at the length assertion.
    #[test]
    fn record_attestation_compute_outcome_does_not_push_on_err() {
        let mut sink: Vec<String> = Vec::new();
        record_attestation_compute_outcome(
            AttestationComputeKind::Image,
            "auth",
            Err::<String, anyhow::Error>(anyhow!("skopeo probe failed")),
            &mut sink,
        );
        assert!(sink.is_empty());
    }

    /// Pin the append-not-replace contract across repeated calls: a
    /// second [`Ok`] outcome extends the existing accumulator rather
    /// than replacing it. The pre-lift stanzas ran inside a `for svc in
    /// &product_config.services` loop and relied on the `Vec<T>::push`
    /// append semantics — a drift that swapped `push` for `insert(0,
    /// …)` or `truncate(0); push(…)` would reorder or drop prior
    /// entries silently; this test compile-flips at the length +
    /// ordering assertions.
    #[test]
    fn record_attestation_compute_outcome_appends_repeated_ok_records_in_order() {
        let mut sink: Vec<String> = Vec::new();
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "auth",
            Ok::<String, anyhow::Error>("first".to_string()),
            &mut sink,
        );
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "billing",
            Ok::<String, anyhow::Error>("second".to_string()),
            &mut sink,
        );
        record_attestation_compute_outcome(
            AttestationComputeKind::Image,
            "auth",
            Ok::<String, anyhow::Error>("third".to_string()),
            &mut sink,
        );
        assert_eq!(sink.len(), 3);
        assert_eq!(sink[0], "first");
        assert_eq!(sink[1], "second");
        assert_eq!(sink[2], "third");
    }

    /// Pin the mixed-outcome interleaving contract: alternating
    /// [`Ok`] / [`Err`] outcomes across the same accumulator produce
    /// exactly the [`Ok`] entries, in call order, with the [`Err`]
    /// outcomes gapped out. The pre-lift compute loop iterated services
    /// where any one service's compute could independently succeed or
    /// fail; the accumulator therefore had to reflect the succeeded
    /// subset without positional gaps. A drift that pushed a synthetic
    /// placeholder on the [`Err`] arm would rewrite this invariant.
    #[test]
    fn record_attestation_compute_outcome_interleaves_ok_and_err_by_ok_only() {
        let mut sink: Vec<String> = Vec::new();
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "auth",
            Ok::<String, anyhow::Error>("kept-1".to_string()),
            &mut sink,
        );
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "billing",
            Err::<String, anyhow::Error>(anyhow!("compute failed")),
            &mut sink,
        );
        record_attestation_compute_outcome(
            AttestationComputeKind::Build,
            "checkout",
            Ok::<String, anyhow::Error>("kept-2".to_string()),
            &mut sink,
        );
        assert_eq!(sink, vec!["kept-1".to_string(), "kept-2".to_string()]);
    }

    /// Positive delegation shield: the pre-lift consumer body of
    /// `commands/product_release.rs` MUST forward at least two sites
    /// through
    /// [`record_attestation_compute_outcome`]. Pre-lift the compute
    /// loop held exactly two sibling match-stanzas (build + image); a
    /// dropped call site post-lift would leave the negative
    /// caller-shield scan below trivially satisfied by absence. This
    /// positive count keeps a dropped-call regression visible.
    #[test]
    fn product_release_forwards_both_attestation_compute_sites_through_primitive() {
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("commands")
                .join("product_release.rs"),
        )
        .unwrap();
        let forwards = source
            .matches(
                "crate::attestation_compute_outcome_ack::\
                 record_attestation_compute_outcome(",
            )
            .count();
        assert!(
            forwards >= 2,
            "commands/product_release.rs must forward at least 2 \
             attestation-compute sites through \
             `crate::attestation_compute_outcome_ack::\
             record_attestation_compute_outcome(`; found {forwards}. \
             A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
        );
    }

    /// Negative caller shield: the pre-`#[cfg(test)]` module body of
    /// `commands/product_release.rs` must hold ZERO code-line hits for
    /// either raw pre-lift ack literal — `"Build attestation: "` /
    /// `"Image attestation: "`. Post-lift both stanzas forward through
    /// [`record_attestation_compute_outcome`], which owns the sole
    /// remaining `"<Kind> attestation: <name>"` composition body at
    /// ONE surface in `cli/src/attestation_compute_outcome_ack.rs`. A
    /// re-inline at either site pushes the count above zero and
    /// compile-flips this shield.
    ///
    /// The needles are `"Build attestation:"` and
    /// `"Image attestation:"` (with the trailing colon that binds them
    /// to the ok-ack shape rather than the `"<Kind> attestation for
    /// <name>"` failure-warn shape). The failure-warn labels
    /// (`"Build attestation for "` / `"Image attestation for "`) are
    /// pinned by the primitive's own body and are outside this
    /// caller-shield's scope.
    #[test]
    fn product_release_pre_cfg_body_holds_no_raw_attestation_ack_literals() {
        let source = include_str!("commands/product_release.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            source,
            "commands/product_release.rs",
        );
        for needle in ["Build attestation:", "Image attestation:"] {
            let hits = crate::test_support::code_line_hits(body, needle);
            assert_eq!(
                hits.len(),
                0,
                "expected ZERO code-line hits for the raw \
                 `{needle}` ok-ack needle in the pre-`#[cfg(test)]` \
                 module body of `commands/product_release.rs` (the \
                 two pre-lift attestation-compute sites both forward \
                 through `crate::attestation_compute_outcome_ack::\
                 record_attestation_compute_outcome`, which owns the \
                 sole remaining `\"<Kind> attestation: <name>\"` \
                 composition body at ONE surface in \
                 `cli/src/attestation_compute_outcome_ack.rs`); got \
                 {}. A count above 0 means a caller site re-inlined \
                 the pre-lift ack stanza. Offending lines: {:#?}",
                hits.len(),
                hits,
            );
        }
    }
}
