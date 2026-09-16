//! Pod-status probe pending-wait acknowledgement primitive — the
//! single-line `println!("   ⏳ Waiting for <target> ({err}, {elapsed}s
//! elapsed)")` stanza the two deployment-image pod-polling loops in
//! `commands/flux.rs` each emit on the `Err(e)` arm of a
//! [`crate::commands::flux::get_pod_status_full`] probe result.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites in `cli/src/commands/flux.rs` each
//! restated the same one-line stanza byte-for-byte:
//!
//! ```ignore
//! Err(e) => {
//!     println!("   ⏳ Waiting for <label> ({}, {}s elapsed)", e, elapsed);
//! }
//! ```
//!
//! - `verify_deployment_image` at :537 with `<label>` = `deployment` —
//!   the post-flux-reconcile confirmation loop that polls until the
//!   pod's image contains `expected_tag_suffix`.
//! - `wait_for_deployment` at :637 with `<label>` = `pod` — the rollout
//!   loop that waits until the pod has the correct image AND is ready.
//!
//! Both live inside a `match get_pod_status_full(...).await { Ok(pod) =>
//! { ... }, Err(e) => { ...one-line println... } }` structure. The
//! `Err(e)` arm is a pending-wait acknowledgement: the probe failed
//! transiently (kubectl not yet returning a pod row, or the row lacked
//! the expected fields) and the loop will retry after
//! [`crate::retry::RetryPolicy::compute_delay`] sleeps. The two axes
//! that legitimately vary between the sites are the target label
//! (`deployment` vs. `pod`) and the two parameter values (`e` and
//! `elapsed`); every other byte — the four-space indent, the ⏳ glyph,
//! the parenthesized `(<err>, <elapsed>s elapsed)` tail — is fixed.
//!
//! # Composition
//!
//! [`print_pod_probe_pending_wait_line`] emits the one-line stanza to
//! [`std::io::stdout()`]; [`write_pod_probe_pending_wait_line`] is the
//! writer-taking sibling that pins the emitted bytes for the
//! fail-before-pass tests. The target-label axis is closed under a
//! [`PodPollTargetLabel`] enum whose [`PodPollTargetLabel::label`]
//! projection is the inverse of the pre-lift `"deployment"` /
//! `"pod"` literal — a future third target (`statefulset`,
//! `daemonset`, …) adds a variant here and gets a byte-identical
//! line for free.

use std::fmt::Display;
use std::io;

/// Which pod-owning workload the polling loop is waiting on. The two
/// pre-lift sites in `commands/flux.rs` spelled `deployment` and
/// `pod` inline; a closed enum here means a future third caller
/// (e.g. a statefulset rollout loop) declares its target-label
/// axis at the type level rather than by copy-pasting the literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodPollTargetLabel {
    /// The `verify_deployment_image` loop at
    /// `commands/flux.rs:537` — waiting for a `Deployment`'s pod
    /// row to become readable via `get_pod_status_full`.
    Deployment,
    /// The `wait_for_deployment` loop at `commands/flux.rs:637` —
    /// same pod-row read, but the outer polling loop is waiting for
    /// the pod to become ready with the correct image.
    Pod,
}

impl PodPollTargetLabel {
    /// The literal label spliced into the pending-wait line — the
    /// inverse of the pre-lift `"deployment"` / `"pod"` string. A
    /// future variant returns its own label here and no consumer
    /// changes.
    pub fn label(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Pod => "pod",
        }
    }
}

/// Print the single-line pod-probe pending-wait stanza —
/// `   ⏳ Waiting for <target-label> (<err>, <elapsed>s elapsed)` —
/// to [`std::io::stdout()`].
///
/// Delegates to [`write_pod_probe_pending_wait_line`] against a locked
/// stdout handle; the writer split exists so the byte-oracle tests can
/// pin the emitted bytes without capturing stdout.
pub fn print_pod_probe_pending_wait_line(
    target: PodPollTargetLabel,
    err: impl Display,
    elapsed_secs: u64,
) {
    let _ = write_pod_probe_pending_wait_line(
        &mut std::io::stdout().lock(),
        target,
        &err,
        elapsed_secs,
    );
}

/// Writer-taking sibling of [`print_pod_probe_pending_wait_line`].
///
/// # Byte contract
///
/// Emits exactly ONE line via [`writeln!`]:
///
/// ```text
///    ⏳ Waiting for <target.label()> (<err>, <elapsed_secs>s elapsed)\n
/// ```
///
/// - `"   "` — three ASCII spaces of indent (matching the pre-lift
///   `"   ⏳ ..."` `println!` literal exactly, NOT four).
/// - `"⏳ "` — U+23F3 HOURGLASS WITH FLOWING SAND glyph + ASCII space.
/// - `"Waiting for "` — literal.
/// - `<target.label()>` — `"deployment"` or `"pod"` per
///   [`PodPollTargetLabel::label`].
/// - `" ("` — literal open-paren.
/// - `<err>` — the [`Display`] projection of the caller's error value,
///   verbatim.
/// - `", "` — literal.
/// - `<elapsed_secs>` — decimal formatting of `u64`.
/// - `"s elapsed)"` — literal close-paren.
/// - `"\n"` — the [`writeln!`] terminator.
pub fn write_pod_probe_pending_wait_line<W: io::Write>(
    w: &mut W,
    target: PodPollTargetLabel,
    err: &dyn Display,
    elapsed_secs: u64,
) -> io::Result<()> {
    writeln!(
        w,
        "   \u{23f3} Waiting for {} ({}, {}s elapsed)",
        target.label(),
        err,
        elapsed_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the [`PodPollTargetLabel::label`] projection is
    /// the inverse of the pre-lift `"deployment"` / `"pod"` literal
    /// under each variant. A future refactor that pluralized to
    /// `"deployments"` (a "match the kubectl resource type" cleanup)
    /// or capitalized to `"Deployment"` (a "match the Kubernetes
    /// kind casing" cleanup) would flip this assertion and would
    /// drift both consumers off the pre-lift wording in lockstep —
    /// which is the point of pinning the mapping here rather than
    /// letting it re-drift from either call site.
    #[test]
    fn pod_poll_target_label_maps_variants_to_pre_lift_literals() {
        assert_eq!(PodPollTargetLabel::Deployment.label(), "deployment");
        assert_eq!(PodPollTargetLabel::Pod.label(), "pod");
    }

    /// Byte-oracle: [`write_pod_probe_pending_wait_line`] emits
    /// exactly ONE line for a `Deployment` target — the pre-lift
    /// `verify_deployment_image` stanza at `commands/flux.rs:537`.
    /// Pins the entire byte sequence (three-space indent, ⏳ glyph,
    /// the parenthesized `(<err>, <elapsed>s elapsed)` tail) so a
    /// refactor that dropped a leading space (regressing to a
    /// two-space indent), fused two `writeln!`s (regressing to a
    /// two-line stanza), or reworded to `elapsed s` (regressing the
    /// suffix) would flip.
    #[test]
    fn write_pod_probe_pending_wait_line_deployment_variant_pins_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_pod_probe_pending_wait_line(
            &mut buf,
            PodPollTargetLabel::Deployment,
            &"connection refused",
            7,
        )
        .unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(
            out, "   \u{23f3} Waiting for deployment (connection refused, 7s elapsed)\n",
            "deployment-variant byte sequence must match the pre-lift \
             `commands/flux.rs:537` stanza verbatim; got {out:?}"
        );
    }

    /// Byte-oracle: [`write_pod_probe_pending_wait_line`] emits
    /// exactly ONE line for a `Pod` target — the pre-lift
    /// `wait_for_deployment` stanza at `commands/flux.rs:637`.
    /// The target label is the ONLY byte that changes between the
    /// two consumer variants.
    #[test]
    fn write_pod_probe_pending_wait_line_pod_variant_pins_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_pod_probe_pending_wait_line(
            &mut buf,
            PodPollTargetLabel::Pod,
            &"kubectl returned no pod row",
            42,
        )
        .unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(
            out, "   \u{23f3} Waiting for pod (kubectl returned no pod row, 42s elapsed)\n",
            "pod-variant byte sequence must match the pre-lift \
             `commands/flux.rs:637` stanza verbatim; got {out:?}"
        );
    }

    /// Byte-oracle: the `err: &dyn Display` parameter reaches the
    /// writer through its own `Display` projection — a caller
    /// passing an [`anyhow::Error`], a typed `*Failed` variant, or
    /// a plain `String` all render through the same `{}` splice.
    /// A refactor that switched the `Display` splice to `Debug`
    /// would wrap the error body in extra `"..."` quotes and fail
    /// here.
    #[test]
    fn write_pod_probe_pending_wait_line_renders_err_through_display() {
        struct CustomDisplay;
        impl Display for CustomDisplay {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "custom-display-body")
            }
        }
        let mut buf: Vec<u8> = Vec::new();
        write_pod_probe_pending_wait_line(&mut buf, PodPollTargetLabel::Pod, &CustomDisplay, 0)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("custom-display-body"),
            "writer must splice the caller's `Display` projection verbatim; got {out:?}"
        );
        assert!(
            !out.contains("CustomDisplay"),
            "writer must NOT switch to `Debug` (`{{:?}}`) — the pre-lift \
             sites used `{{}}` (Display); got {out:?}"
        );
    }

    /// Byte-oracle: `elapsed_secs` is rendered as plain decimal —
    /// no thousands separator, no zero-padding, no rounding to
    /// minutes. A cleanup that reached for a duration-formatter
    /// helper (e.g. `humantime`) would flip this assertion.
    #[test]
    fn write_pod_probe_pending_wait_line_renders_elapsed_as_plain_decimal() {
        let mut buf: Vec<u8> = Vec::new();
        write_pod_probe_pending_wait_line(
            &mut buf,
            PodPollTargetLabel::Deployment,
            &"e",
            1_234_567,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("1234567s elapsed"),
            "elapsed_secs must render as plain decimal, no separators; got {out:?}"
        );
    }

    /// Positive shield: `commands/flux.rs` MUST forward through
    /// [`print_pod_probe_pending_wait_line`] at least the migrated
    /// count (2). A migration that dropped a call site outright
    /// would leave the negative "no raw inline shape" shield below
    /// trivially satisfied by absence — this positive count catches
    /// that.
    #[test]
    fn flux_forwards_both_pod_probe_pending_wait_stanzas() {
        const SOURCE: &str = include_str!("commands/flux.rs");
        let forwards = SOURCE
            .matches("crate::pod_probe_pending_wait_line::print_pod_probe_pending_wait_line(")
            .count();
        assert!(
            forwards >= 2,
            "commands/flux.rs must forward at least 2 pod-probe \
             pending-wait stanzas through \
             `crate::pod_probe_pending_wait_line::print_pod_probe_pending_wait_line(`; \
             found {forwards}. A dropped call would leave the negative \
             raw-shape scan satisfied by absence."
        );
    }

    /// Post-lift shield: no source line under
    /// `cli/src/commands/flux.rs` may still spell the pre-lift
    /// `println!("   ⏳ Waiting for <label> ({}, {}s elapsed)", ...)`
    /// shape inline. Every consumer reaches for
    /// [`print_pod_probe_pending_wait_line`] on first grep, not by
    /// copy-pasting the raw stanza. Scoped to the module body
    /// BEFORE the first `#[cfg(test)]` region so a test-support
    /// mention of the raw shape (there is none today) would not
    /// defeat the shield.
    #[test]
    fn flux_no_longer_spells_raw_pod_probe_pending_wait_stanza() {
        const SOURCE: &str = include_str!("commands/flux.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(SOURCE, "commands/flux.rs");
        let mut offenders: Vec<(usize, String)> = Vec::new();
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            let has_prefix = line.contains("\u{23f3} Waiting for ");
            let has_elapsed_tail = line.contains("s elapsed)");
            if has_prefix && has_elapsed_tail && line.contains("println!(") {
                offenders.push((idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `println!(\"   \u{23f3} Waiting for <label> ({{}}, {{}}s elapsed)\", ...)` \
             stanza(s) survive in commands/flux.rs — route each through \
             `crate::pod_probe_pending_wait_line::print_pod_probe_pending_wait_line(\
             <PodPollTargetLabel>, <err>, <elapsed_secs>)` instead:\n{:#?}",
            offenders
        );
    }
}
