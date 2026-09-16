//! Flux-GitOps pod-monitor hint primitive — the one-line
//! `ℹ️  Flux will handle deployment - use 'kubectl get pods -n <ns>' to monitor`
//! step-info stanza the two GitOps-trigger terminators in
//! `commands/federation.rs` and `commands/rust_service.rs` each emit
//! immediately after handing off to Flux.
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites each restated the same
//! [`crate::ui::print_step_info`] call, wrapping the same `format!`
//! literal with `namespace` as the single interpolation operand:
//!
//! 1. `commands/federation.rs::update_federation` (~L544-547) — the
//!    post-`crate::commands::flux::reconcile(namespace)` monitor hint,
//!    emitted after `print_step_success("Hive Router update triggered
//!    via GitOps")` and before the optional BFF-reload branch.
//! 2. `commands/rust_service.rs::deploy_rust_service_gitops`
//!    (~L2018-2021) — the post-`git_run_inherited_status(["push", ...])`
//!    monitor hint, emitted inside the `if watch { … }` arm after
//!    `print_step_success("Manifest updated and pushed")` and before
//!    the terminal `print_stage_completion_ack("GitOps deployment
//!    triggered!")`.
//!
//! Both sites forward through [`crate::ui::print_step_info`] and both
//! interpolate the same `namespace: String` local into the single
//! `{}` slot of the identical literal
//!
//! ```text
//! Flux will handle deployment - use 'kubectl get pods -n {}' to monitor
//! ```
//!
//! (ASCII hyphens throughout, single ASCII space either side of the
//! ` - ` separator, single-quoted `'kubectl get pods -n <ns>'`
//! sub-command). A drift between the two sites — a typo in the
//! sub-command, a swap to a double-quoted quote form, a rename of
//! `-n` to `--namespace`, or a hidden Unicode dash — would silently
//! diverge the operator-facing monitor hint between the federation
//! GitOps path and the rust-service GitOps path even though the very
//! same `kubectl` invocation monitors both. Post-lift the two stanzas
//! route through ONE typed body; a rename of the sub-command lands at
//! ONE writer and reaches both consumers by construction.
//!
//! # Distinct from the sibling `print_step_info` consumers
//!
//! [`crate::ui::print_step_info`] emits the generic
//! `ℹ️  <message>` one-line grammar 15 pre-lift consumer sites reach
//! for; this primitive owns ONE specific message body: the `kubectl
//! get pods -n <ns>` monitor hint the GitOps-trigger terminators
//! emit. Every peer `print_step_info` call in the crate composes its
//! own `format!` at the caller and passes an arbitrary message —
//! this primitive INSTEAD owns the message shape so a rename of
//! `kubectl` to a wrapper (or of the `-n <ns>` slot to a label
//! selector) lands at the primitive rather than every consumer.
//!
//! # Byte contract
//!
//! [`print_flux_gitops_monitor_hint`] and its writer sibling
//! [`write_flux_gitops_monitor_hint`] emit exactly the same bytes
//! [`crate::ui::write_step_info`] would with the pre-lift
//! `format!("Flux will handle deployment - use 'kubectl get pods -n
//! {}' to monitor", namespace)` message argument — the `ℹ️  ` glyph
//! prefix (`E2 84 B9 EF B8 8F 20 20` — U+2139 INFORMATION SOURCE +
//! U+FE0F VS16 + two ASCII spaces), the message body verbatim, and a
//! trailing `\n`. No ANSI escapes: the pre-lift consumers spelled
//! `print_step_info` (not `print_info`), and `print_step_info` emits
//! a plain uncolored line.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the monitor-hint message shape
//! lives at ONE construction surface so a future refinement — a
//! rename of the sub-command, a swap to a label-selector form
//! (`-l app=<product>-<service>`), an operator-friendly reflow that
//! splits the hint across two lines — lands in one place rather
//! than in every consumer of the `ℹ️  <hint>` idiom.
//!
//! §VI.1 three-is-a-law prospectively: two sites today, and every
//! future GitOps-trigger command that hands off to Flux (`chart
//! deploy`, `kustomization sync`, etc.) will reach for the same
//! monitor hint on first grep.

use std::io;

/// Message body used by the pod-monitor hint stanza. The `{}` slot is
/// filled at [`write_flux_gitops_monitor_hint`] with the caller-owned
/// `namespace`. Exposed for byte-oracle tests that pin the pre-lift
/// literal against every drift class (a hyphen swap, a quote-style
/// swap, an `-n` → `--namespace` rename, a Unicode-dash slip).
const MESSAGE_TEMPLATE: &str =
    "Flux will handle deployment - use 'kubectl get pods -n {}' to monitor";

/// Print the pod-monitor hint stanza — an
/// `ℹ️  Flux will handle deployment - use 'kubectl get pods -n <ns>' to monitor`
/// step-info line — to [`std::io::stdout()`].
///
/// The two consumer sites in `cli/src/commands/federation.rs` and
/// `cli/src/commands/rust_service.rs` each spelled this stanza as an
/// inline `crate::ui::print_step_info(&format!(<literal>, namespace))`
/// pre-lift; post-lift they both forward through this function.
///
/// Delegates to [`write_flux_gitops_monitor_hint`] against a locked
/// stdout handle; the writer split exists so the fail-before-pass
/// tests can pin the emitted bytes without capturing stdout.
pub fn print_flux_gitops_monitor_hint(namespace: &str) {
    let _ = write_flux_gitops_monitor_hint(&mut std::io::stdout().lock(), namespace);
}

/// Writer-taking sibling of [`print_flux_gitops_monitor_hint`]. Emits
/// the single `ℹ️  Flux will handle deployment - use 'kubectl get
/// pods -n <namespace>' to monitor` line via [`writeln!`] against the
/// supplied writer, delegating to [`crate::ui::write_step_info`] for
/// the `ℹ️  <message>` framing so the glyph-prefix + newline byte
/// shape stays byte-identical to every peer `print_step_info`
/// consumer.
///
/// # Byte contract
///
/// The rendered byte sequence is exactly what
/// [`crate::ui::write_step_info`] emits for the composed message —
/// the `ℹ️  ` glyph prefix (U+2139 INFORMATION SOURCE + U+FE0F VS16 +
/// two ASCII spaces), the interpolated message body, and a single
/// trailing `\n`. No ANSI escape sequences: pre-lift consumers
/// spelled [`crate::ui::print_step_info`] (a plain uncolored line),
/// not the milestone-level [`crate::ui::print_info`].
///
/// # Namespace positional invariant
///
/// The `namespace` argument lands at exactly one position in the
/// emitted line: immediately after the ASCII `-n ` token inside the
/// single-quoted `'kubectl get pods -n <ns>'` sub-command. A future
/// refactor that (a) renamed the flag (`-n` → `--namespace`),
/// (b) hoisted the namespace outside the quotes, or (c) added a
/// second interpolation slot would fail the
/// `write_flux_gitops_monitor_hint_places_namespace_after_dash_n`
/// oracle below.
pub fn write_flux_gitops_monitor_hint<W: io::Write>(w: &mut W, namespace: &str) -> io::Result<()> {
    let message = MESSAGE_TEMPLATE.replace("{}", namespace);
    crate::ui::write_step_info(w, &message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the writer emits exactly ONE line, terminated by
    /// a single `\n`. A refactor that (a) split the hint across two
    /// lines (e.g., moving `to monitor` onto a follow-up
    /// `print_step_info` call) or (b) doubled the trailing newline
    /// (e.g., inserting a framing blank the way
    /// `print_stage_completion_ack` does) would flip this assertion.
    #[test]
    fn write_flux_gitops_monitor_hint_emits_one_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_gitops_monitor_hint(&mut buf, "prod-web").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert!(
            out.ends_with('\n'),
            "writer output must end with exactly one `\\n`; got {out:?}"
        );
        assert_eq!(
            out.matches('\n').count(),
            1,
            "writer must emit exactly one line-terminating `\\n`; got {out:?}"
        );
    }

    /// Byte-oracle: the emitted line opens with the literal
    /// `ℹ️  ` glyph prefix (`E2 84 B9 EF B8 8F 20 20` — U+2139
    /// INFORMATION SOURCE + U+FE0F VS16 + two ASCII spaces) — the
    /// same prefix [`crate::ui::write_step_info`] emits for every
    /// peer step-info consumer. A drift that swapped the delegation
    /// to [`crate::ui::write_info`] would introduce
    /// `\x1b[96m`/`\x1b[36m` bright_cyan ANSI escape bytes and fail
    /// here; a drift to [`crate::ui::write_step_info_indented`] would
    /// prepend three ASCII spaces before the glyph and fail here too.
    #[test]
    fn write_flux_gitops_monitor_hint_opens_with_step_info_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_gitops_monitor_hint(&mut buf, "prod-web").unwrap();
        let bytes = buf.as_slice();
        // U+2139 INFORMATION SOURCE = E2 84 B9;
        // U+FE0F VARIATION SELECTOR-16 = EF B8 8F;
        // then two ASCII spaces.
        let expected_prefix: &[u8] = b"\xe2\x84\xb9\xef\xb8\x8f  ";
        assert!(
            bytes.starts_with(expected_prefix),
            "writer output must open with the `ℹ️  ` step-info glyph \
             prefix (U+2139 + U+FE0F + two ASCII spaces); got {bytes:?}"
        );
    }

    /// Byte-oracle: the emitted line carries the pre-lift literal
    /// verbatim between the `ℹ️  ` prefix and the trailing `\n`. Pins
    /// the ASCII hyphens (` - ` between "deployment" and "use"), the
    /// single-quoted `'kubectl get pods -n <ns>'` sub-command, and
    /// the trailing `' to monitor` closing tail. A drift that
    /// (a) swapped `'` for `"` around the sub-command, (b) replaced
    /// ` - ` with a Unicode em-dash or en-dash, (c) rewrote the
    /// sub-command (`kubectl get po` shorthand, `kubectl -n <ns>
    /// get pods` flag-first form), or (d) added trailing punctuation
    /// (`... to monitor.`) would fail here.
    #[test]
    fn write_flux_gitops_monitor_hint_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_gitops_monitor_hint(&mut buf, "prod-web").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out,
            "\u{2139}\u{fe0f}  Flux will handle deployment - use \
             'kubectl get pods -n prod-web' to monitor\n",
            "writer output must render the pre-lift literal \
             byte-for-byte; got {out:?}"
        );
    }

    /// Interpolation-position pin: the `namespace` argument lands
    /// exactly ONCE, immediately after the ASCII `-n ` token, inside
    /// the single-quoted `'kubectl get pods -n <ns>'` sub-command. A
    /// refactor that (a) hoisted the namespace outside the quotes,
    /// (b) added a second interpolation slot (echoing the namespace
    /// twice), or (c) reordered the sub-command tokens
    /// (`kubectl -n <ns> get pods`) would fail here.
    #[test]
    fn write_flux_gitops_monitor_hint_places_namespace_after_dash_n() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_gitops_monitor_hint(&mut buf, "distinct-ns-marker").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("-n distinct-ns-marker'"),
            "writer output must place the namespace immediately after \
             `-n ` inside the single-quoted sub-command; got {out:?}"
        );
        assert_eq!(
            out.matches("distinct-ns-marker").count(),
            1,
            "namespace must appear exactly ONCE in the emitted line — \
             a second interpolation slot would echo it twice; got {out:?}"
        );
    }

    /// Byte-oracle: the writer emits NO ANSI escape sequences. The
    /// pre-lift consumers spelled [`crate::ui::print_step_info`] (the
    /// plain uncolored one-line info grammar), not the milestone-level
    /// [`crate::ui::print_info`] whose `bright_cyan()` palette would
    /// wrap the line in `\x1b[96m…\x1b[0m`. A future refactor that
    /// promoted the hint to the milestone palette would fail here.
    #[test]
    fn write_flux_gitops_monitor_hint_carries_no_ansi_escapes() {
        let mut buf: Vec<u8> = Vec::new();
        write_flux_gitops_monitor_hint(&mut buf, "prod-web").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "writer output must carry no `\\x1b` ANSI escape bytes — \
             the pre-lift consumers spelled `print_step_info`, not the \
             milestone-level `print_info`; got {buf:?}"
        );
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw literal
    /// `"Flux will handle deployment - use 'kubectl get pods -n {}' to monitor"`
    /// inline. Every consumer reaches for
    /// [`print_flux_gitops_monitor_hint`] on first grep, not by
    /// copy-pasting the raw literal into a bespoke
    /// `print_step_info(&format!(...))` stanza.
    #[test]
    fn no_command_module_still_spells_raw_flux_gitops_monitor_hint() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = "Flux will handle deployment - use 'kubectl get pods -n";
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
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
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
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `Flux will handle deployment - use 'kubectl get pods \
             -n {{}}' to monitor` literal(s) survive under `commands/` \
             — route each through `crate::flux_gitops_monitor_hint::\
             print_flux_gitops_monitor_hint(<namespace>)` instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive half): the two pre-lift modules
    /// that housed the two sites MUST each forward through
    /// [`print_flux_gitops_monitor_hint`] at least the pre-lift
    /// count of times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_print_flux_gitops_monitor_hint() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("federation.rs", 1), ("rust_service.rs", 1)];
        let needle = "print_flux_gitops_monitor_hint(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 pod-monitor hint stanza(s) through `{needle}`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }

    /// Distinct-from-peers shield: the message template MUST remain
    /// pinned to the pre-lift literal. A drift that (a) swapped
    /// ASCII hyphens for Unicode dashes, (b) swapped single quotes
    /// for double quotes, or (c) renamed `-n` to `--namespace` would
    /// fail here — the template constant is the single source of
    /// truth for the message body, and the `{}` slot is the single
    /// interpolation point.
    #[test]
    fn message_template_pins_pre_lift_literal() {
        assert_eq!(
            MESSAGE_TEMPLATE,
            "Flux will handle deployment - use 'kubectl get pods -n {}' to monitor",
            "MESSAGE_TEMPLATE must match the pre-lift literal \
             byte-for-byte; a drift here regresses the two consumer \
             sites in `commands/federation.rs` and \
             `commands/rust_service.rs`"
        );
        assert_eq!(
            MESSAGE_TEMPLATE.matches("{}").count(),
            1,
            "MESSAGE_TEMPLATE must carry exactly ONE `{{}}` \
             interpolation slot (the namespace); a second slot would \
             fabricate a two-argument primitive the two pre-lift \
             consumers never spelled"
        );
    }
}
