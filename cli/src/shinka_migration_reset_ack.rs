//! Fused `if let Ok(was_reset) = check_and_reset_shinka_migration(...).await
//! { if was_reset { print_step_pass("Shinka migration reset, will retry with
//! new image"); } }` stanza collapsed onto one typed primitive.
//!
//! # Pre-lift census — two byte-identical sibling stanzas
//!
//! `commands/rust_service.rs` carried two byte-identical stanzas
//! immediately below matching `check_and_reset_shinka_migration` async
//! calls, differing only in the caller-supplied namespace expression:
//!
//! 1. `commands/rust_service.rs::deploy_service_across_environments`
//!    (pre-lift `:1421-:1431`) — inside the
//!    `for (i, env) in environments.iter().enumerate()` per-environment
//!    migration loop, passing `&namespace` (the loop-local `String`
//!    resolved from `deploy_config.env_namespace(env)`).
//! 2. `commands/rust_service.rs::deploy_and_verify` (pre-lift
//!    `:2400-:2410`) — inside the single-environment migration preamble,
//!    passing `&deploy_config.kubernetes_namespace()` (the same
//!    `String`-returning projection at a different fixation point).
//!
//! Both stanzas call `crate::commands::migrations::check_and_reset_shinka_migration`
//! with the same first two positional args (`&deploy_config.product.name`
//! and `&service`), await the `Result<bool>`, silence the Err arm via
//! `if let Ok(...)`, and on `Ok(true)` (the "reset was performed" branch)
//! emit exactly one `crate::ui::print_step_pass(...)` line with the
//! byte-identical `"Shinka migration reset, will retry with new image"`
//! payload. `Ok(false)` (no reset needed — the DatabaseMigration is
//! either absent or in a healthy phase) and the discarded Err arm both
//! fall through silently.
//!
//! # Why a `()`-returning async fn, not a `Result<bool>` probe
//!
//! Both consumers want the *same* side-effect shape on the
//! `Ok(true)` branch — one `print_step_pass` line on a fixed message
//! string — and the *same* silence on both `Ok(false)` and the discarded
//! `Err`. The primitive owns all three arms (the async call, the Err
//! silencing, AND the fixed-message ack) rather than returning a
//! `Result<bool>` that each caller then re-converts to its own
//! print_step_pass stanza. A `Result<bool>`-returning probe would let a
//! future caller drift the ack message (dropping "will retry with new
//! image", swapping the tense, or emitting a `warn!` instead of a
//! `print_step_pass`) and re-introduce the pre-lift duplication class
//! one level deeper.
//!
//! The shape mirrors [`crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running`]
//! and [`crate::docker_installed_preflight::bail_unless_docker_installed`]
//! — typed primitives whose return type is `()` (or `Result<()>`) because
//! the shared side-effect shape is what the primitive is preserving,
//! not just the probe.
//!
//! # Byte-oracle discipline via [`crate::ui::write_step_pass`]
//!
//! The [`write_shinka_migration_reset_ack_line`] writer sibling
//! delegates to [`crate::ui::write_step_pass`] composed with the
//! constant [`SHINKA_MIGRATION_RESET_ACK_MESSAGE`] so the outer
//! `   {✅.green()} <msg>` step-pass template stays a single source of
//! truth in `ui.rs`. Tests compare `write_shinka_migration_reset_ack_line`
//! bytes-for-bytes against `write_step_pass(w, MSG)`, so a fusion that
//! bypassed `write_step_pass` (dropping the three-space indent, the
//! green ANSI `✅` glyph, or the trailing newline) fails here — no
//! `AnsiOverrideForTest` guard needed because both sides of the
//! comparison share the same ambient colored auto-detection state.

use std::io;

/// The exact ack-message string the two pre-lift sites emitted on the
/// `Ok(true)` (reset performed) branch. Constant-lifted so the
/// byte-oracle tests, the caller-shield remediation prose, and every
/// future consumer of the same shape reference one source of truth —
/// a rotation (e.g. shortening to "Shinka migration reset.",
/// adding a docs URL tail, or softening "will retry" to "should retry")
/// happens in exactly one place.
///
/// The message string is what [`crate::ui::print_step_pass`] emits
/// verbatim after its three-space + `✅` prefix; both pre-lift
/// consumer sites in `commands/rust_service.rs` spelled this exact
/// byte sequence inline before the lift.
pub const SHINKA_MIGRATION_RESET_ACK_MESSAGE: &str =
    "Shinka migration reset, will retry with new image";

/// Fused async primitive: probe the Shinka DatabaseMigration for the
/// `<product>-<service>` name in the given namespace, reset it if
/// stuck in `Failed` / `CheckingHealth` phase, and — on the
/// "reset performed" branch — ack via
/// [`crate::ui::print_step_pass`] with the fixed
/// [`SHINKA_MIGRATION_RESET_ACK_MESSAGE`] payload.
///
/// The pre-lift stanza (verbatim, both sites):
///
/// ```ignore
/// if let Ok(was_reset) = crate::commands::migrations::check_and_reset_shinka_migration(
///     &deploy_config.product.name,
///     &service,
///     &<namespace>,
/// )
/// .await
/// {
///     if was_reset {
///         crate::ui::print_step_pass("Shinka migration reset, will retry with new image");
///     }
/// }
/// ```
///
/// Silences both `Err` (kubectl unavailable, DatabaseMigration CRD
/// not installed, RBAC denial) and `Ok(false)` (no reset needed —
/// the DatabaseMigration is either absent or in a healthy phase) — the
/// operator sees the ack line only on `Ok(true)`, matching pre-lift
/// behavior byte-for-byte.
pub async fn try_reset_stuck_shinka_migration_with_ack(
    product: &str,
    service: &str,
    namespace: &str,
) {
    if let Ok(was_reset) =
        crate::commands::migrations::check_and_reset_shinka_migration(product, service, namespace)
            .await
    {
        if was_reset {
            crate::ui::print_step_pass(SHINKA_MIGRATION_RESET_ACK_MESSAGE);
        }
    }
}

/// Byte-oracle sibling of the print-branch inside
/// [`try_reset_stuck_shinka_migration_with_ack`] — writes the exact
/// bytes [`crate::ui::print_step_pass`] would emit against the fixed
/// [`SHINKA_MIGRATION_RESET_ACK_MESSAGE`] payload, into any
/// [`std::io::Write`], so a `#[test]` can capture and compare them.
///
/// Delegates to [`crate::ui::write_step_pass`] so the outer
/// `   {✅.green()} <msg>` step-pass template stays a single source of
/// truth in `ui.rs`; the inner message is exactly
/// [`SHINKA_MIGRATION_RESET_ACK_MESSAGE`]. A fusion that dropped the
/// three-space indent, the `.green()` on the `✅`, the trailing
/// newline, or the constant payload fails the byte-oracle test.
#[allow(dead_code)] // Peer of the print-routed
                    // `try_reset_stuck_shinka_migration_with_ack` fn,
                    // retained for the byte-oracle tests and for a
                    // future summary-report consumer.
pub(crate) fn write_shinka_migration_reset_ack_line<W: io::Write>(w: &mut W) -> io::Result<()> {
    crate::ui::write_step_pass(w, SHINKA_MIGRATION_RESET_ACK_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the shared message string the byte-oracle, the
    /// caller-shield remediation, and every consumer reference is the
    /// pre-lift verbatim literal. A change here rotates every dependent
    /// in lockstep.
    #[test]
    fn test_shinka_migration_reset_ack_message_matches_pre_lift_literal() {
        assert_eq!(
            SHINKA_MIGRATION_RESET_ACK_MESSAGE,
            "Shinka migration reset, will retry with new image"
        );
    }

    /// Byte-oracle: the writer's rendered bytes are exactly what
    /// [`crate::ui::write_step_pass`] emits against the constant
    /// message. Compares against the delegate directly so both sides
    /// share the same ambient `colored` auto-detection state (no
    /// `AnsiOverrideForTest` guard needed) — a fusion that bypassed
    /// `write_step_pass` on the raw glyph, dropped the three-space
    /// indent, or lost the `.green()` on the `✅` fails here.
    #[test]
    fn write_shinka_migration_reset_ack_line_matches_step_pass_template() {
        let mut got: Vec<u8> = Vec::new();
        write_shinka_migration_reset_ack_line(&mut got).unwrap();

        let mut want: Vec<u8> = Vec::new();
        crate::ui::write_step_pass(&mut want, SHINKA_MIGRATION_RESET_ACK_MESSAGE).unwrap();

        assert_eq!(
            got, want,
            "write_shinka_migration_reset_ack_line must render \
             `<step_pass_template> <SHINKA_MIGRATION_RESET_ACK_MESSAGE>` \
             bytes-for-bytes; a fusion that bypassed \
             `crate::ui::write_step_pass` or swapped the constant fails here"
        );
    }

    /// Grammar pin: the rendered line ends with the pre-lift ack
    /// message payload followed by exactly one `\n`. Human-readable
    /// so a future reader can eyeball the tail without decoding the
    /// ANSI-prefixed bytes. Guards against a future adjustment that
    /// slipped a punctuation tail (`.`, `!`, or a docs-URL fragment)
    /// after the message but before the newline.
    #[test]
    fn write_shinka_migration_reset_ack_line_carries_pre_lift_message_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_shinka_migration_reset_ack_line(&mut buf).unwrap();
        let s = String::from_utf8(buf).expect("write_step_pass must emit valid UTF-8");
        let expected_tail = format!("{}\n", SHINKA_MIGRATION_RESET_ACK_MESSAGE);
        assert!(
            s.ends_with(&expected_tail),
            "must end with the pre-lift message + newline `{}`; got: {:?}",
            expected_tail,
            s
        );
    }

    /// Grammar pin: the rendered line is exactly one `\n`-terminated
    /// line — the pre-lift stanza was one `print_step_pass` call, not
    /// two, and carried no framing blank. A future adjustment that
    /// slipped a leading or trailing blank into the primitive body
    /// fails here.
    #[test]
    fn write_shinka_migration_reset_ack_line_emits_exactly_one_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_shinka_migration_reset_ack_line(&mut buf).unwrap();
        let s = String::from_utf8(buf).expect("valid UTF-8");
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "must emit exactly one line — the pre-lift stanza is one \
             `print_step_pass` call carrying no framing blank; got \
             {} lines:\n{}",
            lines.len(),
            s
        );
    }

    /// Negative caller shield: NO line under `cli/src/commands/` may
    /// spell the raw pre-lift `"Shinka migration reset, will retry
    /// with new image"` string literal inline any more. The two
    /// pre-lift sites migrated; any future consumer that wants the
    /// same ack message reaches for
    /// [`try_reset_stuck_shinka_migration_with_ack`] (or the
    /// [`SHINKA_MIGRATION_RESET_ACK_MESSAGE`] constant if it needs the
    /// bare string) on first grep, not by copy-pasting the raw
    /// literal from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] so this shield's own
    /// source text does not false-match itself; the whole-scan
    /// therefore covers both the top-of-file production body AND every
    /// sibling `#[cfg(test)]` block. Line-comment and block-comment
    /// lines are skipped so a future module that quotes the pre-lift
    /// shape as historical prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_shinka_reset_ack_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");

        // Reconstruct the forbidden literal via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!(
            "\"{}\"",
            "Shinka migration reset, will retry with new image"
        );

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir)
            .expect("commands/ directory must be readable at test time");
        for entry in read.flatten() {
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
                if line.contains(&forbidden) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"Shinka migration reset, will retry with new image\"` \
             literal(s) survive under `commands/` — route each through \
             `crate::shinka_migration_reset_ack::try_reset_stuck_shinka_migration_with_ack(...)` \
             (or the `SHINKA_MIGRATION_RESET_ACK_MESSAGE` constant if the \
             bare string is needed) instead:\n{:#?}",
            offenders
        );
    }

    /// Positive caller shield: `commands/rust_service.rs` — the one
    /// pre-lift module that housed the two sites — MUST forward
    /// through [`try_reset_stuck_shinka_migration_with_ack`] at least
    /// twice, so a migration that dropped a call site outright leaves
    /// the negative "no raw inline literal" scan trivially satisfied
    /// by absence but the positive count still fails. Mirrors the
    /// discipline of the sibling
    /// `every_prelift_module_forwards_through_bail_unless_docker_daemon_running`
    /// shield in [`crate::docker_daemon_running_preflight`].
    #[test]
    fn rust_service_forwards_through_try_reset_stuck_shinka_migration_with_ack_at_least_twice() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("rust_service.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let needle = "try_reset_stuck_shinka_migration_with_ack(";
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 2,
            "commands/rust_service.rs must forward at least 2 shinka-reset-ack \
             sites through `{}`; found {}. A dropped call would leave the \
             negative raw-literal scan satisfied by absence.",
            needle,
            forwards
        );
    }
}
