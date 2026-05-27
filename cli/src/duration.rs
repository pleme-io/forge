//! Canonical timeout/duration grammar for forge config + commands.
//!
//! forge's `deploy.yaml` timeout fields (`pre_deployment_tests` /
//! integration-test suite `timeout`) and the `rollout` CLI's `--timeout`
//! all speak the same tiny grammar: an ASCII-decimal magnitude with an
//! optional `s`/`m`/`h` unit suffix (bare number = seconds). That grammar
//! had accreted two independent hand-rolled parsers —
//! `commands/integration_tests.rs::parse_duration` (string → [`Duration`])
//! and `commands/rollout.rs::parse_timeout` (string → poll iterations) —
//! each re-deriving the suffix match. Two copies past the duplication
//! threshold the forge command-module surface enforces (≥2; PRIME
//! DIRECTIVE; THEORY §VI.1 generation-over-composition). This module is
//! the single grammar oracle both collapse onto, so a future unit or
//! call site cannot drift on what "a valid timeout" means.

use anyhow::{anyhow, bail, Result};
use std::time::Duration;

/// Parse a forge timeout string into a [`Duration`].
///
/// Grammar: leading/trailing whitespace is trimmed, then an ASCII-decimal
/// magnitude followed by an optional unit suffix — `s` (seconds, the
/// default when no suffix is given), `m` (minutes), `h` (hours). `"30s"`,
/// `"5m"`, `"2h"`, and the bare `"120"` (= 120s) are the shapes forge's
/// config and CLI accept; `"0s"` is a well-formed zero duration (callers
/// that forbid a zero timeout reject it themselves — see
/// [`crate::config`] validation).
///
/// Returns an error naming the offending input when the string is empty
/// or its magnitude is not a base-10 `u64`. This is the load-bearing
/// fail-fast surface: a malformed `deploy.yaml` timeout (`"5min"`,
/// `"10 minutes"`, `""`) is rejected at config-load through this one
/// oracle, rather than being silently swallowed to a default at run time
/// (the prior `parse_duration(..).unwrap_or(Duration::from_secs(300))`
/// hole at the two test-execution call sites).
pub fn parse_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        bail!(
            "empty timeout string (expected e.g. '30s', '5m', '2h', or a bare number of seconds)"
        );
    }
    // Match on the final byte: s/m/h are single-byte ASCII, so slicing at
    // `len - 1` is always a valid char boundary on the suffixed arms, and
    // the no-suffix arm never slices.
    let (magnitude, unit_secs): (&str, u64) = match trimmed.as_bytes().last() {
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 3600),
        _ => (trimmed, 1),
    };
    let value: u64 = magnitude.parse().map_err(|_| {
        anyhow!(
            "invalid timeout '{}': magnitude '{}' is not a base-10 integer \
             (expected e.g. '30s', '5m', '2h', or a bare number of seconds)",
            s,
            magnitude
        )
    })?;
    // Saturate rather than overflow-panic on absurd magnitudes; any value
    // this large is already far past any sane deploy/test timeout.
    Ok(Duration::from_secs(value.saturating_mul(unit_secs)))
}

/// Reject a zero-length timeout, naming the offending field.
///
/// [`parse_duration`] (the grammar oracle) deliberately treats `"0s"` as a
/// well-formed zero — grammar and magnitude are separate concerns, and a
/// caller is free to want a zero. The callers that *forbid* zero each
/// re-derived their own guard: a pre-deployment test timeout that fires
/// immediately fails every suite (`config::deployment` suite path,
/// `if d.is_zero()`); a deploy-wait of zero is a misconfiguration
/// (`deployment_wait_timeout_secs == 0`); a federation test timeout of zero
/// likewise (`timeout_seconds == 0`). Three guards past the duplication
/// threshold (THEORY §VI.1) — plus one silent *gap*:
/// `nix_connect_timeout_secs` had no check, so a zero connect timeout
/// reached the `nix` invocation. This is the single oracle they collapse
/// onto: the magnitude-layer peer of [`parse_duration`]'s grammar layer.
///
/// On a non-zero `d`, returns it unchanged so a caller can bind the
/// validated [`Duration`] in one expression. On zero, errors naming
/// `label` so a `deploy.yaml` author sees which field forge refused —
/// the same fail-at-load fidelity [`parse_duration`] gives the grammar.
pub fn reject_zero_timeout(d: Duration, label: &str) -> Result<Duration> {
    if d.is_zero() {
        bail!("{label} must be greater than 0 seconds");
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        // A bare zero is a well-formed duration at the grammar layer;
        // semantic rejection of zero timeouts lives in config validation.
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn parses_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parses_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn bare_number_assumes_seconds() {
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(parse_duration(" 30s ").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    /// The load-bearing fail-fast cases: a unit typo (`"5min"` leaves the
    /// magnitude as `"5mi"`), an English phrase, and a non-numeric
    /// magnitude must all error rather than parse to some default. Before
    /// the consolidation these flowed into a `.unwrap_or(300s)` swallow at
    /// the test-execution call sites; routing config validation through
    /// this oracle makes them loud at config-load.
    #[test]
    fn rejects_malformed_units() {
        assert!(parse_duration("5min").is_err());
        assert!(parse_duration("10 minutes").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-5s").is_err());
    }

    /// The error message names the offending input so a `deploy.yaml`
    /// author sees which value forge rejected.
    #[test]
    fn error_names_offending_input() {
        let msg = parse_duration("5min").unwrap_err().to_string();
        assert!(msg.contains("5min"), "error must echo the bad input: {msg}");
    }

    /// An absurd magnitude saturates instead of panicking on the
    /// `value * unit` multiply.
    #[test]
    fn saturates_on_overflow() {
        let huge = format!("{}h", u64::MAX);
        assert_eq!(
            parse_duration(&huge).unwrap(),
            Duration::from_secs(u64::MAX)
        );
    }

    /// A zero duration is rejected by the magnitude oracle, regardless of
    /// whether it arrived from the grammar (`"0s"`) or a `u64`-seconds
    /// config field (`Duration::from_secs(0)`).
    #[test]
    fn reject_zero_timeout_rejects_zero() {
        assert!(reject_zero_timeout(Duration::ZERO, "field").is_err());
        assert!(reject_zero_timeout(Duration::from_secs(0), "field").is_err());
        assert!(reject_zero_timeout(parse_duration("0s").unwrap(), "field").is_err());
    }

    /// Any positive duration passes through unchanged, so a caller can bind
    /// the validated value in one expression.
    #[test]
    fn reject_zero_timeout_passes_nonzero_through() {
        assert_eq!(
            reject_zero_timeout(Duration::from_secs(30), "field").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            reject_zero_timeout(parse_duration("5m").unwrap(), "field").unwrap(),
            Duration::from_secs(300)
        );
    }

    /// The error names the offending field so a `deploy.yaml` author sees
    /// which timeout forge refused — the magnitude-layer peer of
    /// [`error_names_offending_input`].
    #[test]
    fn reject_zero_timeout_error_names_field() {
        let msg = reject_zero_timeout(Duration::ZERO, "nix_connect_timeout_secs")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("nix_connect_timeout_secs"),
            "error must echo the field label: {msg}"
        );
    }
}
