//! Required-nonblank string-field validator for forge `deploy.yaml` config
//!
//! Twelve sibling `if x.trim().is_empty() { bail!("... cannot be empty[...]"); }`
//! stanzas across `config/{deployment (×5: slice name, kustomization, test
//! suite name, test suite command, flux_commands[N]), federation (×2: suite,
//! router_url), migration (×2: schema_migrations_path, data_migrations_path),
//! product (×3: name, environment, cluster)}.rs` each restated the same
//! required-nonblank predicate + bail shape verbatim. This module is the
//! single grammar oracle they collapse onto — the string-field peer of
//! the timeout-layer [`crate::duration::parse_timeout_field`] grammar
//! oracle. Twelve occurrences past THEORY §VI.1's generation-over-
//! composition threshold ("two occurrences is a coincidence; three is a
//! law") and the CLAUDE.md PRIME DIRECTIVE (duplication is a bug).
//!
//! # Semantics
//!
//! [`require_nonblank`] treats "empty" and "whitespace-only" identically —
//! both fail with the label echoed in the emitted error. A `deploy.yaml`
//! author who writes `name: "   "` reads the same rejection a `name: ""`
//! author reads, so config-load fail-fast fidelity is uniform across the
//! grammar-and-magnitude split (grammar layer: `.trim()`; magnitude layer:
//! non-emptiness). This matches the discipline
//! [`crate::duration::parse_duration`] applies at the timeout grammar
//! layer — a `deploy.yaml` author reads ONE grammar-rejected shape across
//! every string field regardless of whether the field is a timeout or a
//! non-empty identifier.
//!
//! # Load-bearing
//!
//! Prior to this consolidation the twelve inline stanzas each restated the
//! `trim().is_empty()` predicate independently. A future refinement of
//! what counts as blank (e.g., unicode-whitespace-aware trim, or rejecting
//! BOM / zero-width characters) would have had to land at twelve sites;
//! post-lift it lands at this one primitive body and every consumer
//! inherits the refinement by construction (THEORY §VI.1
//! generation-over-composition; CLAUDE.md PRIME DIRECTIVE).

use anyhow::{bail, Result};

/// Bail if `value` is empty or whitespace-only, echoing `label` so a
/// `deploy.yaml` author sees which field forge refused. On a non-blank
/// `value`, returns `Ok(())` so a caller can chain further validations
/// in the same function.
///
/// Emits `"{label} cannot be empty"` on rejection — the single required-
/// nonblank oracle every config-layer string-field validation routes
/// through.
pub fn require_nonblank(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(())
}

/// Byte-oracle sibling of [`require_nonblank`]: returns the exact error
/// prose the primitive emits for a given `label`.
///
/// Test-only. A caller that needs to assert the printed error shape
/// byte-for-byte reads through this helper rather than restating the
/// `"{label} cannot be empty"` literal — a future refinement of the
/// error prose lands here and every asserting site inherits it.
#[cfg(test)]
pub(crate) fn require_nonblank_error_message(label: &str) -> String {
    format!("{label} cannot be empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nonblank_value() {
        assert!(require_nonblank("foo", "Field").is_ok());
        assert!(require_nonblank(" foo ", "Field").is_ok());
        assert!(require_nonblank("a", "Field").is_ok());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(require_nonblank("", "Field").is_err());
    }

    /// Whitespace-only inputs — ASCII space, tab, newline, carriage
    /// return, and their combinations — must fail identically to the bare
    /// empty case: the load-bearing invariant that lets a `deploy.yaml`
    /// author reading `name: "   "` see the same rejection a `name: ""`
    /// author reads.
    #[test]
    fn rejects_whitespace_only() {
        assert!(require_nonblank("   ", "Field").is_err());
        assert!(require_nonblank("\t", "Field").is_err());
        assert!(require_nonblank("\n", "Field").is_err());
        assert!(require_nonblank("\r", "Field").is_err());
        assert!(require_nonblank("\t\n \r", "Field").is_err());
    }

    /// The error echoes the label so a `deploy.yaml` author sees which
    /// field forge refused — the field-naming discipline
    /// [`crate::duration::parse_timeout_field`] enforces at the timeout
    /// grammar layer.
    #[test]
    fn error_echoes_label() {
        let err = require_nonblank("", "Slice name (slice index 2)")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Slice name (slice index 2)"),
            "error must echo the label so a deploy.yaml author sees which \
             field forge refused: {err}"
        );
    }

    /// The printed error is byte-for-byte the
    /// [`require_nonblank_error_message`] shape — so a future refinement
    /// of the error prose lands at ONE site and every asserting caller
    /// inherits it by construction.
    #[test]
    fn error_matches_byte_oracle_shape() {
        let err = require_nonblank("   ", "schema_migrations_path")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            require_nonblank_error_message("schema_migrations_path")
        );
    }

    /// Negative caller shield: the pre-lift
    /// `if x.trim().is_empty() { bail!("... cannot be empty[...]"); }`
    /// stanza MUST NOT reappear in the four config files this primitive
    /// lifts from. A future consumer that re-copies the pre-lift stanza
    /// pushes this count above zero and fails the shield before it can
    /// drift on what counts as blank (unicode-aware, BOM, zero-width,
    /// etc.) at that one site — the twelve-site drift the primitive body
    /// was built to close.
    #[test]
    fn no_raw_trim_is_empty_stanzas_survive_in_lifted_config_files() {
        const NEEDLE: &str = ".trim().is_empty()";
        const FILES: &[(&str, &str)] = &[
            (
                "cli/src/config/deployment.rs",
                include_str!("deployment.rs"),
            ),
            (
                "cli/src/config/federation.rs",
                include_str!("federation.rs"),
            ),
            ("cli/src/config/migration.rs", include_str!("migration.rs")),
            ("cli/src/config/product.rs", include_str!("product.rs")),
        ];
        for (name, src) in FILES {
            let hits = crate::test_support::code_line_hits(src, NEEDLE);
            assert!(
                hits.is_empty(),
                "{name} must NOT restate `{NEEDLE}` post-lift — route \
                 through `crate::config::nonblank::require_nonblank`. \
                 Found hits: {hits:#?}"
            );
        }
    }

    /// Positive-delegation shield: each pre-lift file must forward
    /// through [`require_nonblank`] at least the pre-lift count of times.
    /// The counts pin the minimum per-file discipline
    /// — deployment.rs (5), federation.rs (2), migration.rs (2),
    /// product.rs (3) — so a future refactor that folds one call site
    /// into another without adding a new caller elsewhere fails the
    /// shield.
    #[test]
    fn lifted_config_files_forward_through_require_nonblank() {
        const NEEDLE: &str = "require_nonblank(";
        const FILES: &[(&str, &str, usize)] = &[
            (
                "cli/src/config/deployment.rs",
                include_str!("deployment.rs"),
                5,
            ),
            (
                "cli/src/config/federation.rs",
                include_str!("federation.rs"),
                2,
            ),
            (
                "cli/src/config/migration.rs",
                include_str!("migration.rs"),
                2,
            ),
            ("cli/src/config/product.rs", include_str!("product.rs"), 3),
        ];
        for (name, src, min_count) in FILES {
            let hits = crate::test_support::code_line_hits(src, NEEDLE);
            assert!(
                hits.len() >= *min_count,
                "{name} must forward through `{NEEDLE}...)` at least \
                 {min_count} times — found {} hits: {hits:#?}",
                hits.len(),
            );
        }
    }
}
