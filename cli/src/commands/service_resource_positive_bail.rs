//! `bail_unless_service_resource_positive` — three sibling `bail!("Invalid
//! <kind> value '{}'. Must be greater than 0", s)` positivity-gate stanzas
//! across `commands/service_config.rs::{validate_memory_resource,
//! validate_cpu_resource}` collapsed onto one typed primitive.
//!
//! # Pre-lift census — three sibling stanzas, one positivity gate
//!
//! Three call sites in `commands/service_config.rs` each emitted the
//! same bail on the "parsed numeric value not strictly greater than
//! zero" branch, differing only in which resource-kind noun the
//! operator-facing message names:
//!
//! 1. `validate_memory_resource` (:49 pre-lift) — after parsing the
//!    numeric prefix of a Kubernetes memory string (`128Mi`, `1Gi`)
//!    into `u64`, bails on `value == 0` with the memory-noun wording.
//! 2. `validate_cpu_resource` millicores branch (:81 pre-lift) —
//!    after parsing the numeric prefix of a `100m`-shaped millicores
//!    string into `u64`, bails on `value == 0` with the CPU-noun
//!    wording.
//! 3. `validate_cpu_resource` decimal-cores branch (:96 pre-lift) —
//!    after parsing a `"0.5"`-shaped decimal string into `f64`, bails
//!    on `value <= 0.0` with the CPU-noun wording.
//!
//! Three occurrences of a lockstep shape past THEORY §VI.1's
//! three-is-a-law threshold (PRIME DIRECTIVE: the duplication budget
//! is zero). A single-site drift — a rephrase to "must be positive",
//! a change of "greater than" to `">="`, a swap of the single-quote
//! glyph, or a diverging `Invalid <X> value` prefix — pre-lift had to
//! hit three sites in lockstep or diverge; post-lift it hits ONE typed
//! body and every consumer inherits the change from
//! `bail_unless_service_resource_positive`.
//!
//! # Why an `is_positive: bool` axis, not the numeric value itself
//!
//! The three consumers hold their parsed values under different types
//! (`u64` for memory and CPU-millicores, `f64` for CPU-decimal cores)
//! and phrase positivity accordingly (`value == 0` on the integer
//! branches, `value <= 0.0` on the float branch). A primitive taking
//! the raw numeric would need either a generic
//! `T: PartialOrd + num_traits::Zero` bound (a `num-traits` dependency
//! added purely for this one gate) or three overloads. Passing the
//! pre-computed positivity `bool` keeps the primitive free of
//! numeric-trait plumbing and lets each caller keep its own natural
//! comparison — the same shape
//! [`crate::docker_daemon_running_preflight::bail_unless_docker_daemon_running`]
//! carries against its own external probe.
//!
//! # Closed-enum discipline
//!
//! The two variants of [`ServiceResourceKind`] exhaust the pre-lift
//! resource-kind census. A future addition (GPU quotas, ephemeral
//! storage, hugepages) is one new variant plus one arm in
//! [`ServiceResourceKind::label`] — the surrounding bail template
//! stays fixed. Making the noun carrier a closed enum rather than a
//! caller-supplied `&str` means the operator's vocabulary at this
//! stderr line is decided here rather than at every future consumer
//! (THEORY §II — "typed contracts turn a structural drift into a
//! compile error").

use anyhow::{bail, Result};

/// The resource-kind axis of the shared
/// `"Invalid <label> value '{}'. Must be greater than 0"` bail
/// template. Two variants exhaust the pre-lift census; each projects
/// through [`Self::label`] onto the fixed noun the surrounding message
/// splices in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceResourceKind {
    /// Kubernetes memory resource string (e.g. `"128Mi"`, `"1Gi"`).
    /// Projects to the English noun `"memory"` — the pre-lift memory
    /// branch spelled it lowercase.
    Memory,
    /// Kubernetes CPU resource string (e.g. `"100m"`, `"0.5"`, `"2"`).
    /// Projects to the initialism `"CPU"` — the pre-lift CPU branches
    /// spelled it uppercase.
    Cpu,
}

impl ServiceResourceKind {
    /// The per-variant noun spliced into the shared
    /// `"Invalid <label> value '{}'. Must be greater than 0"` bail
    /// template. Byte-for-byte invariant across the three pre-lift
    /// consumer sites.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cpu => "CPU",
        }
    }
}

/// Bail with the pre-lift
/// `"Invalid <kind.label()> value '<value>'. Must be greater than 0"`
/// message unless `is_positive` is `true`.
///
/// Callers pre-compute `is_positive` against their own numeric type
/// (a `u64 != 0` check for the memory and CPU-millicores branches; an
/// `f64 > 0.0` check for the CPU-decimal-cores branch) and pass the
/// bool through together with the original input `value` string that
/// the operator's stderr line echoes back inside single quotes.
///
/// Returns `Ok(())` on the positive branch so the caller composes it
/// with `?` at the point where its own numeric-parse has already
/// decided the positivity question:
///
/// ```ignore
/// let value = numeric_part.parse::<u64>()?;
/// bail_unless_service_resource_positive(
///     value > 0,
///     ServiceResourceKind::Memory,
///     s,
/// )?;
/// ```
pub fn bail_unless_service_resource_positive(
    is_positive: bool,
    kind: ServiceResourceKind,
    value: &str,
) -> Result<()> {
    if !is_positive {
        bail!(
            "Invalid {} value '{}'. Must be greater than 0",
            kind.label(),
            value
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: each variant projects to the exact pre-lift noun.
    /// A drift to `"mem"`, `"cpu"`, or a title-case rephrase flips this
    /// assertion rather than silently rotating three operator-facing
    /// bail lines.
    #[test]
    fn label_matches_pre_lift_noun_for_every_variant() {
        assert_eq!(ServiceResourceKind::Memory.label(), "memory");
        assert_eq!(ServiceResourceKind::Cpu.label(), "CPU");
    }

    /// Byte-oracle (memory, non-positive branch): the returned
    /// [`anyhow::Error`]'s `Display` renders the pre-lift bail message
    /// verbatim, byte-for-byte. A drift to `"must be positive"`, a
    /// missing period, or a swap of the single-quote glyph regresses
    /// this assertion.
    #[test]
    fn bail_unless_service_resource_positive_false_emits_memory_pre_lift_bytes() {
        let err = bail_unless_service_resource_positive(false, ServiceResourceKind::Memory, "0Mi")
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid memory value '0Mi'. Must be greater than 0"
        );
    }

    /// Byte-oracle (CPU-millicores, non-positive branch): the same
    /// rendered message body but with the initialism noun for the CPU
    /// branches. Pins the pre-lift `validate_cpu_resource` millicores
    /// wording byte-for-byte.
    #[test]
    fn bail_unless_service_resource_positive_false_emits_cpu_pre_lift_bytes() {
        let err = bail_unless_service_resource_positive(false, ServiceResourceKind::Cpu, "0m")
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid CPU value '0m'. Must be greater than 0"
        );
    }

    /// Byte-oracle (CPU-decimal-cores, non-positive branch): the pre-
    /// lift wording did not distinguish millicores from decimal cores
    /// at the operator-facing surface, so both CPU branches route
    /// through the same variant and render the identical message
    /// modulo the caller-supplied value string.
    #[test]
    fn bail_unless_service_resource_positive_false_emits_cpu_pre_lift_bytes_for_decimal_shape() {
        let err = bail_unless_service_resource_positive(false, ServiceResourceKind::Cpu, "-1.5")
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid CPU value '-1.5'. Must be greater than 0"
        );
    }

    /// Byte-oracle (positive branch): the primitive returns `Ok(())`
    /// with no side effect on the happy path — every consumer composes
    /// it with `?` at the site where positivity has already been
    /// confirmed and expects a plain `Ok` back.
    #[test]
    fn bail_unless_service_resource_positive_true_returns_ok_for_every_kind() {
        assert!(
            bail_unless_service_resource_positive(true, ServiceResourceKind::Memory, "128Mi")
                .is_ok()
        );
        assert!(
            bail_unless_service_resource_positive(true, ServiceResourceKind::Cpu, "100m").is_ok()
        );
    }

    /// The caller-supplied value string lands inside the pre-lift
    /// `'<value>'` slot exactly once. A future refactor that dropped
    /// the interpolation, doubled it, or moved it outside the single
    /// quotes flips this assertion.
    #[test]
    fn bail_unless_service_resource_positive_interpolates_value_inside_single_quotes_once() {
        let err = bail_unless_service_resource_positive(
            false,
            ServiceResourceKind::Memory,
            "SENTINEL_XYZ",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert_eq!(
            msg.matches("SENTINEL_XYZ").count(),
            1,
            "value must appear exactly once in the bail message; got {msg}"
        );
        assert!(
            msg.contains("'SENTINEL_XYZ'"),
            "value must appear inside single quotes verbatim; got {msg}"
        );
    }

    /// Variant-dispatch pin: the two variants project pairwise-
    /// distinct labels. A regression that folded both arms of the
    /// `match` onto the same string would silently swap the operator-
    /// facing noun — a `"memory"` bail firing on a CPU input string,
    /// or vice versa.
    #[test]
    fn service_resource_kind_variants_project_distinct_labels() {
        assert_ne!(
            ServiceResourceKind::Memory.label(),
            ServiceResourceKind::Cpu.label(),
            "Memory and Cpu labels must not collide"
        );
    }

    /// Variant-dispatch pin (message level): swapping the [`ServiceResourceKind`]
    /// variant swaps the noun in the rendered bail message. Guards
    /// against a regression that ignored the `kind` argument and
    /// always emitted (e.g.) `"memory"`, silently mis-naming every
    /// CPU-branch failure.
    #[test]
    fn bail_unless_service_resource_positive_dispatches_kind_onto_message_noun() {
        let memory_err =
            bail_unless_service_resource_positive(false, ServiceResourceKind::Memory, "v")
                .unwrap_err();
        let cpu_err = bail_unless_service_resource_positive(false, ServiceResourceKind::Cpu, "v")
            .unwrap_err();
        assert!(memory_err.to_string().contains("memory"));
        assert!(!memory_err.to_string().contains("CPU"));
        assert!(cpu_err.to_string().contains("CPU"));
        assert!(!cpu_err.to_string().contains("memory"));
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the raw pre-lift
    /// `bail!("Invalid <kind> value '{}'. Must be greater than 0", …)`
    /// literal inline any more, for either resource-kind variant. The
    /// three pre-lift sites migrated; any future consumer that wants
    /// the same positivity gate reaches for
    /// [`bail_unless_service_resource_positive`] on first grep, not by
    /// copy-pasting the raw bail literal from an existing module.
    ///
    /// Reconstructed at test time via [`format!`] against the enum's
    /// own [`ServiceResourceKind::label`] projection so this shield's
    /// own source text does not false-match itself when the scan
    /// visits its own path (which is additionally excluded by name).
    /// Docstring `///` lines and block-comment ranges are skipped so
    /// a future module that quotes the pre-lift shape as historical
    /// prose does not trip the shield.
    #[test]
    fn no_command_module_still_spells_raw_service_resource_not_positive_bail_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");
        let this_file = scan_dir.join("service_resource_positive_bail.rs");

        // Reconstruct the forbidden literals via `format!` so this
        // shield's own docstring / prose mentions of the pre-lift
        // shape do not false-match themselves.
        let forbidden_memory = format!(
            "bail!(\"Invalid {} value '{{}}'. Must be greater than 0\"",
            ServiceResourceKind::Memory.label()
        );
        let forbidden_cpu = format!(
            "bail!(\"Invalid {} value '{{}}'. Must be greater than 0\"",
            ServiceResourceKind::Cpu.label()
        );

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
                if line.contains(&forbidden_memory) || line.contains(&forbidden_cpu) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `bail!(\"Invalid <kind> value '{{}}'. Must be greater than 0\", <s>)` \
             literal(s) survive under `commands/` — route each through \
             `crate::commands::service_resource_positive_bail::\
             bail_unless_service_resource_positive(...)` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed the three sites (`commands/service_config.rs`) MUST
    /// forward through [`bail_unless_service_resource_positive`] at
    /// least three times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_bail_unless_service_resource_positive() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("service_config.rs"), 3)];
        let needle = "bail_unless_service_resource_positive(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} service-resource-positivity site(s) through \
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
