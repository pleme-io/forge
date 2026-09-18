//! Canonical `<n>s` kubectl-argv duration string constructor — the
//! seconds-suffix rendering of a `u64` timeout value that every
//! `kubectl`-timeout consumer feeds into a `--timeout` argv position.
//!
//! # Pre-lift census — two sibling stanzas, one grammar
//!
//! Two consumer sites each spelled the same `format!("{}s", <u64>)`
//! stanza verbatim on their kubectl-argv timeout preamble:
//!
//! 1. `commands/migrations.rs::run_migration` (around line 597,
//!    `let timeout_str = format!("{}s", config.migration_timeout_secs());`
//!    fed into a `kubectl wait --for=condition=complete <job> -n <ns>
//!    --timeout <val>` argv slice as the space-separated flag body).
//! 2. `commands/product_release.rs::run_health_check` (around line 83,
//!    `let timeout_str = format!("{}s", timeout_secs);` fed into a
//!    `kubectl rollout status <deploy> -n <ns> --timeout=<val>` argv
//!    tail as an equals-fused `--timeout=<val>` composition at line 95).
//!
//! Pre-lift each site restated the bare
//!
//! ```ignore
//! let timeout_str = format!("{}s", <secs>);
//! ```
//!
//! grammar inline. Post-lift each site reaches for
//! [`kubectl_duration_seconds_arg`]; the `s` suffix, the interpolation
//! position, and the "seconds → kubectl duration" invariant are decided
//! once here.
//!
//! # Why the `s` suffix is load-bearing — kubectl duration grammar
//!
//! kubectl parses `--timeout` through Go's `time.ParseDuration`, which
//! accepts `<n>s`, `<n>m`, `<n>h`, `<n>ms`, `<n>us`, `<n>ns` — a bare
//! integer without a unit suffix is rejected as `unknown unit "" in
//! duration ""`. A future drift that dropped the `s` (a rename to
//! `--timeout <secs>` under the assumption that "seconds is the
//! default") would blow up at spawn time on every migration- and
//! rollout-status consumer in lockstep, and the offending literal would
//! live in three places (pre-lift) or one (post-lift). Pinning the
//! suffix at one site also lets a future move to `<n>m` or `<n>h` for
//! long-timeout consumers (a k8s Job that legitimately runs for hours,
//! for example) flow through this ONE constructor rather than by
//! grep-and-replace.
//!
//! # Why a `String` return, not a `&'static str` or `impl Display`
//!
//! The runtime `<n>` value is caller-supplied (a config-read
//! `migration_timeout_secs()` in the migrations flow, a caller-passed
//! `timeout_secs: u64` in the rollout-status flow), so the returned
//! string is necessarily heap-allocated. Callers hold the returned
//! `String` across the `.args(...)` call and take an `&<val>` borrow at
//! the argv position — the same lifetime discipline the sibling
//! `crate::workload_field::format_workload_argv_ref` helper carries for
//! `<kind>/<name>` argv splices.
//!
//! An `impl Display` return would let callers avoid the intermediate
//! allocation, but every consumer already binds a named `timeout_str`
//! before threading it through `.args(&[...])` (kubectl wait, site 1)
//! and a `format!("--timeout={}", timeout_str)` composition (rollout
//! status, site 2), so the `String` return matches the pre-lift
//! ergonomics with zero call-site rewrites.
//!
//! # Distinct from the human-display `format!("{}s", ...)` siblings
//!
//! `commands/status.rs` carries two sibling `format!("{}s", ...)`
//! stanzas at lines 1227 and 1248 that render an elapsed
//! `chrono::Duration` for stdout display, NOT for a kubectl-argv slot.
//! Those are the "human-readable elapsed seconds" grammar (paired with
//! a `{}m{}s` minutes-and-seconds sibling in the same `else` arm) —
//! they answer a different question and stay inline.
//!
//! The two lift targets under `commands/{migrations,product_release}.rs`
//! are the ones whose emitted string reaches Go's `time.ParseDuration`
//! at kubectl-spawn time. That's the invariant this primitive owns.

/// Renders a `u64` seconds value into the pre-lift `<n>s`
/// kubectl-argv duration string.
///
/// # Element grammar
///
/// - The decimal digits of `secs` (via [`u64`]'s [`std::fmt::Display`]
///   impl — no thousands separator, no leading zeros, no sign).
/// - The literal ASCII byte `s` — the seconds-unit suffix Go's
///   `time.ParseDuration` accepts on the kubectl side.
///
/// # Callers
///
/// - `commands/migrations.rs::run_migration` — space-separated
///   `--timeout <val>` argv position on `kubectl wait
///   --for=condition=complete`.
/// - `commands/product_release.rs::run_health_check` — equals-fused
///   `--timeout=<val>` argv position on `kubectl rollout status`.
///
/// # Return type
///
/// Owned [`String`] rather than `&'static str` — the `<n>` value is
/// caller-supplied at runtime. The caller binds the returned string
/// and borrows into the argv slice (or `format!`s a `--timeout=<val>`
/// composition off it, per site 2).
///
/// # `0s` is a valid rendering
///
/// A zero seconds value renders as `"0s"`, not the empty string. Both
/// pre-lift call sites already accepted a `u64` from their upstream
/// (config or caller), so a zero passes through unchanged; kubectl's
/// `time.ParseDuration` accepts `"0s"` as a valid zero-duration input
/// (it does NOT accept the bare empty string, which is the failure
/// mode a `<n>s` → `<n>` drop would introduce).
pub fn kubectl_duration_seconds_arg(secs: u64) -> String {
    format!("{}s", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`kubectl_duration_seconds_arg`] renders each of a
    /// spread of `secs` values as the pre-lift `<decimal><s>` string,
    /// byte-for-byte. A future refactor that (a) dropped the trailing
    /// `s`, (b) added a leading `+` sign, (c) padded with leading
    /// zeros, (d) inserted a thousands separator, or (e) swapped to a
    /// milliseconds `<n>ms` suffix without updating the callers
    /// regresses this assertion.
    #[test]
    fn test_kubectl_duration_seconds_arg_renders_pre_lift_seconds_suffix_grammar() {
        assert_eq!(kubectl_duration_seconds_arg(0), "0s");
        assert_eq!(kubectl_duration_seconds_arg(1), "1s");
        assert_eq!(kubectl_duration_seconds_arg(30), "30s");
        assert_eq!(kubectl_duration_seconds_arg(300), "300s");
        assert_eq!(kubectl_duration_seconds_arg(600), "600s");
        assert_eq!(kubectl_duration_seconds_arg(3600), "3600s");
    }

    /// The trailing `s` suffix is load-bearing at the kubectl-argv
    /// slot: Go's `time.ParseDuration` (kubectl's `--timeout` parser)
    /// rejects a bare integer without a unit suffix. Pin the last byte
    /// so a future rewrite to `format!("{}", secs)` (dropping the
    /// suffix under the mistaken assumption that seconds is the
    /// default) fails here, not silently at spawn time on every
    /// migration- and rollout-status consumer.
    #[test]
    fn test_kubectl_duration_seconds_arg_terminates_with_seconds_suffix() {
        for secs in [0u64, 1, 5, 42, 900, 7200, u64::MAX] {
            let rendered = kubectl_duration_seconds_arg(secs);
            assert!(
                rendered.ends_with('s'),
                "kubectl duration argv rendering must terminate with the `s` \
                 seconds suffix (Go's `time.ParseDuration` rejects a bare \
                 integer without a unit); got: {:?}",
                rendered
            );
            assert_eq!(
                &rendered[..rendered.len() - 1],
                secs.to_string(),
                "the portion preceding the `s` suffix must be the decimal \
                 rendering of the caller-supplied `secs`, byte-for-byte; \
                 got: {:?}",
                rendered
            );
        }
    }

    /// [`u64::MAX`] rendering ceiling: the primitive tolerates the full
    /// `u64` domain because Go's `time.ParseDuration` accepts up to
    /// `1<<63 - 1` nanoseconds — beyond that it saturates or errors,
    /// but the rendering side (this primitive's concern) is
    /// unconditional. A future refactor that added a `u32` narrowing
    /// (e.g. an `as u32` splice under the assumption "kubectl timeouts
    /// never exceed 32 bits") would truncate silently on a
    /// pathological caller and regress this assertion.
    #[test]
    fn test_kubectl_duration_seconds_arg_tolerates_full_u64_domain() {
        let rendered = kubectl_duration_seconds_arg(u64::MAX);
        assert_eq!(rendered, format!("{}s", u64::MAX));
        assert!(
            rendered.starts_with("18446744073709551615"),
            "u64::MAX must render as its full decimal expansion, not a \
             narrowed form; got: {:?}",
            rendered
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/{migrations,product_release}.rs` may spell
    /// the pre-lift raw `format!("{}s", <expr>)` stanza inline any
    /// more. The two pre-lift sites migrated; any future consumer
    /// that wants the same kubectl-timeout shape reaches for
    /// [`kubectl_duration_seconds_arg`] on first grep, not by
    /// copy-pasting the raw literal.
    ///
    /// Scoped to just the two pre-lift modules so a sibling
    /// `format!("{}s", ...)` for a distinct concern (a human-display
    /// duration under `commands/status.rs` at lines 1227 and 1248 —
    /// deliberately disjoint from the kubectl-argv slot) does not
    /// trip the shield. Mirrors the negative half of the sibling
    /// shields on [`crate::kubectl_delete_job_argv`],
    /// [`crate::kubectl_apply_argv`], and every other typed argv /
    /// argv-fragment primitive in the crate.
    #[test]
    fn no_prelift_module_still_spells_raw_kubectl_duration_seconds_format() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_files: &[PathBuf] = &[
            crate_src.join("commands").join("migrations.rs"),
            crate_src.join("commands").join("product_release.rs"),
        ];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for path in scan_files.iter() {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
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
                // Anchor on the exact pre-lift needle: a `format!` call
                // whose template is the two-character `{}s` grammar. A
                // sibling `format!("{}m{}s", ...)` (the minutes-and-
                // seconds human-display shape) does NOT match; a
                // sibling `format!("{}s ago", ...)` prose grammar does
                // not match either. Only the exact
                // `format!("{}s", ...)` pre-lift shape trips.
                if line.contains("format!(\"{}s\",") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"{{}}s\", <expr>)` kubectl-duration argv \
             literal(s) survive under `commands/migrations.rs` or \
             `commands/product_release.rs` — route each through \
             `crate::kubectl_duration_arg::kubectl_duration_seconds_arg()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the two sites MUST each forward through
    /// [`kubectl_duration_seconds_arg`] at least once, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv / argv-fragment
    /// primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_duration_seconds_arg() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("migrations.rs"), 1),
            (crate_src.join("commands").join("product_release.rs"), 1),
        ];
        let needle = "kubectl_duration_seconds_arg(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} kubectl-timeout spawn site(s) \
                 through `{}`; found {}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
