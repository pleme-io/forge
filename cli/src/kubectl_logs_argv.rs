//! Canonical `kubectl logs <target> -n <ns> --tail=<N>` argv slice used at
//! every kubectl-logs diagnostic spawn site.
//!
//! # Pre-lift census — three sibling stanzas, one argv shape
//!
//! Three consumer sites each spelled a five-element `kubectl logs` argv
//! literal verbatim on their `kubectl_command_async()` builder, diverging
//! only on (a) the `<target>` (a raw pod name vs. a
//! `<kind>/<name>` workload reference emitted by
//! [`crate::workload_field::format_workload_argv_ref`]) and (b) the
//! `--tail=<N>` trailing element (`100` on two sites, `50` on one):
//!
//! 1. `commands/migrations.rs::wait_for_job` (migration-Job failure
//!    diagnostic sweep, inherited-stdio surface for the human operator,
//!    spelling `.args(&["logs", pod, "-n", &namespace, "--tail=100"])`
//!    around line 671).
//! 2. `commands/migrations.rs::wait_for_job` (adjacent captured-bytes
//!    variant of the same sweep, threading `logs_tail` into the
//!    downstream event envelope, spelling
//!    `.args(&["logs", pod, "-n", &namespace, "--tail=50"])` around
//!    line 679).
//! 3. `commands/federation_tests.rs::wait_for_federation_test_job`
//!    (federation-Job failure diagnostic, `job/<name>` workload-ref
//!    target routed through
//!    [`crate::workload_field::format_workload_argv_ref`], spelling
//!    `.args(&["logs", "-n", namespace, &job_ref, "--tail=100"])` around
//!    line 378).
//!
//! Three identically-shaped bodies past THEORY §VI.1's three-is-a-law
//! threshold (PRIME DIRECTIVE: duplication budget is zero). A kubectl
//! logs argv drift — a rename of `--tail=` to `--tail `, an added
//! `--timestamps` companion, a `--previous` flag flip for restart-crash
//! diagnostics, a `--since=1m` window shift, or an argv-order shuffle
//! putting `-n <ns>` before `<target>` — pre-lift had to hit three
//! sites in lockstep or diverge; post-lift it hits ONE typed body and
//! the enum's per-variant `arg_literal()` projection, and every consumer
//! inherits the change from
//! `.args(kubectl_logs_argv::kubectl_logs_tail_argv(target, &namespace,
//! KubectlLogsTail::N100))`.
//!
//! # Argv-order canonicalization
//!
//! Two of the three pre-lift sites (both in `wait_for_job`) spelled the
//! target-first order `["logs", <target>, "-n", <ns>, "--tail=<N>"]`; the
//! third (`wait_for_federation_test_job`) spelled the namespace-first
//! order `["logs", "-n", <ns>, <target>, "--tail=<N>"]`. `kubectl logs`
//! accepts both orders — the target argument is positional but the
//! parser tolerates any position among the flag pairs. The primitive
//! collapses onto the target-first form (matching the majority and
//! matching kubectl's own `--help` synopsis) so future consumers reach
//! for one canonical shape, and the third site migrates from
//! namespace-first to target-first with the semantics preserved.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The three consumers differ AFTER the argv slice on two axes:
//!
//! - **Spawn adapter.** Sites 1 and 3 route through `.output().await`
//!   with the captured `Output` classified downstream (site 1 discards
//!   the exit envelope; site 3 branches on `status.success()`). Site 2
//!   routes through `.stdout(Stdio::inherit()).stderr(Stdio::inherit())
//!   .status().await` to stream the log body straight to the operator's
//!   terminal while awaiting the wait-status. A `Command`-builder
//!   primitive would have to expose both surfaces; the argv slice owns
//!   only the shape both `.output()` and `.status()` `Command`s'
//!   `.args()` (and any `&[&str]`-taking helper) consume identically.
//! - **Downstream classification.** Site 1 forwards the captured bytes
//!   into a `logs_tail: Option<String>` for the migration-failure event
//!   envelope. Site 3 branches on `Result<Output, ...>` and either
//!   prints the log body between `━━━` rules or bails with the captured
//!   stderr. Site 2 has no downstream classification — the streamed
//!   stdout is the observable signal.
//!
//! Modeled on the sibling
//! [`crate::kubectl_apply_argv::kubectl_apply_argv`],
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`], and
//! [`crate::cargo_test_argv::cargo_integration_tests_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify layers that legitimately diverge
//! downstream.
//!
//! # The enum-over-`u32` design for `--tail=<N>`
//!
//! [`KubectlLogsTail`] is a closed enum whose two variants
//! ([`KubectlLogsTail::N100`], [`KubectlLogsTail::N50`]) exactly match
//! the two pre-lift `--tail=<N>` line counts. A `u32` parameter would
//! have opened the primitive to arbitrary values — including negative
//! integers (which kubectl rejects), zero (which suppresses output but
//! is a plausible caller footgun), and off-by-one values that a future
//! reader could not distinguish from the intentional pre-lift set. The
//! closed enum documents the exact `--tail` line counts the fleet uses
//! at the type level; a future site that wants a different tail line
//! count adds one variant plus one match arm at
//! [`KubectlLogsTail::arg_literal`], not a fresh raw
//! `format!("--tail={}", n)` at the call site.

/// Number of trailing log lines to request via `--tail=<N>`. Closed
/// enum over the two pre-lift values; divergent per-variant
/// [`KubectlLogsTail::arg_literal`] projections encode the exact byte
/// shape of the emitted fifth argv element for every current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KubectlLogsTail {
    /// `--tail=100` — the majority pre-lift value (used by two of the
    /// three sites: the migration-Job inherited-stdio sweep and the
    /// federation-Job captured-bytes sweep).
    N100,
    /// `--tail=50` — the migration-Job event-envelope sweep that
    /// captures a shorter tail for downstream serialization into the
    /// migration-failure event.
    N50,
}

impl KubectlLogsTail {
    /// The exact fifth-element byte sequence this variant emits on a
    /// `kubectl logs <target> -n <ns> --tail=<N>` spawn. `&'static str`
    /// because both variants project a compile-time literal (the
    /// pre-lift stanzas embed the line count directly into the argv
    /// string, not through a runtime `format!`).
    pub(crate) fn arg_literal(self) -> &'static str {
        match self {
            Self::N100 => "--tail=100",
            Self::N50 => "--tail=50",
        }
    }
}

/// The canonical 5-element `logs <target> -n <ns> --tail=<N>` argv slice
/// used at every kubectl-logs diagnostic spawn site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` vs
/// `.stdout(Stdio::inherit()).stderr(Stdio::inherit()).status().await`,
/// post-spawn classification, and any wrapping retry / bail policy)
/// themselves — those axes vary across the three consumers. This
/// primitive owns ONLY the 5-element argv shape and the per-variant
/// fifth-element projection.
///
/// # Element layout
///
/// - `argv[0] = "logs"` — kubectl verb.
/// - `argv[1] = <target>` — either a raw pod name or a `<kind>/<name>`
///   workload reference emitted by
///   [`crate::workload_field::format_workload_argv_ref`]. `kubectl logs`
///   accepts both forms.
/// - `argv[2] = "-n"` — namespace-scope flag. The short form is what
///   every pre-lift site spelled; a future migration to `--namespace`
///   lands here.
/// - `argv[3] = <namespace>` — the caller-supplied namespace.
/// - `argv[4] = <tail.arg_literal()>` — the `--tail=<N>` byte sequence
///   emitted by the [`KubectlLogsTail`] variant.
///
/// # Lifetime discipline
///
/// The returned array borrows the caller's `target` and `namespace`
/// strings under the shared `'a` bound. The `--tail=<N>` element is a
/// `&'static str` and coerces into `'a` freely. This matches the
/// discipline in [`crate::kubectl_apply_argv::kubectl_apply_argv`] and
/// [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`].
pub(crate) fn kubectl_logs_tail_argv<'a>(
    target: &'a str,
    namespace: &'a str,
    tail: KubectlLogsTail,
) -> [&'a str; 5] {
    ["logs", target, "-n", namespace, tail.arg_literal()]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`KubectlLogsTail::N100`] projects the exact
    /// pre-lift `"--tail=100"` byte sequence. A drift that (a)
    /// separated the flag and value with a space (`"--tail 100"`), (b)
    /// dropped the `=` (kubectl would then treat `100` as the next
    /// argument and fail with "unknown flag" once the argv slice
    /// grows), or (c) renamed the flag to `-c 100` regresses this
    /// assertion.
    #[test]
    fn test_kubectl_logs_tail_n100_projects_pre_lift_dash_dash_tail_100() {
        assert_eq!(KubectlLogsTail::N100.arg_literal(), "--tail=100");
    }

    /// Byte-oracle sibling for the [`KubectlLogsTail::N50`] variant:
    /// the fifth element must carry the `"--tail=50"` byte sequence
    /// verbatim. Guards against a variant-dispatch regression that
    /// (a) collapsed both arms onto the `N100` literal (silently
    /// widening the event-envelope tail from 50 to 100 lines and
    /// bloating downstream serialization), or (b) hard-coded the
    /// pre-lift flag with the `tail` parameter ignored.
    #[test]
    fn test_kubectl_logs_tail_n50_projects_pre_lift_dash_dash_tail_50() {
        assert_eq!(KubectlLogsTail::N50.arg_literal(), "--tail=50");
    }

    /// The two variants project distinct fifth-element bytes. A future
    /// refactor that accidentally folded both arms of the `match` onto
    /// the same string (e.g., a copy-paste in the arm bodies) would
    /// silently route the N50 event-envelope sweep onto the N100
    /// inherited-stdio value and vice versa. Pin the disjointness at
    /// the assertion level so a folded-arm regression is caught by
    /// name.
    #[test]
    fn test_kubectl_logs_tail_variants_project_distinct_arg_literals() {
        assert_ne!(
            KubectlLogsTail::N100.arg_literal(),
            KubectlLogsTail::N50.arg_literal(),
        );
    }

    /// Byte-oracle: [`kubectl_logs_tail_argv`] returns the pre-lift
    /// 5-element slice element-for-element (`"logs"`, `<target>`,
    /// `"-n"`, `<namespace>`, `<tail.arg_literal()>`) in the canonical
    /// target-first order, with no extra element and no rewritten
    /// value, on the [`KubectlLogsTail::N100`] arm. A future refactor
    /// that (a) reordered the flag/value pair, (b) added a
    /// `--timestamps` or `--previous` companion, (c) swapped `-n` for
    /// `--namespace`, or (d) inserted a `--container=<name>` slot in
    /// the middle regresses this assertion.
    #[test]
    fn test_kubectl_logs_tail_argv_emits_pre_lift_five_element_slice_n100() {
        let argv = kubectl_logs_tail_argv("pod-abc", "ns-xyz", KubectlLogsTail::N100);
        assert_eq!(argv[0], "logs");
        assert_eq!(argv[1], "pod-abc");
        assert_eq!(argv[2], "-n");
        assert_eq!(argv[3], "ns-xyz");
        assert_eq!(argv[4], "--tail=100");
        assert_eq!(argv.len(), 5);
    }

    /// Byte-oracle sibling for the [`KubectlLogsTail::N50`] variant on
    /// the argv slice: the fifth element must carry the `"--tail=50"`
    /// sentinel verbatim while the other four elements are unchanged
    /// from the N100 arm. Guards against a variant-dispatch regression
    /// on the argv builder itself (as distinct from the enum's
    /// `arg_literal` projection).
    #[test]
    fn test_kubectl_logs_tail_argv_dispatches_n50_variant() {
        let argv = kubectl_logs_tail_argv("pod-abc", "ns-xyz", KubectlLogsTail::N50);
        assert_eq!(argv[0], "logs");
        assert_eq!(argv[1], "pod-abc");
        assert_eq!(argv[2], "-n");
        assert_eq!(argv[3], "ns-xyz");
        assert_eq!(argv[4], "--tail=50");
    }

    /// Workload-ref target: a `<kind>/<name>` string emitted by
    /// [`crate::workload_field::format_workload_argv_ref`] lands at
    /// argv index 1 verbatim. Pins that the primitive accepts the
    /// same target syntax `kubectl logs` accepts (both raw pod names
    /// and `<kind>/<name>` refs), and that no target-normalization
    /// hook has been silently introduced.
    #[test]
    fn test_kubectl_logs_tail_argv_accepts_workload_ref_target_verbatim() {
        let argv =
            kubectl_logs_tail_argv("job/migrations-1699999999", "prod", KubectlLogsTail::N100);
        assert_eq!(argv[1], "job/migrations-1699999999");
        assert_eq!(argv[3], "prod");
    }

    /// The return type is a fixed-arity `[&str; 5]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this
    /// module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 5]` shape, this line fails to type-check.
    #[test]
    fn test_kubectl_logs_tail_argv_returns_fixed_arity_five() {
        let argv: [&str; 5] = kubectl_logs_tail_argv("t", "n", KubectlLogsTail::N100);
        let [a0, a1, a2, a3, a4] = argv;
        assert_eq!(a0, "logs");
        assert_eq!(a1, "t");
        assert_eq!(a2, "-n");
        assert_eq!(a3, "n");
        assert_eq!(a4, "--tail=100");
    }

    /// Interpolation-position pin: the caller-supplied `target` lands
    /// at index 1, `namespace` at index 3 (AFTER the `-n` flag), not
    /// swapped or shuffled. A future refactor that swapped `target`
    /// and `namespace` would silently pass the namespace as the log
    /// target and vice versa — kubectl would then either bail with
    /// "pod not found" (the target-position case) or fail more
    /// mysteriously against a differently-named namespace. Pin the
    /// positions at the assertion level so a swap is caught by name.
    #[test]
    fn test_kubectl_logs_tail_argv_places_target_at_1_and_namespace_at_3() {
        let argv = kubectl_logs_tail_argv("TARGET-SENTINEL", "NS-SENTINEL", KubectlLogsTail::N100);
        assert_eq!(argv[1], "TARGET-SENTINEL", "index 1 must carry the target");
        assert_eq!(argv[3], "NS-SENTINEL", "index 3 must carry the namespace");
        assert_ne!(
            argv[3], "TARGET-SENTINEL",
            "namespace slot must not hold the target"
        );
        assert_ne!(
            argv[1], "NS-SENTINEL",
            "target slot must not hold the namespace"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw kubectl-logs
    /// argv literal any more. The three pre-lift sites migrated; any
    /// future consumer that wants the same shape reaches for
    /// [`kubectl_logs_tail_argv`] on first grep, not by copy-pasting
    /// the raw literal from an existing module.
    ///
    /// Anchored on the joined adjacency `"logs",` followed on the
    /// same line by `"--tail=` — that pairing is what every pre-lift
    /// stanza carried (the argv opens with `"logs",` and closes with
    /// a `"--tail=<N>"` element), and no post-lift consumer will (the
    /// typed primitive owns both inside its body). Docker-compose
    /// argv literals (like the one under
    /// `commands/comprehensive_release.rs::print_e2e_diagnostics` at
    /// `&["-f", compose_path, "logs", "--tail=100"]`) spell the same
    /// two tokens but on a `docker_bin()` builder rather than a
    /// `kubectl_command_async()` builder — the shield anchors on the
    /// `"logs",` argv opener plus the `"--tail=` companion appearing
    /// on the same line, but explicitly excludes lines that also
    /// carry `"-f", compose_path` (the docker-compose signature) so
    /// the tail-line-count sweep on `docker compose` remains a
    /// separate primitive family.
    #[test]
    fn no_command_module_still_spells_raw_kubectl_logs_tail_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
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
                // Docker-compose `logs --tail=<N>` argv sits on a
                // different tool builder; exclude it explicitly.
                if line.contains("compose_path") {
                    continue;
                }
                // Anchor on the two-token adjacency the pre-lift
                // stanzas all carried on the same line: `"logs",`
                // opener plus a `"--tail=` companion. A future
                // consumer of a different kubectl verb (e.g., `get`,
                // `describe`, `exec`) can still emit either token
                // alone without tripping the shield.
                if line.contains("\"logs\",") && line.contains("\"--tail=") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"logs\", ..., \"--tail=<N>\"]` kubectl-logs argv literal(s) survive under \
             `commands/` — route each through \
             `crate::kubectl_logs_argv::kubectl_logs_tail_argv()` with a \
             `KubectlLogsTail` variant instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the three sites MUST each forward through
    /// [`kubectl_logs_tail_argv`] at least the number of times matching
    /// their pre-lift site count, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_logs_tail_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("migrations.rs"), 2),
            (crate_src.join("commands").join("federation_tests.rs"), 1),
        ];
        let needle = "kubectl_logs_tail_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} kubectl-logs spawn site(s) through \
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
