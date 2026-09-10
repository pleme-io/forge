//! Fixed-arity `kubectl get job <name> -n <namespace> -o
//! jsonpath={.status.conditions[?(@.type=="<Cond>")].status}` argv
//! slice used at every per-condition Job status probe site.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two adjacent consumer sites inside `services/migration_service.rs::
//! MigrationService::wait_for_job` each spelled the same 7-element
//! argv literal verbatim on their `kubectl` builder, diverging only
//! on the condition-type token inside the jsonpath filter:
//!
//! 1. `services/migration_service.rs::MigrationService::wait_for_job`
//!    poll-loop head — the Complete-condition probe routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "kubectl get job (Complete condition)"`, reading
//!    `jsonpath={.status.conditions[?(@.type=="Complete")].status}`
//!    and returning `Ok(())` on `"True"`.
//! 2. `services/migration_service.rs::MigrationService::wait_for_job`
//!    poll-loop failure-check — the Failed-condition probe routed
//!    through the same `kubectl_output_spawn_anyhow` helper with
//!    `op = "kubectl get job (Failed condition)"`, reading
//!    `jsonpath={.status.conditions[?(@.type=="Failed")].status}` and
//!    bailing on `"True"`.
//!
//! Two identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A per-
//! condition Job status argv drift — a rename of the `-n` short form
//! to `--namespace`, an argv-order shuffle putting `-n <ns>` before
//! the resource name, an `-o` swap from `jsonpath=` to
//! `go-template=`, a jsonpath scope change from
//! `.status.conditions[?(@.type=="<Cond>")]` to
//! `.status.conditions[*]` (which would silently concatenate every
//! condition's status and race the `"True"` gate against a stale
//! condition), or a rename of the `@.type` filter key by a future
//! Kubernetes API version — pre-lift had to hit two sites in
//! lockstep or diverge; post-lift it hits ONE typed body and the
//! enum's per-variant jsonpath literal, and every consumer inherits
//! the change from
//! `kubectl_get_job_condition_status_argv(JobCondition::Complete,
//! job_name, namespace)`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on three axes:
//!
//! - **`op` label on the spawn-anyhow surface.** Site 1 tags the
//!   spawn failure as `"kubectl get job (Complete condition)"`; site
//!   2 tags it as `"kubectl get job (Failed condition)"`. Both
//!   labels are load-bearing at [`crate::retry::classify_spawn_anyhow`]
//!   — a shared label would fold the two probes' failure classes
//!   together in the retry log and obscure which condition the poll
//!   loop tripped over.
//! - **Post-spawn classification.** Site 1 returns `Ok(())` when
//!   `status.trim() == "True"`, closing the wait successfully.
//!   Site 2 bails with `anyhow::bail!("Migration job failed")` when
//!   its trim reads `"True"`. Both classifications share the exact
//!   same trim-vs-`"True"` predicate but branch on opposite terminal
//!   outcomes; a merge onto a single shape would silently change one
//!   caller's success semantics.
//! - **Post-spawn effect on the loop.** Site 1's `"True"` returns to
//!   the caller; site 2's `"True"` bails. Neither shape is what an
//!   argv primitive can own — the argv slice owns only the shape
//!   both sites' `&[&str]`-taking helper (
//!   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`])
//!   consumes identically.
//!
//! A `Command`-builder primitive would have to expose all three axes
//! as parameters; the argv slice owns only the shape the shared
//! `&[&str]`-taking helper consumes identically. Modeled on
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
//! (the `FirstPodField::{StatusPhase,SpecContainer0Image}` enum-over-
//! boolean design) and
//! [`crate::kubectl_get_job_status_succeeded_argv::kubectl_get_job_status_succeeded_argv`]
//! (the sibling `.status.succeeded` per-Job probe primitive) — argv-
//! slice primitives that partition their tool's duplication budget
//! without collapsing the classification / op-label / effect layers
//! that legitimately diverge downstream.
//!
//! # The enum-over-boolean design
//!
//! [`JobCondition`] is a closed enum whose per-variant
//! [`JobCondition::jsonpath_literal`] projection returns the exact
//! `jsonpath={.status.conditions[?(@.type=="<Cond>")].status}` byte
//! sequence the pre-lift site spelled. A boolean `looking_for_failure`
//! parameter would have compressed the two variants into a single
//! call surface but would have (a) forced every future condition
//! extension (Suspended, FailureTarget) to grow a second boolean and
//! re-cross-multiply the axes, and (b) made the jsonpath drift
//! invisible at the call site — a site that reads
//! `kubectl_get_job_condition_status_argv(..., true, ...)` cannot be
//! greppable-checked against "which Job condition does this probe
//! filter on?" the way `JobCondition::Failed` can.
//!
//! # Deliberately disjoint from the combined-condition probe
//!
//! `commands/federation_tests.rs::wait_for_job_completion` spells a
//! third jsonpath tail —
//! `{.status.conditions[?(@.type=="Complete")].status},{.status.conditions[?(@.type=="Failed")].status}`
//! — that returns BOTH condition statuses in one probe as a comma-
//! separated pair, terminating early on `.contains("True")`. That
//! query is semantically distinct (it collapses the two-probe
//! bail-vs-return branching at site 1/2 into a single-probe
//! `contains`-classify branch by trading precision — a `True,True`
//! output would falsely accept a Failed Job), and it does not fit as
//! a `JobCondition` variant. It stays out of scope by design; a
//! future consolidation that unifies the three surfaces would take
//! on the semantic drift as a separate change, not as a byte-shape
//! lift.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's job-name and namespace slots interpolate the caller-
//! supplied strings under a single `'a` lifetime bound. Every other
//! element (including the `condition.jsonpath_literal()` tail) is a
//! `&'static str` compile-time literal that coerces into `'a`
//! without extending the lifetime of the caller inputs — the
//! returned `[&'a str; 7]` still binds strictly to the caller
//! strings' scope, matching the discipline in
//! [`crate::kubectl_get_job_status_succeeded_argv::kubectl_get_job_status_succeeded_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`], and
//! [`crate::infrastructure::registry::doca_push_argv`].

/// Closed enum naming which `.status.conditions[?(@.type=="<Cond>")]`
/// jsonpath filter a per-condition Job status probe reads. Divergent
/// per-variant [`JobCondition::jsonpath_literal`] projections encode
/// the exact byte shape of the emitted `-o jsonpath=…` argv element
/// for every current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobCondition {
    /// `jsonpath={.status.conditions[?(@.type=="Complete")].status}` —
    /// the Complete-condition status filter, read at every Job wait-
    /// loop success gate. A `"True"` reading means the Job's
    /// terminal Complete condition has been set by the k8s Job
    /// controller and the caller can return successfully.
    Complete,
    /// `jsonpath={.status.conditions[?(@.type=="Failed")].status}` —
    /// the Failed-condition status filter, read at every Job wait-
    /// loop failure gate. A `"True"` reading means the Job exhausted
    /// its `spec.backoffLimit` and the caller must bail rather than
    /// keep polling.
    Failed,
}

impl JobCondition {
    /// The exact `jsonpath={.status.conditions[?(@.type=="<Cond>")].status}`
    /// byte sequence this variant emits as the seventh argv element
    /// on a `kubectl get job … -o <jsonpath>` spawn. `&'static str`
    /// because every variant's tail is a compile-time literal;
    /// coerces into any lifetime a caller composes over the
    /// surrounding [`kubectl_get_job_condition_status_argv`] array.
    pub(crate) fn jsonpath_literal(self) -> &'static str {
        match self {
            Self::Complete => "jsonpath={.status.conditions[?(@.type==\"Complete\")].status}",
            Self::Failed => "jsonpath={.status.conditions[?(@.type==\"Failed\")].status}",
        }
    }
}

/// The pre-lift 7-element `get job <name> -n <namespace> -o
/// jsonpath={.status.conditions[?(@.type=="<Cond>")].status}` argv
/// slice used at every per-condition Job status probe site.
///
/// Callers assemble the surrounding builder chain (`op` label on the
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
/// surface, trim-vs-`"True"` classification, terminal-branch effect)
/// themselves — those axes vary across the two consumers. This
/// primitive owns ONLY the 7-element argv shape and the per-condition
/// jsonpath literal.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = "job"` — resource kind.
/// - `argv[2] = <job_name>` — caller-supplied Job name.
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = "-o"` — output-format flag.
/// - `argv[6] = <condition.jsonpath_literal()>` — the
///   `jsonpath={.status.conditions[?(@.type=="<Cond>")].status}` tail
///   dispatched off the [`JobCondition`] variant. Renders as the
///   empty string when the named condition is unset, `"True"` when
///   the k8s Job controller has set it, and `"False"` when the
///   controller has evaluated the condition but not yet terminated.
///
/// # Lifetime discipline
///
/// The returned array borrows `job_name` and `namespace` under a
/// single `'a` bound. Every current caller binds both strings ahead
/// of the spawn and holds them alive across the `.args(...)` call;
/// the `[&'a str; 7]` return type pins that requirement at the type
/// level (a caller cannot silently extend the array past either
/// input's scope). The literal elements are `&'static str` and
/// coerce into `'a` freely.
pub(crate) fn kubectl_get_job_condition_status_argv<'a>(
    condition: JobCondition,
    job_name: &'a str,
    namespace: &'a str,
) -> [&'a str; 7] {
    [
        "get",
        "job",
        job_name,
        "-n",
        namespace,
        "-o",
        condition.jsonpath_literal(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`JobCondition::Complete`] projects the exact
    /// pre-lift `jsonpath={.status.conditions[?(@.type=="Complete")].status}`
    /// byte sequence. A drift that (a) dropped the outer `jsonpath=`
    /// wrapper, (b) broadened the filter from a specific type to
    /// `[*]` (silently concatenating every condition's status and
    /// racing the `"True"` gate against a stale condition), (c)
    /// renamed the `@.type` filter key by a future Kubernetes API
    /// version, or (d) swapped the condition token from `Complete`
    /// to a similarly-named-but-distinct alternative regresses this
    /// assertion.
    #[test]
    fn test_job_condition_complete_jsonpath_literal_matches_pre_lift_bytes() {
        assert_eq!(
            JobCondition::Complete.jsonpath_literal(),
            "jsonpath={.status.conditions[?(@.type==\"Complete\")].status}",
        );
    }

    /// Byte-oracle: [`JobCondition::Failed`] projects the exact
    /// pre-lift `jsonpath={.status.conditions[?(@.type=="Failed")].status}`
    /// byte sequence. Same drift-class as the sibling
    /// [`JobCondition::Complete`] byte oracle, plus the specific
    /// per-variant risk that a copy-paste in the enum arm bodies
    /// silently routed the Failed probe onto the Complete tail and
    /// missed a Job that had exhausted its `backoffLimit`.
    #[test]
    fn test_job_condition_failed_jsonpath_literal_matches_pre_lift_bytes() {
        assert_eq!(
            JobCondition::Failed.jsonpath_literal(),
            "jsonpath={.status.conditions[?(@.type==\"Failed\")].status}",
        );
    }

    /// The two variants project distinct jsonpath tails. A future
    /// refactor that accidentally folded both arms of the `match`
    /// onto the same string (e.g., a copy-paste in the arm bodies)
    /// would silently route the Failed probe onto the Complete tail
    /// and never bail on a Job that exhausted its `backoffLimit` —
    /// the migration Job wait would hang until the outer 5-minute
    /// timeout instead of failing fast. Pin the disjointness at
    /// the assertion level so a folded-arm regression is caught by
    /// name.
    #[test]
    fn test_job_condition_variants_project_distinct_jsonpath_literals() {
        assert_ne!(
            JobCondition::Complete.jsonpath_literal(),
            JobCondition::Failed.jsonpath_literal(),
        );
    }

    /// Byte-oracle: [`kubectl_get_job_condition_status_argv`] returns
    /// the pre-lift 7-element slice element-for-element (`"get"`,
    /// `"job"`, `<job_name>`, `"-n"`, `<namespace>`, `"-o"`,
    /// `<condition.jsonpath_literal()>`) in the pre-lift order, with
    /// no extra element and no rewritten value. A future refactor
    /// that (a) reordered the flag/value pairs, (b) added a
    /// `--kubeconfig <path>` or `--context <ctx>` companion, (c)
    /// swapped `-n` for `--namespace`, (d) swapped `-o` for
    /// `--output`, or (e) collapsed the trailing jsonpath into a
    /// formatted string that unfolded `-o` separately regresses
    /// this assertion.
    #[test]
    fn test_kubectl_get_job_condition_status_argv_emits_pre_lift_seven_element_slice_complete() {
        let argv = kubectl_get_job_condition_status_argv(
            JobCondition::Complete,
            "cart-migrations",
            "cart",
        );
        assert_eq!(argv[0], "get");
        assert_eq!(argv[1], "job");
        assert_eq!(argv[2], "cart-migrations");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "cart");
        assert_eq!(argv[5], "-o");
        assert_eq!(
            argv[6],
            "jsonpath={.status.conditions[?(@.type==\"Complete\")].status}",
        );
        assert_eq!(argv.len(), 7);
    }

    /// Byte-oracle sibling for the `Failed` variant: the seventh
    /// element must carry the Failed-condition jsonpath tail
    /// verbatim. Guards against a variant-dispatch regression that
    /// (a) routed every call onto `Complete` regardless of the
    /// `condition` argument, or (b) hard-coded the pre-lift Complete
    /// tail as a constant argv slot with the `condition` parameter
    /// ignored.
    #[test]
    fn test_kubectl_get_job_condition_status_argv_dispatches_failed_variant() {
        let argv =
            kubectl_get_job_condition_status_argv(JobCondition::Failed, "cart-migrations", "cart");
        assert_eq!(
            argv[6],
            "jsonpath={.status.conditions[?(@.type==\"Failed\")].status}",
        );
    }

    /// The return type is a fixed-arity `[&str; 7]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this
    /// module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 7]` shape, this line fails to type-check.
    #[test]
    fn test_kubectl_get_job_condition_status_argv_returns_fixed_arity_seven() {
        let argv: [&str; 7] =
            kubectl_get_job_condition_status_argv(JobCondition::Complete, "j", "ns");
        let [a0, a1, a2, a3, a4, a5, a6] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "job");
        assert_eq!(a2, "j");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "-o");
        assert_eq!(
            a6,
            "jsonpath={.status.conditions[?(@.type==\"Complete\")].status}",
        );
    }

    /// Interpolation-position pin: `job_name` lands at index 2,
    /// `namespace` lands at index 4. A future refactor that swapped
    /// them (e.g., an argv-order shuffle putting `-n <ns>` before
    /// the resource name) would silently pass the namespace as the
    /// Job name and the Job name as the namespace against the
    /// running cluster — a probe that would either return an empty
    /// string (if the resulting `job/<ns>` pair happens to not
    /// exist) or, worse, silently query a same-named Job in a
    /// colliding namespace. Two distinct string arguments make the
    /// swap observable at the assertion level.
    #[test]
    fn test_kubectl_get_job_condition_status_argv_places_job_name_at_index_2_and_namespace_at_index_4(
    ) {
        let argv =
            kubectl_get_job_condition_status_argv(JobCondition::Complete, "job-alpha", "ns-beta");
        assert_eq!(
            argv[2], "job-alpha",
            "index 2 must carry the Job name argument",
        );
        assert_eq!(
            argv[4], "ns-beta",
            "index 4 must carry the namespace argument",
        );
        assert_ne!(argv[2], argv[4], "name and namespace must not collide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/services/` may spell either pre-lift jsonpath tail
    /// verbatim as a raw
    /// `"jsonpath={.status.conditions[?(@.type==\"Complete\")].status}"`
    /// or
    /// `"jsonpath={.status.conditions[?(@.type==\"Failed\")].status}"`
    /// string literal. The two pre-lift sites migrated; any future
    /// consumer that wants the same per-condition Job status probe
    /// shape reaches for [`kubectl_get_job_condition_status_argv`]
    /// on first grep, not by copy-pasting the raw literal from
    /// [`crate::services::migration_service`].
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::first_pod_field_argv`],
    /// [`crate::kubectl_get_job_status_succeeded_argv`],
    /// [`crate::kubectl_delete_job_argv`], and
    /// [`crate::bun_argv`]. Anchored on the exact byte shape of the
    /// jsonpath tail — the combined-condition probe in
    /// `commands/federation_tests.rs` (which merges both filters
    /// into one probe as a comma-separated pair) is a semantically
    /// distinct query and is deliberately outside the shield's
    /// scope.
    #[test]
    fn no_service_module_still_spells_raw_job_condition_status_jsonpath_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("services");

        let needles = [
            "\"jsonpath={.status.conditions[?(@.type==\\\"Complete\\\")].status}\"",
            "\"jsonpath={.status.conditions[?(@.type==\\\"Failed\\\")].status}\"",
        ];

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
                if needles.iter().any(|n| line.contains(n)) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw per-condition Job status jsonpath literal(s) survive under \
             `services/` — route each through \
             `crate::kubectl_get_job_condition_status_argv::\
             kubectl_get_job_condition_status_argv()` with a `JobCondition` \
             variant instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the one pre-lift module that
    /// housed both sites MUST forward through
    /// [`kubectl_get_job_condition_status_argv`] at least twice, so a
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_get_job_condition_status_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("services").join("migration_service.rs"), 2)];
        let needle = "kubectl_get_job_condition_status_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} per-condition Job status probe site(s) \
                 through `{}`; found {}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
