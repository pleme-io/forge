//! Fixed-arity `kubectl get job <name> -n <namespace> -o
//! jsonpath={.status.succeeded}` argv slice used at every Job-success
//! count probe site.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites each spelled the same 7-element argv literal
//! verbatim on their `kubectl` builder, diverging only on the spawn
//! adapter and post-spawn classification:
//!
//! 1. `commands/federation_tests.rs::check_job_success` (post-wait
//!    federation Job success gate, routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "Failed to check job success status"`, comparing
//!    `succeeded.trim() == "1"`).
//! 2. `commands/migrations.rs::run_migration` (fallback branch after
//!    `kubectl wait --for=condition=complete` timed out or errored,
//!    handling the race where the Job finished but `kubectl wait`
//!    missed it — `kubectl_command_async().args(&[...]).output().await`
//!    shape, parsing the trimmed stdout as `i32` and classifying
//!    `n > 0`).
//!
//! Two identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A Job-
//! success-count argv drift — a rename of the `-n` short form to
//! `--namespace`, an argv-order shuffle putting `-n <ns>` before the
//! resource name, an `-o` swap from `jsonpath=` to `go-template=`, a
//! jsonpath field change from `.status.succeeded` to
//! `.status.completions` (which silently returns the *desired*
//! completion count instead of the *achieved* count and inverts the
//! success gate on partially-parallel Jobs), or a rename of the
//! `succeeded` field by a future Kubernetes API version — pre-lift
//! had to hit two sites in lockstep or diverge; post-lift it hits
//! ONE typed body and every consumer inherits the change from
//! `.args(kubectl_get_job_status_succeeded_argv::
//! kubectl_get_job_status_succeeded_argv(job_name, namespace))` (or
//! `&…(...)` for the `&[&str]`-taking
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! helper).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Site 1 routes through
//!   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
//!   whose shared [`crate::retry::classify_spawn_anyhow`] wrapping
//!   surfaces spawn-vs-op failures as a typed `anyhow::Result`.
//!   Site 2 routes through the raw
//!   `kubectl_command_async().args(...).output().await` shape and
//!   ternary-classifies the `io::Result<Output>` itself (an `.ok()`
//!   into `Option<Output>` folded through
//!   `.and_then(|o| String::from_utf8(o.stdout).ok())` — a raw kubectl
//!   error on the fallback path collapses to `false` rather than
//!   bubbling, because the wait's own timeout has already exhausted
//!   the caller's error budget).
//! - **Post-spawn classification.** Site 1 compares
//!   `succeeded.trim() == "1"` — a strict-equality on the "exactly one
//!   completion succeeded" case, tuned to the federation Job's
//!   `spec.completions = 1`. Site 2 parses as `i32` and classifies
//!   `n > 0` — a lax gate that accepts partial success on any Job
//!   shape (a `spec.completions = N` migration Job succeeds if *any*
//!   pod completed). Both classifications are load-bearing at their
//!   respective sites; a merge onto a single shape would silently
//!   change one caller's success semantics.
//! - **Borrow shape.** Site 1's inputs are `&str` parameters (the
//!   caller already borrowed them). Site 2's inputs are `String`
//!   locals (`job_name` and `namespace` bound as owned by the outer
//!   `run_migration` function) that the site borrows into the array
//!   via `&job_name` / `&namespace`. The typed primitive accepts
//!   `&'a str` under a single lifetime and both call sites coerce
//!   into it (Site 1 passes through; Site 2 borrows the `String`s).
//!
//! A `Command`-builder primitive would have to expose all three axes
//! as parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::bun_argv::bun_install_frozen_lockfile_argv`], and
//! [`crate::cargo_test_argv::cargo_integration_tests_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify / display layers that legitimately
//! diverge downstream.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's job-name and namespace slots interpolate the caller-
//! supplied strings under a single `'a` lifetime bound. Every other
//! element is a `&'static str` compile-time literal that coerces
//! into `'a` without extending the lifetime of the caller inputs —
//! the returned `[&'a str; 7]` still binds strictly to the caller
//! strings' scope, matching the discipline in
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`], and
//! [`crate::infrastructure::registry::doca_push_argv`].
//!
//! # Distinct from the `kubectl_command_async()` sigil family
//!
//! Every consumer already resolves the `kubectl` binary via the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil,
//! which reads `KUBECTL_BIN` from the tools registry. That sigil owns
//! *which* binary spawns; this primitive owns *which arguments* it
//! receives on the Job-success-count probe phase. The two concerns
//! compose:
//! `kubectl_command_async().args(kubectl_get_job_status_succeeded_argv::
//! kubectl_get_job_status_succeeded_argv(job_name, namespace))`.

/// The pre-lift 7-element `get job <name> -n <namespace> -o
/// jsonpath={.status.succeeded}` argv slice used at every Job-success
/// count probe site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` vs
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
/// post-spawn classification, and the `op` label on the spawn-anyhow
/// surface) themselves — those axes vary across the two consumers.
/// This primitive owns ONLY the 7-element argv shape.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = "job"` — resource kind.
/// - `argv[2] = <job_name>` — caller-supplied Job name.
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = "-o"` — output-format flag.
/// - `argv[6] = "jsonpath={.status.succeeded}"` — the
///   `succeeded`-completions count as a bare integer string (the
///   Kubernetes API surfaces the field as an `int32` and jsonpath
///   renders it as the decimal ASCII form; an unset field renders as
///   the empty string, which every current caller treats as "not
///   succeeded").
///
/// # Lifetime discipline
///
/// The returned array borrows `job_name` and `namespace` under a
/// single `'a` bound. Every current caller binds both strings ahead
/// of the spawn and holds them alive across the `.args(...)` call;
/// the `[&'a str; 7]` return type pins that requirement at the type
/// level (a caller cannot silently extend the array past either
/// input's scope). The literal elements are `&'static str` and coerce
/// into `'a` freely.
pub(crate) fn kubectl_get_job_status_succeeded_argv<'a>(
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
        "jsonpath={.status.succeeded}",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`kubectl_get_job_status_succeeded_argv`] returns
    /// the pre-lift 7-element slice element-for-element (`"get"`,
    /// `"job"`, `<job_name>`, `"-n"`, `<namespace>`, `"-o"`,
    /// `"jsonpath={.status.succeeded}"`) in the pre-lift order, with
    /// no extra element and no rewritten value. A future refactor
    /// that (a) reordered the flag/value pairs, (b) added a
    /// `--kubeconfig <path>` or `--context <ctx>` companion, (c)
    /// swapped `-n` for `--namespace`, (d) swapped `-o` for
    /// `--output`, or (e) collapsed the trailing jsonpath into a
    /// formatted string that unfolded `-o` separately regresses this
    /// assertion.
    #[test]
    fn test_kubectl_get_job_status_succeeded_argv_emits_pre_lift_seven_element_slice() {
        let argv = kubectl_get_job_status_succeeded_argv("cart-migrations", "cart");
        assert_eq!(argv[0], "get");
        assert_eq!(argv[1], "job");
        assert_eq!(argv[2], "cart-migrations");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "cart");
        assert_eq!(argv[5], "-o");
        assert_eq!(argv[6], "jsonpath={.status.succeeded}");
        assert_eq!(argv.len(), 7);
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
    fn test_kubectl_get_job_status_succeeded_argv_returns_fixed_arity_seven() {
        let argv: [&str; 7] = kubectl_get_job_status_succeeded_argv("j", "ns");
        let [a0, a1, a2, a3, a4, a5, a6] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "job");
        assert_eq!(a2, "j");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "-o");
        assert_eq!(a6, "jsonpath={.status.succeeded}");
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
    fn test_kubectl_get_job_status_succeeded_argv_places_job_name_at_index_2_and_namespace_at_index_4(
    ) {
        let argv = kubectl_get_job_status_succeeded_argv("job-alpha", "ns-beta");
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

    /// Byte-oracle: the jsonpath tail is exactly
    /// `jsonpath={.status.succeeded}` — no whitespace, no wrapping
    /// braces beyond the two the kubectl jsonpath grammar requires,
    /// no field-name drift (`.status.succeededCount` /
    /// `.status.completedCount` / `.status.completions` are all
    /// semantically distinct: `succeeded` is the *achieved*
    /// completion count, while `completions` is the *desired* count
    /// and `succeededCount` is not a Kubernetes API field at all).
    /// A silent rename that inverted the gate on partially-parallel
    /// Jobs regresses this assertion.
    #[test]
    fn test_kubectl_get_job_status_succeeded_argv_jsonpath_tail_matches_pre_lift_bytes() {
        let argv = kubectl_get_job_status_succeeded_argv("j", "ns");
        assert_eq!(argv[6], "jsonpath={.status.succeeded}");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `"jsonpath={.status.succeeded}"` string literal inline any
    /// more. The two pre-lift sites migrated; any future consumer
    /// that wants the same Job-success-count probe shape reaches for
    /// [`kubectl_get_job_status_succeeded_argv`] on first grep, not
    /// by copy-pasting the raw literal from an existing module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::first_pod_field_argv`],
    /// [`crate::kubectl_delete_job_argv`], and
    /// [`crate::bun_argv`]. Anchored on the exact byte shape of the
    /// jsonpath tail — a future consumer that reads a different Job
    /// status field (e.g., `.status.failed`, `.status.active`) is
    /// deliberately outside the shield's scope, and a future consumer
    /// that wants the `succeeded` count must reach for the typed
    /// primitive.
    #[test]
    fn no_command_module_still_spells_raw_jsonpath_status_succeeded_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let needle = "\"jsonpath={.status.succeeded}\"";

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
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\"jsonpath={{.status.succeeded}}\"` literal(s) survive under \
             `commands/` — route each through \
             `crate::kubectl_get_job_status_succeeded_argv::\
             kubectl_get_job_status_succeeded_argv()` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the two sites MUST each forward through
    /// [`kubectl_get_job_status_succeeded_argv`] at least once, so a
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_get_job_status_succeeded_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("federation_tests.rs"), 1),
            (crate_src.join("commands").join("migrations.rs"), 1),
        ];
        let needle = "kubectl_get_job_status_succeeded_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} Job-success-count probe site(s) \
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
