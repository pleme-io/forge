//! Fixed-arity `kubectl delete job <name> -n <namespace>
//! --ignore-not-found` argv slice used at every k8s-Job cleanup spawn
//! site across the crate.
//!
//! # Pre-lift census — three sibling stanzas, one argv shape
//!
//! Three consumer sites each spelled the same 6-element argv literal
//! verbatim on their `kubectl` builder:
//!
//! 1. `commands/migrations.rs::run_migration` (fire-and-forget cleanup
//!    of a failed / timed-out migration Job, `let _ =
//!    kubectl_command_async().args(&[...]).output().await` around
//!    line 686). The `.output().await` result is discarded through
//!    `let _ =` — cleanup runs on the failure path and a further
//!    kubectl error is not actionable there.
//! 2. `commands/migrations.rs::cleanup_migration_jobs` (cleanup-loop
//!    body iterating over the list of pre-existing migration jobs,
//!    routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "kubectl delete job (cleanup loop)"` around line 922).
//! 3. `services/migration_service.rs::MigrationService::delete_existing_job`
//!    (pre-create idempotent cleanup ahead of `kubectl apply -f -`,
//!    routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "kubectl delete job (pre-create cleanup)"` around
//!    line 188).
//!
//! A k8s-Job cleanup argv drift — a `--wait=false` toggle to skip the
//! default terminating-pod wait, a `--force` add on stubborn cluster
//! states, a `--grace-period=0` companion for immediate teardown, an
//! argv-order swap between `-n <namespace>` and `--ignore-not-found`,
//! or a rename of the `--ignore-not-found` flag by a future kubectl
//! release — pre-lift had to hit three sites in lockstep or diverge;
//! post-lift it hits ONE typed body and every consumer inherits the
//! change from `.args(kubectl_delete_job_argv::
//! kubectl_delete_job_ignore_not_found_argv(name, namespace))` (or
//! `&kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv(name,
//! namespace)` for `&[&str]`-taking helpers like
//! `kubectl_output_spawn_anyhow`).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The three consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Site 1 routes through the raw
//!   `kubectl_command_async().args(...).output().await` shape and
//!   discards the result via `let _ =`. Sites 2–3 route through
//!   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
//!   whose shared [`crate::retry::classify_spawn_anyhow`] wrapping
//!   surfaces spawn-vs-op failures as a typed `anyhow::Result`.
//! - **Post-spawn classification.** Site 1 discards the outcome (a
//!   cleanup on a failure path — no further action is meaningful).
//!   Site 2 checks `output.status.success()` and prints a
//!   per-job "Deleted job: {name}" success bullet on `true`. Site 3
//!   surfaces a `warn!` diagnostic if the delete's stderr indicates
//!   the job existed but delete failed for another reason.
//! - **Op label.** Sites 2–3 supply distinct `op` labels
//!   (`"kubectl delete job (cleanup loop)"` vs `"kubectl delete job
//!   (pre-create cleanup)"`) so a spawn-failure trace attributes to the
//!   originating flow.
//!
//! A `Command`-builder primitive would have to expose all three axes
//! as parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::bun_argv::bun_install_frozen_lockfile_argv`],
//! [`crate::cargo_test_argv::cargo_integration_tests_argv`], and
//! [`crate::infrastructure::registry::doca_push_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify / env layers that legitimately
//! diverge downstream.
//!
//! # Borrows from inputs, not `&'static`
//!
//! Unlike [`crate::bun_argv::bun_install_frozen_lockfile_argv`], whose
//! two elements are compile-time literals, this primitive interpolates
//! the caller-supplied `name` and `namespace` into element positions 2
//! and 4. Following [`crate::infrastructure::registry::doca_push_argv`]
//! (9-element slice interpolating four caller strings), the return
//! type is `[&'a str; 6]` with the input lifetime `'a` shared between
//! `name` and `namespace` — the returned array borrows from both
//! inputs, so the caller must hold both alive across the `.args(...)`
//! call. This matches every current call site, all three of which
//! spawn synchronously inside the same expression that binds the
//! borrows.
//!
//! # Distinct from the sibling `kubectl_command_async()` sigil family
//!
//! Every consumer already resolves the `kubectl` binary via the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil,
//! which reads the `KUBECTL_BIN` env-var forward from the tools
//! registry (see the whole-module shields on `commands/status.rs`,
//! `commands/flux.rs`, `commands/rollout.rs`,
//! `services/migration_service.rs`). That sigil owns *which* binary
//! spawns; this primitive owns *which arguments* it receives on the
//! k8s-Job cleanup phase. The two concerns compose:
//! `kubectl_command_async().args(kubectl_delete_job_argv::
//! kubectl_delete_job_ignore_not_found_argv(name, namespace))`.

/// The pre-lift 6-element `delete job <name> -n <namespace>
/// --ignore-not-found` argv slice used at every k8s-Job cleanup spawn
/// site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` vs
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
/// post-spawn classification, and the `op` label on the spawn-anyhow
/// surface) themselves — those axes vary across the three consumers.
/// This primitive owns ONLY the 6-element argv shape.
///
/// # Element layout
///
/// - `argv[0] = "delete"` — kubectl verb.
/// - `argv[1] = "job"` — resource kind.
/// - `argv[2] = <name>` — caller-supplied Job name.
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = "--ignore-not-found"` — idempotent "delete if
///   present, no-op if absent" toggle. Every pre-lift site carried it;
///   without it a repeat cleanup on an already-deleted job would exit
///   non-zero and blow up the spawn-anyhow surface's `?` bubble.
///
/// # Lifetime discipline
///
/// The returned array borrows `name` and `namespace` under a single
/// `'a` bound. Every current caller binds both strings ahead of the
/// spawn and holds them alive across the `.args(...)` call; the
/// `[&'a str; 6]` return type pins that requirement at the type level
/// (a caller cannot silently extend the array past either input's
/// scope).
pub fn kubectl_delete_job_ignore_not_found_argv<'a>(
    name: &'a str,
    namespace: &'a str,
) -> [&'a str; 6] {
    ["delete", "job", name, "-n", namespace, "--ignore-not-found"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`kubectl_delete_job_ignore_not_found_argv`] returns
    /// the pre-lift 6-element slice element-for-element (`"delete"`,
    /// `"job"`, `<name>`, `"-n"`, `<namespace>`, `"--ignore-not-found"`)
    /// in the pre-lift order, with no extra element and no rewritten
    /// value. A future refactor that (a) reordered the slice, (b) added
    /// a `--wait=false` / `--grace-period=0` companion flag, (c) renamed
    /// `--ignore-not-found`, (d) swapped `-n` for `--namespace`, or (e)
    /// collapsed any element regresses this assertion.
    #[test]
    fn test_kubectl_delete_job_ignore_not_found_argv_emits_pre_lift_six_element_slice() {
        let argv = kubectl_delete_job_ignore_not_found_argv("cart-migrations", "cart");
        assert_eq!(argv[0], "delete");
        assert_eq!(argv[1], "job");
        assert_eq!(argv[2], "cart-migrations");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "cart");
        assert_eq!(argv[5], "--ignore-not-found");
        assert_eq!(argv.len(), 6);
    }

    /// The return type is a fixed-arity `[&str; 6]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this module;
    /// a change to a slice reference would allow an unsized-length
    /// pattern that a variadic future refactor might silently exploit.
    /// Pin the fixed arity at compile time via a destructured
    /// binding — if the returned type ever loses its `[_; 6]` shape,
    /// this line fails to type-check.
    #[test]
    fn test_kubectl_delete_job_ignore_not_found_argv_returns_fixed_arity_six() {
        let argv: [&str; 6] = kubectl_delete_job_ignore_not_found_argv("j", "ns");
        let [a0, a1, a2, a3, a4, a5] = argv;
        assert_eq!(a0, "delete");
        assert_eq!(a1, "job");
        assert_eq!(a2, "j");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "--ignore-not-found");
    }

    /// Interpolation-position pin: `name` lands at index 2, `namespace`
    /// lands at index 4. A future refactor that swapped them (e.g. an
    /// argv-order shuffle putting `-n <ns>` before the resource name)
    /// would silently pass `"cart"` as the Job name and `"cart-migrations"`
    /// as the namespace against the running cluster — a
    /// destructive-in-production reordering that a mere length check
    /// would not catch. Two distinct string arguments make the swap
    /// observable at the assertion level.
    #[test]
    fn test_kubectl_delete_job_ignore_not_found_argv_places_name_at_index_2_and_namespace_at_index_4(
    ) {
        let argv = kubectl_delete_job_ignore_not_found_argv("job-x", "ns-y");
        assert_eq!(argv[2], "job-x", "index 2 must carry the Job name argument");
        assert_eq!(argv[4], "ns-y", "index 4 must carry the namespace argument");
        assert_ne!(argv[2], argv[4], "name and namespace must not collide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/services/` may spell the pre-lift
    /// raw 6-element `["delete", "job", ..., "-n", ..., "--ignore-not-found"]`
    /// argv literal inline any more. The three pre-lift sites migrated;
    /// any future consumer that wants the same k8s-Job cleanup shape
    /// reaches for [`kubectl_delete_job_ignore_not_found_argv`] on first
    /// grep, not by copy-pasting the raw literal from an existing module.
    ///
    /// Anchored on the joined pair `"delete", "job"` plus a same-line
    /// `"--ignore-not-found"` occurrence — the two-adjacency + trailing
    /// flag combination is what every pre-lift stanza carried, and no
    /// post-lift consumer will (the typed primitive owns both inside
    /// its body). Mirrors the negative half of the sibling shields on
    /// [`crate::bun_argv`] and [`crate::cargo_test_argv`].
    #[test]
    fn no_command_or_service_module_still_spells_raw_kubectl_delete_job_ignore_not_found_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("services")];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for dir in scan_dirs.iter() {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
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
                    // Anchor on the joined pair `"delete", "job"` plus a
                    // same-line `"--ignore-not-found"` occurrence. A
                    // future consumer of the same 6-element shape can
                    // still spell either token alone (a `delete job`
                    // WITHOUT `--ignore-not-found`, or an
                    // `--ignore-not-found` on a different resource kind)
                    // without tripping the shield.
                    if line.contains("\"delete\", \"job\"")
                        && line.contains("\"--ignore-not-found\"")
                    {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"delete\", \"job\", ..., \"-n\", ..., \"--ignore-not-found\"]` \
             argv literal(s) survive under `commands/` or `services/` — \
             route each through \
             `crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the three sites MUST each forward through
    /// [`kubectl_delete_job_ignore_not_found_argv`] at least the number
    /// of times matching their pre-lift site count, so a migration that
    /// dropped a call site outright leaves the negative "no raw inline
    /// shape" scan trivially satisfied by absence but the positive
    /// count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_delete_job_ignore_not_found_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("migrations.rs"), 2),
            (crate_src.join("services").join("migration_service.rs"), 1),
        ];
        let needle = "kubectl_delete_job_ignore_not_found_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} k8s-Job cleanup spawn site(s) through \
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
