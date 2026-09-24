//! Fused spawn+parse+classify primitive for the per-condition Job
//! status probe: routes the canonical
//! [`crate::kubectl_get_job_condition_status_argv::kubectl_get_job_condition_status_argv`]
//! argv slice through
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`] with
//! the variant's op label from
//! [`crate::kubectl_get_job_condition_status_argv::JobCondition::spawn_op_label`],
//! reads the stdout via [`crate::repo::utf8_lossy_borrow`], and returns
//! `Ok(true)` iff the trimmed reading equals the exact byte sequence
//! `"True"`.
//!
//! # Pre-lift census — two sibling 5-line stanzas share one boolean body
//!
//! Two adjacent consumer sites inside
//! `services/migration_service.rs::MigrationService::wait_for_job`
//! poll loop each spelled the same 5-line stanza verbatim, diverging
//! only on the [`crate::kubectl_get_job_condition_status_argv::JobCondition`]
//! variant and the local binding name:
//!
//! 1. `services/migration_service.rs::MigrationService::wait_for_job`
//!    poll-loop head (pre-lift ~L288-302) — the Complete-condition
//!    probe:
//!    ```ignore
//!    let output = crate::infrastructure::kubectl::kubectl_output_spawn_anyhow(
//!        &crate::kubectl_get_job_condition_status_argv::kubectl_get_job_condition_status_argv(
//!            crate::kubectl_get_job_condition_status_argv::JobCondition::Complete,
//!            name,
//!            namespace,
//!        ),
//!        "kubectl get job (Complete condition)",
//!    )
//!    .await?;
//!
//!    let status = crate::repo::utf8_lossy_borrow(&output.stdout);
//!
//!    if status.trim() == "True" {
//!        return Ok(());
//!    }
//!    ```
//! 2. `services/migration_service.rs::MigrationService::wait_for_job`
//!    poll-loop failure-check (pre-lift ~L305-318) — byte-identical
//!    5-line spawn+parse+classify body except the variant is
//!    [`crate::kubectl_get_job_condition_status_argv::JobCondition::Failed`],
//!    the op label is `"kubectl get job (Failed condition)"`, the
//!    local binding is `failed` (not `status`), and the terminal
//!    branch is `anyhow::bail!("Migration job failed")` (not
//!    `return Ok(())`).
//!
//! Two identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A shared
//! drift — a rename of the `utf8_lossy_borrow` projection to
//! `utf8_lossy_owned` (allocating twice per poll tick), a tightening
//! of the `trim() == "True"` predicate to strict-equality on the raw
//! bytes (silently regressing on a `"True\n"` reading past a future
//! `-o jsonpath=` writer that carries a trailing newline), a swap of
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! for the raw `kubectl_command_async().output().await` shape
//! (bypassing the `KUBECTL_BIN` env override the tools-registry
//! idiom resolves), or a rewrite of the op-label prefix — pre-lift
//! had to hit two sites in lockstep or diverge; post-lift it hits
//! ONE typed body and both consumers inherit the change from
//! `probe_job_condition_status(JobCondition::<X>, name, namespace)`.
//!
//! # What the primitive owns, and what stays at the caller
//!
//! The pre-lift call sites carried three axes:
//!
//! 1. **Argv shape.** Both sites spelled
//!    `kubectl_get_job_condition_status_argv(JobCondition::<X>, name,
//!    namespace)` — the canonical 7-element `get job <name> -n
//!    <namespace> -o jsonpath={...}` slice from the sibling
//!    [`crate::kubectl_get_job_condition_status_argv`] module.
//! 2. **Spawn+parse+classify body.** Both sites routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
//!    read via [`crate::repo::utf8_lossy_borrow`], and classified via
//!    `.trim() == "True"`.
//! 3. **Terminal branch effect.** Site 1's `true` returns
//!    `Ok(())` to the caller; site 2's `true` bails with
//!    `anyhow::bail!("Migration job failed")`. Neither shape is
//!    what the fused probe primitive can own — the primitive returns
//!    a `bool` and the caller dispatches on it.
//!
//! Axes 1 and 2 live at ONE typed body here. Axis 3 stays at the
//! call site (an `if` branch on the returned `bool`). Mirrors the
//! sibling `crate::kubectl_get_job_condition_status_argv` module's
//! "argv slice owns the shape, callers keep the divergent tail"
//! discipline, extended one level up: the fused probe owns the
//! spawn+parse+classify shape, callers keep the divergent terminal
//! branch.
//!
//! # Why `bool`, not a two-variant enum
//!
//! The predicate the primitive answers is "does the condition's
//! status field read `\"True\"`?" — a strict boolean question with
//! no third state at the caller. The k8s Job condition status field
//! itself has three readings — `"True"`, `"False"`, and the empty
//! string (when the condition is unset) — but every caller in the
//! migration-Job-wait pipeline collapses `"False"` and `""` onto
//! the same "keep polling" branch. A two-variant enum
//! (`Reached` / `NotReached`) would force each caller to write a
//! two-arm `match` that maps to the same fall-through branch on
//! `NotReached`; a `bool` matches the `if …await? { … }` shape
//! both sites want without a per-caller unwrap.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the fused spawn+parse+classify
//! body lives at ONE construction surface so a future rewrite (an
//! `utf8_lossy_borrow` → `utf8_lossy_owned` migration, a
//! `.trim() == "True"` → `.eq_ignore_ascii_case("true")` broadening,
//! a `kubectl_output_spawn_anyhow` swap for a differently-classified
//! spawn helper) reaches both migration-Job-wait sites by
//! construction rather than through a per-caller edit.
//!
//! §VI.1 three-is-a-law: two sibling stanzas past the duplication
//! trigger, one primitive.

use anyhow::Result;

use crate::kubectl_get_job_condition_status_argv::{
    kubectl_get_job_condition_status_argv, JobCondition,
};

/// Probe the k8s API for a Job's per-condition status field and
/// return `Ok(true)` iff the trimmed stdout reads verbatim `"True"`.
///
/// Composes the canonical
/// [`kubectl_get_job_condition_status_argv`] argv slice under the
/// caller-supplied `JobCondition` variant, spawns via
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
/// with the variant's [`JobCondition::spawn_op_label`], reads stdout
/// via [`crate::repo::utf8_lossy_borrow`] (single-alloc borrow), and
/// classifies the trimmed reading against the `"True"` literal.
///
/// # Return semantics
///
/// - `Ok(true)` — the k8s Job controller has set this condition on
///   the named Job to `"True"`. The caller decides the terminal
///   branch (return the wait loop successfully on `Complete`, bail
///   with a "migration job failed" envelope on `Failed`).
/// - `Ok(false)` — the condition is either unset (empty stdout) or
///   evaluated to a non-`"True"` reading (`"False"` under the k8s
///   Job controller's ternary condition semantics). The caller
///   keeps polling.
/// - `Err(_)` — spawn failed (a `KUBECTL_BIN`-resolved binary is
///   absent on a Nix-hermetic runner) or the spawn helper's
///   [`crate::retry::classify_spawn_anyhow`] surfaced a typed
///   error. The caller propagates via `?` past the poll loop's
///   timeout gate.
///
/// # Terminal-branch shape at consumers
///
/// The two pre-lift sites read as:
///
/// ```ignore
/// if probe_job_condition_status(JobCondition::Complete, name, namespace).await? {
///     return Ok(());
/// }
///
/// if probe_job_condition_status(JobCondition::Failed, name, namespace).await? {
///     anyhow::bail!("Migration job failed");
/// }
/// ```
///
/// Each caller keeps the terminal branch effect its wait-loop
/// semantics require — this primitive answers the boolean question
/// and stops there.
pub(crate) async fn probe_job_condition_status(
    condition: JobCondition,
    job_name: &str,
    namespace: &str,
) -> Result<bool> {
    let output = crate::infrastructure::kubectl::kubectl_output_spawn_anyhow(
        &kubectl_get_job_condition_status_argv(condition, job_name, namespace),
        condition.spawn_op_label(),
    )
    .await?;
    let status = crate::repo::utf8_lossy_borrow(&output.stdout);
    Ok(status.trim() == "True")
}

#[cfg(test)]
mod tests {
    /// Byte-oracle: the primitive spells the canonical spawn call
    /// through
    /// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
    /// exactly once — the sole spawn surface pre-lift both sites
    /// reached for. A regression that (a) fanned the spawn onto a
    /// raw `kubectl_command_async().output().await` shape (bypassing
    /// the `KUBECTL_BIN` env override), (b) added a second spawn
    /// call to cross-check the reading, or (c) collapsed the spawn
    /// onto a `.status()` variant that discards stdout regresses
    /// this assertion.
    ///
    /// Uses [`crate::test_support::code_line_hits`] rather than a
    /// raw `.matches()` so this module's own docstring mentions of
    /// `kubectl_output_spawn_anyhow(` (in the pre-lift-shape example
    /// blocks) stay out of scope.
    #[test]
    fn probe_forwards_through_kubectl_output_spawn_anyhow_exactly_once() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("kubectl_probe_job_condition_status.rs"),
            "kubectl_probe_job_condition_status.rs",
        );
        let hits = crate::test_support::code_line_hits(
            module_body,
            "crate::infrastructure::kubectl::kubectl_output_spawn_anyhow(",
        );
        assert_eq!(
            hits.len(),
            1,
            "probe_job_condition_status must spawn exactly once via \
             the canonical `kubectl_output_spawn_anyhow` surface — a \
             second spawn or a raw `Command::new(\"kubectl\")` fan-out \
             bypasses the shared classify-spawn-anyhow wrapper. Found \
             hits:\n{}",
            hits.join("\n"),
        );
    }

    /// Byte-oracle: the primitive reads stdout via the canonical
    /// [`crate::repo::utf8_lossy_borrow`] single-alloc borrow. A
    /// migration to `utf8_lossy_owned` would allocate a `String`
    /// per poll tick against the same `output.stdout` bytes; this
    /// scan catches the regression.
    #[test]
    fn probe_reads_stdout_via_utf8_lossy_borrow_not_owned() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("kubectl_probe_job_condition_status.rs"),
            "kubectl_probe_job_condition_status.rs",
        );
        assert!(
            !crate::test_support::code_line_hits(
                module_body,
                "crate::repo::utf8_lossy_borrow(&output.stdout)",
            )
            .is_empty(),
            "probe_job_condition_status must project stdout via the \
             single-alloc `utf8_lossy_borrow`, not the two-alloc \
             `utf8_lossy_owned`.",
        );
        let owned_hits = crate::test_support::code_line_hits(module_body, "utf8_lossy_owned(");
        assert!(
            owned_hits.is_empty(),
            "probe_job_condition_status must NOT allocate a fresh `String` \
             per poll tick via `utf8_lossy_owned` — the canonical shape \
             is a single-alloc borrow. Found:\n{}",
            owned_hits.join("\n"),
        );
    }

    /// Byte-oracle: the primitive classifies via the strict
    /// `.trim() == "True"` predicate both pre-lift sites spelled
    /// verbatim. Neither a broadened `.eq_ignore_ascii_case("true")`
    /// (accepts `"true"` / `"TRUE"` / …, which the k8s Job condition
    /// status field never emits but a proxying layer might rewrite)
    /// nor a raw-bytes strict equality without trim (rejects a
    /// trailing newline a future `-o jsonpath=` writer might carry)
    /// is the pre-lift shape.
    #[test]
    fn probe_classifies_via_trim_equals_true_verbatim() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("kubectl_probe_job_condition_status.rs"),
            "kubectl_probe_job_condition_status.rs",
        );
        assert!(
            !crate::test_support::code_line_hits(module_body, "status.trim() == \"True\"")
                .is_empty(),
            "probe_job_condition_status must classify via the strict \
             `status.trim() == \"True\"` predicate — the exact byte \
             shape both pre-lift sites spelled.",
        );
    }

    /// Byte-oracle: the primitive forwards the variant's op label
    /// through [`JobCondition::spawn_op_label`] rather than
    /// re-spelling the two per-variant labels inline. Pins the
    /// enum-dispatched label as the ONE source of truth for both
    /// variants — a regression that hard-coded either label at the
    /// spawn call breaks a future variant extension.
    #[test]
    fn probe_dispatches_op_label_through_condition_spawn_op_label() {
        let module_body = crate::test_support::module_body_before_tests(
            include_str!("kubectl_probe_job_condition_status.rs"),
            "kubectl_probe_job_condition_status.rs",
        );
        assert!(
            !crate::test_support::code_line_hits(module_body, "condition.spawn_op_label()")
                .is_empty(),
            "probe_job_condition_status must dispatch the op label \
             through `condition.spawn_op_label()` so both variants \
             inherit the label from the enum, not from an inline \
             per-branch literal.",
        );
        let complete_hits = crate::test_support::code_line_hits(
            module_body,
            "\"kubectl get job (Complete condition)\"",
        );
        assert!(
            complete_hits.is_empty(),
            "probe_job_condition_status body must NOT spell the raw \
             Complete op label verbatim — dispatch through \
             `JobCondition::spawn_op_label` instead. Found:\n{}",
            complete_hits.join("\n"),
        );
        let failed_hits = crate::test_support::code_line_hits(
            module_body,
            "\"kubectl get job (Failed condition)\"",
        );
        assert!(
            failed_hits.is_empty(),
            "probe_job_condition_status body must NOT spell the raw \
             Failed op label verbatim — dispatch through \
             `JobCondition::spawn_op_label` instead. Found:\n{}",
            failed_hits.join("\n"),
        );
    }

    /// Caller shield (negative half): no source line inside the
    /// pre-lift consumer file
    /// `cli/src/services/migration_service.rs`'s `wait_for_job`
    /// impl may re-spell either pre-lift 5-line spawn+parse+classify
    /// stanza. Post-lift both sites route through
    /// [`probe_job_condition_status`] and the raw
    /// `kubectl_get_job_condition_status_argv(` call, the
    /// `utf8_lossy_borrow(&output.stdout)` projection, and the
    /// `.trim() == "True"` classify all disappear from
    /// `wait_for_job`.
    ///
    /// Anchored on `wait_for_job`'s method boundary — the outer
    /// module's docstring, the `kubectl_get_job_condition_status_argv`
    /// module cite, or any future kubectl-Job-status helper landing
    /// in a different method inside this file stays out of scope.
    #[test]
    fn wait_for_job_no_longer_spells_pre_lift_spawn_parse_classify_stanza() {
        let source = include_str!("services/migration_service.rs");
        let fn_marker = "async fn wait_for_job(";
        let fn_start = source
            .find(fn_marker)
            .expect("`async fn wait_for_job(` must be present in migration_service.rs");
        // Bound the scan to just this method's body: the next
        // `\n    async fn` line marks the start of `get_job_logs`,
        // the sibling private method that follows `wait_for_job` in
        // the impl block.
        let end_marker = "\n    async fn get_job_logs(";
        let fn_end = source[fn_start..]
            .find(end_marker)
            .map(|i| fn_start + i)
            .expect(
                "the `\\n    async fn get_job_logs(` marker must follow \
                 `wait_for_job` — the shield's slice boundary relies \
                 on this method ordering",
            );
        let body = &source[fn_start..fn_end];

        assert!(
            !body.contains("kubectl_get_job_condition_status_argv("),
            "wait_for_job must NOT call the argv builder directly — \
             route through \
             `crate::kubectl_probe_job_condition_status::\
             probe_job_condition_status` instead.",
        );
        assert!(
            !body.contains("utf8_lossy_borrow(&output.stdout)"),
            "wait_for_job must NOT re-fuse the stdout-parse body — \
             the fused probe primitive owns it.",
        );
        assert!(
            !body.contains(".trim() == \"True\""),
            "wait_for_job must NOT re-spell the `.trim() == \"True\"` \
             classify predicate — the fused probe primitive owns it.",
        );
    }

    /// Caller shield (positive half): the pre-lift consumer module
    /// MUST forward through [`probe_job_condition_status`] at least
    /// twice (the two variants) so a migration that dropped a call
    /// site outright leaves the negative shield satisfied by absence
    /// but the positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn wait_for_job_forwards_through_probe_job_condition_status_twice() {
        let source = include_str!("services/migration_service.rs");
        let fn_marker = "async fn wait_for_job(";
        let fn_start = source
            .find(fn_marker)
            .expect("`async fn wait_for_job(` must be present in migration_service.rs");
        let end_marker = "\n    async fn get_job_logs(";
        let fn_end = source[fn_start..]
            .find(end_marker)
            .map(|i| fn_start + i)
            .expect(
                "the `\\n    async fn get_job_logs(` marker must follow \
                 `wait_for_job`",
            );
        let body = &source[fn_start..fn_end];

        let hits = body.matches("probe_job_condition_status(").count();
        assert!(
            hits >= 2,
            "wait_for_job must call `probe_job_condition_status(` at \
             least twice (Complete + Failed variants); found {} hit(s). \
             A dropped call leaves the negative raw-shape shield \
             satisfied by absence.",
            hits,
        );
    }
}
