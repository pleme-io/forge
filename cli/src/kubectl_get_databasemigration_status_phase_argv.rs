//! Fixed-arity `kubectl get databasemigration <name> -n <namespace> -o
//! jsonpath={.status.phase}` argv slice used at every Shinka
//! `DatabaseMigration` CRD phase-readout probe site.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites in `commands/migrations.rs` each spelled the
//! same 7-element argv literal verbatim on their `kubectl` builder,
//! diverging only on the spawn adapter, the `op` label / classification,
//! and the caller's Failed-phase handling policy:
//!
//! 1. `commands/migrations.rs::check_and_reset_shinka_migration` (pre-
//!    deploy Shinka migration phase probe that auto-resets a
//!    `DatabaseMigration` CRD stuck in `Failed` or `CheckingHealth`,
//!    routed through the raw
//!    `kubectl_command_async().args(&[...]).output().await` shape and
//!    ternary-classifying the `io::Result<Output>` itself — an
//!    `Err(_)` collapses to "no DatabaseMigration found (not managed by
//!    Shinka)" rather than bubbling, because a missing CRD or a
//!    permissions failure is not a deploy-blocking error at this
//!    surface).
//! 2. `commands/migrations.rs::reset_migration` (explicit reset flow
//!    that MUST bail if the `DatabaseMigration` doesn't exist, routed
//!    through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "Failed to check DatabaseMigration status"`, then
//!    inspecting `current_phase.is_empty()` to gate an
//!    `anyhow::bail!("DatabaseMigration '{}' not found in namespace
//!    '{}'", service, namespace)`).
//!
//! Two identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A Shinka
//! `DatabaseMigration` phase-probe argv drift — a rename of the `-n`
//! short form to `--namespace`, an argv-order shuffle putting `-n <ns>`
//! before the resource name, an `-o` swap from `jsonpath=` to
//! `go-template=`, a jsonpath field change from `.status.phase` to
//! `.status.conditions[?(@.type=="Ready")].status` (which silently
//! returns a Kubernetes condition string like `"True"` / `"False"` /
//! `"Unknown"` and would let site 1's `"Failed" || "CheckingHealth"`
//! match on the empty projection while breaking site 2's
//! `Current phase` display), or a rename of the singular resource
//! kind (`databasemigration` → `databasemigrations` or a fully-
//! qualified `databasemigrations.shinka.pleme.io`) — pre-lift had to
//! hit two sites in lockstep or diverge; post-lift it hits ONE typed
//! body and every consumer inherits the change from
//! `.args(kubectl_get_databasemigration_status_phase_argv::
//! kubectl_get_databasemigration_status_phase_argv(name, namespace))`
//! (or `&…(...)` for the `&[&str]`-taking
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! helper).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Site 1 routes through the raw
//!   `kubectl_command_async().args(...).output().await` shape and
//!   ternary-classifies the `io::Result<Output>` itself so a spawn
//!   error is soaked up as "CRD not present / no access" and never
//!   blocks the deploy. Site 2 routes through
//!   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
//!   whose shared [`crate::retry::classify_spawn_anyhow`] wrapping
//!   surfaces spawn-vs-op failures as a typed `anyhow::Result` and
//!   bubbles them, because the explicit reset flow the site drives
//!   must not silently no-op on a permissions failure.
//! - **Post-spawn classification.** Site 1 matches `phase == "Failed"
//!   || phase == "CheckingHealth"` to trigger an auto-reset and treats
//!   every other phase (including the empty-string "no such CRD"
//!   projection) as a no-op. Site 2 gates on
//!   `current_phase.is_empty()` to bail with a "`DatabaseMigration`
//!   not found" message, then feeds the trimmed non-empty phase into
//!   [`crate::ui::print_field`] as `Current phase`. Both classifications
//!   are load-bearing at their respective sites; a merge onto a single
//!   shape would silently change one caller's phase-handling policy.
//! - **Borrow shape.** Site 1's `migration_name` slot is an owned
//!   `String` local (`format!("{}-{}", product, service)`) that the
//!   site borrows into the array via `&migration_name`. Site 2's
//!   `service` slot is a `&str` parameter (the caller already borrowed
//!   it). The typed primitive accepts `&'a str` under a single
//!   lifetime and both call sites coerce into it (site 1 borrows the
//!   `String`; site 2 passes through).
//!
//! A `Command`-builder primitive would have to expose all three axes
//! as parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::kubectl_get_job_status_succeeded_argv::kubectl_get_job_status_succeeded_argv`],
//! [`crate::kubectl_get_job_condition_status_argv`],
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! and [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
//! — argv-slice primitives that partition their tool's duplication
//! budget without collapsing the spawn / classify / display layers
//! that legitimately diverge downstream.
//!
//! # Distinct from the `list_resource_names_by_selector_argv` family
//!
//! [`crate::list_resource_names_by_selector_argv::list_resource_names_by_selector_argv`]
//! reads `jsonpath={.items[*].metadata.name}` under a label-selector
//! (`-l <sel>`) discovery shape whose downstream classify expects a
//! whitespace-separated multi-name list. This primitive reads
//! `jsonpath={.status.phase}` under a resource-name (`<name>`)
//! addressing shape whose downstream classify expects a single trimmed
//! phase string. Merging the two families onto a single enum would
//! either force every label-selected caller to opt into an irrelevant
//! `NameAddressed` variant or force every name-addressed caller to opt
//! into an irrelevant `LabelSelected` variant; the two shapes carry
//! genuinely distinct downstream contracts and belong at distinct
//! typed primitives.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's name and namespace slots interpolate the caller-
//! supplied strings under a single `'a` lifetime bound. Every other
//! element is a `&'static str` compile-time literal that coerces into
//! `'a` without extending the lifetime of the caller inputs — the
//! returned `[&'a str; 7]` still binds strictly to the caller strings'
//! scope, matching the discipline in
//! [`crate::kubectl_get_job_status_succeeded_argv::kubectl_get_job_status_succeeded_argv`],
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
//! receives on the Shinka `DatabaseMigration` phase-readout phase.
//! The two concerns compose:
//! `kubectl_command_async().args(kubectl_get_databasemigration_status_phase_argv::
//! kubectl_get_databasemigration_status_phase_argv(name, namespace))`.

/// The pre-lift 7-element `get databasemigration <name> -n <namespace>
/// -o jsonpath={.status.phase}` argv slice used at every Shinka
/// `DatabaseMigration` CRD phase-readout probe site.
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
/// - `argv[1] = "databasemigration"` — the singular Shinka
///   `DatabaseMigration` CRD kind (kubectl accepts both singular and
///   plural short forms; every current caller spells the singular
///   form and the primitive preserves it byte-for-byte).
/// - `argv[2] = <name>` — caller-supplied `DatabaseMigration` name
///   (`{product}-{service}` at site 1, the bare `service` at site 2).
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = "-o"` — output-format flag.
/// - `argv[6] = "jsonpath={.status.phase}"` — the Shinka-controller-
///   written phase string (`"Pending"` / `"Running"` / `"Succeeded"`
///   / `"Failed"` / `"CheckingHealth"`). An unset `.status.phase`
///   field (either because the CRD does not exist or because the
///   controller has not yet populated the status subresource) renders
///   as the empty string, which each current caller classifies on its
///   own terms (site 1 treats empty as "no DatabaseMigration
///   managed"; site 2 bails with a "not found in namespace" error).
///
/// # Lifetime discipline
///
/// The returned array borrows `name` and `namespace` under a single
/// `'a` bound. Every current caller binds both strings ahead of the
/// spawn and holds them alive across the `.args(...)` call; the
/// `[&'a str; 7]` return type pins that requirement at the type level
/// (a caller cannot silently extend the array past either input's
/// scope). The literal elements are `&'static str` and coerce into
/// `'a` freely.
pub(crate) fn kubectl_get_databasemigration_status_phase_argv<'a>(
    name: &'a str,
    namespace: &'a str,
) -> [&'a str; 7] {
    [
        "get",
        "databasemigration",
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.status.phase}",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle:
    /// [`kubectl_get_databasemigration_status_phase_argv`] returns the
    /// pre-lift 7-element slice element-for-element (`"get"`,
    /// `"databasemigration"`, `<name>`, `"-n"`, `<namespace>`, `"-o"`,
    /// `"jsonpath={.status.phase}"`) in the pre-lift order, with no
    /// extra element and no rewritten value. A future refactor that
    /// (a) reordered the flag/value pairs, (b) added a
    /// `--kubeconfig <path>` or `--context <ctx>` companion, (c)
    /// swapped `-n` for `--namespace`, (d) swapped `-o` for
    /// `--output`, or (e) collapsed the trailing jsonpath into a
    /// formatted string that unfolded `-o` separately regresses this
    /// assertion.
    #[test]
    fn test_kubectl_get_databasemigration_status_phase_argv_emits_pre_lift_seven_element_slice() {
        let argv = kubectl_get_databasemigration_status_phase_argv("cart-api", "cart");
        assert_eq!(argv[0], "get");
        assert_eq!(argv[1], "databasemigration");
        assert_eq!(argv[2], "cart-api");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "cart");
        assert_eq!(argv[5], "-o");
        assert_eq!(argv[6], "jsonpath={.status.phase}");
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
    fn test_kubectl_get_databasemigration_status_phase_argv_returns_fixed_arity_seven() {
        let argv: [&str; 7] = kubectl_get_databasemigration_status_phase_argv("m", "ns");
        let [a0, a1, a2, a3, a4, a5, a6] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "databasemigration");
        assert_eq!(a2, "m");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "-o");
        assert_eq!(a6, "jsonpath={.status.phase}");
    }

    /// Interpolation-position pin: `name` lands at index 2,
    /// `namespace` lands at index 4. A future refactor that swapped
    /// them (e.g., an argv-order shuffle putting `-n <ns>` before
    /// the resource name) would silently pass the namespace as the
    /// `DatabaseMigration` name and the name as the namespace against
    /// the running cluster — a probe that would either return an
    /// empty string (if the resulting
    /// `databasemigration/<ns>` pair happens to not exist) or, worse,
    /// silently query a same-named `DatabaseMigration` in a colliding
    /// namespace. Two distinct string arguments make the swap
    /// observable at the assertion level.
    #[test]
    fn test_kubectl_get_databasemigration_status_phase_argv_places_name_at_index_2_and_namespace_at_index_4(
    ) {
        let argv = kubectl_get_databasemigration_status_phase_argv("name-alpha", "ns-beta");
        assert_eq!(
            argv[2], "name-alpha",
            "index 2 must carry the DatabaseMigration name argument",
        );
        assert_eq!(
            argv[4], "ns-beta",
            "index 4 must carry the namespace argument",
        );
        assert_ne!(argv[2], argv[4], "name and namespace must not collide");
    }

    /// Byte-oracle: the jsonpath tail is exactly
    /// `jsonpath={.status.phase}` — no whitespace, no wrapping
    /// braces beyond the two the kubectl jsonpath grammar requires,
    /// no field-name drift. Silent drifts worth catching by name:
    /// (a) `.status.phase` → `.status.state` (the field name a
    /// different CRD family uses); (b) `.status.phase` →
    /// `.status.conditions[?(@.type=="Ready")].status` (which would
    /// project the empty string on `Failed` and `CheckingHealth`
    /// phases and let site 1's `"Failed" || "CheckingHealth"` match
    /// silently never fire, disabling the auto-reset path); (c) a
    /// swap of the wrapping `jsonpath=` for a `go-template=` prefix,
    /// which follows a different grammar entirely.
    #[test]
    fn test_kubectl_get_databasemigration_status_phase_argv_jsonpath_tail_matches_pre_lift_bytes() {
        let argv = kubectl_get_databasemigration_status_phase_argv("m", "ns");
        assert_eq!(argv[6], "jsonpath={.status.phase}");
    }

    /// Byte-oracle: the resource-kind slot is exactly
    /// `"databasemigration"` — the singular short form every current
    /// caller spells. A silent rename to the plural
    /// `"databasemigrations"` still resolves to the same CRD kind on
    /// modern kubectl, but a fully-qualified drift to
    /// `"databasemigrations.shinka.pleme.io"` would fail on clusters
    /// without the Shinka CRD installed under that group (site 1
    /// already tolerates the failure; site 2 would report a
    /// misleading "not found in namespace" bail instead of the true
    /// "CRD not installed" cause).
    #[test]
    fn test_kubectl_get_databasemigration_status_phase_argv_resource_kind_matches_pre_lift_bytes() {
        let argv = kubectl_get_databasemigration_status_phase_argv("m", "ns");
        assert_eq!(argv[1], "databasemigration");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `"jsonpath={.status.phase}"` string literal inline any more.
    /// The two pre-lift sites migrated; any future consumer that
    /// wants the same Shinka `DatabaseMigration` phase-readout probe
    /// shape reaches for
    /// [`kubectl_get_databasemigration_status_phase_argv`] on first
    /// grep, not by copy-pasting the raw literal from an existing
    /// module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::kubectl_get_job_status_succeeded_argv`],
    /// [`crate::kubectl_get_job_condition_status_argv`],
    /// [`crate::first_pod_field_argv`], and
    /// [`crate::list_resource_names_by_selector_argv`]. Anchored on
    /// the exact byte shape of the jsonpath tail — a future consumer
    /// that reads a different `DatabaseMigration` status field
    /// (e.g., `.status.retryCount`, `.status.lastReconcileTime`) is
    /// deliberately outside the shield's scope, and a future consumer
    /// that wants the `.status.phase` projection must reach for the
    /// typed primitive.
    #[test]
    fn no_command_module_still_spells_raw_jsonpath_status_phase_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let needle = "\"jsonpath={.status.phase}\"";

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
            "raw `\"jsonpath={{.status.phase}}\"` literal(s) survive under \
             `commands/` — route each through \
             `crate::kubectl_get_databasemigration_status_phase_argv::\
             kubectl_get_databasemigration_status_phase_argv()` instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift module that
    /// housed the two sites MUST forward through
    /// [`kubectl_get_databasemigration_status_phase_argv`] at least
    /// twice, so a migration that dropped a call site outright leaves
    /// the negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_get_databasemigration_status_phase_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("migrations.rs"), 2)];
        let needle = "kubectl_get_databasemigration_status_phase_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} Shinka DatabaseMigration \
                 phase-readout probe site(s) through `{}`; found {}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
