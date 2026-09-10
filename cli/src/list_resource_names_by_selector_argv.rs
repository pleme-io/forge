//! Fixed-arity `kubectl get <resource> -n <namespace> -l <selector>
//! -o jsonpath={.items[*].metadata.name}` argv slice used at every
//! label-selected, every-item name-listing probe site.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites in `commands/migrations.rs` each spelled the
//! same 8-element argv literal verbatim on their
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! builder, diverging only on the resource kind and the `op` label:
//!
//! 1. `commands/migrations.rs::get_kustomize_resource_name` — the
//!    Kustomize-generated ConfigMap / Secret name-discovery probe,
//!    routed through `kubectl_output_spawn_anyhow` with the runtime-
//!    interpolated `op = format!("Failed to query {} for {}",
//!    resource_type, service)`. The `resource_type` parameter is
//!    supplied by two callers of `get_kustomize_resource_name` — one
//!    passes `"configmap"`, the other passes `"secret"` — so the
//!    resource slot is dynamic at the site level even though each
//!    downstream caller pins a specific kind.
//! 2. `commands/migrations.rs::cleanup_migration_jobs` — the
//!    pre-existing migration-job listing probe, routed through
//!    `kubectl_output_spawn_anyhow` with the compile-time
//!    `op = "Failed to list migration jobs"`. The resource slot is
//!    the compile-time literal `"jobs"` and the selector is built via
//!    [`crate::k8s_label_selector::format_app_label_selector`].
//!
//! Two identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). An every-
//! item name-listing argv drift — a rename of the `-n` short form to
//! `--namespace`, an argv-order shuffle putting `-l <sel>` before
//! `-n <ns>`, an `-o` swap from `jsonpath=` to `go-template=`, a
//! jsonpath scope change from `.items[*]` to `.items[0]` (which would
//! silently return only the first matching resource's name and let a
//! caller's downstream `.split_whitespace().filter(...)` chain gate
//! on a strictly smaller universe), or a jsonpath field swap from
//! `.metadata.name` to `.metadata.uid` (returning cluster-unique
//! GUIDs that break every downstream prefix-match against a service-
//! plus-suffix name pattern) — pre-lift had to hit two sites in
//! lockstep or diverge; post-lift it hits ONE typed body and every
//! consumer inherits the change from
//! `&list_resource_names_by_selector_argv::
//! list_resource_names_by_selector_argv(resource, namespace,
//! selector)` on the `&[&str]`-taking
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! helper.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on three axes:
//!
//! - **`op` label on the spawn-anyhow surface.** Site 1 tags the
//!   spawn failure with the runtime-interpolated
//!   `format!("Failed to query {} for {}", resource_type, service)`
//!   so an operator sees which resource-kind / service pair tripped
//!   the query; site 2 tags it as the compile-time
//!   `"Failed to list migration jobs"` because its resource kind is
//!   already pinned to migration Jobs by the surrounding cleanup
//!   flow. Both labels are load-bearing at
//!   [`crate::retry::classify_spawn_anyhow`] — a shared label would
//!   fold the two probes' failure classes together in the retry log
//!   and obscure which discovery phase the poll loop tripped over.
//! - **Post-spawn classification.** Site 1 splits the whitespace-
//!   separated names, filters to those whose prefix matches the
//!   Kustomize-generated `{resource_base_name}-{suffix}` pattern,
//!   and returns the first hit (or [`anyhow::bail`] on no match).
//!   Site 2 splits and filters to names that `.contains("migration")`,
//!   then dispatches each survivor into a
//!   [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`]-
//!   backed cleanup loop. Both classifications share the same
//!   whitespace-split shape but branch on distinct filter predicates
//!   and terminal outcomes; a merge onto a single shape would
//!   silently change one caller's downstream semantics.
//! - **Selector construction.** Site 1's selector comes from
//!   `deploy_config.kubernetes_label_selector()` — the
//!   `DeployConfig`-owned selector projection. Site 2's selector
//!   comes from
//!   [`crate::k8s_label_selector::format_app_label_selector`] on the
//!   service name — the canonical `app=<service>` builder. The typed
//!   primitive accepts `&'a str` under a single lifetime and both
//!   call sites coerce into it.
//!
//! A `Command`-builder primitive would have to expose all three axes
//! as parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! and
//! [`crate::kubectl_get_job_status_succeeded_argv::kubectl_get_job_status_succeeded_argv`]
//! — argv-slice primitives that partition their tool's duplication
//! budget without collapsing the spawn / classify / display layers
//! that legitimately diverge downstream.
//!
//! # Distinct from `first_pod_field_argv` and `first_pod_name_args`
//!
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
//! and the private
//! `crate::infrastructure::kubectl::first_pod_name_args` sibling both
//! read `jsonpath={.items[0].<field>}` — a strictly-first-item
//! projection whose downstream classify shapes assume at most one
//! meaningful match. This primitive reads
//! `jsonpath={.items[*].metadata.name}` — the every-matching-item
//! projection whose downstream classify shapes expect a whitespace-
//! separated multi-name list. Merging the two families onto a single
//! enum would either force every first-pod caller to opt into an
//! irrelevant `AllItems` variant or force every all-names caller to
//! opt into an irrelevant `FirstOnly` variant; the two shapes carry
//! genuinely distinct downstream contracts and belong at distinct
//! typed primitives.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's resource, namespace, and label-selector slots
//! interpolate the caller-supplied strings under a single `'a`
//! lifetime bound. Every other element is a `&'static str` compile-
//! time literal that coerces into `'a` without extending the
//! lifetime of the caller inputs — the returned `[&'a str; 8]` still
//! binds strictly to the caller strings' scope, matching the
//! discipline in
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! and
//! [`crate::infrastructure::registry::doca_push_argv`].
//!
//! # Distinct from the `kubectl_command_async()` sigil family
//!
//! Every consumer already resolves the `kubectl` binary via the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil,
//! which reads `KUBECTL_BIN` from the tools registry. That sigil owns
//! *which* binary spawns; this primitive owns *which arguments* it
//! receives on the label-selected every-item name-listing probe
//! phase. The two concerns compose:
//! `kubectl_output_spawn_anyhow(&list_resource_names_by_selector_argv::
//! list_resource_names_by_selector_argv(resource, ns, selector), op)`.

/// The pre-lift 8-element `get <resource> -n <namespace> -l
/// <label_selector> -o jsonpath={.items[*].metadata.name}` argv slice
/// used at every label-selected, every-item name-listing probe site.
///
/// Callers assemble the surrounding builder chain
/// ([`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
/// vs a hand-rolled `kubectl_command_async().args(...).output().await`,
/// post-spawn whitespace-split-and-filter classification, and the
/// `op` label on the spawn-anyhow surface) themselves — those axes
/// vary across the two consumers. This primitive owns ONLY the
/// 8-element argv shape.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = <resource>` — caller-supplied resource kind
///   (`"configmap"`, `"secret"`, `"jobs"`, …). kubectl accepts both
///   singular and plural forms; the primitive is agnostic to the
///   caller's choice and preserves it byte-for-byte.
/// - `argv[2] = "-n"` — namespace-scope flag.
/// - `argv[3] = <namespace>` — caller-supplied namespace.
/// - `argv[4] = "-l"` — label-selector flag.
/// - `argv[5] = <label_selector>` — caller-supplied selector (built
///   via [`crate::k8s_label_selector::format_app_label_selector`] at
///   the migration-job site and via
///   `DeployConfig::kubernetes_label_selector` at the Kustomize
///   name-discovery site).
/// - `argv[6] = "-o"` — output-format flag.
/// - `argv[7] = "jsonpath={.items[*].metadata.name}"` — the every-
///   matching-item name projection. `.items[*]` (not `.items[0]`)
///   returns every match, and `.metadata.name` extracts the resource
///   name; kubectl renders the list as a whitespace-separated string
///   which every current caller consumes via
///   [`str::split_whitespace`].
///
/// # Lifetime discipline
///
/// The returned array borrows `resource`, `namespace`, and
/// `label_selector` under a single `'a` bound. Every current caller
/// binds all three strings ahead of the spawn and holds them alive
/// across the `.args(...)` call; the `[&'a str; 8]` return type pins
/// that requirement at the type level (a caller cannot silently
/// extend the array past any input's scope). The literal elements
/// are `&'static str` and coerce into `'a` freely.
pub(crate) fn list_resource_names_by_selector_argv<'a>(
    resource: &'a str,
    namespace: &'a str,
    label_selector: &'a str,
) -> [&'a str; 8] {
    [
        "get",
        resource,
        "-n",
        namespace,
        "-l",
        label_selector,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`list_resource_names_by_selector_argv`] returns
    /// the pre-lift 8-element slice element-for-element (`"get"`,
    /// `<resource>`, `"-n"`, `<namespace>`, `"-l"`,
    /// `<label_selector>`, `"-o"`,
    /// `"jsonpath={.items[*].metadata.name}"`) in the pre-lift order,
    /// with no extra element and no rewritten value. A future refactor
    /// that (a) reordered the flag/value pairs, (b) added a
    /// `--kubeconfig <path>` or `--context <ctx>` companion, (c)
    /// swapped `-n` for `--namespace`, (d) swapped `-o` for
    /// `--output`, or (e) collapsed the trailing jsonpath into a
    /// formatted string that unfolded `-o` separately regresses this
    /// assertion.
    #[test]
    fn test_list_resource_names_by_selector_argv_emits_pre_lift_eight_element_slice() {
        let argv = list_resource_names_by_selector_argv("configmap", "cart", "app=cart-api");
        assert_eq!(argv[0], "get");
        assert_eq!(argv[1], "configmap");
        assert_eq!(argv[2], "-n");
        assert_eq!(argv[3], "cart");
        assert_eq!(argv[4], "-l");
        assert_eq!(argv[5], "app=cart-api");
        assert_eq!(argv[6], "-o");
        assert_eq!(argv[7], "jsonpath={.items[*].metadata.name}");
        assert_eq!(argv.len(), 8);
    }

    /// The return type is a fixed-arity `[&str; 8]`, NOT a
    /// `Vec<&str>` or a `&[&str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without
    /// touching this module; a change to a slice reference would
    /// allow an unsized-length pattern that a variadic future
    /// refactor might silently exploit. Pin the fixed arity at
    /// compile time via a destructured binding — if the returned
    /// type ever loses its `[_; 8]` shape, this line fails to
    /// type-check.
    #[test]
    fn test_list_resource_names_by_selector_argv_returns_fixed_arity_eight() {
        let argv: [&str; 8] = list_resource_names_by_selector_argv("jobs", "ns", "app=svc");
        let [a0, a1, a2, a3, a4, a5, a6, a7] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "jobs");
        assert_eq!(a2, "-n");
        assert_eq!(a3, "ns");
        assert_eq!(a4, "-l");
        assert_eq!(a5, "app=svc");
        assert_eq!(a6, "-o");
        assert_eq!(a7, "jsonpath={.items[*].metadata.name}");
    }

    /// Interpolation-position pin: `resource` lands at index 1,
    /// `namespace` lands at index 3, `label_selector` lands at index 5.
    /// A future refactor that reordered any pair (e.g., an argv-order
    /// shuffle putting `-l <sel>` before `-n <ns>`) would silently
    /// pass the app-label selector as the namespace-scope value
    /// against the running cluster — a probe that would either return
    /// an empty selection (if the selector-string happens to not
    /// match any namespace) or, worse, silently match a same-named
    /// namespace on a colliding deployment. Three distinct string
    /// arguments make every swap observable at the assertion level.
    #[test]
    fn test_list_resource_names_by_selector_argv_places_resource_ns_selector_at_indices_1_3_5() {
        let argv = list_resource_names_by_selector_argv("secret", "ns-alpha", "app=svc-beta");
        assert_eq!(
            argv[1], "secret",
            "index 1 must carry the resource-kind argument"
        );
        assert_eq!(
            argv[3], "ns-alpha",
            "index 3 must carry the namespace argument"
        );
        assert_eq!(
            argv[5], "app=svc-beta",
            "index 5 must carry the label-selector argument",
        );
        assert_ne!(argv[1], argv[3], "resource and namespace must not collide");
        assert_ne!(argv[3], argv[5], "namespace and selector must not collide");
        assert_ne!(argv[1], argv[5], "resource and selector must not collide");
    }

    /// Byte-oracle: the jsonpath tail is exactly
    /// `jsonpath={.items[*].metadata.name}` — the every-matching-item
    /// scope (`.items[*]`, not `.items[0]`) plus the `metadata.name`
    /// field (not `metadata.uid` and not `metadata.namespace`). A
    /// silent scope drift from `.items[*]` to `.items[0]` would
    /// return only the first match and let a downstream
    /// `.split_whitespace().filter(...)` chain gate on a strictly
    /// smaller universe; a silent field drift from `.metadata.name`
    /// to `.metadata.uid` would return cluster-unique GUIDs that
    /// break every downstream prefix-match against a service-plus-
    /// suffix name pattern.
    #[test]
    fn test_list_resource_names_by_selector_argv_jsonpath_tail_matches_pre_lift_bytes() {
        let argv = list_resource_names_by_selector_argv("configmap", "ns", "app=svc");
        assert_eq!(argv[7], "jsonpath={.items[*].metadata.name}");
    }

    /// The primitive is resource-kind agnostic: kubectl accepts both
    /// singular (`"configmap"`, `"secret"`) and plural (`"jobs"`)
    /// resource forms, and every caller passes its own preferred
    /// spelling. The primitive preserves the byte-for-byte input
    /// without normalization — a caller that spelled `"jobs"` gets
    /// `"jobs"` at index 1, a caller that spelled `"secret"` gets
    /// `"secret"`. A future normalization step (e.g., forced
    /// pluralization) would silently change the argv against the
    /// running cluster and break the pre-lift byte contract every
    /// caller relies on.
    #[test]
    fn test_list_resource_names_by_selector_argv_preserves_caller_resource_byte_shape() {
        let singular = list_resource_names_by_selector_argv("configmap", "ns", "app=svc");
        let plural = list_resource_names_by_selector_argv("jobs", "ns", "app=svc");
        assert_eq!(singular[1], "configmap");
        assert_eq!(plural[1], "jobs");
        assert_ne!(
            singular[1], plural[1],
            "distinct resource inputs must project distinct index-1 bytes",
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `"jsonpath={.items[*].metadata.name}"` string literal inline
    /// any more. The two pre-lift sites migrated; any future consumer
    /// that wants the same label-selected every-item name-listing
    /// probe shape reaches for
    /// [`list_resource_names_by_selector_argv`] on first grep, not by
    /// copy-pasting the raw literal from an existing module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::first_pod_field_argv`],
    /// [`crate::kubectl_delete_job_argv`],
    /// [`crate::kubectl_get_job_status_succeeded_argv`], and
    /// [`crate::bun_argv`]. Anchored on the exact byte shape of the
    /// jsonpath tail — a future consumer that reads a different
    /// every-item field (e.g., `.items[*].metadata.uid`,
    /// `.items[*].status.phase`) is deliberately outside the shield's
    /// scope, and a future consumer that wants the `metadata.name`
    /// projection must reach for the typed primitive.
    #[test]
    fn no_command_module_still_spells_raw_jsonpath_items_star_metadata_name_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let needle = "\"jsonpath={.items[*].metadata.name}\"";

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
            "raw `\"jsonpath={{.items[*].metadata.name}}\"` literal(s) survive \
             under `commands/` — route each through \
             `crate::list_resource_names_by_selector_argv::\
             list_resource_names_by_selector_argv()` instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the pre-lift module that
    /// housed the two sites MUST forward through
    /// [`list_resource_names_by_selector_argv`] at least twice, so a
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_list_resource_names_by_selector_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("migrations.rs"), 2)];
        let needle = "list_resource_names_by_selector_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} label-selected every-item \
                 name-listing probe site(s) through `{}`; found {}. A \
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
