//! Canonical `kubectl get pods -n <ns> -l <selector> -o
//! jsonpath={.items[0].<field>}` argv slice used at every first-pod
//! per-field probe site.
//!
//! # Pre-lift census — three sibling stanzas, one argv shape
//!
//! Three consumer sites each spelled the same 8-element argv literal
//! verbatim on their `kubectl` builder, diverging only on the jsonpath
//! field tail:
//!
//! 1. `commands/product_release.rs::run_health_check` (post-rollout
//!    "at least one pod is Running" probe, routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "Failed to get pod status"`, reading
//!    `jsonpath={.items[0].status.phase}`).
//! 2. `commands/rust_service.rs` PENDING-ROLLOUTS pod-status probe
//!    (`kubectl_command_async().args(&[...]).output().await` shape,
//!    result `is_ok()`-classified, reading
//!    `jsonpath={.items[0].status.phase}`).
//! 3. `commands/rust_service.rs` PENDING-ROLLOUTS pod-image probe
//!    (the same `kubectl_command_async()` frontier used at site 2,
//!    reading `jsonpath={.items[0].spec.containers[0].image}`).
//!
//! Three identically-shaped bodies past THEORY §VI.1's three-is-a-law
//! threshold (PRIME DIRECTIVE: duplication budget is zero). A first-pod
//! probe argv drift — a rename of the `-n` short form to `--namespace`,
//! an argv-order shuffle putting `-l <selector>` before `-n <ns>`, an
//! `-o` swap from `jsonpath=` to `go-template=`, a jsonpath scope
//! change from `.items[0]` to `.items[*]` (which would silently return
//! the concatenation of every matching pod's field instead of the
//! first pod's) — pre-lift had to hit three sites in lockstep or
//! diverge; post-lift it hits ONE typed body and the enum's per-variant
//! jsonpath literal, and every consumer inherits the change from
//! `.args(first_pod_field_argv::first_pod_field_get_pods_argv(ns,
//! selector, FirstPodField::StatusPhase))` (or `&…(...)` for the
//! `&[&str]`-taking [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//! helper).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The three consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Site 1 routes through
//!   [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
//!   whose shared [`crate::retry::classify_spawn_anyhow`] wrapping
//!   surfaces spawn-vs-op failures as a typed `anyhow::Result`.
//!   Sites 2–3 route through the raw
//!   `kubectl_command_async().args(...).output().await` shape and
//!   ternary-classify the `io::Result<Output>` themselves.
//! - **Post-spawn classification.** Site 1 bails on non-Running phase
//!   with a formatted `bail!("Health check failed: … expected 'Running'")`
//!   message. Sites 2–3 print advisory bullets and never bail — a
//!   probe failure on the PENDING-ROLLOUTS surface downgrades to a
//!   "Flux will deploy the new pod" fallback line rather than a hard
//!   error.
//! - **Op label / trim shape.** Site 1 uses
//!   [`crate::repo::utf8_lossy_trim_owned`] to compare exactly against
//!   `"Running"`. Sites 2–3 use [`crate::repo::utf8_lossy_borrow`] and
//!   feed the borrow into a `.contains(tag_suffix)` and a
//!   [`colored::Colorize::dimmed`]-formatted display line.
//!
//! A `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::bun_argv::bun_install_frozen_lockfile_argv`], and
//! [`crate::cargo_test_argv::cargo_integration_tests_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify / display layers that legitimately
//! diverge downstream.
//!
//! # The enum-over-boolean design
//!
//! [`FirstPodField`] is a closed enum whose per-variant
//! [`FirstPodField::jsonpath_literal`] projection returns the exact
//! `jsonpath={.items[0].<field>}` byte sequence the pre-lift site
//! spelled. A boolean `wants_image` parameter would have compressed the
//! two variants into a single call surface but would have (a) forced
//! every future field extension (readiness, restart-count, node name)
//! to grow a second boolean and re-cross-multiply the axes, and (b)
//! made the jsonpath drift invisible at the call site — a site that
//! reads `first_pod_field_argv(..., true)` cannot be greppable-checked
//! against "which pod field does this probe want?" the way
//! `FirstPodField::SpecContainer0Image` can.
//!
//! # Deliberately disjoint from `first_pod_name_args`
//!
//! [`crate::infrastructure::kubectl`] already houses a private
//! `first_pod_name_args` argv builder bound to a
//! [`crate::infrastructure::kubectl::find_first_pod_name_async`]
//! execution primitive that consolidates three
//! `jsonpath={.items[0].metadata.name}` consumers under one
//! `Option<String>`-returning discovery surface. That primitive owns
//! both the argv shape AND the fallible-classify-into-Option shape
//! for the metadata-name family; folding its jsonpath tail into
//! [`FirstPodField`] would either force the execution primitive to
//! grow an enum parameter that only ever takes one variant at each
//! call, or split the primitive apart and reunite it at every
//! call site (a strictly worse arrangement). The
//! `MetadataName` field is therefore deliberately absent from
//! [`FirstPodField`]; a future consolidation that unifies both
//! surfaces would rewrite the metadata-name execution primitive on
//! this enum in one motion, not through a second half-lift.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's namespace and label-selector slots interpolate the
//! caller-supplied strings under a single `'a` lifetime bound. The
//! jsonpath literal is a `&'static str` produced by
//! [`FirstPodField::jsonpath_literal`] which coerces into `'a` without
//! extending the lifetime of the caller inputs — the returned
//! `[&'a str; 8]` still binds strictly to the caller strings' scope,
//! matching the discipline in
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`]
//! and [`crate::infrastructure::registry::doca_push_argv`].
//!
//! # Distinct from the `kubectl_command_async()` sigil family
//!
//! Every consumer already resolves the `kubectl` binary via the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil,
//! which reads `KUBECTL_BIN` from the tools registry. That sigil owns
//! *which* binary spawns; this primitive owns *which arguments* it
//! receives on the first-pod per-field probe phase. The two concerns
//! compose:
//! `kubectl_command_async().args(first_pod_field_argv::
//! first_pod_field_get_pods_argv(ns, selector, FirstPodField::StatusPhase))`.

/// Closed enum naming which `.items[0].<field>` jsonpath tail a first-pod
/// probe reads. Divergent per-variant [`FirstPodField::jsonpath_literal`]
/// projections encode the exact byte shape of the emitted `-o jsonpath=…`
/// argv element for every current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstPodField {
    /// `jsonpath={.items[0].status.phase}` — the pod-phase string
    /// (`"Running"` / `"Pending"` / `"Succeeded"` / `"Failed"` /
    /// `"Unknown"`), read at every post-rollout liveness gate and every
    /// PENDING-ROLLOUTS status readout.
    StatusPhase,
    /// `jsonpath={.items[0].spec.containers[0].image}` — the container-0
    /// image reference (`<registry>/<repo>:<tag>` or `<registry>/<repo>@<digest>`),
    /// read at the PENDING-ROLLOUTS "current image" readout to compare
    /// against the just-pushed tag suffix.
    SpecContainer0Image,
}

impl FirstPodField {
    /// The exact `jsonpath={.items[0].<field>}` byte sequence this
    /// variant emits as the eighth argv element on a `kubectl get pods
    /// … -o <jsonpath>` spawn. `&'static str` because every variant's
    /// tail is a compile-time literal; coerces into any lifetime a
    /// caller composes over the surrounding
    /// [`first_pod_field_get_pods_argv`] array.
    pub(crate) fn jsonpath_literal(self) -> &'static str {
        match self {
            Self::StatusPhase => "jsonpath={.items[0].status.phase}",
            Self::SpecContainer0Image => "jsonpath={.items[0].spec.containers[0].image}",
        }
    }
}

/// The pre-lift 8-element `get pods -n <namespace> -l <label_selector>
/// -o jsonpath={.items[0].<field>}` argv slice used at every first-pod
/// per-field probe site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` vs
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
/// post-spawn classification, trim / borrow choice, and the `op` label
/// on the spawn-anyhow surface) themselves — those axes vary across the
/// three consumers. This primitive owns ONLY the 8-element argv shape
/// and the per-field jsonpath literal.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = "pods"` — resource kind.
/// - `argv[2] = "-n"` — namespace-scope flag.
/// - `argv[3] = <namespace>` — caller-supplied namespace.
/// - `argv[4] = "-l"` — label-selector flag.
/// - `argv[5] = <label_selector>` — caller-supplied selector (built via
///   [`crate::k8s_label_selector::format_app_label_selector`] at every
///   current site).
/// - `argv[6] = "-o"` — output-format flag.
/// - `argv[7] = <field.jsonpath_literal()>` — the
///   `jsonpath={.items[0].<field>}` tail dispatched off the
///   [`FirstPodField`] variant.
///
/// # Lifetime discipline
///
/// The returned array borrows `namespace` and `label_selector` under a
/// single `'a` bound. Every current caller binds both strings ahead of
/// the spawn and holds them alive across the `.args(...)` call; the
/// `[&'a str; 8]` return type pins that requirement at the type level
/// (a caller cannot silently extend the array past either input's
/// scope). The `field.jsonpath_literal()` element is a `&'static str`
/// and coerces into `'a` freely.
pub(crate) fn first_pod_field_get_pods_argv<'a>(
    namespace: &'a str,
    label_selector: &'a str,
    field: FirstPodField,
) -> [&'a str; 8] {
    [
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        label_selector,
        "-o",
        field.jsonpath_literal(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`FirstPodField::StatusPhase`] projects the exact
    /// pre-lift `jsonpath={.items[0].status.phase}` byte sequence. A
    /// drift that (a) renamed the field (`.status.phase` →
    /// `.status.containerStatuses[0].state`), (b) broadened the scope
    /// (`.items[0]` → `.items[*]`, silently returning every matching
    /// pod's phase concatenated), or (c) swapped the wrapping
    /// `jsonpath=` for a `go-template=` regresses this assertion.
    #[test]
    fn test_first_pod_field_status_phase_jsonpath_literal_matches_pre_lift_bytes() {
        assert_eq!(
            FirstPodField::StatusPhase.jsonpath_literal(),
            "jsonpath={.items[0].status.phase}",
        );
    }

    /// Byte-oracle: [`FirstPodField::SpecContainer0Image`] projects the
    /// exact pre-lift `jsonpath={.items[0].spec.containers[0].image}`
    /// byte sequence. A drift that (a) shifted the container index
    /// (`containers[0]` → `containers[*]`, returning every container
    /// image concatenated), (b) followed a different key
    /// (`.image` → `.imageID`, returning the resolved digest instead
    /// of the tag-carrying reference the PENDING-ROLLOUTS
    /// `image.contains(tag_suffix)` check depends on), or (c)
    /// broadened the pod scope (`.items[0]` → `.items[*]`) regresses
    /// this assertion.
    #[test]
    fn test_first_pod_field_spec_container0_image_jsonpath_literal_matches_pre_lift_bytes() {
        assert_eq!(
            FirstPodField::SpecContainer0Image.jsonpath_literal(),
            "jsonpath={.items[0].spec.containers[0].image}",
        );
    }

    /// The two variants project distinct jsonpath tails. A future
    /// refactor that accidentally folded both arms of the `match`
    /// onto the same string (e.g., a copy-paste in the arm bodies)
    /// would silently route the `Image` probe onto the `Phase` tail
    /// and read `"Running"` where every PENDING-ROLLOUTS site expected
    /// a container-image reference. Pin the disjointness at the
    /// assertion level so a folded-arm regression is caught by name.
    #[test]
    fn test_first_pod_field_variants_project_distinct_jsonpath_literals() {
        assert_ne!(
            FirstPodField::StatusPhase.jsonpath_literal(),
            FirstPodField::SpecContainer0Image.jsonpath_literal(),
        );
    }

    /// Byte-oracle: [`first_pod_field_get_pods_argv`] returns the
    /// pre-lift 8-element slice element-for-element (`"get"`,
    /// `"pods"`, `"-n"`, `<namespace>`, `"-l"`, `<label_selector>`,
    /// `"-o"`, `<field.jsonpath_literal()>`) in the pre-lift order,
    /// with no extra element and no rewritten value. A future
    /// refactor that (a) reordered the flag/value pairs, (b) added a
    /// `--kubeconfig <path>` or `--context <ctx>` companion, (c)
    /// swapped `-n` for `--namespace`, or (d) collapsed the trailing
    /// jsonpath into a formatted string that unfolded `-o`
    /// separately regresses this assertion.
    #[test]
    fn test_first_pod_field_get_pods_argv_emits_pre_lift_eight_element_slice_status_phase() {
        let argv =
            first_pod_field_get_pods_argv("cart", "app=cart-api", FirstPodField::StatusPhase);
        assert_eq!(argv[0], "get");
        assert_eq!(argv[1], "pods");
        assert_eq!(argv[2], "-n");
        assert_eq!(argv[3], "cart");
        assert_eq!(argv[4], "-l");
        assert_eq!(argv[5], "app=cart-api");
        assert_eq!(argv[6], "-o");
        assert_eq!(argv[7], "jsonpath={.items[0].status.phase}");
        assert_eq!(argv.len(), 8);
    }

    /// Byte-oracle sibling for the `SpecContainer0Image` variant: the
    /// eighth element must carry the container-image jsonpath tail
    /// verbatim. Guards against a variant-dispatch regression that
    /// (a) routed every call onto `StatusPhase` regardless of the
    /// `field` argument, or (b) hard-coded the pre-lift phase tail
    /// as a constant argv slot with the `field` parameter ignored.
    #[test]
    fn test_first_pod_field_get_pods_argv_dispatches_spec_container0_image_variant() {
        let argv = first_pod_field_get_pods_argv(
            "cart",
            "app=cart-api",
            FirstPodField::SpecContainer0Image,
        );
        assert_eq!(argv[7], "jsonpath={.items[0].spec.containers[0].image}");
    }

    /// The return type is a fixed-arity `[&str; 8]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this
    /// module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 8]` shape, this line fails to type-check.
    #[test]
    fn test_first_pod_field_get_pods_argv_returns_fixed_arity_eight() {
        let argv: [&str; 8] =
            first_pod_field_get_pods_argv("ns", "app=svc", FirstPodField::StatusPhase);
        let [a0, a1, a2, a3, a4, a5, a6, a7] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "pods");
        assert_eq!(a2, "-n");
        assert_eq!(a3, "ns");
        assert_eq!(a4, "-l");
        assert_eq!(a5, "app=svc");
        assert_eq!(a6, "-o");
        assert_eq!(a7, "jsonpath={.items[0].status.phase}");
    }

    /// Interpolation-position pin: `namespace` lands at index 3,
    /// `label_selector` lands at index 5. A future refactor that
    /// swapped them (e.g., an argv-order shuffle putting `-l <sel>`
    /// before `-n <ns>`) would silently pass the app-label selector
    /// as the namespace-scope value against the running cluster — a
    /// probe that would either return an empty selection (if the
    /// selector-string happens to not match any namespace) or, worse,
    /// silently match a same-named namespace on a colliding
    /// deployment. Two distinct string arguments make the swap
    /// observable at the assertion level.
    #[test]
    fn test_first_pod_field_get_pods_argv_places_namespace_at_index_3_and_selector_at_index_5() {
        let argv =
            first_pod_field_get_pods_argv("ns-alpha", "app=svc-beta", FirstPodField::StatusPhase);
        assert_eq!(
            argv[3], "ns-alpha",
            "index 3 must carry the namespace argument",
        );
        assert_eq!(
            argv[5], "app=svc-beta",
            "index 5 must carry the label-selector argument",
        );
        assert_ne!(argv[3], argv[5], "namespace and selector must not collide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell either pre-lift jsonpath tail
    /// verbatim as a raw `"jsonpath={.items[0].status.phase}"` or
    /// `"jsonpath={.items[0].spec.containers[0].image}"` string
    /// literal. The three pre-lift sites migrated; any future consumer
    /// that wants the same first-pod field-probe shape reaches for
    /// [`first_pod_field_get_pods_argv`] on first grep, not by
    /// copy-pasting the raw literal from an existing module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::kubectl_delete_job_argv`] and
    /// [`crate::bun_argv`]. Anchored on the exact byte shape of the
    /// jsonpath tail — a future consumer that spells the same argv
    /// with a different jsonpath (e.g., a `.status.podIP` probe) is
    /// deliberately outside the shield's scope, and a future consumer
    /// that wants the pre-lift tail must reach for the enum variant.
    #[test]
    fn no_command_module_still_spells_raw_first_pod_field_jsonpath_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let needles = [
            "\"jsonpath={.items[0].status.phase}\"",
            "\"jsonpath={.items[0].spec.containers[0].image}\"",
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
            "raw first-pod-field jsonpath literal(s) survive under `commands/` — \
             route each through \
             `crate::first_pod_field_argv::first_pod_field_get_pods_argv()` \
             with a `FirstPodField` variant instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the three sites MUST each forward through
    /// [`first_pod_field_get_pods_argv`] at least the number of times
    /// matching their pre-lift site count, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_first_pod_field_get_pods_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("product_release.rs"), 1),
            (crate_src.join("commands").join("rust_service.rs"), 2),
        ];
        let needle = "first_pod_field_get_pods_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} first-pod-field probe site(s) through \
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
