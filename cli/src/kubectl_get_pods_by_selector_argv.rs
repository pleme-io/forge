//! Fixed-arity `kubectl get pods -n <namespace> -l <label_selector> -o
//! <format>` argv slice used at every whole-object app-label-scoped
//! pod-listing site whose consumer wants the standard `-o json` /
//! `-o wide` renderers rather than the fine-grained
//! `jsonpath={.items[0].<field>}` first-pod projection that
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
//! already owns.
//!
//! # Pre-lift census — four sibling stanzas, two distinct output formats
//!
//! Four consumer sites across three command modules each spelled the
//! same 8-element argv literal verbatim on their `kubectl` builder,
//! diverging only on the trailing `-o <format>` renderer and on the
//! surrounding spawn / classify wiring:
//!
//! 1. `commands/flux.rs::probe_deployment_status` (post-rollout pod
//!    JSON readout, `-o json`, routed through
//!    [`crate::infrastructure::kubectl::kubectl_capture_anyhow`] with
//!    `op = "kubectl get pods"`, piping stdout into
//!    `serde_json::from_str::<serde_json::Value>` and reading the
//!    first pod's phase / image / container-waiting reason).
//! 2. `commands/flux.rs::gather_deployment_diagnostics` (deployment
//!    diagnostic dump, `-o wide`, routed through
//!    [`crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp`]
//!    with `label = "All Pods"`, piping the kubectl-rendered wide
//!    table into an indented "All Pods" section of the diagnostic
//!    string).
//! 3. `commands/status.rs::fetch_pods` (deployment status readout,
//!    `-o json`, routed through the private
//!    [`crate::commands::status::kubectl_list_items`] helper whose
//!    body pipes the stdout bytes into a `.items[*]` walker returning
//!    `Vec<serde_json::Value>`).
//! 4. `commands/github_runner_ci.rs` rollout poll-loop (pod-status
//!    readout, `-o json`, routed through the raw
//!    `kubectl_command_async().args(&[...]).output().await` shape and
//!    piping stdout into `serde_json::from_str::<serde_json::Value>`
//!    with an advisory warn on any spawn / non-success / parse
//!    failure).
//!
//! Four identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A pod
//! label-selected fetch-argv drift — a rename of the `-n` short form
//! to `--namespace`, an argv-order shuffle putting `-l <selector>`
//! before `-n <ns>`, an `-o` swap for `--output`, a rename of the
//! plural resource kind (`pods` → `pod` or a fully-qualified
//! `pods.v1.` API-group prefix), or a drift in the recommended-label
//! selector key that
//! [`crate::k8s_label_selector::format_app_label_selector`] already
//! owns — pre-lift had to hit four sites in lockstep or diverge;
//! post-lift it hits ONE typed body and every consumer inherits the
//! change from
//! `.args(kubectl_get_pods_by_selector_argv(namespace, &selector,
//! PodListingOutput::<variant>))`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The four consumers differ AFTER the argv slice on the spawn adapter
//! ([`crate::infrastructure::kubectl::kubectl_capture_anyhow`] /
//! [`crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp`]
//! / the private `kubectl_list_items(&[&str])` helper / raw
//! `kubectl_command_async().args(...).output().await`), the post-spawn
//! classification (`Result<Output>` propagation, in-place string
//! push, `serde_json` walker, ternary success / warn / retry), and
//! the `op` label on the spawn-anyhow surface. A `Command`-builder
//! primitive would have to expose all four axes as parameters; the
//! argv slice owns only the shape that every `Command`-family
//! adapter's `.args()` (and any `&[&str]`-taking helper) consumes
//! identically. Modeled on
//! [`crate::kubectl_get_databasemigration_output_argv::kubectl_get_databasemigration_output_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::list_resource_names_by_selector_argv`], and
//! [`crate::kubectl_get_job_condition_status_argv`] — enum-driven
//! argv-slice primitives that partition their tool's duplication
//! budget without collapsing the spawn / classify / display layers
//! that legitimately diverge downstream.
//!
//! # Distinct from the sibling first-pod-per-field primitive
//!
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
//! reads a single scalar field of the first pod under a
//! `jsonpath={.items[0].<field>}` projection whose downstream classify
//! expects a trimmed scalar string. This primitive reads the
//! whole-object pod listing under one of kubectl's standard
//! `-o <format>` names (`json` / `wide`) whose downstream classify
//! walks a `.items[*]` array (JSON) or pipes a human-readable table
//! straight to a diagnostic section (Wide). The two families carry
//! genuinely distinct downstream contracts and belong at distinct
//! typed primitives; the first-pod primitive stays bound to the
//! `.items[0]` scope because its consumers need exactly one pod's
//! field, and this primitive adds the `format` axis precisely because
//! its consumers need the multi-pod listing under two of the
//! standard renderers.
//!
//! # Deliberately outside scope — one-off diagnostic jsonpath tails
//!
//! `commands/flux.rs::gather_deployment_diagnostics` also carries two
//! adjacent argv stanzas whose head matches this primitive
//! (`get pods -n <ns> -l <sel> -o <tail>`) but whose `<tail>` is a
//! bespoke multi-line jsonpath template for a diagnostic-only readout
//! (Container States, Waiting/Terminated Reasons). Neither jsonpath
//! is reused elsewhere in the crate, and folding them into the closed
//! [`PodListingOutput`] enum would enshrine one-off byte sequences
//! that carry no compounding leverage — the diagnostic template
//! belongs at the call site alongside the diagnostic section-label
//! literal that names it. The negative caller shield below is scoped
//! to the two standard-renderer variants (`"json"` / `"wide"`) so the
//! two diagnostic jsonpath sites escape the shield by construction.
//!
//! # Compounding
//!
//! Every future kubectl pod-listing added to a command module reaches
//! for this primitive on first grep rather than fabricating a fresh
//! `["get", "pods", "-n", ns, "-l", &format_app_label_selector(name),
//! "-o", "json"]` copy. A future migration to an API-group-prefixed
//! resource kind, a swap from `-n`/`-o` short flags to `--namespace`
//! /`--output`, or a rename of the `-l` short form flows to all four
//! call sites from one edit; the alternative is a grep-and-edit sweep
//! across three command modules on every drift.
//!
//! Grounded in THEORY.md §V.1 (construction guarantees — the knowable
//! platform): the argv shape that binds a kubectl pod-listing to its
//! kubectl surface is a construction detail of the fleet's Kubernetes
//! surface, and its rendering belongs in one typed primitive rather
//! than in four inline `&["get", "pods", …]` stanzas whose drift is a
//! grep away.

/// Closed enum naming which `-o <format>` renderer the whole-object
/// `kubectl get pods` argv emits at every app-label-selected pod
/// listing site. Divergent per-variant [`PodListingOutput::format_literal`]
/// projections encode the exact byte shape of the emitted `-o` value
/// for every current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PodListingOutput {
    /// `-o json` — the full-object JSON renderer. Read at three of the
    /// four current consumer sites: `flux::probe_deployment_status`
    /// (piping into `serde_json::from_str::<serde_json::Value>` for
    /// per-pod phase / image / waiting-reason extraction),
    /// `status::fetch_pods` (piping into the private
    /// `kubectl_list_items` walker returning
    /// `Vec<serde_json::Value>`), and the
    /// `commands::github_runner_ci` rollout poll-loop (piping into
    /// `serde_json::from_str::<serde_json::Value>` with an advisory
    /// warn on any spawn / non-success / parse failure).
    Json,
    /// `-o wide` — the human-readable table renderer with extra
    /// columns beyond the default `get`. Read at
    /// `flux::gather_deployment_diagnostics`'s "All Pods" section,
    /// whose caller pipes the kubectl-rendered table straight into an
    /// indented diagnostic string via
    /// [`crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp`].
    Wide,
}

impl PodListingOutput {
    /// The exact `-o` value this variant emits as the eighth argv
    /// element on a `kubectl get pods … -o <format>` spawn.
    /// `&'static str` because every variant's literal is a
    /// compile-time constant; coerces into any lifetime a caller
    /// composes over the surrounding
    /// [`kubectl_get_pods_by_selector_argv`] array.
    pub(crate) fn format_literal(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Wide => "wide",
        }
    }
}

/// The pre-lift 8-element `get pods -n <namespace> -l <label_selector>
/// -o <format>` argv slice used at every whole-object
/// app-label-selected pod listing site.
///
/// Callers assemble the surrounding builder chain
/// ([`crate::infrastructure::kubectl::kubectl_capture_anyhow`] /
/// [`crate::infrastructure::kubectl::kubectl_probe_push_nonempty_section_4sp`]
/// / the private `kubectl_list_items(&[&str])` helper / raw
/// `kubectl_command_async().args(...).output().await`, post-spawn
/// classification, and the `op` label on the spawn-anyhow surface)
/// themselves — those axes vary across the four consumers. This
/// primitive owns ONLY the 8-element argv shape and the per-format
/// `-o` literal.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = "pods"` — the plural resource kind, preserved
///   byte-for-byte to match the sibling
///   [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
///   primitive.
/// - `argv[2] = "-n"` — namespace-scope flag.
/// - `argv[3] = <namespace>` — caller-supplied namespace.
/// - `argv[4] = "-l"` — label-selector flag.
/// - `argv[5] = <label_selector>` — caller-supplied selector (built
///   via [`crate::k8s_label_selector::format_app_label_selector`] at
///   every current site).
/// - `argv[6] = "-o"` — output-format flag.
/// - `argv[7] = <output.format_literal()>` — one of `"json"` /
///   `"wide"` dispatched off the [`PodListingOutput`] variant.
///
/// # Lifetime discipline
///
/// The returned array borrows `namespace` and `label_selector` under
/// a single `'a` bound. The `output.format_literal()` element is a
/// `&'static str` and coerces into `'a` freely, matching the
/// discipline in
/// [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
/// and
/// [`crate::kubectl_get_databasemigration_output_argv::kubectl_get_databasemigration_output_argv`].
pub(crate) fn kubectl_get_pods_by_selector_argv<'a>(
    namespace: &'a str,
    label_selector: &'a str,
    output: PodListingOutput,
) -> [&'a str; 8] {
    [
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        label_selector,
        "-o",
        output.format_literal(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`PodListingOutput::Json`] projects exactly
    /// `"json"`. A drift to `"yaml"` would silently break
    /// `flux::probe_deployment_status`,
    /// `status::fetch_pods`, and the `commands::github_runner_ci`
    /// rollout poll-loop's `serde_json::from_str::<serde_json::Value>`
    /// parse (a YAML document is not a JSON document), collapsing every
    /// call onto their respective advisory / bail fall-through paths.
    #[test]
    fn test_output_format_json_literal_matches_pre_lift_bytes() {
        assert_eq!(PodListingOutput::Json.format_literal(), "json");
    }

    /// Byte-oracle: [`PodListingOutput::Wide`] projects exactly
    /// `"wide"`. A drift to a synonym kubectl also accepts (e.g., a
    /// hypothetical `"wide-table"` alias) or to a bare `""` would
    /// silently change the rendered stdout the operator sees at
    /// `flux::gather_deployment_diagnostics`'s "All Pods" section.
    #[test]
    fn test_output_format_wide_literal_matches_pre_lift_bytes() {
        assert_eq!(PodListingOutput::Wide.format_literal(), "wide");
    }

    /// The two variants project pairwise-distinct `-o` literals. A
    /// future refactor that accidentally folded both arms of the
    /// `match` onto the same string would silently route one caller's
    /// spawn onto another's renderer — e.g., routing `Json` onto
    /// `"wide"` and starving `status::fetch_pods`'s JSON walker of
    /// its input, or routing `Wide` onto `"json"` and dumping a raw
    /// JSON blob into the operator-facing "All Pods" diagnostic
    /// section.
    #[test]
    fn test_output_format_variants_project_distinct_literals() {
        assert_ne!(
            PodListingOutput::Json.format_literal(),
            PodListingOutput::Wide.format_literal()
        );
    }

    /// Byte-oracle: [`kubectl_get_pods_by_selector_argv`] returns the
    /// pre-lift 8-element slice element-for-element for every variant,
    /// in the pre-lift order, with no extra element and no rewritten
    /// value. A future refactor that (a) reordered the flag/value
    /// pairs, (b) added a `--kubeconfig <path>` or `--context <ctx>`
    /// companion, (c) swapped `-n` for `--namespace`, or (d) swapped
    /// `-o` for `--output` regresses this assertion.
    #[test]
    fn test_argv_emits_pre_lift_eight_element_slice_for_every_variant() {
        for (output, tail) in [
            (PodListingOutput::Json, "json"),
            (PodListingOutput::Wide, "wide"),
        ] {
            let argv = kubectl_get_pods_by_selector_argv("cart", "app=cart-api", output);
            assert_eq!(argv[0], "get");
            assert_eq!(argv[1], "pods");
            assert_eq!(argv[2], "-n");
            assert_eq!(argv[3], "cart");
            assert_eq!(argv[4], "-l");
            assert_eq!(argv[5], "app=cart-api");
            assert_eq!(argv[6], "-o");
            assert_eq!(argv[7], tail);
            assert_eq!(argv.len(), 8);
        }
    }

    /// The return type is a fixed-arity `[&str; 8]`, NOT a
    /// `Vec<&str>` or a `&[&str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without
    /// touching this module; a change to a slice reference would allow
    /// an unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 8]` shape, this line fails to type-check.
    #[test]
    fn test_argv_returns_fixed_arity_eight() {
        let argv: [&str; 8] =
            kubectl_get_pods_by_selector_argv("ns", "app=svc", PodListingOutput::Json);
        let [a0, a1, a2, a3, a4, a5, a6, a7] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "pods");
        assert_eq!(a2, "-n");
        assert_eq!(a3, "ns");
        assert_eq!(a4, "-l");
        assert_eq!(a5, "app=svc");
        assert_eq!(a6, "-o");
        assert_eq!(a7, "json");
    }

    /// Interpolation-position pin: `namespace` lands at index 3,
    /// `label_selector` lands at index 5. A future refactor that
    /// swapped them (e.g., an argv-order shuffle putting `-l <sel>`
    /// before `-n <ns>`) would silently pass the label selector where
    /// kubectl expects a namespace name, matching zero pods against
    /// the running cluster. Two distinct string arguments make the
    /// swap observable at the assertion level.
    #[test]
    fn test_argv_places_namespace_at_index_3_and_selector_at_index_5() {
        let argv =
            kubectl_get_pods_by_selector_argv("ns-alpha", "app=svc-beta", PodListingOutput::Wide);
        assert_eq!(
            argv[3], "ns-alpha",
            "index 3 must carry the namespace argument"
        );
        assert_eq!(
            argv[5], "app=svc-beta",
            "index 5 must carry the label-selector argument"
        );
        assert_ne!(argv[3], argv[5], "namespace and selector must not collide");
    }

    /// Variant-dispatch pin: index 7 tracks the passed `output`, NOT
    /// a hard-coded constant. Guards against a regression that
    /// ignored the `output` argument and always emitted (e.g.)
    /// `"json"`, silently routing every consumer onto the JSON
    /// renderer and collapsing `flux::gather_deployment_diagnostics`'s
    /// human-readable "All Pods" section into a raw JSON dump.
    #[test]
    fn test_argv_dispatches_each_variant_onto_its_own_tail() {
        let json = kubectl_get_pods_by_selector_argv("ns", "app=x", PodListingOutput::Json);
        let wide = kubectl_get_pods_by_selector_argv("ns", "app=x", PodListingOutput::Wide);
        assert_eq!(json[7], "json");
        assert_eq!(wide[7], "wide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift 8-element argv
    /// literal for either of the two standard-renderer variants
    /// inline any more. The four pre-lift sites migrated; any future
    /// consumer that wants the same whole-object app-label-selected
    /// pod-listing shape reaches for
    /// [`kubectl_get_pods_by_selector_argv`] on first grep, not by
    /// copy-pasting the raw literal from an existing module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::first_pod_field_argv`],
    /// [`crate::kubectl_get_databasemigration_output_argv`], and
    /// [`crate::list_resource_names_by_selector_argv`]. Anchored on
    /// the adjacent-line pair `"pods"` + one of `"json"` / `"wide"`
    /// on the `-o` tail with a `"-l"` companion in the same window —
    /// a future consumer that reads a different renderer (a jsonpath
    /// projection, a `-o yaml` dump, a custom-columns template) is
    /// deliberately outside the shield's scope, as documented in the
    /// module preamble.
    #[test]
    fn no_command_module_still_spells_raw_get_pods_by_selector_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let tails = ["\"json\"", "\"wide\""];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            let mut in_block_comment = false;
            for (idx, line) in lines.iter().enumerate() {
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
                if !line.contains("\"pods\"") {
                    continue;
                }
                let window_end = (idx + 10).min(lines.len());
                let window: String = lines[idx..window_end].join("\n");
                if !window.contains("\"get\"") {
                    continue;
                }
                if !window.contains("\"-n\"") {
                    continue;
                }
                if !window.contains("\"-l\"") {
                    continue;
                }
                if !window.contains("\"-o\"") {
                    continue;
                }
                if !tails.iter().any(|t| window.contains(t)) {
                    continue;
                }
                offenders.push((path.clone(), idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `get pods -n <ns> -l <sel> -o (json|wide)` argv literal(s) survive \
             under `commands/` — route each through \
             `crate::kubectl_get_pods_by_selector_argv::\
             kubectl_get_pods_by_selector_argv()` with a \
             `PodListingOutput` variant instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the three pre-lift modules that
    /// housed the four sites MUST forward through
    /// [`kubectl_get_pods_by_selector_argv`] at least the pre-lift
    /// count of times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_get_pods_by_selector_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("flux.rs"), 2),
            (crate_src.join("commands").join("status.rs"), 1),
            (crate_src.join("commands").join("github_runner_ci.rs"), 1),
        ];
        let needle = "kubectl_get_pods_by_selector_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} app-label-selected pod-listing \
                 site(s) through `{}`; found {}. A dropped call would leave \
                 the negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
