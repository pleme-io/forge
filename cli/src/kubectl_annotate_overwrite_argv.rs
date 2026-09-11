//! Fixed-arity `kubectl annotate <resource> <name> -n <namespace>
//! <key=value> --overwrite` argv slice used at every `kubectl annotate`
//! spawn site across the crate.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites each spelled the same 7-element argv literal on
//! their `kubectl` builder, diverging only on the `<resource>` /
//! `<name>` / `<key=value>` interpolations and on the surrounding spawn
//! / classify wiring:
//!
//! 1. `commands/migrations.rs::set_expected_tag_annotation` (Shinka
//!    `DatabaseMigration` release hint at line ~1278, routed through
//!    the raw `kubectl_command_async().args(...).output().await` shape
//!    with a non-fatal `warn_expected_tag_annotation_failed_nonfatal`
//!    dispatch on `!success()` or spawn error — the annotation is a
//!    performance hint for Shinka's cache-invalidation + 1s-vs-60s
//!    requeue partition, so a failure to set it is a soft warning and
//!    the caller falls back to normal polling).
//! 2. `commands/supergraph_verification.rs::annotate_configmap_with_hash`
//!    (ConfigMap `supergraph-hash` provenance annotation at line ~332,
//!    routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "Failed to annotate ConfigMap"` — a hard failure since
//!    the sibling `verify_configmap_hash` reader gates deployment
//!    verdicts on the annotation being present).
//!
//! Pre-lift the two stanzas diverged on argv ELEMENT ORDER — site 1
//! spelled `["annotate", <res>, <name>, "-n", <ns>, <k=v>, "--overwrite"]`
//! (namespace before the annotation key=value), site 2 spelled
//! `["annotate", <res>, <name>, <k=v>, "-n", <ns>, "--overwrite"]`
//! (key=value before namespace). Both orders parse identically at
//! kubectl (its arg parser is order-agnostic within a single
//! subcommand's flag set), so the pre-lift divergence carried no
//! observable behavioral difference — but it silently spread the
//! decision surface across two files, meaning any future refactor
//! (a `--record` companion, a rename of `--overwrite` by a future
//! kubectl release, a swap of `-n` for `--namespace`, an argv-order
//! discipline pass across the crate) had to hit two sites in lockstep
//! or diverge further. Post-lift the argv shape lives at ONE typed
//! body and every consumer inherits the change from
//! `.args(kubectl_annotate_overwrite_argv(resource, name, namespace,
//! key_value))`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on the spawn adapter
//! (raw `kubectl_command_async().output()` vs
//! [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]),
//! the post-spawn classification (soft `warn` on failure vs `?`
//! propagation), and the `op` label on the spawn-anyhow surface. A
//! `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape that every
//! `Command`-family adapter's `.args()` (and any `&[&str]`-taking
//! helper) consumes identically. Modeled on
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::kubectl_get_databasemigration_output_argv::kubectl_get_databasemigration_output_argv`],
//! and [`crate::kubectl_apply_argv`] — argv-slice primitives that
//! partition their tool's duplication budget without collapsing the
//! spawn / classify / display layers that legitimately diverge
//! downstream.
//!
//! # Element order — canonical `-n <ns>` before `<k=v>`
//!
//! The primitive places `-n <namespace>` at indices 3–4 and the
//! `<key=value>` positional at index 5, immediately before the trailing
//! `--overwrite` flag. This matches the canonical argv order the
//! sibling
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`]
//! and
//! [`crate::kubectl_get_databasemigration_output_argv::kubectl_get_databasemigration_output_argv`]
//! primitives already establish (name at 2, `-n` at 3, `<ns>` at 4)
//! and normalizes the pre-lift divergence between the two sites onto
//! one shape.

/// The pre-lift 7-element `annotate <resource> <name> -n <namespace>
/// <key=value> --overwrite` argv slice used at every `kubectl
/// annotate` spawn site.
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
/// - `argv[0] = "annotate"` — kubectl verb.
/// - `argv[1] = <resource>` — the target resource kind
///   (`"databasemigration"`, `"configmap"`, or any other kubectl
///   understands under an unqualified singular name).
/// - `argv[2] = <name>` — caller-supplied resource name.
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = <key_value>` — the `<key>=<value>` positional
///   argument. Callers assemble it via `format!("{key}={value}",
///   ...)` and pass a borrow into this slot; kubectl parses the
///   `=`-separated pair and applies the annotation to the resource.
/// - `argv[6] = "--overwrite"` — idempotent "replace if already
///   present" toggle. Every pre-lift site carried it; without it a
///   repeat annotate on an already-annotated resource would exit
///   non-zero and blow up the spawn-anyhow surface's `?` bubble
///   (site 2) or fire the non-fatal warn (site 1) on every re-run.
///
/// # Lifetime discipline
///
/// The returned array borrows `resource`, `name`, `namespace`, and
/// `key_value` under a single `'a` bound. Every current caller binds
/// all four strings ahead of the spawn and holds them alive across
/// the `.args(...)` call; the `[&'a str; 7]` return type pins that
/// requirement at the type level (a caller cannot silently extend
/// the array past any input's scope).
pub fn kubectl_annotate_overwrite_argv<'a>(
    resource: &'a str,
    name: &'a str,
    namespace: &'a str,
    key_value: &'a str,
) -> [&'a str; 7] {
    [
        "annotate",
        resource,
        name,
        "-n",
        namespace,
        key_value,
        "--overwrite",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`kubectl_annotate_overwrite_argv`] returns the
    /// pre-lift 7-element slice element-for-element (`"annotate"`,
    /// `<resource>`, `<name>`, `"-n"`, `<namespace>`, `<key_value>`,
    /// `"--overwrite"`) in the pre-lift order, with no extra element
    /// and no rewritten value. A future refactor that (a) reordered
    /// the slice, (b) added a `--record` / `--field-manager=<name>`
    /// companion, (c) renamed `--overwrite`, (d) swapped `-n` for
    /// `--namespace`, or (e) collapsed any element regresses this
    /// assertion.
    #[test]
    fn test_kubectl_annotate_overwrite_argv_emits_pre_lift_seven_element_slice() {
        let argv = kubectl_annotate_overwrite_argv(
            "databasemigration",
            "cart-api",
            "cart",
            "release.shinka.pleme.io/expected-tag=v1.2.3",
        );
        assert_eq!(argv[0], "annotate");
        assert_eq!(argv[1], "databasemigration");
        assert_eq!(argv[2], "cart-api");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "cart");
        assert_eq!(argv[5], "release.shinka.pleme.io/expected-tag=v1.2.3");
        assert_eq!(argv[6], "--overwrite");
        assert_eq!(argv.len(), 7);
    }

    /// The return type is a fixed-arity `[&str; 7]`, NOT a
    /// `Vec<&str>` or a `&[&str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without
    /// touching this module; a change to a slice reference would allow
    /// an unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 7]` shape, this line fails to type-check.
    #[test]
    fn test_kubectl_annotate_overwrite_argv_returns_fixed_arity_seven() {
        let argv: [&str; 7] = kubectl_annotate_overwrite_argv("configmap", "cm", "ns", "k=v");
        let [a0, a1, a2, a3, a4, a5, a6] = argv;
        assert_eq!(a0, "annotate");
        assert_eq!(a1, "configmap");
        assert_eq!(a2, "cm");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "k=v");
        assert_eq!(a6, "--overwrite");
    }

    /// Interpolation-position pin: `resource` lands at index 1,
    /// `name` at index 2, `namespace` at index 4, `key_value` at
    /// index 5. A future refactor that swapped any pair (e.g. an
    /// argv-order shuffle putting `<k=v>` at index 4 and `-n <ns>` at
    /// indices 5–6, mirroring the pre-lift `supergraph_verification`
    /// site) would silently confuse kubectl or — worse — pass a
    /// namespace as an annotation key or a resource name as a
    /// namespace. Four distinct string arguments make every pairwise
    /// swap observable at the assertion level.
    #[test]
    fn test_kubectl_annotate_overwrite_argv_places_each_argument_at_its_own_index() {
        let argv = kubectl_annotate_overwrite_argv(
            "res-alpha",
            "name-beta",
            "ns-gamma",
            "key-delta=value-epsilon",
        );
        assert_eq!(argv[1], "res-alpha", "index 1 must carry the resource kind");
        assert_eq!(argv[2], "name-beta", "index 2 must carry the resource name");
        assert_eq!(argv[4], "ns-gamma", "index 4 must carry the namespace");
        assert_eq!(
            argv[5], "key-delta=value-epsilon",
            "index 5 must carry the <key>=<value> positional",
        );
        assert_ne!(argv[1], argv[2], "resource and name must not collide");
        assert_ne!(argv[2], argv[4], "name and namespace must not collide");
        assert_ne!(argv[4], argv[5], "namespace and key_value must not collide");
    }

    /// Namespace-before-key_value pin: `-n <ns>` MUST occupy indices
    /// 3–4, and the `<key=value>` positional MUST land at index 5 —
    /// the primitive normalizes the pre-lift argv-order divergence
    /// between `commands/migrations.rs` (namespace before key=value)
    /// and `commands/supergraph_verification.rs` (key=value before
    /// namespace) onto ONE canonical shape. A regression that
    /// re-fused a "key_value before namespace" variant would re-open
    /// the divergence this primitive closes.
    #[test]
    fn test_kubectl_annotate_overwrite_argv_places_namespace_flag_before_key_value_positional() {
        let argv = kubectl_annotate_overwrite_argv("res", "name", "ns", "k=v");
        assert_eq!(argv[3], "-n");
        assert_eq!(argv[4], "ns");
        assert_eq!(argv[5], "k=v");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw 7-element
    /// `["annotate", ..., "--overwrite"]` argv literal inline any
    /// more. The two pre-lift sites migrated; any future consumer
    /// that wants the same `kubectl annotate ... --overwrite` shape
    /// reaches for [`kubectl_annotate_overwrite_argv`] on first grep,
    /// not by copy-pasting the raw literal from an existing module.
    ///
    /// Anchored on the joined pair `"annotate"` plus a same-window
    /// `"--overwrite"` occurrence — the leading verb + trailing flag
    /// combination is what every pre-lift stanza carried, and no
    /// post-lift consumer will (the typed primitive owns both inside
    /// its body). Mirrors the negative half of the sibling shields on
    /// [`crate::kubectl_delete_job_argv`] and
    /// [`crate::kubectl_get_databasemigration_output_argv`].
    #[test]
    fn no_command_module_still_spells_raw_kubectl_annotate_overwrite_argv() {
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
                if !line.contains("\"annotate\"") {
                    continue;
                }
                // Look ahead a small window to see if `--overwrite`
                // appears in the same argv literal.
                let window_end = (idx + 8).min(lines.len());
                let window: String = lines[idx..window_end].join("\n");
                if !window.contains("\"--overwrite\"") {
                    continue;
                }
                if !window.contains("\"-n\"") {
                    continue;
                }
                offenders.push((path.clone(), idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"annotate\", ..., \"-n\", ..., \"--overwrite\"]` argv literal(s) \
             survive under `commands/` — route each through \
             `crate::kubectl_annotate_overwrite_argv::kubectl_annotate_overwrite_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the two sites MUST each forward through
    /// [`kubectl_annotate_overwrite_argv`] at least once, so a
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_annotate_overwrite_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("migrations.rs"), 1),
            (
                crate_src
                    .join("commands")
                    .join("supergraph_verification.rs"),
                1,
            ),
        ];
        let needle = "kubectl_annotate_overwrite_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} `kubectl annotate ... --overwrite` \
                 spawn site(s) through `{}`; found {}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
