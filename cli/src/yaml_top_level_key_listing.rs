//! "Available top-level keys, comma-joined, or `none`" primitive — the
//! typed body every deploy.yaml lookup-miss diagnostic uses to enumerate
//! the caller's available options.
//!
//! # Pre-lift census — two sibling composition sites
//!
//! Two pre-lift `commands/rust_service.rs` sites each spelled the same
//! six-line `.and_then(|_| _.as_mapping()).map(|m| m.keys().filter_map(
//! |k| k.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_else(||
//! "none".to_string())` stanza verbatim, differing only in the
//! top-level YAML key the enumeration probes:
//!
//! 1. `commands/rust_service.rs::resolve_namespace_for_env` (~L1050-1060) —
//!    the `"Available environments: {}"` tail on the missing-namespace
//!    `anyhow!` error, enumerating the caller's `deploy.yaml`
//!    `environments:` mapping.
//! 2. `commands/rust_service.rs::get_manifest_path_for_env` (~L1082-1092) —
//!    the `"Available manifests: {}"` tail on the missing-manifest-path
//!    `anyhow!` error, enumerating the caller's `deploy.yaml`
//!    `manifests:` mapping.
//!
//! Both sites bind `yaml: serde_yaml::Value` from
//! `load_deploy_yaml_and_resolve_env`, project onto a top-level string
//! key, and render the miss-diagnostic's "Available <thing>:" tail.
//! Two identically-shaped bodies past THEORY.md §VI.1's coincidence
//! threshold; the PRIME DIRECTIVE duplication budget is zero at two
//! sibling occurrences.
//!
//! # Why the tail is load-bearing
//!
//! The miss-diagnostic tail is the caller's ONLY guidance when a
//! deploy.yaml lookup fails: `resolve_namespace_for_env` bails with
//! `Namespace not found for environment '<env>'` and the tail names
//! every environment the caller could pick from instead; the manifest
//! sibling does the same for the `manifests:` block. A future refinement
//! — sorting the keys alphabetically for readability; capping at 5 with
//! a `+N more` suffix; upgrading the placeholder from `"none"` to the
//! typed `"<no environments defined in deploy.yaml>"` guidance; adding
//! an anchor-nearest-match hint like `"did you mean 'preview'?"` on a
//! Levenshtein-1 miss — lands at ONE construction surface post-lift and
//! reaches both consumers by construction.
//!
//! # Post-lift ownership discipline
//!
//! The primitive owns the closed-set constants ([`JOIN_SEPARATOR`] and
//! [`MISSING_PLACEHOLDER`]) and the byte-shape of the returned
//! `String`. Consumer sites forward through a single 1-line call —
//! `joined_top_level_string_keys_or_none(&yaml, "<top>")` — and inherit
//! the closed constants and the missing-key semantics by construction.
//! A future edit that changed the placeholder from `"none"` to
//! `"<empty>"`, swapped the join separator to `" | "`, or refined
//! `Value::as_str` to include stringified numeric keys lands at ONE
//! body and both consumers pick up the change.
//!
//! # Empty-mapping edge preserved verbatim
//!
//! When the top-level key IS present and IS a mapping, but its keys are
//! all non-string values (bare numeric YAML keys `1:` `2:` etc., or
//! `null:` `true:`), the pre-lift stanza collects an empty `Vec<&str>`
//! and `.join(", ")` returns the empty string — NOT the
//! `MISSING_PLACEHOLDER`. The post-lift primitive preserves this
//! semantics byte-for-byte: the `unwrap_or_else` only fires on the
//! `None`-branch of the outer `.and_then(|_| _.as_mapping())`, not on
//! an empty-keys collection. The
//! [`tests::test_returns_empty_string_on_mapping_with_all_non_string_keys`]
//! shield pins this edge so a future refinement that switched to
//! rendering `MISSING_PLACEHOLDER` on the empty-keys case would surface
//! as a byte-form regression.
//!
//! # Distinct from the sibling `resolve_deploy_yaml_from_service_dir` load
//!
//! The sibling deploy.yaml surface at
//! [`crate::config::resolve_deploy_yaml_path`] resolves the on-disk
//! `deploy.yaml` PATH (via `SERVICE_DIR` env var + product-root
//! fallback), and `commands/rust_service.rs::load_deploy_yaml_and_
//! resolve_env` parses it into a `serde_yaml::Value`. This primitive
//! is downstream of both: it consumes the already-parsed `Value` and
//! renders one diagnostic sub-string. Path resolution and YAML parsing
//! stay at their canonical surfaces.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the "available top-level mapping
//! keys" projection lives at ONE construction surface so both miss-
//! diagnostic sites inherit the same closed-set semantics.
//!
//! §VI.1 two-is-a-coincidence, three-is-a-law: two sibling occurrences
//! sit at the coincidence threshold; the negative caller shield forbids
//! the third-site drift by construction so the PRIME DIRECTIVE
//! duplication budget stays at zero.
//!
//! §III typescape: `{"available top-level string keys of a
//! serde_yaml::Value's top-level mapping, comma-joined, `none` if the
//! top key is missing or not a mapping"}` becomes a single named
//! terminal in the deploy-yaml diagnostic typescape; both consumers
//! cite the primitive rather than restating the six-line composition
//! body.

/// The separator inserted between adjacent top-level string keys in the
/// rendered listing. Pinned to `", "` (comma + single space) verbatim
/// as the pre-lift `.join(", ")` argument. Load-bearing: swapping to
/// `" | "` or `" ,"` would change the byte shape of every
/// `anyhow!("Available <thing>: {}", ...)` diagnostic and drift both
/// consumer sites in lockstep — post-lift both inherit the constant.
pub const JOIN_SEPARATOR: &str = ", ";

/// The placeholder string returned when the top-level key is missing
/// or the top-level value is not a mapping. Pinned to `"none"`
/// verbatim as the pre-lift `.unwrap_or_else(|| "none".to_string())`
/// argument. Load-bearing: `resolve_namespace_for_env` and
/// `get_manifest_path_for_env` both bail with
/// `"Available environments: none"` / `"Available manifests: none"`
/// when the caller's `deploy.yaml` has no `environments:` /
/// `manifests:` block at all; the placeholder is what distinguishes
/// that mis-configuration from a "block present but all keys are
/// non-string" edge (which renders as the empty string, preserved
/// pre-lift).
pub const MISSING_PLACEHOLDER: &str = "none";

/// Render the top-level string keys of `yaml`'s mapping at `top`,
/// comma-joined, or [`MISSING_PLACEHOLDER`] if the top-level key is
/// missing or not a mapping.
///
/// # Pre-lift shape
///
/// Byte-for-byte equivalent to the pre-lift six-line composition:
///
/// ```text
/// yaml.get(top)
///     .and_then(|v| v.as_mapping())
///     .map(|m| m
///         .keys()
///         .filter_map(|k| k.as_str())
///         .collect::<Vec<_>>()
///         .join(", "))
///     .unwrap_or_else(|| "none".to_string())
/// ```
///
/// # Return semantics
///
/// - `yaml.get(top)` returns `None` (top key absent) → [`MISSING_PLACEHOLDER`].
/// - `yaml.get(top)` returns `Some(v)` where `v.as_mapping()` is `None`
///   (top value is a scalar, sequence, or null) → [`MISSING_PLACEHOLDER`].
/// - `yaml.get(top)` returns `Some(v)` where `v` is a mapping with
///   zero string keys → `""` (the empty string, NOT the placeholder;
///   the pre-lift `.map(...)` fires with an empty `Vec` and
///   `.join(", ")` returns the empty string).
/// - `yaml.get(top)` returns `Some(v)` where `v` is a mapping with one
///   or more string keys → the string keys, in `serde_yaml::Mapping`'s
///   insertion-preserving iteration order, joined by [`JOIN_SEPARATOR`].
///
/// # Insertion-order preservation
///
/// `serde_yaml::Mapping` is backed by `IndexMap` under the hood in
/// `serde_yaml` 0.9, so `Mapping::keys()` iterates in the order the
/// keys were inserted. The pre-lift stanza inherited this ordering
/// verbatim and both consumer diagnostics rendered whichever order the
/// caller's `deploy.yaml` spelled the block in — an alphabetical sort
/// would be a refinement, not a preservation, and the primitive
/// therefore does NOT sort. A future refinement can add a
/// `sorted_top_level_string_keys_or_none` sibling that opts in to a
/// sort discipline; consumers that want the raw order stay on this
/// primitive.
pub fn joined_top_level_string_keys_or_none(yaml: &serde_yaml::Value, top: &str) -> String {
    yaml.get(top)
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(JOIN_SEPARATOR)
        })
        .unwrap_or_else(|| MISSING_PLACEHOLDER.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(source: &str) -> serde_yaml::Value {
        serde_yaml::from_str(source).expect("valid YAML fixture")
    }

    /// Constant shield: [`JOIN_SEPARATOR`] is exactly `", "` (comma
    /// followed by single space). A future refinement to
    /// `" | "`/`","`/`", "` (trailing space)/`", "` (leading space)
    /// fails here.
    #[test]
    fn test_join_separator_is_exactly_comma_space() {
        assert_eq!(JOIN_SEPARATOR, ", ");
        assert_eq!(JOIN_SEPARATOR.len(), 2);
    }

    /// Constant shield: [`MISSING_PLACEHOLDER`] is exactly the
    /// lowercase four-character `"none"`. A drift to `"None"`,
    /// `"<none>"`, or the empty string fails here.
    #[test]
    fn test_missing_placeholder_is_exactly_lowercase_none() {
        assert_eq!(MISSING_PLACEHOLDER, "none");
        assert_eq!(MISSING_PLACEHOLDER.len(), 4);
    }

    /// Happy path: two string keys, insertion order preserved,
    /// separator exactly `", "` between them, no trailing separator.
    #[test]
    fn test_returns_comma_joined_string_keys_when_mapping_present() {
        let y = yaml(
            "environments:\n  \
             production: {namespace: prod}\n  \
             staging: {namespace: stage}\n",
        );
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            "production, staging"
        );
    }

    /// Insertion-order preservation: a `serde_yaml::Mapping` iterates
    /// in insertion order (IndexMap-backed). A future serde_yaml
    /// upgrade that changed the backing structure to a hash-order map
    /// would break both consumer diagnostics; this shield surfaces the
    /// regression before it lands.
    #[test]
    fn test_preserves_insertion_order_of_string_keys() {
        let y = yaml(
            "environments:\n  \
             zebra: {}\n  \
             alpha: {}\n  \
             middle: {}\n",
        );
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            "zebra, alpha, middle"
        );
    }

    /// Single-key case: no leading or trailing separator, just the
    /// key. A regression that prepended/appended `", "` fails here.
    #[test]
    fn test_returns_single_key_without_leading_or_trailing_separator() {
        let y = yaml("environments:\n  only-one: {}\n");
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            "only-one"
        );
    }

    /// Missing top-level key: the top argument doesn't appear in the
    /// document at all. The `.and_then(...)`-`None` propagates and
    /// [`MISSING_PLACEHOLDER`] fires.
    #[test]
    fn test_returns_none_placeholder_when_top_key_missing() {
        let y = yaml("other_block:\n  foo: bar\n");
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            MISSING_PLACEHOLDER
        );
    }

    /// Non-mapping top-level value: the top key IS present but points
    /// at a scalar (string), so `Value::as_mapping` returns `None` and
    /// [`MISSING_PLACEHOLDER`] fires. Pins the `.as_mapping()` gate.
    #[test]
    fn test_returns_none_placeholder_when_top_value_is_a_scalar() {
        let y = yaml("environments: \"not a mapping\"\n");
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            MISSING_PLACEHOLDER
        );
    }

    /// Non-mapping top-level value: the top key IS present but points
    /// at a sequence, so `Value::as_mapping` returns `None` and
    /// [`MISSING_PLACEHOLDER`] fires.
    #[test]
    fn test_returns_none_placeholder_when_top_value_is_a_sequence() {
        let y = yaml("environments:\n  - production\n  - staging\n");
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            MISSING_PLACEHOLDER
        );
    }

    /// Non-mapping top-level value: the top key IS present but points
    /// at `null`. `Value::as_mapping` returns `None` and
    /// [`MISSING_PLACEHOLDER`] fires — a subtle edge because a caller
    /// might spell `environments:` with no children, which YAML parses
    /// as `null`, not an empty mapping.
    #[test]
    fn test_returns_none_placeholder_when_top_value_is_null() {
        let y = yaml("environments: ~\n");
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            MISSING_PLACEHOLDER
        );
    }

    /// Empty-mapping edge: the top key IS present, IS a mapping, but
    /// has zero string keys. Pre-lift the `.map(...)` closure fires
    /// with an empty `Vec<&str>` and `.join(", ")` returns the empty
    /// string — NOT [`MISSING_PLACEHOLDER`]. Post-lift preserves this
    /// verbatim. `serde_yaml` accepts explicit `{}` for an empty
    /// mapping.
    #[test]
    fn test_returns_empty_string_on_explicit_empty_mapping() {
        let y = yaml("environments: {}\n");
        assert_eq!(joined_top_level_string_keys_or_none(&y, "environments"), "");
    }

    /// Non-string keys are silently dropped by the `filter_map(|k|
    /// k.as_str())` step. A mapping with numeric keys renders as the
    /// empty string, matching the pre-lift `.filter_map` semantics.
    /// Distinct from [`test_returns_empty_string_on_explicit_empty_mapping`]
    /// in that the mapping is non-empty but has no string keys.
    #[test]
    fn test_returns_empty_string_on_mapping_with_all_non_string_keys() {
        let y = yaml("environments:\n  1: production\n  2: staging\n");
        assert_eq!(joined_top_level_string_keys_or_none(&y, "environments"), "");
    }

    /// Mixed string / non-string keys: only the string keys survive
    /// the `filter_map(|k| k.as_str())` gate, in insertion order.
    #[test]
    fn test_drops_non_string_keys_and_keeps_string_keys_in_order() {
        let y = yaml(
            "environments:\n  \
             1: skip-me\n  \
             production: keep-me\n  \
             2: skip-me-too\n  \
             staging: keep-me-too\n",
        );
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            "production, staging"
        );
    }

    /// Manifest-diagnostic sibling: the same primitive drives the
    /// `"Available manifests: {}"` tail. Pins that the primitive is
    /// top-key-generic and does not hardcode `"environments"`.
    #[test]
    fn test_manifest_top_key_is_handled_symmetrically() {
        let y = yaml(
            "manifests:\n  \
             production: {kustomization: manifests/production/kustomization.yaml}\n  \
             staging: {kustomization: manifests/staging/kustomization.yaml}\n",
        );
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "manifests"),
            "production, staging"
        );
    }

    /// Byte-oracle: for a fixture matching a realistic `deploy.yaml`
    /// shape, the primitive returns the exact expected `String`. A
    /// future edit to the primitive that drifted from the pre-lift
    /// shape (e.g. adopted a Debug-formatted `Vec<&str>` in place of
    /// `.join(", ")`, or sorted the keys) would flip this assertion.
    ///
    /// The pre-lift six-line composition is NOT reconstructed inline
    /// here (the self-match shield
    /// [`primitive_body_reaches_filter_map_as_str_at_exactly_one_call`]
    /// pins the primitive body's spelling count at 1, and a
    /// reconstructed inline stanza in a test body would inflate that
    /// count); the byte-form is pinned directly against the expected
    /// output string, which is what every consumer diagnostic renders.
    #[test]
    fn test_renders_expected_byte_form_on_realistic_deploy_yaml() {
        let y = yaml(
            "environments:\n  \
             production: {namespace: prod}\n  \
             staging: {namespace: stage}\n  \
             preview: {namespace: preview}\n",
        );
        assert_eq!(
            joined_top_level_string_keys_or_none(&y, "environments"),
            "production, staging, preview"
        );
    }

    /// Positive delegation shield: `commands/rust_service.rs` MUST
    /// forward through [`joined_top_level_string_keys_or_none`] at
    /// least the pre-lift count of times, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_joined_top_level_string_keys_or_none() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("rust_service.rs", 2)];
        let needle = "joined_top_level_string_keys_or_none(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 top-level-key-listing composition site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }

    /// Negative caller shield: no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `filter_map(|k| k.as_str())` composition inline any more. The
    /// two pre-lift sites in `commands/rust_service.rs` migrated; any
    /// future consumer that wants the same "available top-level mapping
    /// keys" projection reaches for
    /// [`joined_top_level_string_keys_or_none`] on first grep, not by
    /// copy-pasting the six-line stanza. Uses
    /// [`crate::test_support::code_line_hits`] to filter out
    /// `///` / `//!` / `//` doc-comment lines so this crate's own
    /// prose narrating the pre-lift shape does not false-fire.
    #[test]
    fn no_command_module_still_spells_raw_filter_map_as_str_keys_stanza() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct the needle at test time so this test's own
        // executable body does NOT spell the raw stanza verbatim; the
        // sibling self-match shield
        // `primitive_body_reaches_filter_map_as_str_at_exactly_one_call`
        // fixes this file's total hit count at 1 (the primitive body),
        // and a verbatim `let needle = "…"` line here would inflate it.
        let needle = format!("{}{}{}", "filter_map(|k| k", ".as_", "str())");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &needle);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `{needle}` composition(s) survive under `commands/` — route each \
             through `crate::yaml_top_level_key_listing::joined_top_level_string_keys_or_none(&yaml, \"<top>\")` \
             instead:\n{offenders:#?}",
        );
    }

    /// Self-match discipline: this module's own body must be
    /// byte-audit-clean against its negative shield's needle even
    /// though the primitive's DOCSTRING narrates the pre-lift shape
    /// (`filter_map(|k| k.as_str())` in the byte-shape example). The
    /// [`crate::test_support::code_line_hits`] helper filters
    /// `///` / `//!` / `//` doc-comment lines, so this test asserts
    /// the executable body of this module still spells the needle
    /// exactly ONCE (in [`joined_top_level_string_keys_or_none`]
    /// itself). A refactor that inlined the primitive into a caller
    /// or split the closure across two bindings would flip the count.
    #[test]
    fn primitive_body_reaches_filter_map_as_str_at_exactly_one_call() {
        let source = include_str!("yaml_top_level_key_listing.rs");
        // Reconstruct the needle at test time so this shield's own
        // body does NOT contribute a self-hit that inflates the count.
        // The three-token split is the same discipline the sibling
        // `no_command_module_still_spells_raw_filter_map_as_str_keys_stanza`
        // shield uses. Docstring narrations of the pre-lift shape live
        // on `///` lines that `code_line_hits` filters.
        let needle = format!("{}{}{}", "filter_map(|k| k", ".as_", "str())");
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "primitive body must spell `{needle}` at exactly one call site \
             (the closure inside `joined_top_level_string_keys_or_none`); \
             found {}:\n{hits:#?}",
            hits.len(),
        );
    }
}
