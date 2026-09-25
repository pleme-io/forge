//! `- name:` YAML list-entry name-value extraction primitive — the
//! typed body every manifest-line walker uses to recognize a
//! `- name: <value>` list entry and lift out its trimmed value.
//!
//! # Pre-lift census — three sibling composition sites
//!
//! Three pre-lift command-module sites each spelled the same four-line
//! `let trimmed = line.trim(); if trimmed.starts_with("- name:") { let
//! name_value = trimmed.trim_start_matches("- name:").trim(); if
//! <predicate>(name_value) { <state mutation> } }` stanza verbatim,
//! differing only in the predicate applied to `name_value` and the
//! downstream state each site mutates:
//!
//! 1. `commands/bootstrap.rs::release` (~L511-518) — predicate is
//!    `name_value.contains("bootstrap")`, mutation is
//!    `matched_bootstrap = true` plus an `info!` log carrying the
//!    matched name and the incoming `tag_suffix`.
//! 2. `commands/rust_service.rs::update_kustomization_image_tag`
//!    (~L1845-1851) — predicate is `name_value.contains(service_name)`,
//!    mutation is `matched_name = true` (a sibling `repository:` check
//!    runs on the same trimmed line downstream).
//! 3. `commands/push.rs::update_kustomization` (~L113-119) — predicate
//!    is `registry.contains(name_value) || name_value.contains(service_match)`,
//!    mutation is `matched_name = true`.
//!
//! All three walkers scan a `kustomization.yaml` / HelmRelease manifest
//! line by line looking for `- name:` list entries whose value matches
//! a caller-supplied service or bootstrap component name so the walker
//! can rewrite the sibling `newTag:` / `tag:` line one iteration later.
//! Three identically-shaped bodies past THEORY.md §VI.1's three-times
//! threshold — the PRIME DIRECTIVE duplication budget is zero at three
//! sibling occurrences.
//!
//! # Why the shape is load-bearing
//!
//! The three walkers deliberately reach past `serde_yaml` for the
//! manifest rewrite because `serde_yaml`'s round-trip drops comments,
//! reformats multi-line strings, and can corrupt `patch: |` blocks. The
//! rewrite therefore MUST be line-oriented, and the `- name:` prefix
//! plus the trimmed value are the only two features each walker needs
//! to isolate. Any refinement to that recognition (accepting `-name:`
//! without the space, treating a quoted `"- name:"` in a comment as a
//! non-match, adjusting the extractor to strip a trailing `#` comment
//! from the value) belongs at ONE construction surface post-lift and
//! reaches all three walkers by construction.
//!
//! # Return semantics
//!
//! The primitive takes a caller-supplied `trimmed_line: &str` — the
//! outcome of `line.trim()` at the call site, so each walker keeps its
//! existing `trimmed` binding for downstream sibling checks
//! (`starts_with("repository:")` in the `rust_service.rs` walker) — and
//! returns `Some(&str)` (the trimmed value, borrowed from
//! `trimmed_line`) IFF `trimmed_line` starts with the four-character
//! `"- name:"` prefix. Otherwise `None`.
//!
//! # Post-lift ownership discipline
//!
//! The primitive owns the [`LIST_NAME_PREFIX`] constant (the exact
//! four-token `"- name:"` prefix) and the byte-shape of the returned
//! `Option<&str>`. Consumer sites forward through a single
//! `if let Some(name_value) = yaml_list_name_entry_value(trimmed) { ... }`
//! call and inherit the closed prefix and the trim-both-sides semantics
//! by construction. A future edit that widened the prefix to accept
//! `-name:` (no space) OR that switched from `trim_start_matches` to
//! `strip_prefix` semantics (the primitive uses `strip_prefix`
//! internally, which is byte-identical inside the `starts_with` guard
//! but not identical without it — see the shield below) lands at ONE
//! body and every walker picks up the change.
//!
//! # `strip_prefix` vs `trim_start_matches` — byte-identical inside the guard
//!
//! Pre-lift sites spelled `trimmed.trim_start_matches("- name:").trim()`
//! after the `trimmed.starts_with("- name:")` guard. The primitive
//! uses `trimmed_line.strip_prefix(LIST_NAME_PREFIX).map(str::trim)`,
//! which is byte-identical WHEN the prefix is present (both strip the
//! single leading occurrence and hand off the same rest slice to
//! `trim`) and structurally correct WHEN the prefix is absent
//! (`strip_prefix` returns `None`, which the primitive maps to a
//! bare `None`; `trim_start_matches` would have returned the
//! whole string unchanged and never been reached under the pre-lift
//! guard). The `test_returns_none_when_prefix_absent` shield pins the
//! absent-prefix arm; the byte-oracle shields pin the present-prefix
//! extraction against realistic manifest lines.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the "recognize a `- name:` YAML
//! list entry and lift its trimmed value" projection lives at ONE
//! construction surface so all three manifest walkers inherit the
//! same closed prefix and trim discipline.
//!
//! §VI.1 three-is-a-law: three sibling occurrences past the coincidence
//! threshold — the negative caller shield forbids drift by construction
//! so the PRIME DIRECTIVE duplication budget stays at zero as a fourth
//! walker (e.g. a future GitOps overlay editor) is added.
//!
//! §III typescape: `{"the trimmed value of a `- name:` YAML list entry,
//! if the input line's trimmed form starts with `- name:`; None
//! otherwise"}` becomes a single named terminal in the manifest-walker
//! typescape; all three consumers cite the primitive rather than
//! restating the four-line composition body.

/// The exact byte-form prefix that marks a `- name:` YAML list entry.
/// Pinned to the four-token sequence `- name:` (hyphen, space, `name`,
/// colon) verbatim as the pre-lift `.starts_with("- name:")` /
/// `.trim_start_matches("- name:")` argument. Load-bearing: swapping to
/// `"-name:"` (no space after hyphen) or `"- name :"` (space before
/// colon) would change which lines the three walkers recognize as
/// list-name entries and silently break the sibling `newTag:` / `tag:`
/// rewrite one line later — post-lift all three walkers inherit the
/// constant.
pub const LIST_NAME_PREFIX: &str = "- name:";

/// Recognize a `- name: <value>` YAML list entry on `trimmed_line` and
/// return its trimmed value, borrowed from `trimmed_line`. Returns
/// `None` when `trimmed_line` does not start with [`LIST_NAME_PREFIX`].
///
/// # Pre-lift shape
///
/// Byte-for-byte equivalent to the pre-lift four-line composition when
/// the caller has already bound `let trimmed = line.trim();`:
///
/// ```text
/// if trimmed.starts_with("- name:") {
///     let name_value = trimmed.trim_start_matches("- name:").trim();
///     // ... predicate on name_value ...
/// }
/// ```
///
/// becomes
///
/// ```text
/// if let Some(name_value) = yaml_list_name_entry_value(trimmed) {
///     // ... predicate on name_value ...
/// }
/// ```
///
/// # Trim discipline
///
/// The returned slice is trimmed on BOTH sides via `str::trim` so a
/// caller matching against `"foo"` matches a manifest line spelled
/// `- name: foo  ` (trailing whitespace) or `- name:   foo` (extra
/// leading whitespace after the colon). This preserves the pre-lift
/// `.trim()` chained after `.trim_start_matches("- name:")` verbatim.
pub fn yaml_list_name_entry_value(trimmed_line: &str) -> Option<&str> {
    trimmed_line.strip_prefix(LIST_NAME_PREFIX).map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant shield: [`LIST_NAME_PREFIX`] is exactly the seven-byte
    /// `"- name:"` (hyphen, space, `name`, colon). A future refinement
    /// that dropped the space (`"-name:"`), added a space before the
    /// colon (`"- name :"`), or capitalized (`"- Name:"`) fails here.
    #[test]
    fn test_list_name_prefix_is_exactly_hyphen_space_name_colon() {
        assert_eq!(LIST_NAME_PREFIX, "- name:");
        assert_eq!(LIST_NAME_PREFIX.len(), 7);
    }

    /// Happy path: the trimmed line starts with the prefix and carries
    /// a single-word value — returns `Some("foo")`.
    #[test]
    fn test_returns_trimmed_value_on_simple_list_name_entry() {
        assert_eq!(yaml_list_name_entry_value("- name: foo"), Some("foo"));
    }

    /// Extra whitespace between the colon and the value is stripped by
    /// the tail `str::trim` — matches the pre-lift `.trim()` chained
    /// after `.trim_start_matches`.
    #[test]
    fn test_strips_extra_whitespace_between_colon_and_value() {
        assert_eq!(
            yaml_list_name_entry_value("- name:   spaced-out-value"),
            Some("spaced-out-value")
        );
    }

    /// Trailing whitespace on the line is stripped by the tail
    /// `str::trim`. A caller matching against `"foo"` still matches a
    /// manifest line spelled `- name: foo   `.
    #[test]
    fn test_strips_trailing_whitespace_after_value() {
        assert_eq!(yaml_list_name_entry_value("- name: foo   "), Some("foo"));
    }

    /// Realistic manifest line: registry-qualified image name with a
    /// slash and a hyphen — no special-character handling beyond
    /// `str::trim`.
    #[test]
    fn test_returns_registry_qualified_image_name_verbatim() {
        assert_eq!(
            yaml_list_name_entry_value("- name: ghcr.io/pleme-io/backend"),
            Some("ghcr.io/pleme-io/backend")
        );
    }

    /// Absent-prefix arm: a line that does NOT start with `- name:`
    /// returns `None`. This is the byte-form that distinguishes
    /// `strip_prefix` (returns `None`) from `trim_start_matches`
    /// (returns the input unchanged); post-lift the caller sees `None`
    /// and skips the `if let Some(...)` body, matching the pre-lift
    /// `.starts_with("- name:")` guard's `false` arm.
    #[test]
    fn test_returns_none_when_prefix_absent() {
        assert_eq!(yaml_list_name_entry_value("name: foo"), None);
        assert_eq!(yaml_list_name_entry_value("newTag: v1.0"), None);
        assert_eq!(yaml_list_name_entry_value("repository: bar"), None);
        assert_eq!(yaml_list_name_entry_value("# a comment"), None);
        assert_eq!(yaml_list_name_entry_value(""), None);
    }

    /// A trimmed line spelled `- name:` with no value returns
    /// `Some("")` (empty string, not `None`). Pre-lift the sibling
    /// `.contains(<something>)` predicate falls through on an empty
    /// string for every walker, so the post-lift `Some("")` is
    /// behaviorally identical.
    #[test]
    fn test_returns_empty_string_on_bare_prefix_with_no_value() {
        assert_eq!(yaml_list_name_entry_value("- name:"), Some(""));
        assert_eq!(yaml_list_name_entry_value("- name:   "), Some(""));
    }

    /// Off-by-one guard: `"-name:"` (no space between hyphen and
    /// `name`) is NOT a match. Pins that the primitive's prefix is
    /// exactly `LIST_NAME_PREFIX`, not a relaxed form.
    #[test]
    fn test_returns_none_when_hyphen_space_boundary_is_missing() {
        assert_eq!(yaml_list_name_entry_value("-name: foo"), None);
    }

    /// Positive delegation shield: every pre-lift command module MUST
    /// forward through [`yaml_list_name_entry_value`] at least the
    /// pre-lift count of times, so a migration that dropped a call site
    /// outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields the crate carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_yaml_list_name_entry_value() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] =
            &[("bootstrap.rs", 1), ("rust_service.rs", 1), ("push.rs", 1)];
        let needle = "yaml_list_name_entry_value(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `- name:` list-name extraction site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }

    /// Negative caller shield: no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.trim_start_matches("- name:")` composition inline any more.
    /// The three pre-lift sites migrated; any future consumer that
    /// wants the same `- name:` recognition reaches for
    /// [`yaml_list_name_entry_value`] on first grep, not by
    /// copy-pasting the four-line stanza. Uses
    /// [`crate::test_support::code_line_hits`] to filter out
    /// `///` / `//!` / `//` doc-comment lines so this crate's own
    /// prose narrating the pre-lift shape does not false-fire.
    #[test]
    fn no_command_module_still_spells_raw_trim_start_matches_list_name_stanza() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct the needle at test time so this test's own
        // executable body does NOT spell the raw stanza verbatim; the
        // sibling self-match shield
        // `primitive_body_reaches_strip_prefix_list_name_at_exactly_one_call`
        // fixes this file's total hit count at 1 (the primitive body),
        // and a verbatim `let needle = "…"` line here would inflate it.
        let needle = format!("{}{}{}", "trim_start_matches(\"", "- name:", "\")");
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
             through `crate::yaml_list_name_entry_value::yaml_list_name_entry_value(trimmed)` \
             instead:\n{offenders:#?}",
        );
    }

    /// Self-match discipline: this module's own body must be
    /// byte-audit-clean against its negative shield's needle. The
    /// [`crate::test_support::code_line_hits`] helper filters
    /// `///` / `//!` / `//` doc-comment lines, so this test asserts
    /// the executable body of this module spells the primitive body
    /// exactly ONCE (in [`yaml_list_name_entry_value`] itself).
    #[test]
    fn primitive_body_reaches_strip_prefix_list_name_at_exactly_one_call() {
        let source = include_str!("yaml_list_name_entry_value.rs");
        // Reconstruct the primitive's needle at test time so this
        // shield's own body does NOT contribute a self-hit that
        // inflates the count.
        let needle = format!(
            "{}{}{}",
            "strip_prefix(LIST_", "NAME_PREFIX", ").map(str::trim)"
        );
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "primitive body must spell `{needle}` at exactly one call site \
             (the `yaml_list_name_entry_value` body); found {}:\n{hits:#?}",
            hits.len(),
        );
    }
}
