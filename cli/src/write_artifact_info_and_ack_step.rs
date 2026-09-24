//! Fused `write_artifact_info + modified_files.push +
//! print_step_ok(&format!("<verb-phrase> in deploy/{}.artifact.json",
//! <name>))` stanza:
//! the pre-lift 2 sibling stanzas at
//! `commands/product_release.rs::write_artifact_tags` and
//! `commands/rollback.rs::execute` collapse onto ONE typed body.
//!
//! # Pre-lift census — two sibling stanzas, one triad grammar
//!
//! Two consumer sites each spelled the same three-line triad after
//! composing the [`crate::config::ArtifactInfo`] value for a service:
//!
//! 1. **Update** —
//!    [`crate::commands::product_release`], Phase-3 tag-write loop
//!    (`write_artifact_tags` local): `svc.name` binding, verb-phrase
//!    `"Updated artifact tag"`.
//! 2. **Swap** —
//!    [`crate::commands::rollback::execute`], swap-tags loop after the
//!    `Swapping tags in artifact.json...` step-heading: `entry.name`
//!    binding, verb-phrase `"Swapped tags"`.
//!
//! Both stanzas share the same three-line body:
//!
//! ```ignore
//! let json_path =
//!     crate::config::write_artifact_info(&product_dir, &<name>, &artifact)?;
//! modified_files.push(crate::repo::path_to_string_lossy(&json_path));
//! crate::ui::print_step_ok(&format!(
//!     "<verb-phrase> in deploy/{}.artifact.json",
//!     <name>
//! ));
//! ```
//!
//! Post-lift both sites forward through
//! [`write_artifact_info_and_ack_step`], which composes the three-line
//! triad at ONE typed body and projects the per-site verb-phrase
//! through the closed [`ArtifactJsonWriteAck`] enum.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the artifact-json write + push +
//! step-ok triad — the `"deploy/"` path prefix, the `".artifact.json"`
//! path suffix, the `" in "` connective between verb-phrase and path,
//! and the pairing of a `write_artifact_info` call with a
//! `modified_files.push(path_to_string_lossy(&json_path))` follow-up
//! and a `print_step_ok` acknowledgement — lives at ONE surface, so a
//! future refinement (a shift to a `journal.jsonl` audit line
//! alongside the print, a promotion to a typed
//! `substrate::ArtifactJsonPath` newtype, a rewording that swaps `" in
//! "` for `" → "`, an OTLP `artifact_json_write` event wired next to
//! the step-ok) lands here and reaches both consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: two sibling stanzas across two
//! command modules meet the recurring-shape criterion for a helper;
//! the fused triad forecloses the drift class the pre-lift split
//! stanzas were open to — a forgotten `modified_files.push`, an
//! `.artifact.json` misspelling as `.artifact-info.json`, a divergent
//! `print_step_pass` glyph vs the shared `print_step_ok` glyph.
//!
//! # Companion primitives
//!
//! - [`crate::config::write_artifact_info`] owns the JSON serialization,
//!   the `deploy/<name>.artifact.json` path resolution, and the
//!   `write_text_sync` invocation at ONE surface; this primitive is the
//!   caller-side fusion that couples the write with the `modified_files`
//!   accumulator push and the `print_step_ok` acknowledgement.
//! - [`crate::repo::path_to_string_lossy`] owns the lossy UTF-8
//!   projection from [`PathBuf`] to `String` this primitive threads into
//!   the accumulator.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::{write_artifact_info, ArtifactInfo};

/// The literal `" in deploy/"` fragment the pre-lift two sites spelled
/// between the verb-phrase and the service-scoped artifact-json
/// basename. Constant-lifted so the byte-oracle test and the
/// caller-shield remediation prose reference the same source of truth,
/// and a future rewording (a `" → deploy/"` arrow separator, a `" @
/// deploy/"` at-sign prefix) lands on exactly one line.
pub const ARTIFACT_JSON_STEP_OK_LOCATION_LEAD: &str = " in deploy/";

/// The literal `".artifact.json"` fragment the pre-lift two sites
/// spelled after the service name. Split from
/// [`ARTIFACT_JSON_STEP_OK_LOCATION_LEAD`] so a future refinement of
/// the basename (a `.artifact-info.json` rename, a `.artifact.yaml`
/// transport swap) rotates one side at a time.
pub const ARTIFACT_JSON_STEP_OK_LOCATION_TAIL: &str = ".artifact.json";

/// Closed enum of the two verb-phrases the pre-lift sibling sites
/// spelled ahead of the shared `" in deploy/<name>.artifact.json"`
/// path tail. A future third verb (an `"Attested tags"` variant paired
/// with the phase-1.5 attestation write) extends this enum in exactly
/// one place; every consumer that reaches for the fused triad inherits
/// the new grammar by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactJsonWriteAck {
    /// Product-release phase-3 update: `"Updated artifact tag"` —
    /// verb-past-tense plus singular-noun `"artifact tag"`, matching
    /// the semantic that Phase 3 writes exactly one new tag per
    /// service.
    UpdatedArtifactTag,
    /// Rollback swap: `"Swapped tags"` — verb-past-tense plus
    /// plural-noun `"tags"`, matching the semantic that rollback
    /// exchanges the `tag` and `previous_tag` fields (two tags moving
    /// simultaneously).
    SwappedTags,
}

impl ArtifactJsonWriteAck {
    /// The verb-phrase this ack projects ahead of the shared `" in
    /// deploy/<name>.artifact.json"` path tail. Const so a caller that
    /// wants to log or record the same wording alongside a diagnostics
    /// event does not have to re-derive it, and so the byte-oracle
    /// tests can pin the two variants without running a printer.
    pub const fn verb_phrase(self) -> &'static str {
        match self {
            Self::UpdatedArtifactTag => "Updated artifact tag",
            Self::SwappedTags => "Swapped tags",
        }
    }

    /// Compose the pre-lift `format!("<verb-phrase> in
    /// deploy/{}.artifact.json", <name>)` step-ok message without
    /// touching a writer. Split from
    /// [`write_artifact_info_and_ack_step`] so the pure-string
    /// projection can be pinned by unit tests without touching the
    /// filesystem, and so a caller that wants to render the same
    /// message alongside a non-step-ok sink can reuse the composition.
    pub fn step_ok_text(self, service_name: &str) -> String {
        let mut out = String::with_capacity(
            self.verb_phrase().len()
                + ARTIFACT_JSON_STEP_OK_LOCATION_LEAD.len()
                + service_name.len()
                + ARTIFACT_JSON_STEP_OK_LOCATION_TAIL.len(),
        );
        out.push_str(self.verb_phrase());
        out.push_str(ARTIFACT_JSON_STEP_OK_LOCATION_LEAD);
        out.push_str(service_name);
        out.push_str(ARTIFACT_JSON_STEP_OK_LOCATION_TAIL);
        out
    }
}

/// The fused triad the pre-lift two sites each spelled inline: write
/// `<product_dir>/deploy/<service_name>.artifact.json` via
/// [`crate::config::write_artifact_info`], push the resulting path
/// (lossy UTF-8 projection) into `modified_files`, and print the
/// step-ok acknowledgement via [`crate::ui::print_step_ok`] with the
/// per-site verb-phrase carried by `ack`.
///
/// Returns the resolved [`PathBuf`] so a caller that needs the on-disk
/// path (e.g., to feed a downstream diff) does not have to re-derive it
/// via [`crate::config::resolve_artifact_json_path`]; both pre-lift
/// callers discarded the return value, but the pass-through keeps the
/// primitive composable with future consumers.
pub fn write_artifact_info_and_ack_step(
    product_dir: &Path,
    service_name: &str,
    artifact: &ArtifactInfo,
    modified_files: &mut Vec<String>,
    ack: ArtifactJsonWriteAck,
) -> Result<PathBuf> {
    let json_path = write_artifact_info(product_dir, service_name, artifact)?;
    modified_files.push(crate::repo::path_to_string_lossy(&json_path));
    crate::ui::print_step_ok(&ack.step_ok_text(service_name));
    Ok(json_path)
}

/// Writer-taking sibling to [`write_artifact_info_and_ack_step`]. Runs
/// the same [`crate::config::write_artifact_info`] + `modified_files`
/// push, but emits the step-ok line via [`crate::ui::write_step_ok`]
/// against the supplied writer so tests can pin the pre-lift byte-shape
/// (three-space indent, `OK` text label, `\x1b[32m` green ANSI palette
/// on the label) without capturing stdout.
#[cfg_attr(not(test), allow(dead_code))]
pub fn write_artifact_info_and_ack_step_to<W: std::io::Write>(
    w: &mut W,
    product_dir: &Path,
    service_name: &str,
    artifact: &ArtifactInfo,
    modified_files: &mut Vec<String>,
    ack: ArtifactJsonWriteAck,
) -> Result<PathBuf> {
    let json_path = write_artifact_info(product_dir, service_name, artifact)?;
    modified_files.push(crate::repo::path_to_string_lossy(&json_path));
    crate::ui::write_step_ok(w, &ack.step_ok_text(service_name))?;
    Ok(json_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constant pin: the location-lead half the pre-lift two sites
    /// spelled between the verb-phrase and the service-scoped
    /// artifact-json basename is the verbatim `" in deploy/"`
    /// fragment.
    #[test]
    fn artifact_json_step_ok_location_lead_matches_pre_lift_literal() {
        assert_eq!(ARTIFACT_JSON_STEP_OK_LOCATION_LEAD, " in deploy/");
    }

    /// Constant pin: the location-tail half the pre-lift two sites
    /// spelled after the service name is the verbatim `".artifact.json"`
    /// fragment.
    #[test]
    fn artifact_json_step_ok_location_tail_matches_pre_lift_literal() {
        assert_eq!(ARTIFACT_JSON_STEP_OK_LOCATION_TAIL, ".artifact.json");
    }

    /// Verb-phrase pin: `UpdatedArtifactTag` projects the verbatim
    /// `"Updated artifact tag"` fragment the pre-lift
    /// `commands/product_release.rs::write_artifact_tags` site spelled
    /// inline.
    #[test]
    fn updated_artifact_tag_verb_phrase_matches_pre_lift_literal() {
        assert_eq!(
            ArtifactJsonWriteAck::UpdatedArtifactTag.verb_phrase(),
            "Updated artifact tag",
        );
    }

    /// Verb-phrase pin: `SwappedTags` projects the verbatim
    /// `"Swapped tags"` fragment the pre-lift
    /// `commands/rollback.rs::execute` site spelled inline.
    #[test]
    fn swapped_tags_verb_phrase_matches_pre_lift_literal() {
        assert_eq!(
            ArtifactJsonWriteAck::SwappedTags.verb_phrase(),
            "Swapped tags",
        );
    }

    /// Format pin: `UpdatedArtifactTag` composes exactly `"Updated
    /// artifact tag in deploy/<name>.artifact.json"` — the pre-lift
    /// byte-shape `commands/product_release.rs::write_artifact_tags`
    /// spelled inline with `format!(...)`.
    #[test]
    fn step_ok_text_updated_artifact_tag_matches_pre_lift_format() {
        assert_eq!(
            ArtifactJsonWriteAck::UpdatedArtifactTag.step_ok_text("frontier"),
            "Updated artifact tag in deploy/frontier.artifact.json",
        );
        assert_eq!(
            ArtifactJsonWriteAck::UpdatedArtifactTag.step_ok_text("backend"),
            "Updated artifact tag in deploy/backend.artifact.json",
        );
    }

    /// Format pin: `SwappedTags` composes exactly `"Swapped tags in
    /// deploy/<name>.artifact.json"` — the pre-lift byte-shape
    /// `commands/rollback.rs::execute` spelled inline with
    /// `format!(...)`.
    #[test]
    fn step_ok_text_swapped_tags_matches_pre_lift_format() {
        assert_eq!(
            ArtifactJsonWriteAck::SwappedTags.step_ok_text("frontier"),
            "Swapped tags in deploy/frontier.artifact.json",
        );
        assert_eq!(
            ArtifactJsonWriteAck::SwappedTags.step_ok_text("backend"),
            "Swapped tags in deploy/backend.artifact.json",
        );
    }

    /// Empty-service-name boundary: an empty `service_name` renders as
    /// `"deploy/.artifact.json"` with a bare dot in the basename slot.
    /// The pre-lift `format!("... deploy/{}.artifact.json", "")` shape
    /// projects the same string; this pin guards against a future
    /// refactor that silently short-circuited the empty-name path.
    #[test]
    fn step_ok_text_empty_service_name_renders_bare_dot() {
        assert_eq!(
            ArtifactJsonWriteAck::UpdatedArtifactTag.step_ok_text(""),
            "Updated artifact tag in deploy/.artifact.json",
        );
        assert_eq!(
            ArtifactJsonWriteAck::SwappedTags.step_ok_text(""),
            "Swapped tags in deploy/.artifact.json",
        );
    }

    /// Byte-oracle: the writer sibling projects the pre-lift
    /// `crate::ui::print_step_ok(&format!("<verb-phrase> in
    /// deploy/{}.artifact.json", <name>))` byte-shape verbatim.
    /// Compares against a direct [`crate::ui::write_step_ok`] against
    /// the same composed payload so the pin holds whether ANSI is
    /// auto-enabled or auto-disabled on the host running the suite.
    /// Also fully round-trips the on-disk write: reads the file back
    /// through [`crate::config::load_artifact_info`] and confirms the
    /// `modified_files` accumulator captured the path via
    /// [`crate::repo::path_to_string_lossy`].
    #[test]
    fn write_artifact_info_and_ack_step_to_projects_prelift_shape() {
        let tmp = tempfile::tempdir().expect("tempdir must succeed");
        let product_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(product_dir.join("deploy")).expect("deploy dir must be created");

        for (ack, service_name, expected_payload) in [
            (
                ArtifactJsonWriteAck::UpdatedArtifactTag,
                "frontier",
                "Updated artifact tag in deploy/frontier.artifact.json",
            ),
            (
                ArtifactJsonWriteAck::SwappedTags,
                "backend",
                "Swapped tags in deploy/backend.artifact.json",
            ),
        ] {
            let artifact = ArtifactInfo {
                tag: "test-tag".to_string(),
                built_at: "2026-01-01T00:00:00Z".to_string(),
                previous_tag: "prior-tag".to_string(),
                attestation: None,
            };
            let mut modified_files: Vec<String> = Vec::new();
            let mut buf: Vec<u8> = Vec::new();
            let json_path = write_artifact_info_and_ack_step_to(
                &mut buf,
                &product_dir,
                service_name,
                &artifact,
                &mut modified_files,
                ack,
            )
            .expect("write against a Vec<u8> writer must succeed");

            let mut peer: Vec<u8> = Vec::new();
            crate::ui::write_step_ok(&mut peer, expected_payload)
                .expect("peer write against a Vec<u8> writer must succeed");
            assert_eq!(
                buf, peer,
                "the primitive's writer sibling must project the same byte-shape as \
                 `crate::ui::write_step_ok(w, \"{expected_payload}\")`",
            );

            let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
            assert!(
                out.contains(expected_payload),
                "emitted line must carry the `<verb-phrase> in deploy/<name>.artifact.json` \
                 payload verbatim; got {out:?}",
            );

            assert_eq!(
                modified_files,
                vec![crate::repo::path_to_string_lossy(&json_path)],
                "modified_files must capture the returned json_path via path_to_string_lossy",
            );
            assert!(
                json_path.exists(),
                "write_artifact_info must have produced the on-disk file at {}",
                json_path.display(),
            );

            let loaded = crate::config::load_artifact_info(
                &product_dir,
                service_name,
                &product_dir.join(service_name),
            )
            .expect("just-written artifact.json must load back");
            assert_eq!(loaded.tag, "test-tag");
            assert_eq!(loaded.previous_tag, "prior-tag");
        }
    }

    /// Delegation shield (positive half): the two pre-lift consumer
    /// modules
    /// (`commands/{product_release, rollback}.rs`) MUST each forward
    /// through [`write_artifact_info_and_ack_step`] at least once, so
    /// a migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails.
    #[test]
    fn write_artifact_tags_and_rollback_forward_through_the_primitive() {
        use std::path::PathBuf;
        for module in ["commands/product_release.rs", "commands/rollback.rs"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join(module);
            let needle = "write_artifact_info_and_ack_step(";
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= 1,
                "{} must forward at least 1 artifact-json triad site through `{}`; \
                 found {}. A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
                path.display(),
                needle,
                forwards,
            );
        }
    }

    /// Caller shield (negative half): the pre-`#[cfg(test)]` module
    /// bodies of `commands/{product_release, rollback}.rs` must hold
    /// ZERO code-line hits for either verbatim pre-lift `format!(...)`
    /// literal — `"Updated artifact tag in deploy/{}.artifact.json"`
    /// and `"Swapped tags in deploy/{}.artifact.json"` — that the two
    /// pre-lift sites spelled inline. After the lift, both sites
    /// forward through [`write_artifact_info_and_ack_step`], which
    /// owns the sole remaining `" in deploy/"` + `".artifact.json"`
    /// composition inside [`ArtifactJsonWriteAck::step_ok_text`] at
    /// ONE body in `cli/src/write_artifact_info_and_ack_step.rs`.
    ///
    /// The needles are reconstructed via [`format!`] so this shield's
    /// own source text does not false-match itself.
    #[test]
    fn product_release_and_rollback_hold_no_raw_artifact_json_step_ok_literal() {
        let updated_needle = format!("\"Updated artifact tag in deploy/{}.artifact.json\"", "{}");
        let swapped_needle = format!("\"Swapped tags in deploy/{}.artifact.json\"", "{}");
        for (module_path, source) in [
            (
                "commands/product_release.rs",
                include_str!("commands/product_release.rs"),
            ),
            ("commands/rollback.rs", include_str!("commands/rollback.rs")),
        ] {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            for needle in [updated_needle.as_str(), swapped_needle.as_str()] {
                let hits = crate::test_support::code_line_hits(body, needle);
                assert_eq!(
                    hits.len(),
                    0,
                    "expected ZERO code-line hits for the raw pre-lift step-ok \
                     format-string `{needle}` in the pre-`#[cfg(test)]` module body of \
                     `{module_path}` (the two pre-lift sites forward through \
                     `crate::write_artifact_info_and_ack_step::write_artifact_info_and_ack_step`, \
                     which owns the sole remaining `\" in deploy/\" + \".artifact.json\"` \
                     composition at ONE body in \
                     `cli/src/write_artifact_info_and_ack_step.rs`); got {}. \
                     Offending lines: {:#?}",
                    hits.len(),
                    hits,
                );
            }
        }
    }
}
