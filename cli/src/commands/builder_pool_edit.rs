//! Builder-pool YAML field-splice helper.
//!
//! Shape-adapter over the six-piece `require + info + read + splice +
//! write + success` fusion that the two sibling builder-pool YAML update
//! functions in `commands/{kenshi_agent (×2 call sites into
//! `update_builder_pool_agent_image`), nix_builder (×2 call sites into
//! `update_builder_pool_builder_image`)}.rs` each spelled — VERBATIM,
//! modulo the single YAML field-name identifier — the same 34-line
//! sequence for. The pre-lift split lifted the four call sites through
//! two per-field wrapper functions whose bodies were byte-identical up
//! to `agentImage` vs `builderImage`:
//!
//! ```text
//! let path = crate::repo::require_existing_labeled(builder_pool_path, "Builder pool file")?;
//! info!("📝 Updating: {}", builder_pool_path);
//! let content = crate::repo::read_text_async(path).await?;
//! let new_image = crate::oci_manifest::image_reference(registry, new_tag);
//! // per-line splice preserving indent for `line.trim().starts_with("<FIELD>:")`
//! // ...
//! anyhow::bail!("No <FIELD> field found in {}", builder_pool_path);   // miss arm
//! crate::repo::write_text_async(path, &final_content).await?;
//! crate::info_indented_success!("Builder pool updated");
//! ```
//!
//! Two occurrences of a fully identical shape past the routine's
//! `≥2` PRIME-DIRECTIVE threshold; this module is the extraction
//! `commands/kustomization_edit.rs` explicitly reserved on its
//! `# Distinct from the sibling update_builder_pool_agent_image shape`
//! module-doc section — "a `builder_pool_edit` sibling on the same
//! shape is the future extraction if that helper repeats." That helper
//! now repeats (nix-builder's builder-pool overlay ships the same shape
//! against the sibling `builderImage:` field), and this module redeems
//! the reservation.
//!
//! Post-lift each of the four call sites reaches [`update_builder_pool_field`]
//! with a `BuilderPoolField::{AgentImage,BuilderImage}` selector and
//! inherits the canonical `"Builder pool file"` existence-check label,
//! the `"📝 Updating: <path>"` operator-facing announcement, the
//! `image_reference(registry, new_tag)` composition, the
//! indent-preserving `line.trim().starts_with(<field>:)` splice, the
//! `"No <field> field found in {}"` miss envelope, and the
//! `info_indented_success!("Builder pool updated")` acknowledgment
//! through one site.
//!
//! # `BuilderPoolField` — closed enum, exhaustive on splice
//!
//! The two YAML field names are held as a Rust enum variant rather than
//! as a `&str` slot so a future third builder-pool field (a hypothetical
//! `runnerImage:` for a new pool CRD variant) surfaces as a compile-time
//! pattern-match exhaustion in every writer arm rather than as a silent
//! `"line.trim().starts_with(field_name)"` predicate that quietly no-ops
//! on a mis-typed literal — the same closed-enum discipline
//! `commands/gem.rs` uses for its version-form palette (see the forge
//! CLAUDE.md `## ★★ Version bumping` section: "A closed enum whose
//! `render` is the inverse of the `pattern` that detected it.").
//!
//! # Pure splicer + I/O wrapper split
//!
//! [`splice_builder_pool_field`] is the pure content-transform (input:
//! `&str` content + field selector + new image; output: `Option<(String,
//! usize)>` where `Some((rewritten, match_count))` is the hit arm and
//! `None` is the miss arm). The outer [`update_builder_pool_field`]
//! wraps it with the `require + info + read + write + success` I/O
//! stanza. The split means `#[cfg(test)]` can pin the exact spliced-line
//! bytes without a filesystem or a tracing subscriber — the same
//! `writer + macro` split
//! [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
//! [`crate::warn_nonfatal!`] and
//! [`crate::success_step::write_success_step`] carries against
//! [`crate::info_success!`].
//!
//! # Peer of `kustomization_edit.rs`
//!
//! This module is the file-kind sibling of
//! `commands/kustomization_edit.rs::open_for_update`. Kustomization
//! overlays open with `apiVersion: kustomize.config.k8s.io/v1beta1` +
//! `kind: Kustomization`; builder-pool CRD instances open with
//! `kind: BuilderPool`. The label difference (`"Kustomization file"`
//! vs `"Builder pool file"`) semantically separates the two miss
//! envelopes so a future per-file-kind remediation hint can diverge
//! without rewriting either primitive.

use anyhow::Result;
use std::fmt;
use tracing::info;

/// The two builder-pool YAML fields any sibling flow may need to update.
///
/// Ruby-idiomatic closed enum: adding a new field is a compile-time
/// pattern-match exhaustion and cannot silently fall off the splicer,
/// the miss envelope, or the acknowledgment log the way a `&str`-slot
/// design would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuilderPoolField {
    /// `agentImage:` — the field kenshi-agent's builder-pool references.
    /// The pre-lift home was
    /// `commands/kenshi_agent.rs::update_builder_pool_agent_image`.
    AgentImage,
    /// `builderImage:` — the field nix-builder's builder-pool references.
    /// The pre-lift home was
    /// `commands/nix_builder.rs::update_builder_pool_builder_image`.
    BuilderImage,
}

impl BuilderPoolField {
    /// The literal YAML field name spliced into the rewritten line,
    /// matched against `line.trim().starts_with("<name>:")`, and
    /// interpolated into the `"   Updated <name> to: {}"` info log and
    /// the `"No <name> field found in {}"` bail message.
    ///
    /// Pinning the two literal names at this one site means a future
    /// re-spelling of the YAML schema (a rename to `agent_image:` /
    /// `builder_image:` under a v2 CRD) surfaces as a localized edit at
    /// one enum body rather than as four inline literals to hunt down
    /// across the two consumer modules and every future sibling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentImage => "agentImage",
            Self::BuilderImage => "builderImage",
        }
    }
}

impl fmt::Display for BuilderPoolField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a [`splice_builder_pool_field`] hit: the rewritten
/// content (with the trailing-newline normalization the pre-lift sites
/// each applied inline: `new_content.trim_end().to_string() + "\n"`),
/// plus the count of matching lines the splicer rewrote.
///
/// Pre-lift each per-line hit emitted its own
/// `info!("   Updated <field> to: {}", new_image)` inside the splice
/// loop, so a builder-pool file with two matching field lines produced
/// two announcement lines. The `match_count` slot preserves that
/// per-match emission contract when the outer wrapper re-emits the
/// announcement N times.
#[derive(Debug, PartialEq, Eq)]
pub struct BuilderPoolSpliceOutcome {
    /// The full rewritten YAML with the target field's value spliced
    /// on every matching line, its indent preserved, and the trailing
    /// newline normalized to exactly one.
    pub content: String,
    /// The number of lines the splicer rewrote. Pre-lift each hit
    /// emitted one `info!` announcement, so the outer
    /// [`update_builder_pool_field`] wrapper re-emits `match_count`
    /// announcements to preserve the exact per-hit acknowledgment
    /// contract every operator's log pipeline expects.
    pub match_count: usize,
}

/// Pure content-transform: rewrite every line whose `.trim()` starts
/// with `"<field>:"` to `"<indent><field>: <new_image>"` (indent
/// preserved), pass every other line through verbatim, and normalize
/// the trailing newline to exactly one. Returns
/// `Some(BuilderPoolSpliceOutcome { content, match_count })` on hit
/// or `None` when the target field appeared on no line.
///
/// No I/O, no tracing, no `tokio` context — the splicer is pure so
/// `#[cfg(test)]` can pin the exact spliced-line bytes, the indent-
/// preservation contract, and the miss-vs-hit outcome across the
/// full input-value space without a filesystem or a tracing
/// subscriber.
pub fn splice_builder_pool_field(
    content: &str,
    field: BuilderPoolField,
    new_image: &str,
) -> Option<BuilderPoolSpliceOutcome> {
    let field_name = field.as_str();
    let needle = format!("{}:", field_name);
    let mut match_count: usize = 0;
    let mut out = String::new();

    for line in content.lines() {
        if line.trim().starts_with(&needle) {
            // The indent-preserving `{indent}{field_name}: {new_image}
            // \n` splice rides the shared
            // `crate::repo::indent_preserving_kv_line` primitive —
            // sibling of the three `commands/{kenshi,kenshi_agent,
            // nix_builder}.rs::update_kustomization_image` `newTag:`
            // splices — so the byte shape stays pinned at one body
            // across the four sibling flows and any future refinement
            // of the indent-computation surface lands there.
            out.push_str(&crate::repo::indent_preserving_kv_line(
                line, field_name, new_image,
            ));
            match_count += 1;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    if match_count == 0 {
        return None;
    }

    Some(BuilderPoolSpliceOutcome {
        content: out.trim_end().to_string() + "\n",
        match_count,
    })
}

/// Emit the canonical builder-pool update stanza + splice the field +
/// write back. Fusion of the eight lines the two pre-lift call sites
/// each spelled inline (see the module-level doc comment for the exact
/// pre-lift shape).
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The splice grammar is pinned by [`splice_builder_pool_field`] under
/// `#[cfg(test)]`; a drift here (an indent-preservation regression, a
/// trailing-newline drift, a `line.trim()` semantic drift) surfaces as
/// a localized test failure at one site, not as silent YAML corruption
/// across the two builder-pool consumer flows.
///
/// # Announcement contract
///
/// The `"   Updated <field> to: <new_image>"` acknowledgment is emitted
/// exactly `match_count` times — once per rewritten line — preserving
/// the pre-lift per-hit contract every operator's log pipeline expects.
/// A builder-pool file with the target field on one line produces one
/// announcement; a hypothetical file with the field on two lines
/// produces two.
pub async fn update_builder_pool_field(
    builder_pool_path: &str,
    field: BuilderPoolField,
    registry: &str,
    new_tag: &str,
) -> Result<()> {
    let path = crate::repo::require_existing_labeled(builder_pool_path, "Builder pool file")?;

    info!("\u{1F4DD} Updating: {}", builder_pool_path);

    let content = crate::repo::read_text_async(path).await?;
    let new_image = crate::oci_manifest::image_reference(registry, new_tag);

    let outcome = match splice_builder_pool_field(&content, field, &new_image) {
        Some(o) => o,
        None => anyhow::bail!("No {} field found in {}", field, builder_pool_path),
    };

    for _ in 0..outcome.match_count {
        crate::info_updated_field!(field, new_image);
    }

    crate::repo::write_text_async(path, &outcome.content).await?;

    crate::info_indented_success!("Builder pool updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `as_str` accessor MUST render each variant to its canonical
    /// pre-lift YAML field name byte-for-byte. Pins the two literal
    /// spellings at ONE test so a future re-spelling of the schema
    /// (a rename to snake_case under a v2 CRD, a `spec.` prefix) fails
    /// at one assertion rather than at every downstream `contains(":")`
    /// splice.
    #[test]
    fn builder_pool_field_as_str_renders_canonical_yaml_field_names() {
        assert_eq!(BuilderPoolField::AgentImage.as_str(), "agentImage");
        assert_eq!(BuilderPoolField::BuilderImage.as_str(), "builderImage");
    }

    /// `Display` MUST forward to `as_str` verbatim so the `info!` and
    /// `anyhow::bail!` sites in [`update_builder_pool_field`] that
    /// interpolate the field via `{}` render exactly the same
    /// canonical YAML field name the splicer matches against.
    #[test]
    fn builder_pool_field_display_matches_as_str() {
        assert_eq!(format!("{}", BuilderPoolField::AgentImage), "agentImage");
        assert_eq!(
            format!("{}", BuilderPoolField::BuilderImage),
            "builderImage"
        );
    }

    /// The splicer MUST rewrite a single `agentImage:` line in place,
    /// preserving its two-space indent and normalizing the trailing
    /// newline. Pins the pre-lift
    /// `commands/kenshi_agent.rs::update_builder_pool_agent_image`
    /// per-line rewrite shape byte-for-byte.
    #[test]
    fn splice_agent_image_rewrites_single_line_preserving_indent() {
        let input = "kind: BuilderPool\nspec:\n  agentImage: ghcr.io/pleme-io/kenshi-agent:old\n";
        let out = splice_builder_pool_field(
            input,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:amd64-deadbeef",
        )
        .unwrap();
        assert_eq!(
            out.content,
            "kind: BuilderPool\nspec:\n  agentImage: ghcr.io/pleme-io/kenshi-agent:amd64-deadbeef\n"
        );
        assert_eq!(out.match_count, 1);
    }

    /// The splicer MUST rewrite a single `builderImage:` line in place,
    /// preserving its four-space indent and normalizing the trailing
    /// newline. Pins the pre-lift
    /// `commands/nix_builder.rs::update_builder_pool_builder_image`
    /// per-line rewrite shape byte-for-byte.
    #[test]
    fn splice_builder_image_rewrites_single_line_preserving_indent() {
        let input =
            "kind: BuilderPool\nspec:\n    builderImage: ghcr.io/pleme-io/nix-builder:old\n";
        let out = splice_builder_pool_field(
            input,
            BuilderPoolField::BuilderImage,
            "ghcr.io/pleme-io/nix-builder:amd64-cafef00d",
        )
        .unwrap();
        assert_eq!(
            out.content,
            "kind: BuilderPool\nspec:\n    builderImage: \
             ghcr.io/pleme-io/nix-builder:amd64-cafef00d\n"
        );
        assert_eq!(out.match_count, 1);
    }

    /// The splicer MUST return `None` when the target field does not
    /// appear on any line — the pre-lift `if !updated { anyhow::bail!
    /// ("No <field> field found in {}", ...) }` shape depends on this
    /// signal to fire its miss envelope rather than to silently write
    /// an unchanged file back to disk.
    #[test]
    fn splice_returns_none_when_field_absent() {
        let input = "kind: BuilderPool\nspec:\n  runnerImage: ghcr.io/pleme-io/runner:1.0\n";
        assert!(splice_builder_pool_field(
            input,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:amd64-deadbeef",
        )
        .is_none());
        assert!(splice_builder_pool_field(
            input,
            BuilderPoolField::BuilderImage,
            "ghcr.io/pleme-io/nix-builder:amd64-cafef00d",
        )
        .is_none());
    }

    /// The splicer MUST NOT rewrite the sibling field: an `agentImage`
    /// splice on a file that carries only `builderImage:` (and vice
    /// versa) returns `None`. Pins the closed-enum's byte-level
    /// separation so a future third variant cannot silently overwrite
    /// the wrong field via a `contains(":")` mis-fire.
    #[test]
    fn splice_isolates_target_field_from_its_sibling() {
        let input_agent_only =
            "kind: BuilderPool\nspec:\n  agentImage: ghcr.io/pleme-io/kenshi-agent:v1\n";
        assert!(splice_builder_pool_field(
            input_agent_only,
            BuilderPoolField::BuilderImage,
            "ghcr.io/pleme-io/nix-builder:amd64-deadbeef",
        )
        .is_none());

        let input_builder_only =
            "kind: BuilderPool\nspec:\n  builderImage: ghcr.io/pleme-io/nix-builder:v1\n";
        assert!(splice_builder_pool_field(
            input_builder_only,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:amd64-cafef00d",
        )
        .is_none());
    }

    /// The splicer MUST pass every non-matching line through verbatim:
    /// interior comments, blank lines, YAML anchors, whitespace-only
    /// runs, and the terminating newline all survive unchanged. Pins
    /// the pre-lift `else { new_content.push_str(line); new_content.
    /// push('\n'); }` verbatim-forwarding contract byte-for-byte so a
    /// splice does not accidentally strip an operator's carefully
    /// crafted comment.
    #[test]
    fn splice_forwards_non_matching_lines_verbatim() {
        let input = "# builder pool for kenshi-agent\n\
                     kind: BuilderPool\n\
                     metadata:\n  name: kenshi-agent-primary  # primary cluster\n\
                     spec:\n  agentImage: old:tag\n  # keep this comment\n\n  replicas: 3\n";
        let out = splice_builder_pool_field(
            input,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:new",
        )
        .unwrap();
        assert_eq!(
            out.content,
            "# builder pool for kenshi-agent\n\
             kind: BuilderPool\n\
             metadata:\n  name: kenshi-agent-primary  # primary cluster\n\
             spec:\n  agentImage: ghcr.io/pleme-io/kenshi-agent:new\n  # keep this comment\n\n  \
             replicas: 3\n"
        );
        assert_eq!(out.match_count, 1);
    }

    /// The splicer MUST rewrite every matching line and report the
    /// total `match_count`. A builder-pool CRD variant that carries
    /// the target field on multiple lines (a hypothetical multi-
    /// architecture pool that pins `builderImage:` per arch) MUST have
    /// every occurrence rewritten AND MUST see one `info!("   Updated
    /// <field> to: {}", ...)` announcement per rewritten line — the
    /// pre-lift per-hit contract every operator's log pipeline
    /// expects.
    #[test]
    fn splice_rewrites_every_matching_line_and_counts_hits() {
        let input = "kind: BuilderPool\n\
                     spec:\n  builderImage: old-a\n  peer:\n    builderImage: old-b\n";
        let out = splice_builder_pool_field(
            input,
            BuilderPoolField::BuilderImage,
            "ghcr.io/pleme-io/nix-builder:new",
        )
        .unwrap();
        assert_eq!(
            out.content,
            "kind: BuilderPool\n\
             spec:\n  builderImage: ghcr.io/pleme-io/nix-builder:new\n  peer:\n    \
             builderImage: ghcr.io/pleme-io/nix-builder:new\n"
        );
        assert_eq!(out.match_count, 2);
    }

    /// The splicer MUST normalize the trailing newline to exactly one:
    /// an input without a trailing newline gains one; an input with
    /// several trailing newlines collapses to one. Pins the pre-lift
    /// `new_content.trim_end().to_string() + "\n"` normalization
    /// byte-for-byte so a splice never leaves a builder-pool file with
    /// zero (git-unfriendly) or several (also git-unfriendly) trailing
    /// newlines.
    #[test]
    fn splice_normalizes_trailing_newline_to_exactly_one() {
        let no_trailing = "spec:\n  agentImage: old";
        let out = splice_builder_pool_field(
            no_trailing,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:new",
        )
        .unwrap();
        assert!(out.content.ends_with("agent:new\n"));
        assert!(!out.content.ends_with("agent:new\n\n"));

        let many_trailing = "spec:\n  agentImage: old\n\n\n\n";
        let out2 = splice_builder_pool_field(
            many_trailing,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:new",
        )
        .unwrap();
        assert!(out2.content.ends_with("agent:new\n"));
        assert!(!out2.content.ends_with("agent:new\n\n"));
    }

    /// The splicer's `.trim().starts_with("<field>:")` predicate MUST
    /// match a leading-whitespace-only prefix — an operator that
    /// carefully indented the field under `spec:` still gets it
    /// rewritten. But it MUST NOT match a similar-looking line where
    /// the trim-prefix is a non-empty non-whitespace run (e.g. a
    /// comment or a longer field name) — pins the pre-lift
    /// `.trim().starts_with` predicate boundary.
    #[test]
    fn splice_matches_indented_field_but_not_prefixed_variants() {
        let input =
            "# agentImage: not-a-field-decl\nspec:\n      agentImage: old\n  myAgentImage: nope\n";
        let out = splice_builder_pool_field(
            input,
            BuilderPoolField::AgentImage,
            "ghcr.io/pleme-io/kenshi-agent:new",
        )
        .unwrap();
        assert_eq!(
            out.content,
            "# agentImage: not-a-field-decl\nspec:\n      agentImage: \
             ghcr.io/pleme-io/kenshi-agent:new\n  myAgentImage: nope\n"
        );
        assert_eq!(out.match_count, 1);
    }

    /// The splicer MUST forward the `new_image` slot verbatim: a value
    /// carrying a colon (`registry:tag`), a slash-delimited path
    /// (`ghcr.io/org/name`), a plus-tagged suffix
    /// (`ghcr.io/org/name:amd64-deadbeef+build.1`), or a
    /// digest-addressed reference
    /// (`ghcr.io/org/name@sha256:0123...`) all travel through
    /// unchanged. Pins the pre-lift inline
    /// `format!("{}<field>: {}\n", indent_str, new_image)` behavior
    /// so a future digest-pinned CRD variant flows through the same
    /// splicer without a per-caller escape.
    #[test]
    fn splice_forwards_new_image_slot_verbatim() {
        let input = "spec:\n  builderImage: old\n";
        for image in [
            "ghcr.io/pleme-io/nix-builder:amd64-deadbeef",
            "ghcr.io/pleme-io/nix-builder:amd64-deadbeef+build.1",
            "ghcr.io/pleme-io/nix-builder@sha256:\
             0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let out =
                splice_builder_pool_field(input, BuilderPoolField::BuilderImage, image).unwrap();
            assert_eq!(
                out.content,
                format!("spec:\n  builderImage: {}\n", image),
                "the new_image slot must forward verbatim: {image}"
            );
        }
    }

    /// Whole-module shield: no source line under `cli/src/commands/`
    /// (excluding this module itself) may spell the pre-lift stanza's
    /// load-bearing opening — `require_existing_labeled(<...>,
    /// "Builder pool file")` — inline any more. Every builder-pool
    /// edit-preamble must route through [`update_builder_pool_field`]
    /// so a future refinement of the `"Builder pool file"` label,
    /// the announcement grammar, the miss envelope, the indent-
    /// preserving splice, or the trailing acknowledgment reaches all
    /// consumers by construction rather than through inline literal
    /// edits that inevitably drift.
    #[test]
    fn no_command_module_still_spells_raw_builder_pool_file_require() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip the primitive's own home module — its body legitimately
            // spells the label literal.
            if path.file_name().and_then(|n| n.to_str()) == Some("builder_pool_edit.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("require_existing_labeled(")
                    && line.contains("\"Builder pool file\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `require_existing_labeled(<...>, \"Builder pool file\")` stanza(s) \
             survive under `commands/` — route each through \
             `crate::commands::builder_pool_edit::update_builder_pool_field` instead:\n{:#?}",
            offenders
        );
    }

    /// Positive half of the shield: the two pre-lift consumer modules
    /// MUST each forward through
    /// `crate::commands::builder_pool_edit::update_builder_pool_field(`
    /// at least the pre-lift call-site count of times, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// label literal" scan trivially satisfied by absence but the
    /// positive count still fails.
    ///
    /// Pre-lift census: `commands/kenshi_agent.rs` called
    /// `update_builder_pool_agent_image` twice (primary + secondary
    /// cluster builder pools); `commands/nix_builder.rs` called
    /// `update_builder_pool_builder_image` twice (primary + secondary
    /// cluster builder pools).
    #[test]
    fn every_prelift_module_forwards_through_update_builder_pool_field() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("kenshi_agent.rs", 2), ("nix_builder.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("builder_pool_edit::update_builder_pool_field(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} builder-pool edit call \
                 site(s) through \
                 `crate::commands::builder_pool_edit::update_builder_pool_field(`; \
                 found {forwards}. A dropped call would leave the negative raw-label \
                 scan satisfied by absence.",
            );
        }
    }

    /// Whole-module shield: the pre-lift per-field wrapper function
    /// names (`update_builder_pool_agent_image`,
    /// `update_builder_pool_builder_image`) MUST no longer be declared
    /// as `async fn` bodies in the two consumer modules. Both bodies
    /// were byte-identical up to `agentImage` vs `builderImage`; the
    /// fusion primitive now owns that shape, so leaving either
    /// wrapper behind re-introduces the duplication the lift redeemed.
    #[test]
    fn no_command_module_still_declares_per_field_wrapper_fn() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let offenders: Vec<(&str, &str)> = [
            (
                "kenshi_agent.rs",
                "async fn update_builder_pool_agent_image(",
            ),
            (
                "nix_builder.rs",
                "async fn update_builder_pool_builder_image(",
            ),
        ]
        .into_iter()
        .filter(|(file, needle)| {
            let path = commands_dir.join(file);
            let source = std::fs::read_to_string(&path).unwrap();
            source.contains(needle)
        })
        .collect();
        assert!(
            offenders.is_empty(),
            "the pre-lift per-field wrapper function(s) survived — the fusion \
             primitive `crate::commands::builder_pool_edit::update_builder_pool_field` \
             now owns that shape and the two wrappers must be dropped so a future \
             sibling can't fork them again: {:#?}",
            offenders
        );
    }
}
