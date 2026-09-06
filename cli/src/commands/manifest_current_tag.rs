//! Read the current `images[0].newTag` string from a Kustomize manifest.
//!
//! Two pre-lift sibling nine-line stanzas — one at
//! `commands/deploy.rs::execute` (applied against the caller's
//! `kustomization_path`) and one at
//! `commands/github_runner_ci.rs::execute` (applied against the
//! caller's `manifest_path`) — each spelled the same verbatim shape,
//! differing only in the two per-caller closure-parameter names
//! (`image` vs `img`, `tag_val` vs `tag`) and the `ok_or_else` error
//! literal (`"kustomization.yaml"` vs `"manifest"`):
//!
//! ```ignore
//! let yaml: serde_yaml::Value = crate::repo::read_yaml_async(<path>).await?;
//! let old_tag = yaml
//!     .get("images")
//!     .and_then(|images| images.as_sequence())
//!     .and_then(|seq| seq.first())
//!     .and_then(|image| image.get("newTag"))
//!     .and_then(|tag_val| tag_val.as_str())
//!     .ok_or_else(|| anyhow::anyhow!("Could not find images[0].newTag in <literal>"))?
//!     .to_string();
//! ```
//!
//! Both flows extract the SAME value: the current `images[0].newTag`
//! string used verbatim by the two downstream calls
//! [`crate::commands::manifest_configmap_git_sha_sync::sync_manifest_tag_and_configmap_git_sha`]
//! and
//! [`crate::commands::manifest_push::commit_and_push_manifest_with_progress`]
//! as the `old_tag` argument that anchors the write against the
//! observed pre-image. The value is functionally identical on both
//! sides — the same YAML field, from the same Kustomize
//! `images[0].newTag` shape — and the two callers only diverged on
//! the two immaterial names above and the one drift-prone error
//! literal.
//!
//! Post-lift the read-and-extract-old-tag preamble lives at ONE
//! typed boundary: [`read_current_new_tag`] takes a `&Path` and
//! returns the current `images[0].newTag` string, threading the
//! caller's `path.display()` through BOTH the read envelope
//! ([`crate::repo::read_text_async`] via [`crate::repo::read_yaml_async`])
//! AND the not-found envelope. An operator diagnosing a missing
//! `images[0].newTag` field now sees the actual manifest path in the
//! failure message — a strict improvement over the pre-lift literal
//! `"kustomization.yaml"` / `"manifest"` that could drift from the
//! actual `path` argument silently, the same drift-window the
//! sibling [`crate::repo::read_text_async`] docs already name for the
//! `.context("Failed to read <literal>")` shape it replaced.
//!
//! Sibling of `commands/manifest_configmap_git_sha_sync.rs` and
//! `commands/manifest_push.rs` — same visual-grammar-fusion pattern
//! applied to the READ preamble of the single-manifest deployment
//! flow. The three primitives now partition the single-manifest
//! deployment surface: this module owns the read+extract preamble,
//! `manifest_configmap_git_sha_sync` owns the paired write step,
//! `manifest_push` owns the commit-and-push step. A future consumer
//! that reaches for the wrong stage fails at the type boundary
//! rather than by silent log-drift.

use anyhow::{anyhow, Result};
use std::path::Path;

/// The canonical `Could not find images[0].newTag in {path}` failure
/// prefix the primitive emits when the parsed manifest is missing
/// the `images[0].newTag` field. Named as a `const` so a future
/// re-phrasing of the diagnostic flows through one edit rather than
/// through two inline literal edits; also the anchor the caller
/// shield below matches against.
pub(crate) const MISSING_NEW_TAG_ERROR_PREFIX: &str = "Could not find images[0].newTag in";

/// Read the file at `path` as YAML, then return the current
/// `images[0].newTag` string.
///
/// Fusion primitive over the two sibling nine-line stanzas the
/// single-manifest deployment flows in
/// `commands/{deploy,github_runner_ci}.rs` each spelled inline (see
/// the [module docs](self) for the pre-lift shape). The parsed
/// value is walked at an OPEN [`serde_yaml::Value`] target — the
/// same shape [`crate::repo::read_yaml_async`]'s test at
/// `read_yaml_async_parses_at_open_serde_yaml_value_for_get_chain_consumers`
/// already pins for both consumer sites, so a regression that
/// specialized the primitive to a closed struct would surface at
/// that test AND at the byte-oracle tests below rather than as a
/// silent drift.
///
/// # Envelope
///
/// Read failure surfaces through [`crate::repo::read_yaml_async`]'s
/// canonical `Failed to read {path}` / `Failed to parse {path} as
/// YAML` envelope. Not-found failure (a well-formed YAML file that
/// lacks the `images[0].newTag` shape) surfaces
/// `Could not find images[0].newTag in {path}` — the operator's next
/// step in both arms is `ls` / `cat` on the exact path.
pub async fn read_current_new_tag(path: &Path) -> Result<String> {
    let yaml: serde_yaml::Value = crate::repo::read_yaml_async(path).await?;
    yaml.get("images")
        .and_then(|images| images.as_sequence())
        .and_then(|seq| seq.first())
        .and_then(|image| image.get("newTag"))
        .and_then(|tag_val| tag_val.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("{} {}", MISSING_NEW_TAG_ERROR_PREFIX, path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Happy path: a well-formed Kustomize manifest with an
    /// `images:` sequence whose first entry carries a `newTag:`
    /// scalar returns the tag string verbatim.
    #[tokio::test]
    async fn read_current_new_tag_returns_first_images_new_tag() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        tokio::fs::write(
            &path,
            "images:\n  - name: ghcr.io/pleme-io/github-runner\n    newTag: amd64-abcdef0\n",
        )
        .await
        .expect("seed write");

        let tag = read_current_new_tag(&path).await.expect("must extract");
        assert_eq!(tag, "amd64-abcdef0");
    }

    /// A well-formed YAML file whose top level lacks the `images:`
    /// key surfaces the canonical `Could not find images[0].newTag
    /// in {path}` error, with the caller's `path.display()` threaded
    /// through — a strict improvement over the pre-lift literals
    /// (`"kustomization.yaml"` at one caller, `"manifest"` at the
    /// other) that could drift from the actual argument silently.
    #[tokio::test]
    async fn read_current_new_tag_missing_images_key_surfaces_path_in_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        tokio::fs::write(&path, "resources:\n  - deployment.yaml\n")
            .await
            .expect("seed write");

        let err = read_current_new_tag(&path).await.expect_err("must reject");
        let rendered = format!("{err}");
        assert!(
            rendered.contains(MISSING_NEW_TAG_ERROR_PREFIX),
            "error must carry canonical prefix, got: {rendered}"
        );
        assert!(
            rendered.contains(&path.display().to_string()),
            "error must thread the offending path.display() through, got: {rendered}"
        );
    }

    /// A well-formed YAML file whose `images:` sequence is empty
    /// surfaces the same canonical not-found envelope — the
    /// `.and_then(|seq| seq.first())` step collapses to `None` and
    /// the primitive routes through the same `ok_or_else` arm as
    /// the missing-key case.
    #[tokio::test]
    async fn read_current_new_tag_empty_images_seq_surfaces_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        tokio::fs::write(&path, "images: []\n")
            .await
            .expect("seed write");

        let err = read_current_new_tag(&path).await.expect_err("must reject");
        let rendered = format!("{err}");
        assert!(
            rendered.contains(MISSING_NEW_TAG_ERROR_PREFIX),
            "empty images sequence must surface the not-found envelope, \
             got: {rendered}"
        );
    }

    /// A well-formed YAML file whose first `images[]` entry lacks a
    /// `newTag:` field surfaces the same canonical not-found
    /// envelope — pins that the primitive rejects a partial-image
    /// entry rather than silently returning an empty or `null`
    /// string.
    #[tokio::test]
    async fn read_current_new_tag_missing_new_tag_field_surfaces_not_found() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        tokio::fs::write(&path, "images:\n  - name: ghcr.io/pleme-io/x\n")
            .await
            .expect("seed write");

        let err = read_current_new_tag(&path).await.expect_err("must reject");
        let rendered = format!("{err}");
        assert!(
            rendered.contains(MISSING_NEW_TAG_ERROR_PREFIX),
            "missing newTag field must surface the not-found envelope, \
             got: {rendered}"
        );
    }

    /// A missing file surfaces the canonical
    /// [`crate::repo::read_yaml_async`] read envelope
    /// (`Failed to read {path}`) — pins that the primitive does NOT
    /// swallow read errors into the not-found arm. The two failure
    /// modes stay distinct so an operator's next step (`ls` for a
    /// read error, `cat` for a not-found error) diverges correctly.
    #[tokio::test]
    async fn read_current_new_tag_missing_file_surfaces_read_envelope() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.yaml");

        let err = read_current_new_tag(&path).await.expect_err("must reject");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("Failed to read"),
            "read failure must surface the canonical read envelope, got: {rendered}"
        );
        assert!(
            !rendered.contains(MISSING_NEW_TAG_ERROR_PREFIX),
            "read failure must NOT be classified as a not-found error, got: {rendered}"
        );
    }

    /// Canonical const carries its exact pre-lift byte sequence.
    /// A future edit that touched the const without updating the
    /// mirrored inline literal in the caller-shield below cannot
    /// silently proceed.
    #[test]
    fn canonical_error_prefix_carries_pre_lift_byte_sequence() {
        assert_eq!(
            MISSING_NEW_TAG_ERROR_PREFIX,
            "Could not find images[0].newTag in"
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift extraction chain
    /// `.and_then(|images| images.as_sequence())` inline any more.
    /// Every read of the current `images[0].newTag` in a deployment
    /// flow must resolve through [`read_current_new_tag`] so a
    /// future drift on the walk shape, the not-found envelope, or
    /// the path-threading in the error message flows to both flows
    /// from one edit.
    ///
    /// The forbidden shape is reconstructed at test time from the
    /// bare tokens `images` / `as_sequence` so this shield's own
    /// source text does not false-match itself. Every hit routes
    /// through [`crate::test_support::code_line_hits`] for
    /// anti-comment-line-self-match discipline.
    #[test]
    fn no_command_module_still_spells_raw_images_as_sequence_walk() {
        use std::path::PathBuf;
        let forbidden = format!(".and_then(|{}| {}.as_sequence())", "images", "images");
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Skip THIS module — its own byte-oracle test strings
            // mention the pre-lift walk verbatim by design.
            if path.file_name().and_then(|n| n.to_str()) == Some("manifest_current_tag.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `{}` walk stanza(s) survive under `commands/` — \
             route each through `crate::commands::\
             manifest_current_tag::read_current_new_tag(path)` \
             instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift not-found literal
    /// `Could not find images[0].newTag in <literal>` inline any
    /// more. Every not-found envelope must resolve through
    /// [`read_current_new_tag`] so a future drift on the diagnostic
    /// prose flows from one edit rather than through two
    /// diverging literals.
    #[test]
    fn no_command_module_still_spells_raw_not_found_literal() {
        use std::path::PathBuf;
        let forbidden = format!("{} images", "Could not find");
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, Vec<String>)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("manifest_current_tag.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let hits = crate::test_support::code_line_hits(&source, &forbidden);
            if !hits.is_empty() {
                offenders.push((path, hits));
            }
        }
        assert!(
            offenders.is_empty(),
            "pre-lift `{}...` not-found literal(s) survive under \
             `commands/` — route each through \
             `crate::commands::manifest_current_tag::\
             read_current_new_tag(path)` instead:\n{:#?}",
            forbidden,
            offenders,
        );
    }

    /// Positive-half delegation shield: the two consumer modules
    /// MUST each carry exactly one call to
    /// [`read_current_new_tag`]. Guards against a silent removal
    /// of the current-tag read from a consumer (a refactor that
    /// accidentally dropped the read while migrating a step, a
    /// merge that lost the call in a conflict resolution). The two
    /// downstream calls
    /// (`sync_manifest_tag_and_configmap_git_sha` and
    /// `commit_and_push_manifest_with_progress`) both take `old_tag`
    /// as their second positional argument, so a flow that ran to
    /// completion without the read would either fail to type-check
    /// or silently pass a stale value.
    #[test]
    fn every_manifest_current_tag_consumer_delegates_through_primitive() {
        // Match the CALL-syntax `(` suffix so a leading `use` import
        // line carrying the identifier without a call does not
        // double-count against the per-consumer invocation invariant.
        let needle = "read_current_new_tag(";
        for (path, source) in [
            ("commands/deploy.rs", include_str!("deploy.rs")),
            (
                "commands/github_runner_ci.rs",
                include_str!("github_runner_ci.rs"),
            ),
        ] {
            let count = source.matches(needle).count();
            assert_eq!(
                count, 1,
                "`{path}` must invoke `crate::commands::\
                 manifest_current_tag::{needle}` exactly once for \
                 its images[0].newTag read preamble; found {count}. \
                 A flow that runs past this preamble without emitting \
                 the read either fails to compile (the downstream \
                 `old_tag` binding is unbound) or, if a stale local \
                 shadows the read, silently propagates a wrong \
                 pre-image to the sync + commit-and-push writes."
            );
        }
    }
}
