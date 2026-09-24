//! Kustomization overlay edit-preamble helper.
//!
//! Shape-adapter over the three-line `require_existing_labeled + info!("📝
//! Updating: {}", <path>) + read_text_async` preamble that opens every
//! kustomization-overlay `update_*` helper across `commands/{kenshi (×1
//! `update_kustomization_image`), kenshi_agent (×1
//! `update_kustomization_image`), nix_builder (×2:
//! `update_kustomization_image` + `update_kenshi_builder_image`), push
//! (×1 `update_kustomization`)}.rs`. Four of those five helpers spelled
//! — VERBATIM, modulo the surrounding blank / `// Read content` comment
//! lines — the same three-piece stanza immediately after the `<path>:
//! &str, <registry>: &str, <new_tag>: &str` parameter list:
//!
//! ```text
//! let path = crate::repo::require_existing_labeled(kustomization_path, "Kustomization file")?;
//!
//! info!("📝 Updating: {}", kustomization_path);
//!
//! // Read content
//! let content = crate::repo::read_text_async(path).await?;
//! ```
//!
//! Four occurrences of an identical shape past THEORY §VI.1's
//! three-is-a-law threshold; this module is the law-redeeming extraction.
//! The fifth site in `commands/push.rs::update_kustomization` spelled a
//! near-identical stanza with the same `"Kustomization file"` label but
//! a slightly divergent `"📝 Updating kustomization: <path>"` announcement
//! (with the redundant `kustomization: ` prefix already implied by the
//! path suffix and file kind). Post-lift the five sites collapse to the
//! canonical `"📝 Updating: <path>"` grammar so the operator sees one
//! announcement shape across every kustomization edit path in forge.
//! Post-lift each helper opens with a single `(path, content) =
//! kustomization_edit::open_for_update(kustomization_path).await?` binding
//! and inherits the canonical `"Kustomization file"` existence-check label,
//! the `"📝 Updating: <path>"` operator-facing announcement, and the
//! `read_text_async` load surface through one site.
//!
//! # The load-bearing `"Kustomization file"` existence-check label
//!
//! Every pre-lift site passed the identical `"Kustomization file"`
//! literal into [`crate::repo::require_existing_labeled`], so every miss
//! arm rendered as `"Kustomization file not found: <path>"`. Consolidating
//! the label at ONE body means a future refinement of the miss envelope
//! (a `next-step ls {path}` suggestion, a `Kustomization overlay file not
//! found — was the overlay generated? Try `flux reconcile`.` remediation
//! hint, a typed `KustomizationMissing { path }` error branch) reaches
//! all four consumers by construction rather than through four inline
//! literal edits that inevitably drift.
//!
//! # Distinct from the sibling `builder_pool_edit` shape
//!
//! `commands/builder_pool_edit.rs::update_builder_pool_field` carries a
//! near-identical three-line preamble but with a `"Builder pool file"`
//! existence-check label + `builder_pool_path` variable rather than
//! `kustomization_path`. The label semantically distinguishes a
//! Kustomization overlay (opens with `apiVersion:` + `kind:
//! Kustomization`) from a Builder-pool CRD instance (opens with `kind:
//! BuilderPool`) so a future miss envelope refinement per file-kind
//! (`Kustomization overlay file not found — was the overlay generated?`
//! vs. `Builder pool file not found — was the CRD applied?`) can diverge
//! without rewriting either primitive. This module is scoped to the
//! Kustomization-overlay label; the sibling `builder_pool_edit` module
//! (redeeming the reservation this comment previously held) owns the
//! `"Builder pool file"` label and the `agentImage:` / `builderImage:`
//! YAML field splice.
//!
//! # `info!` at the primitive body, byte-oracle writer alongside
//!
//! The pre-lift sites each emitted the announcement through
//! [`tracing::info!`] at the call site, which meant per-command
//! `RUST_LOG=forge::commands::kenshi=info` filter routing distinguished
//! the four call sites. Post-lift the `info!` collapses to this
//! primitive's `module_path` (`forge::commands::kustomization_edit`) —
//! the same tradeoff every sibling fusion primitive
//! (`cluster_overlay_release_preamble`, `release_commit`, `step_header`)
//! already accepted, because the operator-facing routing is by workflow
//! phase (`preamble`, `commit`, `step-header`, `kustomization edit`), not
//! by parent command module. Callers that need a command-scoped filter
//! reach for the [`tracing::span!`] mechanism at the outer flow, not by
//! duplicating the emission grammar.
//!
//! The byte-oracle sibling [`write_kustomization_update_announcement`]
//! captures the exact announcement line's bytes (the `📝` glyph, the
//! one-space gap, the `Updating: ` label, the trailing newline) so a
//! future drift to a different glyph, label, or separator surfaces as a
//! localized test failure rather than as silent log-drift across four
//! kustomization-edit sites.

use anyhow::Result;
use std::fmt;
use std::io;
use std::path::Path;
use tracing::info;

/// Emit the canonical `"📝 Updating: <path>\n"` announcement bytes to
/// `w`, byte-for-byte identical to the single-line stanza the four
/// kustomization-edit helpers each spelled inline before invoking
/// [`crate::repo::read_text_async`].
///
/// The direct-writer variant exists so the fail-before-pass tests can
/// pin the exact emitted bytes (the `📝` glyph U+1F4DD, the one-space
/// gap, the `Updating: ` label, the trailing newline) without capturing
/// a tracing subscriber and without racing an ambient logger — the same
/// split [`crate::nonfatal_warning::write_nonfatal_warn`] carries against
/// [`crate::warn_nonfatal!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `path` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (used by all four pre-lift call
/// sites), a `&Path::display()` wrapper, a `PathBuf`-borrowed
/// `.display()`, and a future typed `KustomizationPath` newtype all flow
/// through the same writer without a per-caller `.to_string()`
/// intermediate.
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed `open_for_update`, and
                    // a future `collect_kustomization_edits` audit
                    // sibling will consume it directly.
pub fn write_kustomization_update_announcement<W: io::Write>(
    w: &mut W,
    path: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "\u{1F4DD} Updating: {}", path)
}

/// Open a kustomization overlay file for update: assert it exists (with
/// the canonical `"Kustomization file"` label on the miss arm), emit the
/// `📝 Updating: <path>` announcement via [`tracing::info!`], and load
/// its full text through [`crate::repo::read_text_async`]. Returns the
/// `(path, content)` pair the caller feeds into its per-helper line-by-
/// line transform loop.
///
/// The returned `&Path` is borrowed from `kustomization_path` (inherited
/// from [`crate::repo::require_existing_labeled`]'s
/// `path: &'a str -> Result<&'a Path>` signature) so it remains valid for
/// the duration of the caller's `write_text_async(path, ...)` call on the
/// transformed content without a `.to_owned()` intermediate.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The announcement grammar is pinned by
/// [`write_kustomization_update_announcement`] under `#[cfg(test)]`; a
/// drift here (a glyph change, a `"Updating: "` label change, an
/// indentation change, a trailing-newline change) surfaces as a
/// localized test failure at one site, not as silent log-drift across
/// four kustomization-edit flows.
pub async fn open_for_update(kustomization_path: &str) -> Result<(&Path, String)> {
    let path = crate::repo::require_existing_labeled(kustomization_path, "Kustomization file")?;
    info!("\u{1F4DD} Updating: {}", kustomization_path);
    let content = crate::repo::read_text_async(path).await?;
    Ok((path, content))
}

/// Emit the canonical trailing-newline-normalized closing bytes of a
/// kustomization overlay to `w`: `unfinalized.trim_end() + "\n"`,
/// byte-for-byte identical to the two-line `let final_content = <var>
/// .trim_end().to_string() + "\n"; write_text_async(path, &final_content)
/// .await?;` closure the four `update_*` helpers each spelled inline
/// before invoking [`crate::info_indented_success!`].
///
/// The direct-writer variant exists so the fail-before-pass tests can
/// pin the exact emitted bytes (the trim of every trailing ASCII
/// whitespace character, then exactly one U+000A `\n`) without touching
/// the filesystem or racing an ambient logger — the same split
/// [`write_kustomization_update_announcement`] carries against
/// [`open_for_update`].
#[allow(dead_code)] // Byte-oracle peer of `finalize_and_announce`: see
                    // the module docs for the writer/tracing split.
pub fn write_finalized_content_bytes<W: io::Write>(w: &mut W, unfinalized: &str) -> io::Result<()> {
    w.write_all(unfinalized.trim_end().as_bytes())?;
    w.write_all(b"\n")
}

/// Close a kustomization overlay after update: normalize the caller's
/// unfinalized content (`unfinalized.trim_end() + "\n"`), write the file
/// through [`crate::repo::write_text_async`], and emit the operator-
/// facing `"   ✅ <message>"` sub-step success acknowledgement via
/// [`crate::info_indented_success!`]. The natural closing sibling of
/// [`open_for_update`]: every kustomization-overlay `update_*` helper
/// opens with `open_for_update` and closes with `finalize_and_announce`.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The trim-then-append-newline finalize step is pinned by
/// [`write_finalized_content_bytes`] under `#[cfg(test)]`; a drift here
/// (a `.trim()` that also removes leading whitespace, a `\r\n` line-
/// ending flavor, a dropped trailing newline) surfaces as a localized
/// test failure at one site, not as silent trailing-whitespace drift
/// across four kustomization-edit flows.
///
/// The announcement grammar (`"   ✅ <message>\n"`) is inherited from
/// [`crate::info_indented_success!`] and byte-pinned in
/// `crate::indented_success_step::tests`.
pub async fn finalize_and_announce(
    path: &Path,
    unfinalized: &str,
    success_message: &str,
) -> Result<()> {
    let final_content = unfinalized.trim_end().to_string() + "\n";
    crate::repo::write_text_async(path, &final_content).await?;
    crate::info_indented_success!("{}", success_message);
    Ok(())
}

/// Splice the `newTag:` value of the FIRST `images[]` entry whose `name:`
/// line satisfies `image_name_line_matches`, returning the transformed
/// content and whether any splice happened.
///
/// Walks `content` line-by-line: enters the target block on any line
/// containing `name:` AND satisfying the predicate; exits on the next
/// line whose trimmed prefix is `- name:` and which does NOT satisfy the
/// predicate; splices `newTag:` within the target block via
/// [`crate::repo::indent_preserving_kv_line`] so the pre-lift
/// `{indent}newTag: {new_tag}\n` byte shape lands at ONE body. Every
/// non-splice line is emitted verbatim with a `\n` terminator, matching
/// the pre-lift `.lines()`-driven passthrough shape.
///
/// # Consolidated pre-lift stanza
///
/// Fusion primitive over the pre-lift `for line in content.lines() { …
/// in_<block>_image toggle + newTag splice + passthrough … }` walk that
/// three sibling `commands/{kenshi,kenshi_agent,nix_builder}.rs::
/// update_kustomization_image` bodies each spelled inline (~30 lines
/// each, verbatim modulo the per-site enter/exit predicate) before this
/// module owned it. The three pre-lift openers
/// (`let mut in_kenshi_image = false;`,
/// `let mut in_kenshi_agent_image = false;`,
/// `let mut in_target_image = false;`) collapse onto the single
/// `in_target_image` flag inside this body.
///
/// # Predicate is called for both enter and exit
///
/// Pre-lift `commands/kenshi.rs` used
/// `line.contains("kenshi") && !line.contains("kenshi-agent")` on the
/// enter arm but `!line.contains(registry)` on the exit arm; the two
/// arms could disagree on a `- name: ghcr.io/…/kenshi-agent` line (the
/// enter predicate rejects it, but the exit predicate would ALSO reject
/// leaving because the line contains the `ghcr.io/…/kenshi` registry
/// substring). This body threads ONE predicate through both arms so a
/// caller's enter and exit stay coherent by construction — a defect the
/// pre-lift kenshi flow carried latently and this lift removes. On real
/// overlay inputs (a single `kenshi` image and no adjacent
/// `kenshi-agent` block sharing the same file) the byte-for-byte output
/// is identical.
///
/// # Sibling per-line splice
///
/// The `newTag:` splice rides [`crate::repo::indent_preserving_kv_line`]
/// — the same primitive the sibling
/// `commands/builder_pool_edit::splice_builder_pool_field` uses for its
/// `agentImage:` / `builderImage:` YAML field splice — so a future
/// refinement of the indent-computation or per-line YAML shape lands at
/// ONE body across the four sibling flows.
pub fn splice_first_images_new_tag_content<F: Fn(&str) -> bool>(
    content: &str,
    image_name_line_matches: F,
    new_tag: &str,
) -> (String, bool) {
    let mut new_content = String::new();
    let mut updated = false;
    let mut in_target_image = false;

    for line in content.lines() {
        if line.contains("name:") && image_name_line_matches(line) {
            in_target_image = true;
        }
        if in_target_image && line.trim().starts_with("- name:") && !image_name_line_matches(line) {
            in_target_image = false;
        }

        if in_target_image && line.contains("newTag:") {
            new_content.push_str(&crate::repo::indent_preserving_kv_line(
                line, "newTag", new_tag,
            ));
            updated = true;
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    (new_content, updated)
}

/// Open a kustomization overlay, splice the FIRST `images[]` entry's
/// `newTag:` matching `image_name_line_matches`, emit
/// [`crate::info_updated_field!`] with `updated_field_label` on splice,
/// bail on miss with `"No <missing_target_label> entry found in images[]
/// in <path>"`, and finalize + announce the write.
///
/// # Consolidated pre-lift stanza
///
/// Fusion primitive over the pre-lift `open_for_update + walk + emit +
/// bail-or-finalize` closing sequence that
/// `commands/{kenshi,nix_builder}.rs::update_kustomization_image` each
/// spelled inline. The sibling
/// `commands/kenshi_agent.rs::update_kustomization_image` reaches for
/// only the pure [`splice_first_images_new_tag_content`] transform
/// because it interleaves an AGENT_IMAGE env-var splice into the same
/// open→finalize span and its bail phrase names both branches.
///
/// # Canonicalized miss envelope
///
/// The unified miss envelope pins the operator-facing miss line at ONE
/// grammar across kenshi and nix-builder. The pre-lift nix-builder
/// stanza rendered `"No images[] entry found for <registry> in <path>"`
/// with the same semantic content in a different word order; the
/// unification here means a future refinement (a
/// `next-step ls {path}` suggestion, a typed
/// `KustomizationImageMissing { path, target }` variant) reaches both
/// consumers by construction.
pub async fn splice_first_images_new_tag<F: Fn(&str) -> bool>(
    kustomization_path: &str,
    image_name_line_matches: F,
    new_tag: &str,
    updated_field_label: &str,
    missing_target_label: &str,
) -> Result<()> {
    let (path, content) = open_for_update(kustomization_path).await?;
    let (new_content, updated) =
        splice_first_images_new_tag_content(&content, image_name_line_matches, new_tag);
    if updated {
        crate::info_updated_field!(updated_field_label, new_tag);
    } else {
        anyhow::bail!(
            "No {} entry found in images[] in {}",
            missing_target_label,
            kustomization_path
        );
    }
    finalize_and_announce(path, &new_content, "Kustomization updated").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact announcement bytes: `📝` (U+1F4DD, 4 bytes F0 9F
    /// 93 9D), one ASCII space, the `Updating: ` label, the interpolated
    /// path Display, then `\n`. A future refactor that swapped the
    /// glyph, dropped the one-space gap, retitled the label, or dropped
    /// the trailing newline regresses this assertion at one site rather
    /// than silently across the four kustomization-edit consumers.
    #[test]
    fn write_kustomization_update_announcement_emits_prefix_path_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_kustomization_update_announcement(&mut buf, &"clusters/primary/kustomization.yaml")
            .unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x93\x9d Updating: clusters/primary/kustomization.yaml\n"
        );
    }

    /// Human-readable pin of the exact grammar so a future reader can
    /// eyeball the render without decoding UTF-8. Doubles as a
    /// Display-forwarding pin: the `&dyn Display` slot receives a path
    /// with interior slashes and dots; the interior punctuation MUST
    /// survive verbatim without the writer re-quoting or re-escaping the
    /// inner text.
    #[test]
    fn write_kustomization_update_announcement_forwards_display_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_kustomization_update_announcement(
            &mut buf,
            &"clusters/secondary/overlays/nix-builder/kustomization.yaml",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4DD} Updating: clusters/secondary/overlays/nix-builder/kustomization.yaml\n"
        );
    }

    /// The writer MUST forward a `Path::display()` wrapper without
    /// mediation — the future `open_for_update` caller that already
    /// carries a `&Path` (rather than the pre-lift `&str`) reaches for
    /// `path.display()` and lands in the exact same rendered bytes as
    /// the pre-lift `&str` call sites.
    #[test]
    fn write_kustomization_update_announcement_accepts_path_display() {
        let mut buf: Vec<u8> = Vec::new();
        let p = Path::new("clusters/primary/kustomization.yaml");
        write_kustomization_update_announcement(&mut buf, &p.display()).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F4DD} Updating: clusters/primary/kustomization.yaml\n"
        );
    }

    /// The `open_for_update` primitive MUST bail with the canonical
    /// `"Kustomization file not found: <path>"` miss envelope when the
    /// path does not exist — the pre-lift shape every call site
    /// inherited through [`crate::repo::require_existing_labeled`]. Pins
    /// the label at ONE test so a future re-wording of the miss envelope
    /// per file-kind (a `next-step ls {path}` suggestion, a `flux
    /// reconcile` remediation hint) reaches all four consumers from one
    /// edit rather than through four inline literal edits.
    #[tokio::test]
    async fn open_for_update_bails_with_kustomization_file_label_on_missing_path() {
        // Point at a path that cannot exist on any hermetic test
        // filesystem — the leading NUL segment is illegal in POSIX path
        // components so no legitimate file can shadow it.
        let missing = "/nonexistent/forge-test/kustomization-that-cannot-exist.yaml";
        let err = open_for_update(missing).await.unwrap_err();
        let rendered = format!("{}", err);
        assert!(
            rendered.starts_with("Kustomization file not found: "),
            "open_for_update miss envelope must open with `Kustomization file not found: ` \
             so the four consumer miss arms speak with one voice; got: {:?}",
            rendered
        );
        assert!(
            rendered.contains(missing),
            "open_for_update miss envelope must echo the offending path verbatim \
             so the operator can `ls {missing}` without scrolling; got: {:?}",
            rendered
        );
    }

    /// The `open_for_update` primitive MUST return the same `(path,
    /// content)` pair the pre-lift stanza produced — the returned `path`
    /// is the `&Path` view of the caller's `&str` (with the same
    /// lifetime, so the caller can pass it to `write_text_async` after
    /// its per-helper transform without a `.to_owned()`), and the
    /// returned `content` is the file's full UTF-8 text.
    #[tokio::test]
    async fn open_for_update_returns_path_and_content_on_hit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kustomization.yaml");
        let payload = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n";
        tokio::fs::write(&file, payload).await.unwrap();
        let file_str = file.to_str().unwrap();

        let (returned_path, content) = open_for_update(file_str).await.unwrap();
        assert_eq!(returned_path, file.as_path());
        assert_eq!(content, payload);
    }

    /// Whole-module shield: no source line under `cli/src/commands/` may
    /// spell the pre-lift 3-line stanza's opening literal
    /// `require_existing_labeled(<...>, "Kustomization file")` inline
    /// any more (excluding this module itself, which is the primitive's
    /// home). Every kustomization-overlay edit-preamble must route
    /// through [`open_for_update`] so a future refinement of the
    /// existence-check label reaches all consumers by construction.
    ///
    /// The `commands/builder_pool_edit.rs::update_builder_pool_field`
    /// sibling on the `"Builder pool file"` label is deliberately out
    /// of scope — see the module docs for why the two file-kinds are
    /// held apart.
    #[test]
    fn no_command_module_still_spells_raw_kustomization_file_require() {
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
            if path.file_name().and_then(|n| n.to_str()) == Some("kustomization_edit.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("require_existing_labeled(")
                    && line.contains("\"Kustomization file\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `require_existing_labeled(<...>, \"Kustomization file\")` \
             stanza(s) survive under `commands/` — route each through \
             `crate::commands::kustomization_edit::open_for_update` instead:\n{:#?}",
            offenders
        );
    }

    /// Pin the exact finalized-content bytes: every trailing ASCII
    /// whitespace character (spaces, tabs, and every flavor of newline)
    /// stripped from the input, then exactly one U+000A `\n` appended.
    /// A future refactor that swapped `.trim_end()` for `.trim()` (which
    /// also strips leading whitespace and would destroy YAML indentation
    /// of the first line), dropped the trailing newline, or added a
    /// `\r` before it regresses this assertion at one site rather than
    /// silently across the four kustomization-edit consumers.
    #[test]
    fn write_finalized_content_bytes_trims_trailing_ws_and_appends_single_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_finalized_content_bytes(
            &mut buf,
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\n\n",
        )
        .unwrap();
        assert_eq!(
            buf,
            b"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        );
    }

    /// Leading whitespace on the first line MUST be preserved verbatim
    /// — `.trim_end()` is asymmetric on purpose. A drift to `.trim()`
    /// would silently destroy YAML block indentation and pass every
    /// end-of-file test; this test pins the negative side.
    #[test]
    fn write_finalized_content_bytes_preserves_leading_indent() {
        let mut buf: Vec<u8> = Vec::new();
        write_finalized_content_bytes(&mut buf, "    - name: kenshi\n      newTag: amd64-abc\n\n")
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "    - name: kenshi\n      newTag: amd64-abc\n"
        );
    }

    /// The primitive MUST append exactly one `\n` even when the caller's
    /// unfinalized content ends with no newline at all — the pre-lift
    /// shape `<var>.trim_end().to_string() + "\n"` unconditionally
    /// appends. A drift to a conditional append (e.g. only when the
    /// input does not already end with `\n`) would leave a
    /// double-newline on some inputs and no-newline on others.
    #[test]
    fn write_finalized_content_bytes_appends_newline_when_input_has_none() {
        let mut buf: Vec<u8> = Vec::new();
        write_finalized_content_bytes(&mut buf, "kind: Kustomization").unwrap();
        assert_eq!(buf, b"kind: Kustomization\n");
    }

    /// The `finalize_and_announce` primitive MUST write the finalized
    /// bytes returned by the byte-oracle sibling to the target file
    /// path, then return `Ok(())` — the pre-lift shape every call site
    /// spelled with `let final_content = ...; write_text_async(...); ..
    /// info_indented_success!(...); Ok(())`.
    #[tokio::test]
    async fn finalize_and_announce_writes_finalized_content_and_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kustomization.yaml");
        // Seed a file that the primitive will overwrite; the seeded
        // content is a decoy so a mistakenly no-op write would leave
        // the decoy behind rather than the finalized content.
        tokio::fs::write(&file, "seeded-decoy").await.unwrap();

        finalize_and_announce(&file, "kind: Kustomization\n\n\n", "Kustomization updated")
            .await
            .unwrap();

        let written = tokio::fs::read_to_string(&file).await.unwrap();
        assert_eq!(written, "kind: Kustomization\n");
    }

    /// Whole-module shield: no source line under `cli/src/commands/`
    /// (excluding this module) may spell the pre-lift 2-line closing
    /// stanza `let final_content = <var>.trim_end().to_string() + "\n"`
    /// inline any more. Every kustomization-overlay finalize+write must
    /// route through [`finalize_and_announce`] so a future refinement
    /// of the trailing-newline contract (a `\r\n` flavor, a no-newline
    /// variant, a canonical two-newline separator) reaches all four
    /// consumers by construction.
    #[test]
    fn no_command_module_still_spells_raw_trim_end_finalize_stanza() {
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
            // Skip the primitive's own home module — its body and its
            // doc-comment prose legitimately quote the pre-lift stanza.
            if path.file_name().and_then(|n| n.to_str()) == Some("kustomization_edit.rs") {
                continue;
            }
            // Skip `builder_pool_edit.rs` — its
            // `splice_builder_pool_field` returns finalized content
            // through a `BuilderPoolSpliceOutcome { content, .. }`
            // struct field for a caller that writes the file and
            // announces success separately (the fusion primitive
            // `update_builder_pool_field` in the same module owns the
            // write + announce steps). The normalization step there
            // sits inside a pure content-transform, NOT the
            // write+announce closing stanza this shield targets.
            if path.file_name().and_then(|n| n.to_str()) == Some("builder_pool_edit.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains(".trim_end().to_string() + \"\\n\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `<var>.trim_end().to_string() + \"\\n\"` closing stanza(s) survive under \
             `commands/` — route each through \
             `crate::commands::kustomization_edit::finalize_and_announce` instead:\n{:#?}",
            offenders
        );
    }

    /// Positive half of the closing-stanza shield: the three pre-lift
    /// files under `commands/` MUST each forward through
    /// `crate::commands::kustomization_edit::finalize_and_announce(` at
    /// least the pre-lift count of times, so a migration that dropped a
    /// call site outright leaves the negative raw-stanza scan trivially
    /// satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_finalize_and_announce() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the current-tree
        // census). kenshi.rs and nix_builder.rs::update_kustomization_
        // image both migrated onto the fused `splice_first_images_new_
        // tag` primitive, which owns the finalize forward inside this
        // module — the direct forwards from those two call sites are
        // now subsumed there. kenshi_agent.rs still finalizes directly
        // because it interleaves an AGENT_IMAGE env-var splice into
        // the same open→finalize span. nix_builder.rs keeps one direct
        // forward from `update_kenshi_builder_image`.
        let expectations: &[(&str, usize)] = &[("kenshi_agent.rs", 1), ("nix_builder.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("kustomization_edit::finalize_and_announce(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} kustomization edit-finalize \
                 site(s) through `crate::commands::kustomization_edit::finalize_and_announce(`; \
                 found {forwards}. A dropped call would leave the negative raw-stanza scan \
                 satisfied by absence.",
            );
        }
    }

    /// Positive half of the shield: the four pre-lift files under
    /// `commands/` MUST each forward through
    /// `crate::commands::kustomization_edit::open_for_update(` at least
    /// the pre-lift count of times, so a migration that dropped a call
    /// site outright leaves the negative "no raw label literal" scan
    /// trivially satisfied by absence but the positive count still
    /// fails.
    #[test]
    fn every_prelift_module_forwards_through_open_for_update() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        // kenshi.rs and nix_builder.rs::update_kustomization_image both
        // migrated onto the fused `splice_first_images_new_tag`
        // primitive, so their direct forwards through `open_for_update`
        // are subsumed by the fusion primitive's forward (which lives in
        // this module's body). kenshi_agent.rs still opens directly
        // because it interleaves an AGENT_IMAGE env-var splice into the
        // same open→finalize span. nix_builder.rs retains one direct
        // forward from `update_kenshi_builder_image`.
        let expectations: &[(&str, usize)] = &[
            ("kenshi_agent.rs", 1),
            ("nix_builder.rs", 1),
            ("push.rs", 1),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("kustomization_edit::open_for_update(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} kustomization edit-preamble \
                 site(s) through `crate::commands::kustomization_edit::open_for_update(`; \
                 found {forwards}. A dropped call would leave the negative raw-label scan \
                 satisfied by absence.",
            );
        }
    }

    // ---- splice_first_images_new_tag_content ----------------------------
    //
    // The pre-lift `for line in content.lines() { … in_<block>_image
    // toggle + newTag splice … }` walk that
    // `commands/{kenshi,kenshi_agent,nix_builder}.rs::update_kustomization_image`
    // each spelled inline. Each case pins the primitive's byte-for-byte
    // output on a canonical kustomization overlay input against the
    // predicate that pre-lift site used, so a future refinement of the
    // enter/exit selector coherence, the passthrough-line trailing-
    // newline shape, or the indent-preserving newTag splice regresses
    // this assertion at one site rather than silently across three.
    //
    // Fail-before-pass-after: the primitive did not exist pre-lift; each
    // case would have been a compile error before the primitive landed
    // and a passing shape assertion after.

    /// Kenshi kustomization overlay pre-lift shape: an `images:` header
    /// followed by a single `- name: …/kenshi` entry with an inline
    /// `newTag:`. The predicate is the pre-lift kenshi selector
    /// `contains("kenshi") && !contains("kenshi-agent")`. The primitive
    /// MUST land a byte-identical transform.
    #[test]
    fn splice_first_images_new_tag_content_kenshi_shape() {
        let input = "\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: ghcr.io/pleme-io/kenshi
    newName: ghcr.io/pleme-io/kenshi
    newTag: amd64-oldsha
";
        let (rendered, updated) = splice_first_images_new_tag_content(
            input,
            |line| line.contains("kenshi") && !line.contains("kenshi-agent"),
            "amd64-newsha",
        );
        assert!(updated, "kenshi predicate must hit the images[] entry");
        assert_eq!(
            rendered,
            "\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: ghcr.io/pleme-io/kenshi
    newName: ghcr.io/pleme-io/kenshi
    newTag: amd64-newsha
"
        );
    }

    /// Kenshi-agent kustomization overlay pre-lift shape: the predicate
    /// is the pre-lift kenshi-agent selector `contains("kenshi-agent")`.
    /// The transform must splice only the `- name: …/kenshi-agent`
    /// entry's `newTag:` and leave the adjacent `- name: …/kenshi`
    /// entry's `newTag:` verbatim — the enter/exit predicate coherence
    /// pinned at ONE body.
    #[test]
    fn splice_first_images_new_tag_content_kenshi_agent_shape_leaves_sibling_kenshi_untouched() {
        let input = "\
images:
  - name: ghcr.io/pleme-io/kenshi
    newTag: amd64-kenshi-old
  - name: ghcr.io/pleme-io/kenshi-agent
    newTag: amd64-agent-old
";
        let (rendered, updated) = splice_first_images_new_tag_content(
            input,
            |line| line.contains("kenshi-agent"),
            "amd64-agent-new",
        );
        assert!(
            updated,
            "kenshi-agent predicate must hit its images[] entry"
        );
        assert_eq!(
            rendered,
            "\
images:
  - name: ghcr.io/pleme-io/kenshi
    newTag: amd64-kenshi-old
  - name: ghcr.io/pleme-io/kenshi-agent
    newTag: amd64-agent-new
",
            "the predicate must gate BOTH enter and exit so the sibling \
             kenshi block's newTag survives verbatim"
        );
    }

    /// Nix-builder kustomization overlay pre-lift shape: the predicate
    /// is the pre-lift nix-builder selector `contains(registry)`. Pin
    /// the indent-preserving `newTag:` splice at a six-space indent
    /// (the canonical nested indent under `  - name:`) so a drift in
    /// the indent computation regresses this case.
    #[test]
    fn splice_first_images_new_tag_content_nix_builder_shape() {
        let registry = "ghcr.io/pleme-io/nix-builder";
        let input = "\
images:
  - name: ghcr.io/pleme-io/nix-builder
    newName: ghcr.io/pleme-io/nix-builder
    newTag: amd64-oldbuilder
";
        let (rendered, updated) = splice_first_images_new_tag_content(
            input,
            |line| line.contains(registry),
            "amd64-newbuilder",
        );
        assert!(updated, "nix-builder predicate must hit the images[] entry");
        assert_eq!(
            rendered,
            "\
images:
  - name: ghcr.io/pleme-io/nix-builder
    newName: ghcr.io/pleme-io/nix-builder
    newTag: amd64-newbuilder
"
        );
    }

    /// Miss arm: the predicate matches nothing in the content. The
    /// transform MUST return `updated == false` and the passthrough
    /// content (with `.lines()`-normalized trailing newlines) so the
    /// caller can spell its own bail-vs-continue behavior at the site.
    #[test]
    fn splice_first_images_new_tag_content_returns_updated_false_on_no_match() {
        let input = "\
images:
  - name: ghcr.io/other/service
    newTag: amd64-something
";
        let (rendered, updated) = splice_first_images_new_tag_content(
            input,
            |line| line.contains("kenshi"),
            "amd64-newsha",
        );
        assert!(
            !updated,
            "no matching name: line must yield updated == false"
        );
        assert_eq!(
            rendered, input,
            "the passthrough must preserve every source byte on a miss"
        );
    }

    /// Passthrough lines outside the target block MUST be emitted
    /// verbatim with a trailing `\n` — the pre-lift `push_str(line) +
    /// push('\n')` shape at every site. This case pins the trailing-
    /// newline shape on lines the primitive did NOT splice.
    #[test]
    fn splice_first_images_new_tag_content_appends_newline_to_passthrough_lines() {
        let input = "kind: Kustomization\nimages: []";
        let (rendered, updated) = splice_first_images_new_tag_content(input, |_| false, "amd64-x");
        assert!(!updated);
        // The `.lines()` iterator strips the terminator; every emitted
        // line MUST re-append exactly one `\n`.
        assert_eq!(rendered, "kind: Kustomization\nimages: []\n");
    }

    /// The primitive MUST route the `newTag:` splice through
    /// `crate::repo::indent_preserving_kv_line` so the pre-lift
    /// `{indent}newTag: {new_tag}\n` byte shape lands at one body. Pin
    /// the ten-space `newTag:` indent nested under an eight-space
    /// `- name:` header that deeply-nested overlays use.
    #[test]
    fn splice_first_images_new_tag_content_preserves_deep_new_tag_indent() {
        let input = "\
        - name: ghcr.io/org/svc
          newTag: amd64-old
";
        let (rendered, _) = splice_first_images_new_tag_content(
            input,
            |line| line.contains("ghcr.io/org/svc"),
            "amd64-new",
        );
        assert!(
            rendered.contains("          newTag: amd64-new\n"),
            "ten-space `newTag:` indent must be preserved verbatim by \
             the indent-preserving-kv-line delegate. Got: {rendered:?}"
        );
    }

    /// The `splice_first_images_new_tag` fusion primitive MUST bail
    /// with the canonical miss envelope `"No <label> entry found in
    /// images[] in <path>"` on a predicate miss, pinning the operator-
    /// facing miss line at ONE grammar across kenshi + nix-builder.
    #[tokio::test]
    async fn splice_first_images_new_tag_bails_with_canonical_miss_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kustomization.yaml");
        tokio::fs::write(
            &file,
            "\
images:
  - name: ghcr.io/other/service
    newTag: amd64-x
",
        )
        .await
        .unwrap();
        let file_str = file.to_str().unwrap();

        let err = splice_first_images_new_tag(
            file_str,
            |line| line.contains("kenshi"),
            "amd64-newsha",
            "images[] newTag",
            "kenshi",
        )
        .await
        .unwrap_err();
        let rendered = format!("{}", err);
        assert!(
            rendered.starts_with("No kenshi entry found in images[] in "),
            "miss envelope must open with `No <label> entry found in images[] in `; \
             got: {rendered:?}"
        );
        assert!(
            rendered.contains(file_str),
            "miss envelope must echo the offending path verbatim; got: {rendered:?}"
        );
    }

    /// The `splice_first_images_new_tag` fusion primitive MUST write
    /// the transformed content through
    /// [`finalize_and_announce`] on a predicate hit — end-to-end pin
    /// spanning open → transform → emit → finalize.
    #[tokio::test]
    async fn splice_first_images_new_tag_writes_finalized_transform_on_hit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kustomization.yaml");
        tokio::fs::write(
            &file,
            "\
images:
  - name: ghcr.io/pleme-io/kenshi
    newTag: amd64-oldsha
",
        )
        .await
        .unwrap();
        let file_str = file.to_str().unwrap();

        splice_first_images_new_tag(
            file_str,
            |line| line.contains("kenshi") && !line.contains("kenshi-agent"),
            "amd64-newsha",
            "images[] newTag",
            "kenshi",
        )
        .await
        .unwrap();

        let written = tokio::fs::read_to_string(&file).await.unwrap();
        assert_eq!(
            written,
            "\
images:
  - name: ghcr.io/pleme-io/kenshi
    newTag: amd64-newsha
"
        );
    }

    /// Whole-module shield: no source line under `cli/src/commands/`
    /// (excluding this module) may spell any of the pre-lift walk
    /// openers `let mut in_kenshi_image = false;`,
    /// `let mut in_kenshi_agent_image = false;`, or
    /// `let mut in_target_image = false;` any more. Every kustomization
    /// overlay `images[] newTag` walk must route through
    /// [`splice_first_images_new_tag_content`] (or its
    /// bail-plus-finalize sibling [`splice_first_images_new_tag`]) so a
    /// future refinement of the enter/exit-selector coherence, the
    /// passthrough shape, or the indent-preserving splice reaches all
    /// consumers by construction.
    #[test]
    fn no_command_module_still_spells_pre_lift_target_image_flag_opener() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let openers: &[&str] = &[
            "let mut in_kenshi_image = false;",
            "let mut in_kenshi_agent_image = false;",
            "let mut in_target_image = false;",
        ];
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("kustomization_edit.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                for needle in openers {
                    if line.contains(needle) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw target-image walk opener(s) survive under `commands/` — route each \
             through `crate::commands::kustomization_edit::splice_first_images_new_tag_content` \
             (or its bail+finalize sibling `splice_first_images_new_tag`) instead:\n{:#?}",
            offenders
        );
    }

    /// Positive half of the target-image walk shield: the three pre-
    /// lift modules under `commands/` MUST each forward through one of
    /// the two new primitives (`splice_first_images_new_tag(` for
    /// kenshi + nix-builder; `splice_first_images_new_tag_content(` for
    /// kenshi-agent whose outer wrapper still spans the AGENT_IMAGE
    /// env-var pass) so a migration that dropped a call site outright
    /// leaves the negative opener-scan trivially satisfied by absence
    /// but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_splice_first_images_new_tag() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, needle, minimum forward count from the pre-lift census)
        let expectations: &[(&str, &str, usize)] = &[
            ("kenshi.rs", "splice_first_images_new_tag(", 1),
            ("nix_builder.rs", "splice_first_images_new_tag(", 1),
            ("kenshi_agent.rs", "splice_first_images_new_tag_content(", 1),
        ];
        for (basename, needle, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} images[] newTag walk site(s) \
                 through `crate::commands::kustomization_edit::{needle}`; found {forwards}.",
            );
        }
    }
}
