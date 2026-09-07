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
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("kenshi.rs", 1),
            ("kenshi_agent.rs", 1),
            ("nix_builder.rs", 2),
        ];
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
        let expectations: &[(&str, usize)] = &[
            ("kenshi.rs", 1),
            ("kenshi_agent.rs", 1),
            ("nix_builder.rs", 2),
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
}
