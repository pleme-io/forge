//! `let git_sha = git::get_short_sha()?; crate::info_git_sha_field!(git_sha);`
//! fused resolve-then-announce short-SHA preamble.
//!
//! # Pre-lift census — two sibling stanzas, one composition
//!
//! Two pre-lift call sites at
//! `commands/{comprehensive_release,github_runner_ci}.rs::execute` each
//! restated the same byte-identical three-line stanza verbatim:
//!
//! ```ignore
//! // Get git SHA for tagging
//! let git_sha = git::get_short_sha()?;
//! crate::info_git_sha_field!(git_sha);
//! ```
//!
//! - `commands/comprehensive_release.rs:270-272` — the STEP-0 preamble
//!   between the `Input validation complete` acknowledgement and the
//!   `crate::info_registry_field!(registry)` / `🌍 Namespace: <ns>` /
//!   subsequent per-step build+push+deploy body.
//! - `commands/github_runner_ci.rs:137-139` — the top-of-command
//!   preamble immediately after the `GitHub Runner CI Workflow` banner
//!   and before the `crate::info_deploy_target_field!(registry, git_sha)`
//!   deploy-target readout.
//!
//! Post-lift both sites reach for
//! [`resolve_and_announce_short_sha_for_tagging`]; the sync-flavored
//! `git::get_short_sha()?` I/O, the `crate::info_git_sha_field!(<sha>)`
//! narration, and the "in that order" composition land at ONE body.
//!
//! # Distinct from the async sibling `get_short_sha_async_for_image_tag`
//!
//! [`crate::git::get_short_sha_async_for_image_tag`] is the ASYNC-only
//! sibling for the deploy-tag surface — it resolves the SHA via the
//! tokio-flavored `get_short_sha_async` primitive AND, on failure,
//! decorates the error with the image-tagging context, but it does NOT
//! emit the `📦 Git SHA:` announcement. Its callers
//! (`commands/{push,rust_service}.rs`) surface the SHA at a different
//! grammar (`📦 Building image …` / `Image pushed to …`) that does not
//! belong to the top-of-preamble family this primitive owns.
//!
//! This primitive is the SYNC-flavored resolve-then-announce sibling —
//! `git::get_short_sha()` (blocking, non-async) plus the
//! `crate::info_git_sha_field!` narration in that order. The two families
//! stay apart: a sync consumer of `get_short_sha_async_for_image_tag`
//! would need a `block_on` bridge it does not want, and an async consumer
//! of this primitive would need to lift the sync call across an `.await`
//! that would fabricate a spuriously async caller.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the sync resolve-then-announce
//! composition lives at ONE surface, so a future refinement (a swap to
//! `Path::join`-based repo-root discovery for callers that spawn from a
//! non-repo-root working directory, a telemetry sigil separating the
//! "SHA resolved" event from the "announcement emitted" event, a typed
//! `substrate::ShortSha` newtype on the return) lands here and reaches
//! both consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: two sibling stanzas across two
//! command modules materially match the recurring-shape criterion; the
//! primitive body is the promotion.

use anyhow::Result;

/// Resolve the 7-character short git SHA of `HEAD` for image-tag
/// composition AND emit the `📦 Git SHA: <sha>` announcement to the
/// tracing pipeline, in that order.
///
/// Delegates to [`crate::git::get_short_sha`] for the sync-flavored
/// SHA-capture I/O and to [`crate::info_git_sha_field!`] for the
/// narration. Returns the same `Result<String>` the raw
/// [`crate::git::get_short_sha`] would return; on the `Err` arm no
/// announcement is emitted, matching the pre-lift order at both sites
/// (a `?`-propagated `get_short_sha` failure short-circuited BEFORE the
/// pre-lift `info_git_sha_field!` line ran).
///
/// # Byte contract
///
/// The `Ok` value is byte-identical to the value
/// [`crate::git::get_short_sha`] returns: the trimmed stdout of
/// `git rev-parse --short=7 HEAD`, exactly 7 hex characters
/// (`--short=7` is explicit, not `core.abbrev`-dependent). The
/// announcement lands via [`crate::info_git_sha_field!`], which emits
/// the `📦 Git SHA: <sha>` field-readout at the tracing `info` level.
///
/// # Composition order
///
/// The I/O runs BEFORE the announcement — a failure to resolve the SHA
/// short-circuits the announcement rather than emitting a broken
/// `📦 Git SHA: <error>` line. Both pre-lift sites relied on this
/// ordering via the `?` operator on the resolve step; post-lift the
/// ordering is the primitive's responsibility.
pub fn resolve_and_announce_short_sha_for_tagging() -> Result<String> {
    let git_sha = crate::git::get_short_sha()?;
    crate::info_git_sha_field!(git_sha);
    Ok(git_sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Positive-delegation shield: every pre-lift consumer must forward
    /// at least once through
    /// [`resolve_and_announce_short_sha_for_tagging`]. A dropped call
    /// site would leave the negative "no raw `get_short_sha` binding"
    /// scan trivially satisfied by absence; this positive count keeps
    /// that failure visible.
    #[test]
    fn every_prelift_consumer_forwards_through_resolve_and_announce_short_sha() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] =
            &[("comprehensive_release.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches(
                    "crate::short_sha_tagging_preamble::\
                     resolve_and_announce_short_sha_for_tagging(",
                )
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} short-SHA-\
                 for-tagging preamble site(s) through \
                 `crate::short_sha_tagging_preamble::\
                 resolve_and_announce_short_sha_for_tagging(`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }

    /// Negative caller shield: no source line under `cli/src/commands/`
    /// may spell the pre-lift raw two-line stanza
    ///
    /// ```ignore
    /// let git_sha = git::get_short_sha()?;
    /// crate::info_git_sha_field!(git_sha);
    /// ```
    ///
    /// any more. The two pre-lift sites migrated; any future consumer
    /// that wants the same resolve-then-announce grammar reaches for
    /// [`resolve_and_announce_short_sha_for_tagging`] on first grep, not
    /// by copy-pasting the raw stanza from an existing command module.
    ///
    /// The scan is anchored to the pre-lift PAIR — a
    /// `git::get_short_sha()?` binding IMMEDIATELY followed (skipping
    /// blank / comment lines) by a `crate::info_git_sha_field!(` call.
    /// The pairing keeps the shield from tripping on the bare
    /// `commands/image_release.rs::execute` sync-SHA site (which
    /// consumes the SHA for a tag composition without emitting the
    /// `📦 Git SHA:` announcement — a distinct semantic that this
    /// primitive deliberately does not own) nor on the async siblings
    /// [`crate::git::get_short_sha_async`] and
    /// [`crate::git::get_short_sha_async_for_image_tag`], both of
    /// which retain their own consumer set.
    #[test]
    fn no_command_module_still_spells_raw_get_short_sha_announce_pair() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose does not self-hit.
                if trimmed.starts_with("//") {
                    continue;
                }
                if !line.contains("git::get_short_sha()?") {
                    continue;
                }
                // Walk forward past blank / comment lines and see whether
                // the very next non-trivial line forwards through the
                // announcement macro — the two-line pair the primitive
                // owns.
                let mut cursor = idx + 1;
                while cursor < lines.len() {
                    let next = lines[cursor];
                    let next_trimmed = next.trim_start();
                    if next_trimmed.is_empty() || next_trimmed.starts_with("//") {
                        cursor += 1;
                        continue;
                    }
                    if next.contains("crate::info_git_sha_field!(")
                        || next.contains("info_git_sha_field!(")
                    {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                    break;
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `get_short_sha()? → info_git_sha_field!(` pair(s) \
             survive under `commands/` — route each resolve-then-\
             announce preamble through `crate::short_sha_tagging_preamble::\
             resolve_and_announce_short_sha_for_tagging()` instead. \
             Offenders:\n{:#?}",
            offenders
        );
    }

    /// Byte-oracle: the primitive returns a value byte-identical to
    /// [`crate::git::get_short_sha`]'s output. The test is gated on
    /// `get_short_sha` succeeding — the surrounding harness runs from
    /// the forge repo root, where the call resolves; if a future test
    /// harness spawns from a non-repo working directory both branches
    /// short-circuit at the same failure point.
    #[test]
    fn resolve_and_announce_returns_same_sha_as_raw_get_short_sha() {
        let raw = match crate::git::get_short_sha() {
            Ok(sha) => sha,
            Err(_) => return,
        };
        let wrapped = resolve_and_announce_short_sha_for_tagging().expect(
            "resolve_and_announce_short_sha_for_tagging must succeed when raw get_short_sha does",
        );
        assert_eq!(
            wrapped, raw,
            "resolve_and_announce_short_sha_for_tagging must return the \
             byte-identical SHA `get_short_sha` returns — a drift here \
             would mean the primitive has grown a rewrite step the \
             consumers do not want",
        );
        assert_eq!(
            wrapped.len(),
            7,
            "the returned SHA must be exactly 7 characters (`--short=7` \
             is explicit in `read_head_sha`, not `core.abbrev`-dependent); \
             a drift here would break the `{{arch}}-<sha>` image-tag \
             composition at both consumers",
        );
    }
}
