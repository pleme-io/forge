//! Cluster-overlay release commit helper.
//!
//! Shape-adapter over [`crate::infrastructure::git::GitClient::stage_commit_push_release`]
//! for the three sibling cluster-overlay release flows in
//! `commands/{kenshi,kenshi_agent,nix_builder}.rs`. Each of those flows
//! used to spell out — VERBATIM, modulo the component-name token —
//! the same three-piece stanza after computing `new_tag` and assembling
//! the per-flow file slice:
//!
//! 1. `let commit_msg = format!("chore(release): Update <component> to {}\n\nUpdated target clusters", new_tag);`
//! 2. `GitClient::new().stage_commit_push_release(&[...], &commit_msg, "main").await?`
//! 3. `match outcome { Pushed => info!("   ✅ Changes committed and pushed"),
//!     NoChangesStaged => info!("   No changes to commit (already at this version)") }`
//!
//! Three occurrences of an identical shape past THEORY §VI.1's
//! three-is-a-law threshold; this module is the law-redeeming extraction.
//! Post-lift each flow calls
//! [`commit_cluster_overlay_release`] with `(component, new_tag, files)`
//! and inherits the canonical commit subject + the canonical
//! Pushed-vs-NoChangesStaged log pair through one site.
//!
//! Sibling of `commands/product_release.rs::commit_artifact_tags` —
//! same `workdir: Option<&str>` test-discipline shape (production passes
//! `None`; hermetic tests pass `Some(temp_dir)`), same typed
//! [`CommitPushOutcome`] return so callers / future Phase 1 attestation
//! consumers (THEORY §V.4) compose on a single typed surface across
//! every release-commit path in forge.

use anyhow::Result;
use std::io;
use tracing::info;

use crate::infrastructure::git::{CommitPushOutcome, GitClient};

/// The canonical `Commit and Push` step title carried by the final step
/// header of every cluster-overlay release flow. Named as a `const` so
/// a future re-titling (`Publish`, `Land Release`) flows to all three
/// flows from one edit rather than through three inline literal edits.
const COMMIT_AND_PUSH_STEP_TITLE: &str = "Commit and Push";

/// The canonical `📤 Committing release changes...` info line the
/// three cluster-overlay release flows in
/// `commands/{kenshi,kenshi_agent,nix_builder}.rs` each emitted
/// immediately before invoking [`commit_cluster_overlay_release`].
/// Named as a `const` so a future drift to a different verb (a
/// `🚀 Publishing`, a `📦 Landing`) flows to all three flows from one
/// edit rather than through three inline literal edits.
const COMMIT_RELEASE_CHANGES_INFO_LINE: &str = "📤 Committing release changes...";

/// Build the canonical cluster-overlay release commit subject.
///
/// Pure function — no I/O, no allocations beyond the returned `String`.
/// Pinning the format at one site means a future drift to a new commit
/// convention (e.g. embedding a SLSA provenance link, or changing the
/// `chore(release)` Conventional Commit type) flows to all three flows
/// from one edit, and downstream `git log --grep='chore(release): Update'`
/// audit queries continue to resolve against a single canonical shape.
pub fn cluster_overlay_release_commit_subject(component: &str, new_tag: &str) -> String {
    format!(
        "chore(release): Update {} to {}\n\nUpdated target clusters",
        component, new_tag
    )
}

/// Stage `files`, commit with the canonical cluster-overlay release
/// subject for `(component, new_tag)`, and push to `origin/main`.
///
/// `workdir` is `None` in production (`GitClient::new()` resolves git
/// commands against the current process cwd, which is the repo root by
/// invariant); tests pass `Some(temp_dir)` to drive the helper against
/// a hermetic bare-repo pair. Returns the typed [`CommitPushOutcome`]
/// so callers / future composition points see the structural skip
/// signal verbatim; the three production callers currently discard
/// the outcome via `let _ = ...` / implicit drop.
///
/// Emits the canonical log pair on the typed outcome:
/// `Pushed` → `   ✅ Changes committed and pushed`;
/// `NoChangesStaged` → `   No changes to commit (already at this version)`.
pub async fn commit_cluster_overlay_release(
    workdir: Option<&str>,
    component: &str,
    new_tag: &str,
    files: &[&str],
) -> Result<CommitPushOutcome> {
    let commit_msg = cluster_overlay_release_commit_subject(component, new_tag);
    let client = match workdir {
        Some(dir) => GitClient::in_dir(dir.to_string()),
        None => GitClient::new(),
    };
    let outcome = client
        .stage_commit_push_release(files, &commit_msg, "main")
        .await?;
    match outcome {
        CommitPushOutcome::Pushed => info!("   ✅ Changes committed and pushed"),
        CommitPushOutcome::NoChangesStaged => {
            info!("   No changes to commit (already at this version)")
        }
    }
    Ok(outcome)
}

/// Emit the canonical `Commit and Push` step-header + `📤 Committing
/// release changes...` info-line preamble bytes to `w` — byte-for-byte
/// identical to the two-line stanza the three cluster-overlay release
/// flows in `commands/{kenshi,kenshi_agent,nix_builder}.rs` each
/// spelled inline immediately before invoking
/// [`commit_cluster_overlay_release`].
///
/// Composes with [`crate::step_header::write_step_header`] at
/// `total_steps/total_steps` (the `Commit and Push` step is the
/// terminal step of each of the three flows) so the step-index
/// invariant (`1 <= step <= total`, `total >= 1`) is inherited from
/// the sibling primitive and enforced at ONE typed boundary rather
/// than restated at each consumer.
///
/// The direct-writer variant exists so the fail-before-pass test can
/// pin the exact emitted bytes (the three `━` opener + closer, the
/// `Step {total}/{total}: Commit and Push` label, the `📤 ` opener
/// on the info line, the trailing newlines) without capturing a
/// tracing subscriber and without racing an ambient logger — the
/// same split every prior sibling-writer refactor honors (see
/// `nonfatal_warning.rs`, `success_step.rs`, `skipping_step.rs`,
/// `step_header.rs` for the canonical split rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the tracing-routed
                    // `announce_and_commit_cluster_overlay_release_step`,
                    // and a future `collect_commit_and_push_preambles`
                    // audit sibling will consume it directly.
pub fn write_commit_and_push_step_preamble<W: io::Write>(
    w: &mut W,
    total_steps: usize,
) -> io::Result<()> {
    crate::step_header::write_step_header(
        w,
        total_steps,
        total_steps,
        &COMMIT_AND_PUSH_STEP_TITLE,
    )?;
    writeln!(w, "{}", COMMIT_RELEASE_CHANGES_INFO_LINE)?;
    Ok(())
}

/// Announce the terminal `Commit and Push` step of a cluster-overlay
/// release flow at position `total_steps/total_steps`, emit the
/// canonical `📤 Committing release changes...` info line, then
/// delegate to [`commit_cluster_overlay_release`] to stage `files`,
/// commit with the canonical subject for `(component, new_tag)`, and
/// push to `origin/main`.
///
/// Fusion primitive over the three sibling four-line stanzas the
/// cluster-overlay release flows in
/// `commands/{kenshi,kenshi_agent,nix_builder}.rs` each spelled
/// inline verbatim (modulo the per-flow `total_steps`, `component`,
/// and `files` slice):
///
/// ```ignore
/// crate::step_header::announce_step_header(N, N, "Commit and Push");
/// info!("📤 Committing release changes...");
/// commit_cluster_overlay_release(None, "<component>", &new_tag, &<files>).await?;
/// ```
///
/// Three occurrences of an identical shape past THEORY §VI.1's
/// three-is-a-law threshold; this primitive is the law-redeeming
/// extraction. Post-lift each flow calls
/// [`announce_and_commit_cluster_overlay_release_step`] with
/// `(total_steps, component, new_tag, files)` and inherits the
/// canonical `Step N/N: Commit and Push` header, the canonical
/// `📤 Committing release changes...` info line, the `main`-branch
/// push target, and the `Pushed`-vs-`NoChangesStaged` outcome log
/// pair through one site.
///
/// # Grammar pinned by the byte-oracle sibling
///
/// The two-line preamble bytes
/// (`━━━ Step N/N: Commit and Push ━━━\n` + `📤 Committing release
/// changes...\n`) are pinned by [`write_commit_and_push_step_preamble`]
/// under `#[cfg(test)]`; a drift here (a step-title rename, an emoji
/// swap on the info line, a color change on either line) surfaces as
/// a localized test failure at one site, not as silent log-drift
/// across three release flows.
///
/// # Types-as-theorems: the terminal-step invariant
///
/// The primitive fixes `step == total_steps` at the call site so an
/// operator eyeballing the header sees `Step N/N: Commit and Push`
/// unambiguously flagged as the terminal step of the flow. A future
/// consumer that reached for this primitive for a non-terminal
/// commit step (a mid-flow `Publish and Continue`) would need a
/// separate primitive with distinct semantics — a design-level
/// forcing function rather than an implicit off-by-one.
pub async fn announce_and_commit_cluster_overlay_release_step(
    total_steps: usize,
    component: &str,
    new_tag: &str,
    files: &[&str],
) -> Result<CommitPushOutcome> {
    crate::step_header::announce_step_header(total_steps, total_steps, COMMIT_AND_PUSH_STEP_TITLE);
    info!("{}", COMMIT_RELEASE_CHANGES_INFO_LINE);
    commit_cluster_overlay_release(None, component, new_tag, files).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::git_command_sync;
    use crate::test_support::{init_repo_with_one_commit, make_seeded_work_and_bare_origin};

    /// The pure commit-subject helper MUST produce the canonical
    /// `"chore(release): Update <component> to <new_tag>\n\nUpdated
    /// target clusters"` format byte-for-byte — the audit-grep target
    /// `git log --grep='chore(release): Update'` and the three
    /// pre-lift inline format strings (now retired in
    /// `commands/{kenshi,kenshi_agent,nix_builder}.rs`) depend on
    /// this exact shape. Pinning the format at the pure helper means
    /// a future drift to a new commit convention surfaces as a
    /// localized test failure at one site, not as silent log-drift
    /// across three release flows.
    #[test]
    fn test_cluster_overlay_release_commit_subject_canonical_format() {
        let subject = cluster_overlay_release_commit_subject("kenshi operator", "amd64-deadbeef");
        assert_eq!(
            subject,
            "chore(release): Update kenshi operator to amd64-deadbeef\n\nUpdated target clusters"
        );
    }

    /// `commit_cluster_overlay_release` MUST land the canonical commit
    /// subject on `origin/main` via the underlying
    /// `stage_commit_push_release` primitive. Pins the round-trip
    /// every release-commit flow now drives: the subject the audit
    /// query greps for actually appears on origin, not just in the
    /// caller-local string.
    #[tokio::test]
    async fn test_commit_cluster_overlay_release_lands_canonical_subject_on_origin() {
        let (parent, bare, work) = make_seeded_work_and_bare_origin();
        std::fs::write(work.join("kustomization.yaml"), "images: []\n").unwrap();

        let outcome = commit_cluster_overlay_release(
            Some(&work.to_string_lossy()),
            "nix-builder",
            "amd64-cafef00d",
            &["kustomization.yaml"],
        )
        .await
        .expect("happy-path commit_cluster_overlay_release must succeed");
        assert_eq!(outcome, CommitPushOutcome::Pushed);

        // Hold `GIT_BIN_ENV_LOCK` across the probe so a concurrently-running
        // shim test cannot mutate `GIT_BIN` between the clone and the log
        // spawns inside `clone_bare_and_read_head_subject` — closes a
        // pre-lift race hole the inline probe pair carried.
        let probe = parent.path().join("probe");
        let _guard = crate::test_support::GIT_BIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let subject = crate::test_support::clone_bare_and_read_head_subject(&bare, &probe);
        assert_eq!(
            subject, "chore(release): Update nix-builder to amd64-cafef00d",
            "commit subject must match the canonical cluster-overlay release format"
        );
    }

    /// `commit_cluster_overlay_release` invoked against files whose
    /// content already matches `HEAD` MUST return
    /// `CommitPushOutcome::NoChangesStaged` and MUST NOT attempt a
    /// commit or push. Pins the idempotent-re-release contract: a
    /// re-run of a release at the same tag does not produce an
    /// orphaned empty commit and does not contact the (in-test:
    /// absent) remote. A fall-through to the primitive's
    /// `push_to("origin", "main")` step would fail with a typed
    /// `GitError::OpFailed` / `RemoteOpFailed` against the
    /// unconfigured remote and the test would surface that error; a
    /// clean `Ok(NoChangesStaged)` proves the skip happened before
    /// any push spawn.
    #[tokio::test]
    async fn test_commit_cluster_overlay_release_returns_no_changes_on_idempotent_re_release() {
        let work = tempfile::tempdir().expect("work tempdir");
        init_repo_with_one_commit(work.path());
        let outcome = commit_cluster_overlay_release(
            Some(&work.path().to_string_lossy()),
            "kenshi-agent",
            "amd64-abc1234",
            &["seed.txt"],
        )
        .await
        .expect("re-staging an already-committed file must succeed");
        assert_eq!(
            outcome,
            CommitPushOutcome::NoChangesStaged,
            "re-staging unchanged file must skip commit + push"
        );
    }

    /// `commit_cluster_overlay_release` MUST surface a typed error
    /// when the push step fails — symmetric with the discipline pinned
    /// for `commit_artifact_tags` in `product_release.rs`. The
    /// underlying primitive's `run_inherited_status` envelope bails on
    /// non-zero exit by construction, and that failure must travel
    /// verbatim through the helper to the caller's `?` operator.
    /// Configures `origin` to point at a non-existent path so `git
    /// push` fails deterministically (the canonical shape of every
    /// transient-push failure that escapes the retry budget in
    /// production).
    #[tokio::test]
    async fn test_commit_cluster_overlay_release_surfaces_push_failure() {
        let work = tempfile::tempdir().expect("work tempdir");
        init_repo_with_one_commit(work.path());
        let bogus = work.path().join("bogus-origin.does-not-exist");
        let add = git_command_sync()
            .args([
                "remote",
                "add",
                "origin",
                bogus.to_str().expect("bogus path utf-8"),
            ])
            .current_dir(work.path())
            .status()
            .expect("git remote add");
        assert!(add.success(), "git remote add must succeed");
        std::fs::write(work.path().join("kustomization.yaml"), "images: []\n").unwrap();

        let result = commit_cluster_overlay_release(
            Some(&work.path().to_string_lossy()),
            "kenshi operator",
            "amd64-deadbeef",
            &["kustomization.yaml"],
        )
        .await;
        assert!(
            result.is_err(),
            "push to a non-existent remote MUST surface a typed error, \
             never a silent Ok(Pushed); got: {result:?}"
        );
    }

    /// Whole-module shield: no raw `Command::new(<bare>)` on the
    /// `git` binary may live in `commands/release_commit.rs`. Every
    /// git spawn on this surface must resolve `GIT_BIN` via the
    /// canonical [`crate::git::git_command_sync`] constructor so a
    /// hermetic-runner (Nix `mkRuntimeToolsEnv`) invocation with a
    /// pinned substrate-derivation git falls through to that shim
    /// rather than whichever `git` sits first on `PATH`. Pre-lift the
    /// three test-side probe sites (`git clone` at the origin-round-
    /// trip pin, `git log -1 --pretty=%s` at the subject-verification
    /// pin, and `git remote add origin` at the push-failure pin) each
    /// spelled the bare shape `SyncCommand::new(<bare>)` verbatim (the
    /// local `use std::process::Command as SyncCommand` alias resolves
    /// to the same shape the sibling shields forbid). The alias was
    /// removed at the top of the `tests` module and the three sites
    /// now route through `git_command_sync()` — same discipline as
    /// the sibling
    /// `test_git_spawn_routes_through_git_command_sync_not_raw_literal`
    /// shield in `commands/attestation.rs`.
    ///
    /// The three forbidden shapes (`std::process::Command::new(...)`,
    /// bare `Command::new(...)`, `tokio::process::Command::new(...)`)
    /// are reconstructed via `format!` from the bare string `"git"` so
    /// this shield's own source text does not false-match itself — the
    /// whole-module scan therefore covers both the top-of-file
    /// production body AND every sibling `#[cfg(test)]` block, any of
    /// which could otherwise silently re-introduce a raw literal.
    /// Also asserts the canonical `crate::git::git_command_sync`
    /// delegation form is present in the module so the sigil-body
    /// itself cannot silently drift away from the substrate-exported
    /// env-var contract.
    ///
    /// The end-to-end `GIT_BIN`-routing invariant of the underlying
    /// primitive is pinned separately by
    /// [`crate::git::tests::test_git_command_sync_routes_through_git_bin_env_var`];
    /// this shield only certifies that every git-spawning site in this
    /// module reads through `git_command_sync()`.
    #[test]
    fn test_git_spawn_routes_through_git_command_sync_not_raw_literal() {
        const SOURCE: &str = include_str!("release_commit.rs");

        crate::test_support::assert_source_forbids_bare_spawn_shapes(
            SOURCE,
            "commands/release_commit.rs",
            "git",
            "resolve `GIT_BIN` via `crate::git::git_command_sync()`",
        );

        crate::test_support::assert_source_delegates_via_constructor_call_code_line(
            SOURCE,
            "commands/release_commit.rs",
            "git",
            "git_command_sync",
        );
    }

    /// Pin the exact two-line preamble bytes emitted by
    /// [`write_commit_and_push_step_preamble`]: the three-`━` opener +
    /// `Step N/N: Commit and Push` label + three-`━` closer + newline,
    /// then the `📤 Committing release changes...` info line + newline.
    /// A future refactor that renamed the step title, swapped the
    /// `📤` glyph, dropped one of the trailing newlines, or promoted
    /// either line to a colored ANSI rendering (which would break
    /// parity with the three consumers' pre-lift plain
    /// `info!`-routed emission) regresses this assertion.
    #[test]
    fn write_commit_and_push_step_preamble_emits_the_canonical_two_line_stanza() {
        let mut buf: Vec<u8> = Vec::new();
        write_commit_and_push_step_preamble(&mut buf, 4).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{2501}\u{2501}\u{2501} Step 4/4: Commit and Push \u{2501}\u{2501}\u{2501}\n\
             \u{1f4e4} Committing release changes...\n"
        );
    }

    /// The preamble writer MUST emit `Step N/N` with the caller's
    /// `total_steps` in BOTH slots — the `Commit and Push` step is by
    /// construction the terminal step of every cluster-overlay
    /// release flow, so an operator eyeballing the header sees
    /// `Step 7/7: Commit and Push` unambiguously flagged as the last
    /// step. Pins the terminal-step invariant against a future
    /// refactor that walked the numerator past the total, or dropped
    /// the numerator/denominator symmetry.
    #[test]
    fn write_commit_and_push_step_preamble_carries_terminal_step_over_total_workflow_widths() {
        for total in [4usize, 6, 7] {
            let mut buf: Vec<u8> = Vec::new();
            write_commit_and_push_step_preamble(&mut buf, total).unwrap();
            let rendered = String::from_utf8(buf).unwrap();
            let expected_header = format!(
                "\u{2501}\u{2501}\u{2501} Step {total}/{total}: Commit and Push \
                 \u{2501}\u{2501}\u{2501}\n"
            );
            assert!(
                rendered.starts_with(&expected_header),
                "preamble for total_steps={total} must open with `{expected_header:?}`; \
                 got: {rendered:?}"
            );
            assert!(
                rendered.ends_with("\u{1f4e4} Committing release changes...\n"),
                "preamble must terminate with the canonical `📤 Committing …` line; \
                 got: {rendered:?}"
            );
        }
    }

    /// The preamble writer MUST inherit the sibling
    /// [`crate::step_header::write_step_header`] step-index invariant
    /// (`total >= 1`) — a `total_steps = 0` invocation is impossible
    /// by construction (a workflow has at least one step), and the
    /// underlying primitive's debug-only assertion is the enforcement
    /// point. Pinned here so a future off-by-one in the fusion
    /// primitive's `total`-forwarding surfaces at ONE site rather
    /// than through a live release surface.
    #[test]
    #[should_panic(expected = "workflow step total must be >= 1")]
    fn write_commit_and_push_step_preamble_rejects_zero_total_steps() {
        let mut buf: Vec<u8> = Vec::new();
        let _ = write_commit_and_push_step_preamble(&mut buf, 0);
    }

    /// Caller shield: no `info!("📤 Committing release changes...")`
    /// literal may survive in the three consumer modules
    /// (`commands/{kenshi,kenshi_agent,nix_builder}.rs`). Every
    /// `Commit and Push` step preamble in a cluster-overlay release
    /// flow must resolve through
    /// [`announce_and_commit_cluster_overlay_release_step`] so a
    /// future drift to a new preamble shape (a new verb on the info
    /// line, a re-titled step) flows to all three flows from one
    /// edit.
    ///
    /// The forbidden shape is reconstructed at test time via
    /// `format!` from the bare string `"Committing release changes"`
    /// so this shield's own source text does not false-match itself.
    #[test]
    fn commit_and_push_step_preamble_routes_through_fusion_not_inline_info_literal() {
        let forbidden = format!("{}{}", "\u{1f4e4} ", "Committing release changes...");
        for (path, source) in [
            ("commands/kenshi.rs", include_str!("kenshi.rs")),
            ("commands/kenshi_agent.rs", include_str!("kenshi_agent.rs")),
            ("commands/nix_builder.rs", include_str!("nix_builder.rs")),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{path}` must not spell the inline `info!(\"{forbidden}\")` line; \
                 route through `crate::commands::release_commit::\
                 announce_and_commit_cluster_overlay_release_step` instead \
                 (the byte-oracle-covered canonical Commit-and-Push step preamble)."
            );
        }
    }

    /// Positive-half delegation shield: the three consumer modules
    /// MUST each carry exactly one call to
    /// [`announce_and_commit_cluster_overlay_release_step`]. Guards
    /// against a silent removal of the terminal-commit step from a
    /// consumer (a refactor that accidentally dropped the fusion
    /// call while migrating a step, a merge that lost the call in a
    /// conflict resolution) — the commit + push is load-bearing for
    /// the release actually landing on `origin/main`, so its presence
    /// at exactly one site per flow is a structural invariant.
    #[test]
    fn every_cluster_overlay_release_consumer_delegates_through_commit_and_push_fusion() {
        // Match the CALL-syntax `(` suffix so the leading `use
        // crate::commands::release_commit::announce_and_...;` import
        // line — which carries the identifier without a call — does
        // not double-count against the per-consumer invocation
        // invariant.
        let needle = "announce_and_commit_cluster_overlay_release_step(";
        for (path, source) in [
            ("commands/kenshi.rs", include_str!("kenshi.rs")),
            ("commands/kenshi_agent.rs", include_str!("kenshi_agent.rs")),
            ("commands/nix_builder.rs", include_str!("nix_builder.rs")),
        ] {
            let count = source.matches(needle).count();
            assert_eq!(
                count, 1,
                "`{path}` must invoke `crate::commands::release_commit::\
                 {needle}` exactly once for its terminal Commit-and-Push \
                 step; found {count}. A flow that runs to completion \
                 without emitting the commit + push breaks the release \
                 landing on `origin/main`."
            );
        }
    }
}
