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
use tracing::info;

use crate::infrastructure::git::{CommitPushOutcome, GitClient};

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
}
