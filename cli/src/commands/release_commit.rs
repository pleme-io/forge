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
    use std::path::Path;
    use std::process::Command as SyncCommand;

    /// Initialize a hermetic git repo with one committed file under
    /// `dir`, configured with a stable identity + signing disabled so
    /// `git commit` works on a managed remote-execution host whose
    /// global `commit.gpgsign=true` would otherwise trip the seed
    /// commit. Mirror of the canonical fixture used by
    /// `infrastructure/git.rs` and `commands/product_release.rs` tests.
    fn init_repo_with_one_commit(dir: &Path) {
        let run = |args: &[&str]| {
            let status = SyncCommand::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .expect("git spawn");
            assert!(status.success(), "git {args:?} failed in {dir:?}");
        };
        run(&["init", "-q", "-b", "main"]);
        run(&["config", "user.email", "forge-test@example.invalid"]);
        run(&["config", "user.name", "forge-test"]);
        run(&["config", "commit.gpgsign", "false"]);
        std::fs::write(dir.join("seed.txt"), "seed\n").unwrap();
        run(&["add", "seed.txt"]);
        run(&["commit", "-q", "-m", "seed"]);
    }

    /// Configure `dir` to push to a fresh bare repo at `bare_dir` as
    /// the `origin` remote. `--initial-branch=main` keeps the bare's
    /// HEAD aligned with the work-tree's `main` branch so a subsequent
    /// `git clone <bare>` resolves HEAD against a real ref instead of
    /// a dangling `master` (some git versions' system default).
    fn add_bare_origin(dir: &Path, bare_dir: &Path) {
        let init = SyncCommand::new("git")
            .args(["init", "-q", "--bare", "--initial-branch=main"])
            .current_dir(bare_dir)
            .status()
            .expect("git init --bare");
        assert!(init.success());
        let add = SyncCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                bare_dir.to_str().expect("bare path utf-8"),
            ])
            .current_dir(dir)
            .status()
            .expect("git remote add");
        assert!(add.success());
    }

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
        let parent = tempfile::tempdir().expect("parent tempdir");
        let work = parent.path().join("work");
        let bare = parent.path().join("origin.git");
        std::fs::create_dir(&work).expect("mkdir work");
        std::fs::create_dir(&bare).expect("mkdir bare");
        init_repo_with_one_commit(&work);
        add_bare_origin(&work, &bare);
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

        let probe = parent.path().join("probe");
        let clone = SyncCommand::new("git")
            .args([
                "clone",
                bare.to_str().expect("bare utf-8"),
                probe.to_str().expect("probe utf-8"),
            ])
            .status()
            .expect("git clone");
        assert!(clone.success(), "probe clone must succeed");
        let subject_out = SyncCommand::new("git")
            .args(["log", "-1", "--pretty=%s"])
            .current_dir(&probe)
            .output()
            .expect("git log");
        let subject = String::from_utf8_lossy(&subject_out.stdout)
            .trim()
            .to_string();
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
        let add = SyncCommand::new("git")
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
}
