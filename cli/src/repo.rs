//! Repository utilities for forge
//!
//! Provides common repository-related functions like finding the repo root,
//! detecting environment, and working with paths.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Read a YAML file at `path` and deserialize it into `T`.
///
/// The sync sibling of
/// [`crate::git::yaml_read_modify_write_async`] on the read-only arm.
/// Where the async primitive owns the read/parse/mutate/serialize/write
/// round-trip on the async-fs surface, `read_yaml_sync` owns the
/// read/parse prefix on the sync-fs surface: the shape every consumer
/// that loads a typed config off disk (a `ProductConfig`, a
/// `ReleaseConfig`, a `serde_yaml::Value` for `.get(...)` navigation)
/// spelled inline pre-lift.
///
/// # Envelope
///
/// Each failure branch surfaces the offending `path.display()` via
/// [`anyhow::Context`] on the operator's next-step classifier:
///
/// - Read failure: `"Failed to read {path}"` — operator's next step is
///   `ls` on the exact path.
/// - Parse failure: `"Failed to parse {path} as YAML"` — operator's
///   next step is `yamllint` on the exact path, not `ls`.
///
/// Pre-lift six sibling consumer sites in `cli/src/config/mod.rs` each
/// carried its own per-consumer "role" label (`"product config"`,
/// `"service config"`) inside the context string, decoupling the
/// diagnostic wording from the offending path. Post-lift the primitive's
/// canonical `path.display()` envelope reaches every consumer by
/// construction; the role a config plays in the loader is preserved by
/// the caller's function name in the anyhow backtrace, not by a redundant
/// label inside the failure classifier.
///
/// # Type parameter
///
/// `T: DeserializeOwned` — accepts both closed-shape structs
/// (`ProductConfig`, `ServiceConfig`, `GlobalConfig`) and the open
/// [`serde_yaml::Value`] target (for a caller that navigates the
/// document tree via `.get(...)` chains rather than deserializing into
/// a struct). One primitive body serves both shapes.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read (missing, unreadable, EIO)
/// or cannot be parsed as YAML into `T` (invalid YAML syntax, schema
/// mismatch). On the read-Err path no parse is attempted; on the
/// parse-Err path the read has already succeeded, so the offending file
/// is present on disk and the operator can inspect it directly.
pub fn read_yaml_sync<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content = read_text_sync(path)?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {} as YAML", path.display()))
}

/// Remediation hints threaded into the [`read_yaml_sync_hinted`] envelope.
///
/// The canonical [`read_yaml_sync`] envelope carries only the operator's
/// next-step classifier (`"Failed to read {path}"` → `ls`,
/// `"Failed to parse {path} as YAML"` → `yamllint`) and the offending
/// `path.display()`. Three consumer sites in
/// `cli/src/config/mod.rs::DeployConfig::load_for_service` (service,
/// product, global config paths) legitimately carry richer per-config
/// remediation prose — the read-arm hint may add "and not corrupted"
/// or a service-specific context; the parse-arm hint may enumerate
/// common YAML-syntax pitfalls or point at `CONFIGURATION.md`. That
/// prose is load-bearing signal the canonical envelope would erase, so
/// this struct threads it through the primitive at ONE typed boundary
/// rather than at N inline call sites.
///
/// The struct-shape (rather than a two-`&str` positional API) prevents
/// a caller from silently swapping `read_hint` and `parse_hint` at a
/// call site — a swap the compiler could not catch on
/// `read_yaml_sync_hinted(path, "hint-A", "hint-B")` but rejects on
/// `YamlLoadHints { role, read_hint: ..., parse_hint: ... }` because
/// the field names are named at the point of construction.
#[derive(Debug, Clone, Copy)]
pub struct YamlLoadHints<'a> {
    /// Prose describing the config's role (e.g. `"service config"`,
    /// `"product config"`, `"global config"`). Threads into BOTH the
    /// read-arm and parse-arm classifiers so an operator reading the
    /// runner log knows which of the three configs failed without
    /// having to cross-reference the offending path against the loader
    /// source.
    pub role: &'a str,
    /// Remediation prose appended to the read-arm envelope after the
    /// offending path. Operator's next step is still `ls`; the hint
    /// may add "and not corrupted" or a service-specific reason to
    /// look at the file's byte-level state.
    pub read_hint: &'a str,
    /// Remediation prose appended to the parse-arm envelope after the
    /// offending path. Operator's next step is still `yamllint`; the
    /// hint may list common indentation/quoting pitfalls or point at
    /// `CONFIGURATION.md` for the schema.
    pub parse_hint: &'a str,
}

/// Read a YAML file at `path` and deserialize it into `T`, threading
/// [`YamlLoadHints`] into BOTH failure envelopes.
///
/// The hinted sibling of [`read_yaml_sync`]: where the canonical form
/// carries only the operator's next-step classifier and the offending
/// path, this form additionally threads `hints.role` into both
/// classifiers and appends `hints.read_hint` / `hints.parse_hint` after
/// the path.
///
/// # Envelope
///
/// - Read failure: `"Failed to read {role} file: {path}\n  {read_hint}"`
///   — operator's next step is `ls` on the exact path; the hint may
///   name a corruption class to look for.
/// - Parse failure: `"Failed to parse {role}: {path}\n  {parse_hint}"`
///   — operator's next step is `yamllint` on the exact path; the hint
///   may enumerate syntax pitfalls or point at `CONFIGURATION.md`.
///
/// The parse-arm envelope omits the canonical `"as YAML"` classifier
/// suffix because the hint prose (`"Check YAML syntax ..."` at the
/// three consumer sites) already tells the operator the parser is
/// YAML — the classifier's job (name the tool) is filled by the
/// hint. A future refinement that promotes `"as YAML"` back into the
/// classifier lands here and reaches all three consumers by
/// construction.
///
/// # Errors
///
/// Same shape as [`read_yaml_sync`]: `Err` on read failure or parse
/// failure. On the read-Err path no parse is attempted.
pub fn read_yaml_sync_hinted<T: DeserializeOwned>(
    path: &Path,
    hints: &YamlLoadHints<'_>,
) -> Result<T> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read {} file: {}\n  {}",
            hints.role,
            path.display(),
            hints.read_hint
        )
    })?;
    serde_yaml::from_str(&content).with_context(|| {
        format!(
            "Failed to parse {}: {}\n  {}",
            hints.role,
            path.display(),
            hints.parse_hint
        )
    })
}

/// Best-effort YAML load — returns `Some(T)` iff the file exists, is
/// readable, AND parses as YAML into `T`. Any failure (missing file,
/// read error, parse error) collapses to `None`.
///
/// The silent-probe sibling of [`read_yaml_sync`] on the fs-read arm.
/// Where the canonical form propagates every failure with a rich
/// `?`-shaped envelope (path + classifier), this form absorbs every
/// failure at the primitive body so a caller's control flow reads as
/// a simple `if let Some(yaml) = try_read_yaml_sync(&path) { ... }`.
///
/// # When to reach for this form
///
/// Reach for this primitive when a missing/malformed file is a
/// LEGITIMATE fall-through, not an operator-visible defect — a probe
/// that walks a chain of candidate paths, a backward-compatibility
/// fallback whose `None` triggers a stricter loader downstream, a
/// best-effort optional-config load whose absence means "use
/// defaults". Reach for [`read_yaml_sync`] (or the hinted peer) when
/// a missing/malformed file IS an operator-visible defect the
/// runner's log must surface. The two primitives partition the fs-
/// read arm cleanly: propagate-with-envelope on the operator-visible
/// arm, silently-collapse-to-`None` on the probe arm. One primitive
/// per side, no drift possible.
///
/// # Type parameter
///
/// `T: DeserializeOwned` — the same generic bound as
/// [`read_yaml_sync`]. Consumers today all pass
/// [`serde_yaml::Value`] and navigate via `.get(...)` chains, but a
/// future consumer parsing into a closed struct (an `Option<Config>`
/// probe) inherits the primitive by writing exactly ONE line.
///
/// # The pre-lift `.exists()` guard is redundant
///
/// Five pre-lift consumer sites (three in `config/mod.rs`, two in
/// `commands/prerelease.rs`, one in `commands/rollback.rs`) split
/// four ways in the outer control flow: two guarded the read arm
/// with an outer `if path.exists()` before opening the file, three
/// did not. Both shapes collapse identically at the primitive
/// because `std::fs::read_to_string` returns `Err` (ENOENT) for a
/// missing file — the `.ok()` on the read result absorbs it. Post-
/// lift every consumer converges on the outer-guard-free shape by
/// construction, closing a TOCTOU (time-of-check-to-time-of-use)
/// class of defect that lived at the two guarded sites: pre-lift a
/// concurrent `mv` between the `.exists()` sniff and the
/// `read_to_string` call turned the "path missing" probe into a
/// "path unreadable" error the outer guard promised to catch. The
/// primitive collapses BOTH ENOENT paths at ONE code point, so no
/// window remains.
pub fn try_read_yaml_sync<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&content).ok()
}

/// Read a YAML file at `path` and deserialize it into `T`, on the async
/// fs-read surface.
///
/// The async sibling of [`read_yaml_sync`] on the `?`-propagating arm.
/// Where the sync form owns the [`std::fs::read_to_string`] +
/// [`serde_yaml::from_str`] prefix at ONE code point, this form owns
/// the [`tokio::fs::read_to_string`] + [`serde_yaml::from_str`] prefix
/// at ONE code point — every consumer that loads a typed config off
/// disk from an async context (a `kustomization.yaml` `.newTag` sniff,
/// a `MigrationManifest` for the migrations gate) routes through here
/// so the operator-next-step envelope stays canonical.
///
/// # Envelope
///
/// Each failure branch surfaces the offending `path.display()` via
/// [`anyhow::Context`] on the operator's next-step classifier:
///
/// - Read failure: `"Failed to read {path}"` — operator's next step is
///   `ls` on the exact path.
/// - Parse failure: `"Failed to parse {path} as YAML"` — operator's
///   next step is `yamllint` on the exact path, not `ls`.
///
/// Pre-lift four sibling consumer sites each carried its own per-
/// consumer wording inside the `.context(...)` string, and two of the
/// four DROPPED the offending path entirely from both arms
/// (`commands/deploy.rs::execute`, `commands/github_runner_ci.rs::
/// update_manifest_and_deploy`). Post-lift the primitive's canonical
/// `path.display()` envelope reaches every consumer by construction;
/// the role the file plays in the loader is preserved by the caller's
/// function name in the anyhow backtrace, not by a redundant label
/// inside the failure classifier.
///
/// # Sibling primitives
///
/// - Sync `?`-propagating arm: [`read_yaml_sync`].
/// - Sync hint-carrying `?`-propagating arm: [`read_yaml_sync_hinted`].
/// - Sync silent-probe arm: [`try_read_yaml_sync`].
/// - Async read-modify-write shell: [`crate::git::
///   yaml_read_modify_write_async`] (owns the full round-trip; this
///   primitive owns the read/parse prefix only, for consumers that
///   inspect the parsed document without writing it back).
///
/// # Type parameter
///
/// `T: DeserializeOwned` — accepts both closed-shape structs (e.g.
/// `MigrationManifest` at `commands/migration_validation.rs`) and the
/// open [`serde_yaml::Value`] target (e.g. `commands/deploy.rs`
/// navigating a `.get("images")` chain). One primitive body serves
/// both shapes, as with the sync sibling.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read (missing, unreadable, EIO)
/// or cannot be parsed as YAML into `T` (invalid YAML syntax, schema
/// mismatch). On the read-Err path no parse is attempted; on the
/// parse-Err path the read has already succeeded, so the offending
/// file is present on disk and the operator can inspect it directly.
pub async fn read_yaml_async<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let content = read_text_async(path).await?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse {} as YAML", path.display()))
}

/// Read the entire contents of a file at `path` into a `String`, on the
/// async fs-read surface.
///
/// The text-mode sibling of [`read_yaml_async`] on the read arm: the
/// canonical [`tokio::fs::read_to_string`] + [`anyhow::Context`] prefix
/// every consumer that loads a file for line-oriented text mutation
/// (`kustomization.yaml` `newTag:` splice, `Cargo.toml` `[[bin]]`
/// sniff, `builder-pool.yaml` `agentImage:` splice) spelled inline
/// pre-lift.
///
/// # Envelope
///
/// Read failure surfaces `"Failed to read {path}"` — operator's next
/// step is `ls` on the exact path, matching the canonical read-arm
/// envelope [`read_yaml_sync`] / [`read_yaml_async`] already carry.
///
/// Pre-lift ten sibling consumer sites spelled the primitive's OWN
/// shape one level down from this body: a
/// `tokio::fs::read_to_string(path).await.context("Failed to read
/// <literal>")?` composition whose per-site `.context(...)` string
/// (a) hard-coded a filename literal — `"kustomization.yaml"` at eight
/// sites, `"builder-pool.yaml"` at one, `"Cargo.toml"` at one, `"manifest"`
/// at one — that could drift from the actual `path` argument
/// silently, and (b) DROPPED the offending `path.display()` from the
/// failure classifier entirely, so an operator reading a runner log
/// could not tell which of several candidate paths tripped the read.
/// Post-lift the primitive's canonical `path.display()` envelope
/// reaches every consumer by construction; the role the file plays in
/// the caller is preserved by the caller's function name in the
/// anyhow backtrace, not by a redundant filename literal inside the
/// failure classifier.
///
/// # Sibling primitives
///
/// - YAML parse extension on the async surface: [`read_yaml_async`]
///   composes over this primitive's read arm.
/// - Sync YAML parse: [`read_yaml_sync`] owns the sync analogue's
///   read+parse prefix at one code point; this primitive owns the
///   async text-mode read only.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read (missing, unreadable,
/// EIO). The offending `path.display()` is threaded through the
/// [`anyhow::Context`] envelope on every failure branch.
pub async fn read_text_async(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read {}", path.display()))
}

/// Read the entire contents of a file at `path` into a `String`, on the
/// sync fs-read surface.
///
/// The sync sibling of [`read_text_async`] on the read arm: the
/// canonical [`std::fs::read_to_string`] + [`anyhow::Context`] prefix
/// every consumer that loads a file for line-oriented text mutation
/// (`Cargo.toml` version splice, `Chart.yaml` `file://` dep splice,
/// `version.rb` `VERSION=` splice, `seed/profiles.toml` TOML load,
/// `migration-manifest.yaml` append) spelled inline pre-lift.
///
/// # Envelope
///
/// Read failure surfaces `"Failed to read {path}"` — operator's next
/// step is `ls` on the exact path, matching the canonical read-arm
/// envelope [`read_yaml_sync`] / [`read_yaml_async`] / [`read_text_async`]
/// already carry.
///
/// Pre-lift seven sibling consumer sites spelled the primitive's OWN
/// shape one level down from this body: a
/// `std::fs::read_to_string(path).with_context(|| format!("Failed to
/// read {}", path.display()))?` composition. Three lived inside
/// [`crate::version`] shell primitives ([`crate::version`]'s
/// `apply_version_write`, `read_version_by_span`, and
/// `apply_optional_dep_write` bodies) that already redeem duplication
/// two layers below the fs-read arm; four more lived at straggler call
/// sites (`commands/helm.rs::stage_file_sibling_deps` for Chart.yaml
/// `file://` dep staging, `commands/gem.rs::bump` for the version.rb
/// literal read, `commands/seed.rs::load_profiles` for the profiles.toml
/// load, `commands/migration_new.rs::migration_new` for the manifest
/// append) that each re-derived the primitive's envelope by hand. Post-
/// lift the primitive's canonical `path.display()` envelope reaches
/// every consumer by construction; the role the file plays in the
/// caller is preserved by the caller's function name in the anyhow
/// backtrace, not by a redundant filename literal inside the failure
/// classifier.
///
/// # Sibling primitives
///
/// - Async text-mode read: [`read_text_async`] owns the async analogue
///   at ONE code point; this primitive owns the sync surface.
/// - Sync YAML parse: [`read_yaml_sync`] composes over this primitive's
///   read arm and adds the [`serde_yaml::from_str`] parse arm — post-
///   lift its body is one line (`let content = read_text_sync(path)?;`)
///   plus the parse arm.
/// - Sync hint-carrying YAML parse: [`read_yaml_sync_hinted`] carries a
///   distinct envelope (`"Failed to read {role} file: {path}\n  {hint}"`)
///   for the three `load_for_service` config sites that thread
///   remediation prose per role; that shape does not lift here.
/// - Sync silent-probe YAML: [`try_read_yaml_sync`] collapses read AND
///   parse failures to `None`; this primitive propagates read failure
///   with an envelope.
///
/// # Errors
///
/// Returns `Err` if the file cannot be read (missing, unreadable,
/// EIO). The offending `path.display()` is threaded through the
/// [`anyhow::Context`] envelope on every failure branch.
pub fn read_text_sync(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))
}

/// Write `content`'s bytes to a file at `path`, on the sync fs-write
/// surface.
///
/// The write-arm sibling of [`read_text_sync`]: the canonical
/// [`std::fs::write`] + [`anyhow::Context`] composition every consumer
/// that renders a file back to disk after a text-splice or serialization
/// (`Cargo.toml` version splice write, `version.rb` `VERSION=` splice
/// write, `migration-manifest.yaml` scaffold write,
/// `deploy/<svc>.artifact.json` rollback swap) spelled inline pre-lift.
///
/// # Envelope
///
/// Write failure surfaces `"Failed to write {path}"` — operator's next
/// step is `ls -la` and `df -h` on the offending path's ancestor
/// (missing dir, EROFS, ENOSPC, EACCES), matching the read-arm
/// envelope's `path.display()` discipline exactly. The classifier is
/// distinct from the read arm (`"Failed to write"` vs `"Failed to
/// read"`) so an operator reading the runner log can tell one bounce
/// from the other without cross-referencing the caller.
///
/// Pre-lift seven sibling consumer sites spelled the primitive's OWN
/// shape one level down from this body: a `std::fs::write(path,
/// content).with_context(|| format!("Failed to write {}",
/// path.display()))?` composition. Two lived inside [`crate::version`]
/// shell primitives ([`crate::version`]'s `apply_version_write` and
/// `apply_optional_dep_write` bodies) that already redeem write-arm
/// duplication one layer below the fs-write surface; five more lived at
/// straggler call sites (`commands/gem.rs::bump` for the `version.rb`
/// literal write, `commands/rollback.rs::execute` and
/// `commands/product_release.rs::execute` for the twin
/// `deploy/<svc>.artifact.json` swaps that carry byte-identical shells,
/// `commands/migration_new.rs::execute` for both the schema and data-
/// companion scaffolds) that each re-derived the primitive's envelope
/// by hand. Post-lift the primitive's canonical `path.display()`
/// envelope reaches every consumer by construction; the role the file
/// plays in the caller is preserved by the caller's function name in
/// the anyhow backtrace, not by a redundant filename literal inside
/// the failure classifier.
///
/// # Sibling primitives
///
/// - Sync text-mode read: [`read_text_sync`] owns the read-arm analogue
///   at ONE code point; this primitive owns the write-arm counterpart.
/// - Async YAML read-modify-write: [`crate::git::yaml_read_modify_write_async`]
///   owns the full round-trip on the async surface; this primitive owns
///   only the write arm on the sync surface, so a sync caller that
///   already holds the rendered bytes writes them directly rather than
///   round-tripping through a YAML parse.
///
/// # Verb variance is load-bearing signal
///
/// The `"Failed to write {path}"` envelope covers the shape "the file's
/// final bytes could not be persisted." Two `commands/migration_new.rs`
/// sites carry legitimately distinct verbs (`"Failed to update {path}"`,
/// `"Failed to create {path}"`) that name the branch (append to an
/// existing manifest vs. write a new one) rather than the fs-op, and
/// that per-branch signal would be erased by routing through this
/// canonical envelope. Those sites stay unlifted by design.
///
/// # Type parameter
///
/// `C: AsRef<[u8]>` — accepts every rendered-bytes form a caller holds:
/// `&str`, `&String`, `String`, `&[u8]`, `Vec<u8>`, and the `format!(…)`
/// output shape (`String`) some callers hand in directly.
///
/// # Errors
///
/// Returns `Err` if the file cannot be written (parent dir missing,
/// EROFS, ENOSPC, EACCES). The offending `path.display()` is threaded
/// through the [`anyhow::Context`] envelope on every failure branch.
pub fn write_text_sync<C: AsRef<[u8]>>(path: &Path, content: C) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))
}

/// Write `content`'s bytes to a file at `path`, on the async fs-write
/// surface.
///
/// The async sibling of [`write_text_sync`] on the write arm, and the
/// write-arm peer of [`read_text_async`] on the async surface: the
/// canonical [`tokio::fs::write`] + [`anyhow::Context`] composition every
/// consumer that renders a file back to disk from an in-tokio splice-and-
/// write mutator (`kustomization.yaml` `newTag` splice, `builder-pool.yaml`
/// `agentImage:` / `builderImage:` splice, migration job manifest scaffold
/// write, in-place YAML round-trip's final write arm) spelled inline
/// pre-lift.
///
/// # Envelope
///
/// Write failure surfaces `"Failed to write {path}"` — operator's next
/// step is `ls -la` and `df -h` on the offending path's ancestor
/// (missing dir, EROFS, ENOSPC, EACCES), matching the sync-arm sibling
/// [`write_text_sync`]'s `path.display()` discipline exactly. The
/// classifier is distinct from the read arm (`"Failed to write"` vs
/// `"Failed to read"`) so an operator reading the runner log can tell
/// one bounce from the other without cross-referencing the caller.
///
/// Pre-lift ten sibling consumer sites spelled the primitive's OWN
/// shape one level down from this body: a
/// `tokio::fs::write(path, content).await.context("Failed to write
/// <literal>")?` composition whose per-site `.context(...)` string
/// hard-coded a filename literal — `"kustomization.yaml"` at seven
/// sites, `"builder-pool.yaml"` at two, `"migration job manifest"` at
/// one, `"updated manifest"` at one — that could drift from the actual
/// `path` argument silently, and that DROPPED the offending
/// `path.display()` from the failure classifier entirely, so an
/// operator reading a runner log could not tell which of several
/// candidate paths tripped the write. One eleventh site inside
/// [`crate::git::yaml_read_modify_write_async`]'s five-line
/// read/parse/mutate/serialize/write shell spelled the canonical
/// `path.display()` envelope directly (`"Failed to write {}",
/// path.display()`); it lifts here for the same reason the read-arm
/// prefix already lifts onto [`read_text_async`] — one primitive body
/// per fs-op surface, same canonical operator-next-step contract.
/// Post-lift the primitive's canonical `path.display()` envelope
/// reaches every consumer by construction; the role the file plays in
/// the caller is preserved by the caller's function name in the anyhow
/// backtrace, not by a redundant filename literal inside the failure
/// classifier.
///
/// # Sibling primitives
///
/// - Sync text-mode write: [`write_text_sync`] owns the sync analogue's
///   write arm at ONE code point; this primitive owns the async
///   counterpart.
/// - Async text-mode read: [`read_text_async`] owns the read-arm
///   analogue on the async surface; this primitive owns the write-arm
///   counterpart.
/// - Async YAML read-modify-write: [`crate::git::yaml_read_modify_write_async`]
///   owns the full round-trip on the async surface with a parsed-YAML
///   mutator contract, and post-lift its final write arm delegates
///   here; this primitive owns only the byte-mode write arm on the
///   async surface, so a caller that already holds the rendered bytes
///   (a text-splice consumer that mutates line-by-line rather than
///   round-tripping through a YAML parse) writes them directly.
///
/// # Verb variance is load-bearing signal
///
/// The `"Failed to write {path}"` envelope covers the shape "the file's
/// final bytes could not be persisted." Two consumer sites carry
/// legitimately distinct verbs that name what the file IS (a schema
/// staged for codegen input, a `.version` file), not merely that a
/// write failed: `commands/codegen_validation.rs::execute` spells
/// `"Failed to write schema to {path}"` where "schema to" tags the
/// staged-input role that a bare `"Failed to write {path}"` would erase,
/// and `commands/rust_service.rs::execute` spells `"Failed to write
/// .version file to {path}"` where ".version file to" tags the
/// deploy-metadata role a bare envelope would erase. Those sites stay
/// unlifted by design — the shield source-scan matches only the
/// canonical `"Failed to write"` classifier so they survive by
/// construction, mirroring the sync sibling [`write_text_sync`]'s
/// discipline that leaves `commands/migration_new.rs`'s `"Failed to
/// update"`/`"Failed to create"` sites unlifted for the same reason.
///
/// # Type parameter
///
/// `C: AsRef<[u8]>` — accepts every rendered-bytes form a caller holds:
/// `&str`, `&String`, `String`, `&[u8]`, `Vec<u8>`, and the `format!(…)`
/// output shape (`String`) some callers hand in directly.
///
/// # Errors
///
/// Returns `Err` if the file cannot be written (parent dir missing,
/// EROFS, ENOSPC, EACCES). The offending `path.display()` is threaded
/// through the [`anyhow::Context`] envelope on every failure branch.
pub async fn write_text_async<C: AsRef<[u8]>>(path: &Path, content: C) -> Result<()> {
    tokio::fs::write(path, content)
        .await
        .with_context(|| format!("Failed to write {}", path.display()))
}

/// Create the directory at `path` and every missing ancestor, on the
/// sync fs surface.
///
/// The directory-side sibling of [`write_text_sync`]: the canonical
/// [`std::fs::create_dir_all`] + [`anyhow::Context`] composition every
/// consumer that materializes an output directory ahead of a subsequent
/// write (`helm package`'s `output` dir, `helm publish`'s `dist` dir,
/// `copy_dir_recursive`'s destination root, `dashboards.rs`'s parent-dir
/// scaffold, `pangea.rs`'s spec-directory scaffold, `gem.rs`'s
/// `~/.gem` credentials dir) spelled inline pre-lift.
///
/// # Envelope
///
/// Failure surfaces `"Failed to create directory {path}"` — operator's
/// next step is `ls -la` on the offending path's ancestor, `df -h`, and
/// a permissions read on the writable branch (EROFS, ENOSPC, EACCES,
/// ENOTDIR when a component is a regular file). The classifier is
/// distinct from the file-write sibling ([`write_text_sync`]'s
/// `"Failed to write"`) so an operator reading the runner log can tell
/// a mkdir bounce from a write bounce without cross-referencing the
/// caller — a real signal, because create-directory bounces almost
/// always resolve at the parent (`chmod`, `mkdir`, a missing volume
/// mount) while file-write bounces almost always resolve at the file
/// (`chown`, `truncate`, `df` on the enclosing filesystem).
///
/// Pre-lift seven sibling consumer sites spelled the primitive's OWN
/// shape one level down from this body: a bare
/// `std::fs::create_dir_all(<path>)?` composition whose failure would
/// surface only the underlying `io::Error` classifier (`No such file or
/// directory (os error 2)`, `Permission denied (os error 13)`,
/// `Not a directory (os error 20)`) with NO offending path, so an
/// operator reading a runner log could not tell which of several
/// candidate paths tripped the mkdir without re-deriving the site's
/// call context from the anyhow backtrace. Post-lift the primitive's
/// canonical `path.display()` envelope reaches every consumer by
/// construction; the role the directory plays in the caller is
/// preserved by the caller's function name in the anyhow backtrace,
/// not by a redundant filename literal inside the failure classifier.
///
/// # Sibling primitives
///
/// - File-mode sync write: [`write_text_sync`] owns the write-arm
///   analogue at ONE code point on the file surface; this primitive
///   owns the directory-scaffold peer, so a caller that must both
///   scaffold a parent directory and persist a file writes
///   `create_dir_all_sync(parent)?; write_text_sync(&path, bytes)?;`
///   through two canonically-enveloped primitives rather than
///   re-deriving both envelopes inline.
/// - File-mode sync read: [`read_text_sync`] owns the read-arm
///   analogue on the file surface. The directory arm has no read peer —
///   a directory's contents are read via [`std::fs::read_dir`] which
///   yields entries, not text — so this primitive stands alone on the
///   directory-scaffold surface.
///
/// # Verb variance is load-bearing signal
///
/// The `"Failed to create directory {path}"` envelope covers the shape
/// "the directory could not be scaffolded." Two consumer sites carry
/// legitimately distinct verbs that name what the directory IS (a
/// per-tool locks scaffold, a per-service subgraph scaffold), not
/// merely that a mkdir failed: `commands/tool.rs::execute` spells
/// `"Failed to create locks directory: {path}"` where "locks
/// directory" tags the per-tool-lock role a bare envelope would erase,
/// and `commands/schema_validation.rs::execute` spells `"Failed to
/// create subgraph directory: {path}"` where "subgraph directory" tags
/// the codegen-input role a bare envelope would erase. Those sites
/// stay unlifted by design — the shield source-scan matches only the
/// canonical `"Failed to create directory"` classifier so they survive
/// by construction, mirroring the sibling [`write_text_sync`]'s
/// discipline that leaves `commands/migration_new.rs`'s
/// `"Failed to update"`/`"Failed to create"` sites unlifted for the
/// same reason.
///
/// # Errors
///
/// Returns `Err` if the directory cannot be created (a component of
/// the path is a regular file — ENOTDIR, a writable ancestor is
/// read-only — EROFS, an ancestor is on a full filesystem — ENOSPC,
/// the process lacks write permission — EACCES). The offending
/// `path.display()` is threaded through the [`anyhow::Context`]
/// envelope on every failure branch.
pub fn create_dir_all_sync(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create directory {}", path.display()))
}

/// Replace the symlink at `link_name` so it points at `target`, on the
/// async fs surface.
///
/// The atomic-symlink-replace primitive on the async fs surface: the
/// canonical "silently drop any existing entry at `link_name`, then
/// create a fresh symlink pointing at `target`" composition every
/// consumer that stages a build-output symlink at a well-known path
/// (`{working_dir}/{output}` in `commands/build.rs`, `{repo_root}/result`
/// in `commands/comprehensive_release.rs`, `{working_dir}/result-runner`
/// in `commands/github_runner_ci.rs`) spelled inline pre-lift.
///
/// # Envelope
///
/// Failure surfaces `"Failed to create symlink {link_name} -> {target}"`
/// — operator's next step is `ls -la` on `link_name`'s parent (a missing
/// dir, EACCES on the writable ancestor, ENOSPC on the mount, or EEXIST
/// when the pre-remove failed to clear the slot because `link_name` was
/// a non-empty directory rather than a file or symlink) and a probe of
/// `target` (a missing target is not itself an error at symlink-creation
/// time — Unix symlinks may dangle — but the operator can then confirm
/// the intended target still exists in the nix store). The classifier
/// renders BOTH paths so an operator reading the runner log can tell
/// which of several staged symlinks tripped without cross-referencing
/// the caller, and can tell target from link at a glance. Pre-lift the
/// three inline consumer sites spelled `"Failed to create symlink"` /
/// `"Failed to create result symlink"` / `"Failed to create result-runner
/// symlink"` — no target, no link, operator had to grep for the call
/// context to know which build-output symlink stage bounced.
///
/// # Silent remove-arm is load-bearing
///
/// The pre-existence sweep is intentionally best-effort. Pre-lift every
/// consumer spelled `tokio::fs::remove_file(link).await.ok();` (or
/// `let _ = tokio::fs::remove_file(link).await;`) explicitly — the sweep
/// exists solely to reserve the `link_name` slot from the underlying
/// [`tokio::fs::symlink`] (which fails with `EEXIST` when `link_name`
/// already exists), and every well-defined outcome except "the slot is
/// now clear" surfaces on the create arm anyway (the create's `EEXIST`
/// if the remove did not actually clear the slot surfaces post-lift on
/// this primitive's own `"Failed to create symlink"` envelope, and the
/// operator inspects `link_name` directly). Threading the remove's
/// `io::Error` back to the caller would surface spurious `ENOENT` on
/// the first-run path — the sweep is expected to no-op when the link
/// does not exist yet — the exact opposite of the semantics every
/// pre-lift consumer relied on.
///
/// # Arg order
///
/// `(target, link_name)` — matches Unix `symlink(2)`, the underlying
/// [`tokio::fs::symlink`], and every pre-lift consumer's spelling
/// (`tokio::fs::symlink(&target, &link_name).await…`). A drift that
/// swapped the two would silently create the inverse symlink (a link
/// whose target is the original link path and a target with no reader),
/// and the shield tests below pin both the shape and the order.
///
/// # Sibling primitives
///
/// - Sync directory scaffold: [`create_dir_all_sync`] owns the
///   materialize-a-directory arm on the sync fs surface; a caller that
///   must both scaffold the parent of the symlink and stage the link
///   writes `create_dir_all_sync(link_name.parent().unwrap_or(…))?;`
///   ahead of `replace_symlink_async(target, link_name).await?`. The
///   two primitives compose without either re-deriving the other's
///   envelope.
///
/// # Errors
///
/// Returns `Err` if the symlink cannot be created (parent dir missing —
/// ENOENT, the writable ancestor is read-only — EROFS, the mount is
/// full — ENOSPC, the process lacks write permission — EACCES, or the
/// pre-remove failed to clear the slot — EEXIST). Both
/// `link_name.display()` and `target.display()` are threaded through
/// the [`anyhow::Context`] envelope on every failure branch. A
/// `remove_file` failure on the pre-existence sweep is silently
/// discarded by design (see "Silent remove-arm is load-bearing" above).
pub async fn replace_symlink_async(target: &Path, link_name: &Path) -> Result<()> {
    tokio::fs::remove_file(link_name).await.ok();
    tokio::fs::symlink(target, link_name)
        .await
        .with_context(|| {
            format!(
                "Failed to create symlink {} -> {}",
                link_name.display(),
                target.display()
            )
        })
}

/// Read the process's current working directory into an owned
/// [`PathBuf`], envelope-tagging the underlying [`std::io::Error`] with
/// the operator's next-step classifier `"Failed to get current
/// directory"`.
///
/// The atomic sync-fs primitive that owns the exact shape every
/// pre-lift consumer spelled inline:
///
/// ```text
/// std::env::current_dir().context("Failed to get current directory")?
/// ```
///
/// Pre-lift four call sites carried the classifier shape verbatim
/// ([`find_repo_root`] and [`in_directory`] in this module,
/// `commands::e2e::get_working_directory`, and
/// `path_builder::PathBuilder::new`); a fifth
/// (`commands::federation::update_federation`) carried the shorter
/// naked `env::current_dir()?` shape that surfaced the raw
/// [`std::io::Error`] with no operator-facing classifier. Post-lift
/// every one routes through this one body so the read is spelled
/// exactly once and the envelope wording is one edit away from every
/// caller by construction — the "solve once at the primitive" shape
/// (THEORY §V) also every sibling `crate::repo::*` primitive on the
/// sync-fs surface already carries.
///
/// # Envelope
///
/// A failure of the underlying [`std::env::current_dir`] (the cwd was
/// unlinked mid-run, or the process lacks read permission on it — the
/// classic `getcwd(3)` `ENOENT` / `EACCES` return codes) surfaces
/// through [`anyhow::Context`] as `"Failed to get current directory"`.
/// The offending path is not carried in the envelope because on the
/// failure branch there is no path to carry — the query itself failed.
///
/// # Errors
///
/// Returns `Err` if [`std::env::current_dir`] fails. The most common
/// production trigger is a cwd that has been unlinked or renamed out
/// from under the process (a common shape in test suites that chdir
/// into a [`tempfile::tempdir`] and then let the tempdir drop).
///
/// # See also
///
/// * [`find_repo_root`] — layers this primitive with an
///   ancestor-walking flake.nix probe.
/// * [`in_directory`] — layers this primitive with a scope-guarded
///   `set_current_dir` pivot.
/// * [`set_current_dir_labeled`] — the peer on the cwd-write surface;
///   `current_dir` reads, `set_current_dir_labeled` writes.
pub fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().context("Failed to get current directory")
}

/// Find repository root by looking for flake.nix
///
/// Search order:
/// 1. Current directory
/// 2. Parent directories (up to 10 levels)
/// 3. REPO_ROOT environment variable
///
/// # Errors
///
/// Returns an error if no flake.nix is found in any searched location.
///
/// # Examples
///
/// ```rust,ignore
/// let repo_root = find_repo_root()?;
/// println!("Repository root: {}", repo_root.display());
/// ```
pub fn find_repo_root() -> Result<PathBuf> {
    let current = current_dir()?;

    debug!("Searching for repo root from: {}", current.display());

    // Check current directory
    if current.join("flake.nix").exists() {
        debug!("Found flake.nix in current directory");
        return Ok(current);
    }

    // Check parent directories (up to 10 levels)
    let mut dir = current.as_path();
    for level in 1..=10 {
        if let Some(parent) = dir.parent() {
            if parent.join("flake.nix").exists() {
                debug!(
                    "Found flake.nix {} level(s) up at: {}",
                    level,
                    parent.display()
                );
                return Ok(parent.to_path_buf());
            }
            dir = parent;
        } else {
            break;
        }
    }

    // Check REPO_ROOT env var
    if let Some(path) = path_from_env_optional("REPO_ROOT") {
        if path.join("flake.nix").exists() {
            debug!("Found flake.nix via REPO_ROOT env var: {}", path.display());
            return Ok(path);
        }
        debug!(
            "REPO_ROOT set to {} but no flake.nix found there",
            path.display()
        );
    }

    anyhow::bail!(
        "Cannot find repository root (flake.nix not found).\n\n  \
         Searched:\n  \
         - Current directory: {}\n  \
         - Parent directories (up to 10 levels)\n  \
         - REPO_ROOT environment variable\n\n  \
         Solutions:\n  \
         - Run this command from the repository root directory\n  \
         - Set REPO_ROOT environment variable to the repository root",
        current.display()
    )
}

/// Get a tool binary path from environment or fallback to PATH
///
/// Two-arg env-var-with-`String`-fallback sigil on the tool-name
/// surface: where [`env_var_or_default`] takes an arbitrary
/// substrate-supplied string as the fallback (an environment alias,
/// a registry URL, a server name, a cluster name),
/// [`get_tool_path`] takes a *command name* as the fallback (a
/// shell-name used as a PATH lookup by the caller). Post-lift the
/// body is `env_var_or_default(env_var, fallback)` — the
/// `env::var → String` shape lives at the ONE primitive body so a
/// future refinement of the shape (logging every resolve,
/// canonicalizing the value against a closed enum, a telemetry
/// sigil separating explicit-value from default-fallback paths, or
/// a swap to a typed `substrate::EnvVar(String)` newtype) lands at
/// [`env_var_or_default`] and reaches every sigil by construction
/// (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to check first
/// * `fallback` - Command name to use if env var not set
///
/// # Examples
///
/// ```rust,ignore
/// let cargo = get_tool_path("CARGO", "cargo");
/// let crate2nix = get_tool_path("CRATE2NIX", "crate2nix");
/// ```
pub fn get_tool_path(env_var: &str, fallback: &str) -> String {
    env_var_or_default(env_var, fallback)
}

/// Resolve a substrate-declared directory-path env var into a
/// [`PathBuf`], surfacing `miss_context` via [`anyhow::Context`] on the
/// unset case.
///
/// Result<PathBuf> peer to [`get_tool_path`] — where `get_tool_path`
/// takes an env var and a PATH-lookup fallback (infallible, `String`),
/// `path_from_env` takes an env var and a caller-supplied
/// operator-facing miss wording (fallible, `PathBuf`). Every consumer
/// that resolves a substrate-declared directory path from an env var
/// (`SERVICE_DIR`, `REPO_ROOT`, etc.) routes through this one body so
/// the `env::var` read and the `PathBuf::from` projection live at
/// EXACTLY one point. A future refinement of the substrate-path
/// contract — a canonicalize hook, a must-exist check, a swap to a
/// typed `substrate::ServiceDir(PathBuf)` newtype, a telemetry sigil
/// on the resolved path — lands here and reaches every caller by
/// construction (THEORY §VI.1 — every recurring shape becomes a helper
/// before it becomes duplicated code).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to read
/// * `miss_context` - Operator-facing wording forwarded to
///   [`anyhow::Context`] on the miss. Each caller keeps its own
///   domain-specific wording (`"SERVICE_DIR not set - this should be
///   called via substrate wrapper"`, `"SERVICE_DIR environment variable
///   not set"`, `"SERVICE_DIR not set - required for deploy.yaml
///   lookup"`) so the consumer's downstream diagnostic prose stays
///   grep-visible verbatim.
pub fn path_from_env(env_var: &str, miss_context: &'static str) -> Result<PathBuf> {
    let raw = std::env::var(env_var).context(miss_context)?;
    Ok(PathBuf::from(raw))
}

/// Resolve a substrate-declared directory-path env var into a
/// [`PathBuf`], folding the unset case into `None`.
///
/// `Option<PathBuf>` peer to [`path_from_env`] (Result<PathBuf>) and
/// [`env_var_optional`] (Option<String>) on the env-var-projection
/// algebra. Where [`path_from_env`] carries a caller-supplied
/// operator-facing miss wording and surfaces the unset case as a
/// [`Result::Err`] via [`anyhow::Context`] (the "the env var MUST be
/// set" contract used by callers that bail immediately), and
/// [`env_var_optional`] carries the raw `String` value forward
/// (leaving downstream projection to the caller), `path_from_env_optional`
/// closes the "env var MAY be set; if it is, treat it as a path"
/// contract at one body — the shape every `if let Ok(v) =
/// env::var(NAME) { PathBuf::from(v) }` inline stanza in the crate
/// spelled verbatim.
///
/// Composed on top of [`env_var_optional`] so the empty-string-is-a-
/// VALUE semantic is inherited by construction: an operator's
/// explicit-empty export (`REPO_ROOT=""`, `NIX_HOOKS_PATH=""`) lands
/// on `Some(PathBuf::new())`, not `None`. Parity with every pre-lift
/// consumer's inline `if let Ok(v) = env::var(NAME)` shape, where
/// `Ok(String::new())` matched the arm and flowed into
/// `PathBuf::from("")`. A future primitive refinement that swapped
/// `env_var_optional` for `release_git_sha_from_env`-style
/// `.filter(|s| !s.is_empty())` semantics would silently reroute
/// every `<NAME>=""` export from `Some(PathBuf::new())` to `None` and
/// misroute every consumer's `if let Some(_) = ...` dispatch.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Six byte-similar inline `if let Ok(v) = std::env::var(NAME) {
/// PathBuf::from(v) }` stanzas spelled the shape across six CLI-facing
/// modules before this lift:
///
/// - [`find_repo_root`] (`REPO_ROOT`) — flake.nix-validated fallback
///   arm after the current-directory / parent-walk searches fail.
/// - `crate::git::get_repo_root` (`REPO_ROOT`) — env-var-first
///   shortcut before falling back to `git rev-parse --show-toplevel`.
/// - `crate::path_builder::PathBuilder::new` (`REPO_ROOT`) —
///   env-var-first shortcut before falling back to
///   `DeployConfig::find_repo_root(&current_dir)`.
/// - `commands/bootstrap.rs::get_bootstrap_dir` (`SERVICE_DIR`) —
///   env-var-first shortcut before falling back to `find_repo_root()
///   .join("pkgs/platform/bootstrap")`.
/// - `commands/pangea.rs::find_external_repo` (`<NAME>_DIR`, dynamic)
///   — env-var-first shortcut before searching standard `$HOME/code`
///   / `$HOME/.local/src` locations.
/// - `nix_hooks.rs::NixHooksPackage::discover` (`NIX_HOOKS_PATH`) —
///   env-var-first shortcut before building `.#nix-hooks` via `nix
///   build`.
///
/// # Post-lift refinement surface
///
/// Post-lift a future refinement of the shape — canonicalizing the
/// path via `std::fs::canonicalize`, absolutizing against the current
/// working directory, a telemetry sigil separating explicit-value from
/// unset paths, a must-exist check via `.filter(|p| p.exists())`, or
/// a swap to a typed `substrate::SubstratePath(PathBuf)` newtype —
/// lands at this body and reaches every consumer by construction. The
/// same solve-once-at-the-primitive discipline [`env_var_or_default`]
/// closes on the `String`-fallback surface, [`path_from_env`] closes
/// on the `Result<PathBuf>` surface, [`env_var_optional`] closes on
/// the `Option<String>` surface, and [`safe_mode_from_env`] /
/// [`truthy_flag_from_env`] close on the `bool` surface (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
pub fn path_from_env_optional(env_var: &str) -> Option<PathBuf> {
    env_var_optional(env_var).map(PathBuf::from)
}

/// Verify a directory exists and contains expected files
///
/// # Arguments
///
/// * `dir` - Directory path to check
/// * `required_files` - List of files that must exist in the directory
///
/// # Errors
///
/// Returns an error if the directory doesn't exist or is missing required files.
pub fn verify_directory(dir: &Path, required_files: &[&str]) -> Result<()> {
    if !dir.exists() {
        anyhow::bail!(
            "Directory not found: {}\n\n  \
             If this is a new setup, you may need to create the directory.\n  \
             If on a different machine, try: git pull origin main",
            dir.display()
        );
    }

    if !dir.is_dir() {
        anyhow::bail!("Path exists but is not a directory: {}", dir.display());
    }

    for file in required_files {
        let file_path = dir.join(file);
        if !file_path.exists() {
            anyhow::bail!(
                "Required file not found: {}\n  \
                 Expected in: {}",
                file,
                dir.display()
            );
        }
    }

    Ok(())
}

/// Resolve a `working_dir: &str` command argument into a lifetime-borrowed
/// [`Path`] after asserting it exists on disk. Owns the exact `"Working
/// directory not found: {working_dir}"` bail wording every command module
/// entry point that accepts a `working_dir: &str` and immediately gates on
/// its existence spelled inline pre-lift.
///
/// # Pre-lift shape
///
/// 10 sibling command-entry-point sites spelled the 3-line stanza verbatim:
///
/// ```text
/// let dir = Path::new(working_dir);
/// if !dir.exists() {
///     bail!("Working directory not found: {}", working_dir);
/// }
/// ```
///
/// The 10 sites, all authoring the same three lines independently:
///
/// - [`crate::commands::test_ci::execute`]
/// - [`crate::commands::test_ci::coverage`]
/// - [`crate::commands::gem::bump`]
/// - [`crate::commands::gem::build`]
/// - [`crate::commands::gem::test`]
/// - [`crate::commands::tool::release`]
/// - [`crate::commands::tool::bump`]
/// - [`crate::commands::tool::check`]
/// - [`crate::commands::tool::regenerate`]
/// - [`crate::commands::tool::lock`]
///
/// Post-lift each collapses to `let dir = crate::repo::
/// require_existing_working_dir(working_dir)?;` — the [`Path::new`]
/// construction, the [`Path::exists`] gate, and the exact bail wording
/// all live at ONE body.
///
/// # Return
///
/// Returns a lifetime-borrowed `&Path` (bound to the `working_dir: &str`
/// input via lifetime elision) rather than an owned [`PathBuf`], so the
/// caller's downstream `.join(...)` / `.current_dir(dir)` / `.display()`
/// reads are zero-alloc and structurally identical to the pre-lift
/// `let dir = Path::new(working_dir);` idiom. A future refinement of the
/// shape (canonicalize hook, a must-be-a-directory check that upgrades
/// the `.exists()` gate to `.is_dir()`, a hermetic-scratch relocation)
/// lands here and reaches every consumer by construction (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # Errors
///
/// Returns `Err` with the exact message `"Working directory not found: {}"`
/// interpolating the `working_dir: &str` VERBATIM (NOT
/// `Path::new(working_dir).display()`) — pre-lift every consumer bailed
/// with the raw string, so the operator sees the value they passed on
/// the CLI without a trailing-slash normalization or a redundant
/// re-projection through [`Path::display`]. A drift that swapped the
/// interpolation to `dir.display()` would silently change the operator-
/// facing wording for every one of the ten consumers.
///
/// # Sibling primitives
///
/// - [`verify_directory`] — `&Path` + required-files, with a
///   `"Directory not found"` prose and a next-step git-pull hint.
///   Different consumer surface: takes a `&Path` (not `&str`), asserts
///   the directory is-a-dir (not just exists), and enforces per-file
///   requirements. This primitive is the smaller
///   `&str → Result<&Path>` peer at the command-entry-point-only surface.
/// - [`path_from_env`] — the `env-var-name → Result<PathBuf>` peer at
///   the env-var-sourced-path surface.
pub fn require_existing_working_dir(working_dir: &str) -> Result<&Path> {
    require_existing_labeled(working_dir, "Working directory")
}

/// Resolve a caller-owned `path: &str` into a lifetime-borrowed [`Path`]
/// after asserting it exists on disk, interpolating a caller-supplied
/// `label` into the `"{label} not found: {path}"` bail envelope.
///
/// The generalized `&str + &str` peer of [`require_existing_working_dir`]
/// on the `path-string + role-noun → Result<&Path>` surface — pre-lift
/// nine sibling command-module sites spelled the 3-line
/// `let path = Path::new(<str>); if !path.exists() { bail!("<Label> not
/// found: {}", <str>); }` stanza verbatim, each with a different noun
/// (`"Kustomization file"`, `"Builder pool file"`, `"Chart tarball"`,
/// `"runtime image tarball"`, `"Working directory"`) fixed at its own
/// call site. Post-lift the [`Path::new`] construction, the
/// [`Path::exists`] gate, the exact `"{label} not found: {path}"` bail
/// wording, and the `&Path` return-shape all live at ONE body; the
/// per-site noun is threaded through as a `label: &str` parameter and
/// the caller's compile-time-known role reaches the operator's log
/// verbatim.
///
/// # Pre-lift sites fused into ONE body
///
/// - [`crate::commands::kenshi_agent::release`] x2 —
///   `"Kustomization file"` + `"Builder pool file"`.
/// - [`crate::commands::kenshi::release`] — `"Kustomization file"`.
/// - [`crate::commands::push::update_kustomization`] —
///   `"Kustomization file"`.
/// - [`crate::commands::nix_builder::release`] x3 — two
///   `"Kustomization file"` sites and one `"Builder pool file"` site.
/// - [`crate::commands::crossplane::function_release`] —
///   `"runtime image tarball"`.
/// - [`crate::commands::helm::push`] — `"Chart tarball"`.
///
/// [`require_existing_working_dir`] itself delegates through this body
/// with `label = "Working directory"`, so the ten
/// `working_dir: &str` command-entry-point sites at
/// [`require_existing_working_dir`]'s pre-lift trace also route through
/// here transitively — the `Path::new` / `.exists()` / bail-envelope
/// discipline appears at EXACTLY one primitive across the whole crate.
///
/// # Envelope
///
/// The bail wording is `"{label} not found: {path}"`, interpolating the
/// `path: &str` argument VERBATIM (NOT `Path::new(path).display()`) —
/// pre-lift every consumer bailed with the raw string, so the operator
/// sees the value they passed on the CLI (or an env var, or a config
/// row) without a trailing-slash normalization or a redundant
/// re-projection through [`Path::display`]. A drift that swapped the
/// interpolation to `p.display()` would silently change the operator-
/// facing wording for every one of the nine consumers.
///
/// # Return
///
/// Returns a lifetime-borrowed `&Path` (bound to the `path: &str` input
/// via the `'a` lifetime on both parameters and the return) rather than
/// an owned [`PathBuf`], so the caller's downstream
/// `crate::repo::read_text_async(path).await?;` or `.join(...)` reads
/// are zero-alloc and structurally identical to the pre-lift
/// `let path = Path::new(<str>);` idiom the nine sites relied on. A
/// future refinement of the shape — canonicalize hook, a
/// must-be-a-file check that upgrades the `.exists()` gate to
/// `.is_file()`, a symlink-resolution branch — lands here and reaches
/// every consumer by construction (THEORY §V.1 —
/// Types → Invariants → Proofs; §VI.1 — three-times rule, extract an
/// archetype and generate from it).
///
/// # Type contract
///
/// The `'a` lifetime binds the returned `&Path` to the `path: &str`
/// argument's lifetime (via the explicit `'a` annotation on the input
/// and the return, not lifetime elision — the two-arg signature makes
/// the elided version ambiguous). The `label: &str` argument has an
/// independent, unnamed lifetime so a caller passing a static `&'static
/// str` literal for `label` and a function-parameter `&str` for `path`
/// compiles without lifetime coercion.
///
/// # Errors
///
/// Returns `Err` if the resolved [`Path`] does not exist on disk. On
/// the miss arm the caller-facing wording is
/// `"{label} not found: {path}"`; the primitive does NOT probe why the
/// path is missing (permission denied, ENOENT on an intermediate
/// component, dangling symlink) — the discipline is a next-step `ls
/// {path}` for the operator, not a diagnostic tree at the primitive
/// body.
pub fn require_existing_labeled<'a>(path: &'a str, label: &str) -> Result<&'a Path> {
    let p = Path::new(path);
    if !p.exists() {
        anyhow::bail!("{} not found: {}", label, path);
    }
    Ok(p)
}

/// Assert a caller-owned [`&Path`] exists on disk, bailing with the exact
/// `"{label} not found: {path.display()}"` envelope on the miss arm.
///
/// The `&Path + &str → Result<()>` peer of [`require_existing_labeled`]
/// on the caller-already-owns-the-path surface. Where
/// [`require_existing_labeled`] takes a `path: &str` and constructs the
/// [`Path`] inside the body (returning the borrowed `&Path` so downstream
/// code can `.join(...)` off it), this variant is for the consumer that
/// has already resolved a [`PathBuf`] / `&Path` on their side — typically
/// via a preceding `.join(...)`, a `deploy_config.<...>_directory()?`, or
/// a config-typed accessor — and just needs the `.exists()` gate + bail
/// wording. Returning `Ok(())` keeps the caller's existing binding in
/// scope; a `&Path`-echoing return would be redundant identity work at
/// every call site.
///
/// # Pre-lift sites fused into ONE body
///
/// Seven sibling command-module sites spelled the 3-line
///
/// ```text
/// if !<pathbuf>.exists() {
///     bail!("<Label> not found: {}", <pathbuf>.display());
/// }
/// ```
///
/// stanza verbatim, each with a different noun fixed at its own call site:
///
/// - [`crate::commands::gem::build`] — `"Gemspec"` on `dir.join(&gemspec)`.
/// - [`crate::commands::helm`] — `"Library chart"` on
///   `charts_path.join(lib_chart_name).join("Chart.yaml")`.
/// - [`crate::commands::web_build_verify`] x2 — `"Assets directory"` on
///   `dist_dir.join("assets")` and `"index.html"` on
///   `dist_dir.join("index.html")`.
/// - [`crate::commands::federation::update_federation`] —
///   `"Federation directory"` on `deploy_config.federation_directory()?`.
/// - [`crate::commands::migration_new`] — `"SeaORM migrations directory"`
///   on `base_dir.join("services/rust/migration/src")`.
/// - [`crate::commands::federation_tests`] —
///   `"Federation tests deploy.yaml"` on
///   `federation_tests_dir.join("deploy.yaml")`.
///
/// # Envelope
///
/// The bail wording is `"{label} not found: {path.display()}"`,
/// projecting the [`Path`] through [`Path::display`] because pre-lift every
/// consumer already projected via `.display()` — the caller-owned
/// [`PathBuf`] has no raw-`&str` form the operator originally typed (unlike
/// [`require_existing_labeled`], which interpolates the raw string
/// verbatim). A drift that swapped the interpolation to `path.to_string_lossy()`
/// or a debug-format `{:?}` variant would silently change the operator-
/// facing wording for every one of the seven consumers.
///
/// # Errors
///
/// Returns `Err` if `path` does not exist on disk. On the miss arm the
/// caller-facing wording is `"{label} not found: {path.display()}"`; the
/// primitive does NOT probe why the path is missing (permission denied,
/// ENOENT on an intermediate component, dangling symlink) — the
/// discipline is a next-step `ls {path}` for the operator, not a
/// diagnostic tree at the primitive body.
///
/// # Sibling primitives
///
/// - [`require_existing_labeled`] — the `&str + &str → Result<&Path>` peer
///   at the caller-supplies-a-string surface. Interpolates the raw `&str`
///   verbatim, NOT via `.display()`, because the pre-lift `&str` consumers
///   carried the operator-typed value directly.
/// - [`require_existing_working_dir`] — the `&str → Result<&Path>`
///   command-entry-point specialization that fixes `label = "Working
///   directory"`.
pub fn require_existing_path(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("{} not found: {}", label, path.display());
    }
    Ok(())
}

/// Resolve a substrate-declared env var into a `String`, falling back
/// to `default` on the unset case.
///
/// Peer to [`get_tool_path`] on the env-var-with-`String`-fallback
/// surface — where `get_tool_path` is documented as "env var or PATH
/// lookup" and takes a *command name* as the fallback (a shell-name),
/// `env_var_or_default` takes an *arbitrary substrate-supplied
/// string* as the fallback (an environment alias, a registry URL, a
/// server name, a cluster name). Every crate site that resolved a
/// substrate-declared env var into a `String` with a hard-coded
/// literal fallback — the shape
///
/// ```text
/// std::env::var(<NAME>).unwrap_or_else(|_| <DEFAULT>.to_string())
/// ```
///
/// — routes through this one body so the `env::var` read and the
/// `String::from(default)` projection live at EXACTLY one point.
///
/// Pre-lift five per-module sigils spelled the pattern verbatim:
///
/// - [`get_environment`] (`FORGE_ENV` / `"staging"`)
/// - [`crate::infrastructure::attic::attic_server_alias`]
///   (`ATTIC_SERVER_NAME` / `"default"`)
/// - [`crate::config::default_cluster`] (`FORGE_CLUSTER` /
///   `"default"`)
/// - `crate::domain::service::get_registry_base`
///   (`SERVICE_REGISTRY_BASE` / `"ghcr.io/org/project"`)
/// - `crate::commands::pangea::get_registry_base` (`PANGEA_REGISTRY`
///   / `"ghcr.io/org/project"`)
///
/// Each per-module sigil kept its identity — the `(env_var, default)`
/// pair is baked into the sigil's body, so the caller-facing type is
/// still `fn() -> String` with no env-var name to typo at the call
/// site. Post-lift a future refinement of the shape — logging every
/// resolve, canonicalizing the value against a closed enum, a
/// telemetry sigil separating explicit-value from default-fallback
/// paths, or a swap to a typed `substrate::EnvVar(String)` newtype —
/// lands here and reaches every sigil by construction (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # Arguments
///
/// * `env_var` - Environment variable name to read
/// * `default` - Literal fallback returned when the env var is unset
///   or unreadable. Cloned into a `String` on the fallback path,
///   consumed as `String::from(default)`.
pub fn env_var_or_default(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

/// Resolve an env-var read onto `Option<String>` with empty-string-is-a-value
/// parity — the shape every `std::env::var(NAME).ok()` inline stanza in the
/// crate spelled verbatim.
///
/// # The mirror-of-[`crate::git::release_git_sha_from_env`] contract
///
/// Peer to [`crate::git::release_git_sha_from_env`] on the `Option<String>`
/// surface, split by empty-string semantics: where `release_git_sha_from_env`
/// closes the empty-string-is-MISS shape (an unset env var and a
/// `RELEASE_GIT_SHA=""` export both fold to `None`), `env_var_optional`
/// closes the empty-string-is-a-VALUE shape (an unset env var folds to
/// `None`, a `DATABASE_URL=""` / `PUSHGATEWAY_URL=""` / `HOSTNAME=""`
/// export folds to `Some(String::new())`). The two primitives split the
/// crate's `env::var → Option<String>` surface exhaustively so a fresh
/// consumer picks its primitive by asking "does an explicit-empty export
/// count as a value or as a miss?" — the closed choice a per-module inline
/// `env::var(NAME).ok()` stanza does not present.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Six byte-similar inline `std::env::var(NAME).ok()` stanzas spelled the
/// shape across three CLI-facing modules before this lift:
///
/// - `commands/sync.rs::generate_entities` (`DATABASE_URL`) — gate on the
///   env var before invoking `sea-orm-cli generate entity`.
/// - `observability.rs::EventMetadata::new` (`HOSTNAME`) — enrich every
///   structured event with the host emitting it.
/// - `observability.rs::EventMetadata::new` (`CI_JOB_ID` fallback of the
///   `GITHUB_RUN_ID` primary) — the `.or_else(|| env::var("CI_JOB_ID").ok())`
///   chain arm on the CI-job-id enrichment surface.
/// - `observability.rs::metrics::pushgateway_url` (`PUSHGATEWAY_URL`) —
///   gate on the env var before pushing Prometheus metrics.
/// - `infrastructure/registry.rs::RegistryCredentials::discover_token`
///   (`GHCR_TOKEN`) — first env-var arm of the GHCR-token discovery chain.
/// - `infrastructure/registry.rs::RegistryCredentials::discover_token`
///   (`GITHUB_TOKEN`) — second env-var arm of the same chain.
///
/// # Post-lift refinement surface
///
/// Post-lift a future refinement of the shape — logging every resolve, a
/// telemetry sigil separating explicit-value from unset paths, a swap to a
/// typed `substrate::EnvVar(Option<String>)` newtype, or canonicalizing the
/// value against a closed enum — lands at this body and reaches every
/// consumer by construction. The same solve-once-at-the-primitive
/// discipline [`env_var_or_default`] closes on the `String`-fallback
/// surface, [`path_from_env`] closes on the `Result<PathBuf>` surface,
/// [`safe_mode_from_env`] / [`truthy_flag_from_env`] close on the `bool`
/// surface, and [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` mirror (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # The empty-string case
///
/// `Some(String::new())` on the empty-string set path — an operator's
/// explicit-empty export (`PUSHGATEWAY_URL=""`) lands on `Some(_)`, not
/// `None`. Parity with every pre-lift consumer's inline `.ok()`
/// behaviour: `env::var(NAME).ok()` on an `Ok(String::new())` is
/// `Some(String::new())`, not `None`. A future primitive refinement that
/// swapped `.ok()` for `.ok().filter(|s| !s.is_empty())` would silently
/// re-route every `<NAME>=""` export from `Some("")` to `None` and reopen
/// the class the peer split closes — that is the exact projection
/// [`crate::git::release_git_sha_from_env`] closes for the empty-is-miss
/// half, and a callers-facing merge would defeat the split.
pub fn env_var_optional(env_var: &str) -> Option<String> {
    std::env::var(env_var).ok()
}

/// Get the current environment (staging, production, etc.)
///
/// Reads from `FORGE_ENV` environment variable, defaults to `"staging"`.
///
/// This is the ONE body across the crate that reads `FORGE_ENV` into a
/// `String` with the `"staging"` default — the shape
/// `commands/status.rs` spelled inline as `std::env::var("FORGE_ENV")
/// .unwrap_or_else(|_| "staging".to_string())` before lifting through
/// here. Routes through the crate-scoped [`env_var_or_default`]
/// primitive so the `env::var`-read-with-`String`-fallback projection
/// lives at ONE body across the crate — a future refinement of the
/// shape (logging the resolved environment, canonicalizing it against
/// a closed enum of known environments, a telemetry sigil on the
/// value, or a swap to a typed `substrate::Environment(String)`
/// newtype) lands at the primitive and reaches every consumer by
/// construction (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// The `"staging"` default matches the `#[arg(long, env = "FORGE_ENV",
/// default_value = "staging")]` clap attribute at `cli.rs:397` so the
/// CLI-flag path and the env-read path agree on the fallback.
pub fn get_environment() -> String {
    env_var_or_default("FORGE_ENV", "staging")
}

/// Resolve SAFE mode from the environment.
///
/// Reads the `SAFE` environment variable and folds it to a `bool` with
/// the "default TRUE — disable with `false` or `0` (case-insensitive)"
/// contract. Unset → `true`; `SAFE=false` / `SAFE=FALSE` / `SAFE=False`
/// / `SAFE=0` → `false`; anything else (including `SAFE=""`, `SAFE=no`,
/// `SAFE=off`, `SAFE=maybe`) → `true`.
///
/// This is the ONE body across the crate that reads `SAFE` into a
/// `bool` with the disable-with-`false`-or-`0` semantic. Pre-lift two
/// byte-equivalent inline stanzas spelled the shape:
///
/// ```text
/// std::env::var("SAFE")
///     .map(|v| {
///         let val = v.to_lowercase();
///         val != "false" && val != "0"
///     })
///     .unwrap_or(true)
/// ```
///
/// at `main.rs::main` (the `Commands::Rollout` arm's `safe_mode` local)
/// and `commands/github_runner_ci.rs::is_safe_mode`. Both consumers
/// govern retry semantics on the same operator-facing toggle: the
/// rollout dispatch's `RetryPolicy::network_or_immediate(safe_mode)`
/// arm and the github-runner-CI Attic-login/push retry-budget
/// partition. A drift at one site — a typo `SAFE_MODE`, a lost
/// `to_lowercase()` making `SAFE=FALSE` silently truthy, a swap to
/// `!= "0"` alone dropping the `"false"` half, an accidental default
/// flip to `false` — would silently misroute the operator's `SAFE`
/// toggle at one dispatch surface only, and the mismatch would surface
/// as a rollout that retries where the operator asked it not to (or
/// vice versa) on one CLI entry point while the other honors the
/// override.
///
/// Post-lift a future refinement of the shape (logging every resolve,
/// widening the disable set to `{no, off}`, a telemetry sigil
/// separating explicit-value from default-fallback paths, or a swap to
/// a typed `substrate::SafeMode(bool)` newtype) lands at this body and
/// reaches every consumer by construction — the same
/// solve-once-at-the-primitive discipline
/// [`env_var_or_default`] closes on the `String`-fallback surface,
/// [`path_from_env`] closes on the `Result<PathBuf>` surface, and
/// [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` surface
/// (THEORY §V — solve-once-at-the-primitive; §VI.1 —
/// recurring-shape-to-helper).
///
/// The empty-string parity (`SAFE=""` → `true`) is deliberate: a
/// `to_lowercase()`d empty string satisfies both `!= "false"` and
/// `!= "0"`, so an operator's explicit-empty export lands on the
/// default-true branch alongside an unset env var. A future primitive
/// refinement that swapped the shape for `.ok().filter(|s|
/// !s.is_empty()).map(...).unwrap_or(true)` would preserve this
/// empty-is-truthy semantic; a swap to
/// `.ok().is_some_and(...)`-style dispatch would flip it and misroute
/// every `SAFE=""` export.
pub fn safe_mode_from_env() -> bool {
    std::env::var("SAFE")
        .map(|v| {
            let val = v.to_lowercase();
            val != "false" && val != "0"
        })
        .unwrap_or(true)
}

/// Resolve a "default FALSE — enable on `1` / `true` (case-insensitive)"
/// env-var flag onto a `bool`.
///
/// Reads `env_var` and returns `true` iff its value is `"1"` or the letters
/// `t-r-u-e` in any case (`true`, `TRUE`, `True`, `tRuE`, `TrUe`, …).
/// Unset → `false`; every other value (`""`, `"0"`, `"false"`, `"yes"`,
/// `"on"`, `"maybe"`, `"2"`) → `false`.
///
/// # The mirror-of-[`safe_mode_from_env`] contract
///
/// Peer to [`safe_mode_from_env`] on the flag-parsing surface: where
/// `safe_mode_from_env` folds the DEFAULT-TRUE / disable-with-`false`-or-`0`
/// operator toggle onto ONE body, `truthy_flag_from_env` folds the DEFAULT-
/// FALSE / enable-with-`1`-or-`true` mirror toggle onto ONE body. The two
/// primitives split the crate's opt-out (`SAFE`) versus opt-in
/// (`FORGE_HELM_REPUBLISH`, `SKIP_INTEGRATION`, `SKIP_E2E`) env-var-to-bool
/// surface exhaustively so a fresh consumer picks its primitive by asking
/// "is the default TRUE (safety-on) or FALSE (opt-in-only)?" — the closed
/// choice a per-module inline stanza does not present.
///
/// # Pre-lift stanzas fused into ONE body
///
/// Three byte-similar inline stanzas spelled the shape across three CLI
/// entry points:
///
/// - `commands/helm.rs::republish_enabled` (`FORGE_HELM_REPUBLISH`) —
///   `std::env::var("FORGE_HELM_REPUBLISH").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))`.
///   Governs whether an already-published `(name, version)` Helm chart is
///   force-re-uploaded to `oci://ghcr.io/pleme-io/charts` (immutable by
///   default; enabling the flag is a "repair a corrupt upload"
///   escape hatch).
/// - `commands/prerelease.rs` `SKIP_INTEGRATION` — pre-lift
///   `.map(|v| v == "true" || v == "1").unwrap_or(false)`. Governs whether
///   the G13 gate (Postgres + Redis + NATS testcontainers) is skipped.
/// - `commands/prerelease.rs` `SKIP_E2E` — same pre-lift shape. Governs
///   whether the G14 gate (chromiumoxide + full stack) is skipped.
///
/// The two prerelease sites drifted from `helm.rs` on case-sensitivity: an
/// operator's `SKIP_INTEGRATION=TRUE` / `SKIP_E2E=TRUE` (uppercase) was
/// silently ignored — the `v == "true"` clause matches lowercase only —
/// while `FORGE_HELM_REPUBLISH=TRUE` fired via `.eq_ignore_ascii_case`.
/// Post-lift both consumers route through the case-insensitive body, so a
/// mixed-case `TRUE` / `True` / `TrUe` export from any of the three
/// operator-facing entry points behaves identically. That parity is a
/// load-bearing behavioral improvement, not a shuffle: a CI operator's
/// `SKIP_E2E=TRUE` now actually skips G14 instead of silently running it.
///
/// # Post-lift refinement surface
///
/// A future refinement of the shape (widening the enable set to include
/// `yes` / `on`, adding a telemetry sigil separating explicit-value from
/// default-fallback paths, a swap to a typed `substrate::FeatureFlag(bool)`
/// newtype, canonicalizing the accepted values against a closed enum, or
/// logging every resolve) lands at this body and reaches every consumer by
/// construction — the same solve-once-at-the-primitive discipline
/// [`safe_mode_from_env`] closes on the DEFAULT-TRUE mirror,
/// [`env_var_or_default`] closes on the `String`-fallback surface,
/// [`path_from_env`] closes on the `Result<PathBuf>` surface, and
/// [`crate::git::release_git_sha_from_env`] closes on the
/// empty-string-is-miss `Option<String>` surface (THEORY §V — solve-once-
/// at-the-primitive; §VI.1 — recurring-shape-to-helper).
///
/// # The empty-string case
///
/// `""` → `false`: an operator's explicit-empty export (`SKIP_E2E=""`)
/// does NOT enable the flag — `v == "1"` is false, and the empty string
/// matched against `eq_ignore_ascii_case("true")` is false (lengths
/// differ). Parity with every pre-lift consumer's inline behaviour.
pub fn truthy_flag_from_env(env_var: &str) -> bool {
    std::env::var(env_var).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Which product-directory layouts [`find_product_dir`] accepts as terminal.
///
/// The monorepo layout is universal — every consumer honors it. The
/// standalone layout is additive and consumed only by the rust-service
/// entry point, where a product may live as its own repository rather
/// than a `pkgs/products/{product}` subtree of a larger monorepo. The
/// named-standalone variant is additive on top of that: it also parses
/// the standalone `deploy.yaml` and requires a top-level string `name:`
/// field to be present, matching the `config::DeployConfig` loader's
/// pre-lift acceptance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductDirLayout {
    /// Monorepo pattern only: an ancestor whose parent is named `products`
    /// and whose grandparent is named `pkgs` — i.e. `.../pkgs/products/{product}`.
    Monorepo,
    /// Monorepo pattern OR standalone: additionally accept any ancestor
    /// directory that carries both `deploy.yaml` and `.git`, i.e. a
    /// product repository whose root IS the product directory.
    MonorepoOrStandalone,
    /// Monorepo pattern OR named standalone: additionally accept any
    /// ancestor directory that carries `deploy.yaml` and `.git` AND whose
    /// `deploy.yaml` parses as YAML with a top-level string `name:` field.
    /// The parse-and-verify step distinguishes a genuine product-repo root
    /// from any other `.git` directory that happens to carry an unrelated
    /// `deploy.yaml` (a deploy-manifest fragment for something else, a
    /// stray file). Matches the pre-lift
    /// `config::DeployConfig::find_product_directory` acceptance rule; a
    /// `.git`+`deploy.yaml` node without a valid `name:` string CONTINUES
    /// the climb rather than terminating, so an inner match at a deeper
    /// ancestor still resolves.
    MonorepoOrNamedStandalone,
}

/// Does `dir/deploy.yaml` parse as YAML and expose a top-level string
/// `name:` field? Extracted verbatim from the pre-lift
/// `config::DeployConfig::find_product_directory` inline check so the
/// named-standalone layout terminal preserves the same
/// tolerate-parse-failures shape: an unreadable file, an unparseable
/// YAML document, a document without a top-level `name`, or a `name`
/// whose value is not a string all return `false` (i.e. the walker
/// CONTINUES the climb) rather than propagating a parse error.
///
/// Post-lift the fs-read + serde-parse prefix routes through
/// [`try_read_yaml_sync`] — the sibling silent-probe primitive one
/// function up in this module. Pre-lift the body spelled the same
/// `let Ok(content) = std::fs::read_to_string(...)` +
/// `let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(...)`
/// pair `try_read_yaml_sync`'s body owns, so the primitive's own module
/// carried a sibling that hand-rolled the shape one function down from
/// the primitive body. Post-lift only ONE code point across the crate
/// (the primitive body) spells the `read_to_string.ok()? +
/// from_str.ok()` silent-probe shell (THEORY §V —
/// solve-once-at-the-primitive; §VI.1 — every recurring shape becomes
/// a helper before it becomes duplicated code).
///
/// The `is_some_and` fold on the primitive's `Option<serde_yaml::Value>`
/// preserves the pre-lift `let Ok(...) else { return false }` `bool`
/// contract at the caller — a `None` from `try_read_yaml_sync`
/// (missing file OR unparseable YAML) folds to `false` by construction,
/// same as the two pre-lift `return false` arms. A future refinement
/// of the silent-probe contract — a canonicalize-path hook, an exists()
/// skip optimization, a telemetry probe on the miss branch — lands at
/// [`try_read_yaml_sync`] and reaches THIS caller (the walker's
/// named-standalone terminal, called once per parent-climb iteration)
/// by construction.
fn standalone_deploy_yaml_has_name(dir: &Path) -> bool {
    try_read_yaml_sync::<serde_yaml::Value>(&dir.join("deploy.yaml"))
        .is_some_and(|yaml| yaml.get("name").and_then(|n| n.as_str()).is_some())
}

/// Walk up from `start` toward the filesystem root, returning the first
/// ancestor (including `start` itself) that satisfies `layout`.
///
/// Fuses five sibling walkers that spelled the same parent-climb loop
/// verbatim across the crate:
///
/// - `commands/integration_tests.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/status.rs::find_product_dir_from_service`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/test.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::Monorepo`])
/// - `commands/rust_service.rs::find_product_dir_from_path`
///   ([`ProductDirLayout::MonorepoOrStandalone`])
/// - `config::DeployConfig::find_product_directory`
///   ([`ProductDirLayout::MonorepoOrNamedStandalone`])
///
/// Three of the five sites carried a byte-identical monorepo-only
/// walker; the fourth extended it with a per-iteration standalone
/// check; the fifth extended THAT with a `deploy.yaml`-parse-plus-`name:`
/// verification. Post-lift the walk lives at ONE place with the layout
/// choice encoded in the closed enum — a future refinement (a fourth
/// layout, a per-layer audit hook, a symlink-cycle guard) lands
/// atomically across every consumer rather than at whichever copy the
/// author notices.
///
/// Walker mechanics — matches the pre-lift shape at every consumer
/// site:
///
/// 1. The monorepo terminal is checked at every iteration against the
///    CURRENT node: `current.parent()` must be named `products` and
///    `current.parent().parent()` must be named `pkgs`. The `current`
///    node itself (the `{product}` component) is what is returned.
/// 2. The standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrStandalone`]) is checked at every
///    iteration against the CURRENT node: `current/deploy.yaml` and
///    `current/.git` must both exist. Order matches the pre-lift
///    `commands/rust_service.rs::find_product_dir_from_path` layout —
///    monorepo terminal first, standalone terminal second — so a path
///    that satisfies both (a `pkgs/products/{product}` node that
///    additionally carries a nested `.git`) returns via the monorepo
///    branch, preserving the pre-lift precedence.
/// 3. The named-standalone terminal (only under
///    [`ProductDirLayout::MonorepoOrNamedStandalone`]) is checked at
///    every iteration against the CURRENT node: `current/.git` and
///    `current/deploy.yaml` must both exist AND `current/deploy.yaml`
///    must parse as YAML exposing a top-level string `name:` field —
///    see [`standalone_deploy_yaml_has_name`]. A parse failure or a
///    missing / non-string `name:` field CONTINUES the climb rather
///    than terminating, so a deeper ancestor whose `deploy.yaml` DOES
///    carry a valid `name:` still resolves.
/// 4. On no match, climb by `current.parent()` and repeat. Terminate
///    with `None` when there is no parent (i.e. the filesystem root
///    was reached without hitting either terminal).
pub fn find_product_dir(start: &Path, layout: ProductDirLayout) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if let Some(parent) = current.parent() {
            if let Some(grandparent) = parent.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some("products")
                    && grandparent.file_name().and_then(|n| n.to_str()) == Some("pkgs")
                {
                    return Some(current);
                }
            }
        }
        match layout {
            ProductDirLayout::Monorepo => {}
            ProductDirLayout::MonorepoOrStandalone => {
                if current.join("deploy.yaml").exists() && current.join(".git").exists() {
                    return Some(current);
                }
            }
            ProductDirLayout::MonorepoOrNamedStandalone => {
                if current.join(".git").exists()
                    && current.join("deploy.yaml").exists()
                    && standalone_deploy_yaml_has_name(&current)
                {
                    return Some(current);
                }
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Activate the root-flake pattern: publish `REPO_ROOT` + `SERVICE_DIR`
/// to the process environment and change the working directory to
/// `repo_root`.
///
/// Fuses three sibling call sites that each hand-spelled the same
/// three-line stanza verbatim:
///
/// - `main.rs::setup_service_directory` (the top-level CLI entry point;
///   pre-lift `set_var("REPO_ROOT", &root); set_var("SERVICE_DIR",
///   &dir); set_current_dir(&root)?`)
/// - `commands/status.rs::execute` (pre-lift `set_var("REPO_ROOT",
///   repo_root); set_var("SERVICE_DIR", service_dir);
///   set_current_dir(repo_root)?`)
/// - `commands/integration_tests.rs::execute_manual` (pre-lift
///   `set_var("REPO_ROOT", repo_root); set_var("SERVICE_DIR",
///   service_dir); set_current_dir(repo_root)?`)
///
/// The invariant every consumer honors — and that a fresh consumer
/// would forget by omission — is composed at ONE surface here:
///
/// 1. `REPO_ROOT` is set FIRST, so every downstream reader
///    (`repo::find_repo_root`, `git::get_repo_root`,
///    `PathBuilder::new`, `DeployConfig::load_for_service`) sees the
///    caller-supplied root regardless of whether the chdir succeeds.
/// 2. `SERVICE_DIR` is set SECOND, so `DeployConfig::load_for_service`
///    and every `commands/*::execute` that reads `SERVICE_DIR` sees the
///    caller-supplied service directory. Omitting this line at any of
///    the three pre-lift sites would have silently misrouted service
///    discovery to whatever `SERVICE_DIR` the calling shell inherited
///    from — a class of bug that structurally cannot occur post-lift.
/// 3. The chdir targets `repo_root`, NOT `service_dir` — the root
///    flake pattern (documented at `main.rs::setup_service_directory`)
///    is "run `nix build` from the repo root; the SERVICE_DIR env var
///    identifies the service to operate on." A caller that chdir'd to
///    `service_dir` instead would break every `nix flake` invocation
///    that follows.
///
/// The env vars are set BEFORE the chdir so a chdir failure still
/// leaves them populated — every pre-lift site had this property by
/// accident of source-order (the two `set_var` lines preceded the `?`
/// on `set_current_dir`); the primitive preserves it by construction.
///
/// # Errors
///
/// Returns an error if `set_current_dir(repo_root)` fails (e.g. the
/// path does not exist, the process lacks permission to enter it, or
/// the path is not a directory).
pub fn activate_root_flake<R, S>(repo_root: R, service_dir: S) -> Result<()>
where
    R: AsRef<Path>,
    S: AsRef<Path>,
{
    let repo_root = repo_root.as_ref();
    let service_dir = service_dir.as_ref();
    std::env::set_var("REPO_ROOT", repo_root);
    std::env::set_var("SERVICE_DIR", service_dir);
    std::env::set_current_dir(repo_root).with_context(|| {
        format!(
            "Failed to change working directory to repo root: {}",
            repo_root.display()
        )
    })
}

/// Change the process working directory to `dir` permanently, labeling
/// the failure envelope with a short human-readable directory role.
///
/// The sibling of [`in_directory`] on the permanent-pivot arm: where
/// [`in_directory`] swaps cwd for a closure's duration and restores on
/// drop, this primitive pivots cwd for the remainder of the process — the
/// shape every consumer that pivots ahead of a subsequent [`Command`]
/// spawn (`rust dev up`, `rust dev down`, `rust cargo regenerate`,
/// `rust cargo update`, `federation compose`) spelled inline pre-lift.
///
/// [`Command`]: tokio::process::Command
///
/// Pre-lift five sibling consumer sites spelled the primitive's OWN shape
/// one level down from this body, each a
/// `env::set_current_dir(<path>).context("Failed to change to <label>
/// directory")?;` composition whose per-site `.context(...)` string
/// baked the role label (`"workspace"`, `"service"`, `"federation"`)
/// into a hand-typed literal that could drift from the actual role the
/// pivot served silently, and whose per-site `env::set_current_dir` call
/// spelled the same three-token shape at five points across two files:
///
/// - `crate::commands::federation::update_federation` (`federation_dir`,
///   `"federation"`)
/// - `crate::commands::developer_tools::rust_regenerate`
///   (`workspace_root`, `"workspace"`)
/// - `crate::commands::developer_tools::rust_cargo_update`
///   (`workspace_root`, `"workspace"`)
/// - `crate::commands::developer_tools::rust_dev` (`service_path`,
///   `"service"`)
/// - `crate::commands::developer_tools::rust_dev_down` (`service_path`,
///   `"service"`)
///
/// Post-lift each collapses to `crate::repo::set_current_dir_labeled(<
/// path>, "<label>")?;` — the [`std::env::set_current_dir`] call and the
/// exact `"Failed to change to {label} directory"` classifier all live
/// at ONE body.
///
/// # Envelope
///
/// Failure surfaces `"Failed to change to {label} directory"` —
/// interpolating the caller-supplied `label` VERBATIM. The operator-
/// facing prose reads the SAME as the pre-lift five sites, so a runner
/// log that grep-matched `"Failed to change to workspace directory"`
/// keeps matching post-lift. A future refinement of the shape (structured
/// failure telemetry that discriminates permission-denied from
/// not-a-directory, a canonicalize hook on the `dir` argument, a swap to
/// a typed `WorkingDir(PathBuf)` newtype) lands here and reaches every
/// consumer by construction (THEORY §V — solve-once-at-the-primitive;
/// §VI.1 — recurring-shape-to-helper).
///
/// # Sibling primitives
///
/// - [`in_directory`] — closure-scope temporary cwd swap on the async
///   surface with automatic RAII restore on drop; this primitive is the
///   permanent-pivot sync peer for consumers that stay in the target
///   directory for the remainder of the process (subsequent [`Command`]
///   spawns, subsequent path-relative reads).
/// - [`activate_root_flake`] — publishes `REPO_ROOT` / `SERVICE_DIR` env
///   vars AND pivots cwd to `repo_root` with the load-bearing
///   `"Failed to change working directory to repo root: {path}"`
///   envelope that names the raw path (not a label). This primitive owns
///   the general-purpose labeled-pivot surface for consumers where the
///   directory's ROLE (workspace / service / federation) is the load-
///   bearing operator-facing signal, not the raw path.
/// - [`require_existing_working_dir`] — pre-check `&str` → `&Path` peer
///   on the working-directory surface; a caller that must both pre-check
///   and pivot writes `let dir = require_existing_working_dir(<str>)?;
///   set_current_dir_labeled(dir, "working")?;` through two canonically-
///   enveloped primitives rather than re-deriving both envelopes inline.
///
/// # Arguments
///
/// * `dir` - Target directory to pivot cwd to. Passed verbatim to
///   [`std::env::set_current_dir`], so the OS-level semantics
///   (permission checks, symlink following, ENOTDIR on a regular-file
///   component) match the underlying call exactly.
/// * `label` - Short human-readable directory role (e.g. `"workspace"`,
///   `"service"`, `"federation"`); interpolated into the failure
///   envelope's `"Failed to change to {label} directory"` classifier
///   VERBATIM. A drift that swapped the interpolation to `dir.display()`
///   would silently change the operator-facing wording for every one of
///   the five consumers.
///
/// # Errors
///
/// Returns `Err` if the underlying [`std::env::set_current_dir`] fails
/// (`dir` does not exist — ENOENT, the process lacks permission to
/// enter it — EACCES, `dir` is not a directory — ENOTDIR). The failure
/// envelope carries the `label` in the classifier; the offending
/// `dir.display()` is NOT interpolated (mirroring the pre-lift five
/// sites' envelope shape exactly).
pub fn set_current_dir_labeled(dir: &Path, label: &str) -> Result<()> {
    std::env::set_current_dir(dir).with_context(|| format!("Failed to change to {label} directory"))
}

/// Return the file-name component of `path` as `&str`, or `""` if the
/// path has no file-name component (`path` ends in `..` or is `/`) or
/// the file name is not valid UTF-8.
///
/// # The pre-lift sigil
///
/// Ten sibling consumers on the borrow-only "read the file name as a
/// stringly key" surface spelled the same triple-projection inline
/// (five in `commands/*.rs`, five in `test_support.rs`'s shield-scan
/// bodies):
///
/// ```ignore
/// let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
/// ```
///
/// Each consumer fed the resulting `&str` into a downstream string
/// predicate — a prefix check (`name.starts_with("pleme-")`), a suffix
/// trim (`filename.trim_end_matches(".rs")`), a
/// [`regex::Regex::is_match`], a substring `.parse::<u32>()` gate, or
/// an equality against a fixed shield-exempt filename (`name ==
/// "test_support.rs"`). Every one of those consumers wanted the
/// borrow-only, zero-alloc projection with the `""` unit on the miss
/// arm — no consumer needed a separate [`Option`]-shaped short-circuit
/// branch, because the empty string propagates the "no match" verdict
/// through the downstream predicate by construction (`"".starts_with(
/// "pleme-")` is `false`, `regex.is_match("")` is `false` for every
/// regex demanding at least one character, `"".trim_end_matches(".rs")`
/// is `""`, and `"" == "sentinel-filename"` is `false`).
///
/// The `""` unit is thus the canonical projection of the miss arm, and
/// bundling the three-step chain plus the miss-arm literal into one
/// primitive removes ten hand-typed spellings the borrow-checker could
/// not otherwise cross-check.
///
/// # Zero-alloc borrow lifetime
///
/// The returned `&str` borrows from `path` (via
/// [`std::ffi::OsStr::to_str`]'s contract on Unix, where the UTF-8
/// projection of the file-name segment is a byte-slice view over the
/// underlying [`std::ffi::OsStr`]), so no [`String`] allocation
/// happens on any call. A downstream
/// [`regex::Regex::is_match`] or [`str::starts_with`] can consume the
/// `&str` directly without an intermediate owned copy — the exact
/// zero-alloc discipline every pre-lift consumer relied on.
///
/// # Peer
///
/// Sibling to [`require_existing_working_dir`] on the borrow-only,
/// return-`&`-borrowed-from-input path-projection surface: both
/// primitives project a caller-owned path bytewise into a canonical
/// downstream shape with no allocation and no path normalization
/// (`.canonicalize()` is not called).
pub fn file_name_str(path: &Path) -> &str {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("")
}

/// Project a caller-owned [`Path`] into an owned [`String`] via the
/// lossy UTF-8 repair every pre-lift consumer relied on: a non-UTF-8
/// byte is replaced by [`U+FFFD REPLACEMENT CHARACTER`], and the
/// resulting string is returned owned. The exact shape every pre-lift
/// consumer spelled inline (`path.to_string_lossy().to_string()`), now
/// with ONE body owning the projection.
///
/// # Duplication lift (the one-primitive-per-projection discipline)
///
/// The pre-lift shape recurred at eleven sibling call sites across
/// five command modules — `commands/product_release.rs` ×3,
/// `commands/helm.rs` ×3, `commands/rust_service.rs` ×2,
/// `commands/rollback.rs` ×1, `commands/dashboards.rs` ×2 — every one
/// of them spelling the same `.to_string_lossy().to_string()` two-step
/// projection over a `PathBuf` or `&Path` receiver.
///
/// Fanned out across eleven hand-typed spellings, the shape was
/// invisible to the borrow-checker: a helpful "let's make this
/// [`std::borrow::Cow`]-shaped for zero-alloc UTF-8 paths" cleanup at
/// any one site would quietly fork one consumer at a time from its ten
/// siblings. Lifting to a single primitive with one owner keeps the
/// projection uniform and refuses drift by construction.
///
/// # The `.into_owned()` alternative to `.to_string()`
///
/// The primitive body calls [`std::borrow::Cow::into_owned`] rather
/// than the [`ToString::to_string`] tail every pre-lift site spelled.
/// On the [`std::borrow::Cow::Borrowed`] arm (the path is already
/// valid UTF-8) both spellings allocate one fresh [`String`] and are
/// bytewise indistinguishable. On the [`std::borrow::Cow::Owned`] arm
/// (the path carried non-UTF-8 bytes and [`Path::to_string_lossy`]
/// synthesized a repair-string), `.into_owned()` unwraps the already-
/// owned [`String`] in place while `.to_string()` allocates a second
/// [`String`] and copies through it — a silent double-alloc the
/// pre-lift shape carried at every site. On Linux CI the observable
/// difference is nil (every path is UTF-8), so this is not a
/// behavioral change; it is a canonical shape the primitive owns once
/// on behalf of every consumer.
///
/// # Peer
///
/// Sibling to [`file_name_str`] on the caller-owned-path-projection
/// surface: [`file_name_str`] is the borrow-only, zero-alloc peer that
/// projects a [`Path`] into a borrowed `&str` (the file-name segment);
/// [`path_to_string_lossy`] is the owned, one-alloc peer that projects
/// a [`Path`] into an owned [`String`] (the full path). Together they
/// discharge the `<path> → <string-shape>` primitive family the
/// `crate::repo::*` surface owns.
pub fn path_to_string_lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Project the file-name segment of a [`std::fs::DirEntry`] into an
/// owned [`String`] via the lossy UTF-8 repair every pre-lift consumer
/// relied on: a non-UTF-8 byte in the entry's file name is replaced by
/// [`U+FFFD REPLACEMENT CHARACTER`], and the resulting string is
/// returned owned so it outlives the [`std::ffi::OsString`]
/// [`std::fs::DirEntry::file_name`] freshly allocates on each call.
///
/// # Duplication lift (the one-primitive-per-projection discipline)
///
/// The pre-lift shape recurred at five sibling consumer sites across
/// four command modules on the directory-listing "read the entry's
/// file name as an owned stringly key" surface:
///
/// - `commands/pangea.rs:633` (inside the `.filter(|e| { let name =
///   e.file_name().to_string_lossy().to_string(); ... })` closure
///   that gates provider-prefixed resource dirs — the `name` is fed
///   into a `name.contains('_') && !name.starts_with('.')` predicate).
/// - `commands/pangea.rs:650` (inside the `for entry in &resource_dirs`
///   body that spells `let resource_name = entry.file_name()
///   .to_string_lossy().to_string();` — `resource_name` is fed into a
///   [`Path::join`] to build the per-resource `synthesis_spec.rb`
///   path).
/// - `commands/helm.rs:1823` (inside the `for entry in std::fs
///   ::read_dir(dir)?.filter_map(...)` body that spells `let name =
///   entry.file_name().to_string_lossy().to_string();` — `name` is
///   fed into an `exclude_name` equality and an `info!("Skipping {}",
///   name)` progress line).
/// - `commands/migration_new.rs:44` (inside the `for entry in entries`
///   body that spells `let filename = entry.file_name().to_string_lossy()
///   .to_string();` — `filename` is fed into a `.starts_with(&date_prefix)
///   && .ends_with(".rs")` predicate and a `.split('_')` sequence-number
///   parse).
/// - `commands/gem.rs:643` (inside the `.map(|e| e.file_name()
///   .to_string_lossy().to_string())` on the sorted-by-mtime
///   `.first()` — the returned [`String`] is the freshly-built gem
///   file's basename the caller returns to its `.context(...)` /
///   downstream `attic push <path>` argv slot).
///
/// Every one of those sites carried the same
/// `<entry>.file_name().to_string_lossy().to_string()` triple-projection
/// over a [`std::fs::DirEntry`] receiver: [`std::fs::DirEntry::file_name`]
/// returns a fresh owned [`std::ffi::OsString`] (unlike
/// [`Path::file_name`] which returns a borrowed `Option<&OsStr>`), then
/// [`std::ffi::OsStr::to_string_lossy`] projects the OS bytes through
/// [`String::from_utf8_lossy`] returning [`std::borrow::Cow<str>`],
/// then [`ToString::to_string`] allocates a fresh owned [`String`] the
/// caller can outlive the temporary [`std::ffi::OsString`] with.
///
/// Fanned out across five hand-typed spellings, the shape was invisible
/// to the borrow-checker: a helpful "let's keep the [`std::ffi::OsString`]
/// alive and hand back a `&str` slice" cleanup at any one site would
/// quietly fork one consumer at a time from its four siblings. Lifting
/// to a single primitive with one owner keeps the projection uniform
/// and refuses drift by construction.
///
/// # The `.into_owned()` alternative to `.to_string()`
///
/// Like [`path_to_string_lossy`], the primitive body calls
/// [`std::borrow::Cow::into_owned`] rather than the [`ToString::to_string`]
/// tail every pre-lift site spelled. On the [`std::borrow::Cow::Borrowed`]
/// arm (the file name is already valid UTF-8) both spellings allocate one
/// fresh [`String`] and are bytewise indistinguishable. On the
/// [`std::borrow::Cow::Owned`] arm (the file name carried non-UTF-8 bytes
/// and [`std::ffi::OsStr::to_string_lossy`] synthesized a repair-string),
/// `.into_owned()` unwraps the already-owned [`String`] in place while
/// `.to_string()` allocates a second [`String`] and copies through it —
/// a silent double-alloc the pre-lift shape carried at every site. On
/// Linux CI the observable difference is nil (every filename is UTF-8),
/// so this is not a behavioral change; it is a canonical shape the
/// primitive owns once on behalf of every consumer.
///
/// # Peer
///
/// Sibling to [`file_name_str`] on the file-name-projection surface:
/// [`file_name_str`] is the borrow-only, zero-alloc [`Path`] peer that
/// projects a [`Path::file_name`] into a borrowed `&str` (with `""`
/// on the miss arm); [`dir_entry_name_lossy`] is the owned, one-alloc
/// [`std::fs::DirEntry`] peer that projects a
/// [`std::fs::DirEntry::file_name`] into an owned [`String`] via
/// lossy UTF-8 repair. The two primitives own the two ends of the
/// "read the file name off a path-like receiver as a stringly key"
/// primitive family — no consumer needs to hand-spell either
/// projection.
pub fn dir_entry_name_lossy(entry: &std::fs::DirEntry) -> String {
    entry.file_name().to_string_lossy().into_owned()
}

/// Sort a slice of [`std::fs::DirEntry`] newest-first by modification
/// time, treating an entry whose metadata or `mtime` cannot be resolved
/// as ancient ([`std::time::SystemTime::UNIX_EPOCH`]) so it sorts to the
/// tail rather than propagating the error to the caller.
///
/// # Duplication lift
///
/// Pre-lift two sibling `find_latest_<artifact>` selectors in the
/// tarball-scanning surface each spelled the same byte-identical
/// `entries.sort_by(|a, b| { b.metadata().and_then(|m| m.modified()).
/// unwrap_or(std::time::SystemTime::UNIX_EPOCH).cmp(&a.metadata().
/// and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::
/// UNIX_EPOCH)) })` closure inline, each `dir/prefix`-scoped over a
/// `Vec<DirEntry>` collected from a [`std::fs::read_dir`] walk:
///
/// - `commands/helm.rs::find_latest_tgz` — selects the newest
///   `<prefix>*.tgz` under a `helm package` output directory (the
///   packaged chart tarball whose path feeds the OCI push).
/// - `commands/gem.rs::find_gem_file` — selects the newest
///   `<prefix>*.gem` (excluding `.gemspec`) under a `gem build` output
///   directory (the built gem whose path feeds the RubyGems push).
///
/// Both call `newest = entries[0]` after the sort, so the entire
/// domain fact — "of the matching entries in a directory, pick the
/// most-recently-written one" — is captured by the primitive, and
/// consumers do not restate the mtime-comparator direction or the
/// unreadable-metadata fallback at each site.
///
/// # Two silent-drift classes this closes
///
/// 1. **Comparator direction.** The closure spelling `b.cmp(&a)`
///    (descending, so `entries[0]` is the newest) is one paren-swap
///    away from `a.cmp(&b)` (ascending, so `entries[0]` is the
///    OLDEST). At a call site named `find_latest_tgz` a swap would
///    silently return the STALE tarball — an image tag that was
///    packaged in a prior run of the same directory, which the OCI
///    push would then advertise as the release. Lifting to a named
///    primitive with a name that carries the ordering (`_desc`) and a
///    single owner refuses the accidental swap at every future call
///    site by construction.
/// 2. **Unreadable-metadata fallback.** A `map_err`-style rewrite
///    that lets a metadata failure bubble as `Err` would make the
///    entire selector reject the directory on the first unreadable
///    entry (a foreign-owned file, a broken symlink, an ACL denial),
///    even when a perfectly readable matching artifact sits next to
///    it. The `UNIX_EPOCH` fallback sorts the offending entry to the
///    tail without failing the selector, and a single primitive keeps
///    both call sites on the same tolerant contract.
///
/// # Behavior
///
/// - **Stability.** Uses [`slice::sort_by`], which is guaranteed
///   stable, so entries whose mtimes tie preserve their pre-sort
///   order (the [`std::fs::read_dir`] enumeration order). Neither
///   call site relies on a tiebreak, but the guarantee is useful
///   for reproducibility when two `helm package` runs land in the
///   same clock second.
/// - **Empty slice.** The sort is a no-op; the caller's
///   `entries.first()` on an empty [`Vec`] correctly yields
///   [`None`] and the caller's own `.context(...)` chain produces
///   the "no artifact found" diagnostic.
pub fn sort_dir_entries_by_mtime_desc(entries: &mut [std::fs::DirEntry]) {
    fn mtime_or_epoch(entry: &std::fs::DirEntry) -> std::time::SystemTime {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    }
    entries.sort_by_key(|e| std::cmp::Reverse(mtime_or_epoch(e)));
}

/// Project a captured process output byte slice
/// ([`std::process::Output::stdout`] / [`std::process::Output::stderr`],
/// or any owned `Vec<u8>` that traveled through the same OS pipe) into
/// an owned [`String`] via the lossy UTF-8 repair every pre-lift
/// consumer relied on, then trim the leading and trailing whitespace
/// so the returned [`String`] carries only the operator-visible payload
/// (a digest, a phase, an image tag, a `stderr` diagnostic).
///
/// # Duplication lift (the one-primitive-per-projection discipline)
///
/// The pre-lift shape recurred at eight sibling consumer sites across
/// four files, each spelling the same three-step
/// `String::from_utf8_lossy(&<bytes>).trim().to_string()` projection
/// inline:
///
/// - Three command modules on the pod-status / registry-digest /
///   deployed-image read path:
///   `commands/product_release.rs:112` (phase from `kubectl get pods
///   -o jsonpath={.items[0].status.phase}` fed into a `"Running"`
///   equality gate that produces the deploy-health verdict),
///   `commands/rust_service.rs:758` (digest from `crane digest ...`
///   fed into a [`String::is_empty`] check + a `[..19]` prefix slice
///   the operator sees in the "✅ Image verified" progress line),
///   `commands/github_runner_ci.rs:767` (deployed image from `kubectl
///   get sts -o jsonpath={image}` fed into a [`str::contains`]
///   check against the expected git-sha).
/// - One [`crate::infrastructure::attic::AtticClient`] error site
///   (`infrastructure/attic.rs:538`, `stderr` field of the typed
///   `AtticError::ClosurePushFailed` variant returned when the Attic
///   `push` output has a non-success status).
/// - Four [`crate::retry`] retry-boundary primitives:
///   `retry.rs:12690` ([`crate::retry::CapturedFailure::from_output`]'s
///   `stderr` field), `retry.rs:13086`
///   ([`crate::retry::classify_capture_query_anyhow`]'s success-arm
///   trimmed-stdout return), and `retry.rs:13926-13927`
///   ([`crate::retry::CommandAttemptFailure::from_capture`]'s
///   `stderr`+`stdout` fields for the op-failure variant).
///
/// Every one of those sites carried the same lossy-repair-plus-trim
/// projection: `Vec<u8>` bytes captured from an OS pipe are not
/// guaranteed UTF-8 (a spawned child's stdout can carry any byte
/// sequence, and a tokio subprocess pipe hands the buffer back
/// verbatim), so a non-lossy [`str::from_utf8`] projection would
/// [`Result::Err`] on the first invalid byte and lose the diagnostic
/// the operator needs to act. And every consumer wanted the trailing
/// newline the child process almost always emits (`kubectl -o
/// jsonpath` closes with `\n`, `crane digest` closes with `\n`,
/// `stderr` diagnostics usually close with `\n`) stripped, so the
/// downstream equality / substring / `[..19]` prefix slice sees only
/// the payload bytes and not the trailing whitespace that would
/// silently break a `==` comparison or shift the prefix slice off by
/// one.
///
/// Fanned out across eight hand-typed spellings, the projection was
/// invisible to the borrow-checker: a helpful "let's return
/// [`std::borrow::Cow`]-shaped so an all-ASCII payload skips the
/// allocation" cleanup at any one site would quietly fork one
/// consumer at a time from its seven siblings. Lifting to a single
/// primitive with one owner keeps the projection uniform and refuses
/// drift by construction.
///
/// # Behavior
///
/// - **Invalid UTF-8** — replaced by [`U+FFFD REPLACEMENT CHARACTER`]
///   via [`String::from_utf8_lossy`]. A non-UTF-8 byte in the child's
///   captured output never fails the projection; the operator sees a
///   diagnostic with `\u{FFFD}` markers rather than a swallowed error.
/// - **Whitespace** — leading and trailing ASCII / Unicode whitespace
///   (matching [`char::is_whitespace`], the same class
///   [`str::trim`] recognizes) is removed. Internal whitespace is
///   preserved so a multi-line `stderr` diagnostic survives
///   line-for-line into the typed error record.
/// - **Empty input** — returns [`String::new`]. The exact result every
///   pre-lift `<x>.stdout.is_empty() → ""` short-circuit relied on.
///
/// # Peer
///
/// Sibling to [`path_to_string_lossy`] on the caller-owned-bytes
/// projection surface: [`path_to_string_lossy`] is the [`Path`]-
/// receiving peer that projects into an owned [`String`] via the
/// same [`String::from_utf8_lossy`] repair (over the path's OS
/// bytes); [`utf8_lossy_trim_owned`] is the byte-slice-receiving
/// peer that projects into an owned trimmed [`String`] (over process
/// output bytes). Together they discharge the `<owned-bytes> →
/// <owned-string-shape>` primitive family the `crate::repo::*`
/// surface owns.
pub fn utf8_lossy_trim_owned(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Project a captured process output byte slice
/// ([`std::process::Output::stdout`] / [`std::process::Output::stderr`],
/// or any owned `Vec<u8>` that traveled through the same OS pipe) into
/// an owned [`String`] via the lossy UTF-8 repair every pre-lift
/// consumer relied on — WITHOUT trimming. Trailing whitespace (the
/// child's closing `\n`, indent runs, blank continuation lines) is
/// preserved verbatim so consumers whose downstream logic depends on
/// the byte sequence surviving intact (a whitespace-split iteration,
/// a substring-search over an `expected + "\n"` slice, a re-emitted
/// diagnostic that must round-trip line-for-line, a `stdout+stderr`
/// concatenation) see the same shape they would have seen from an
/// inline `String::from_utf8_lossy(&<x>).to_string()`.
///
/// # Duplication lift (the one-primitive-per-projection discipline)
///
/// The pre-lift shape recurred at eight sibling consumer sites across
/// four files, each spelling the same two-step
/// `String::from_utf8_lossy(&<bytes>).to_string()` projection inline:
///
/// - Four sites on the Shinka / DatabaseMigration pod-status +
///   job-listing polling paths in `commands/migrations.rs`
///   (`:678` — pod-logs tail captured on failed-job cleanup and
///   fed into the [`Option::filter`] of an
///   [`Option::is_empty`] gate; `:793` — phase from `kubectl get
///   shinkamigration -o jsonpath={.status.phase}` bound owned so
///   a later `phase.trim()` re-borrow can equality-check against
///   `"Failed"` / `"CheckingHealth"` without dropping the temporary;
///   `:852` — `current_phase` from `kubectl get databasemigration`
///   whose [`String::is_empty`] check gates a
///   [`anyhow::bail`] on missing resources and a later
///   `current_phase.trim()` re-borrow feeds the status log line;
///   `:908` — whitespace-separated job names from `kubectl get jobs
///   -o jsonpath={.items[*].metadata.name}` fed into a
///   [`str::split_whitespace`] iteration bound to `Vec<&str>` — a
///   pre-lift `.trim().to_string()` here would still work but the
///   internal-whitespace preservation is load-bearing).
/// - One site on the seed / psql `stdout` capture path
///   (`commands/seed.rs:124` — the whole `stdout` buffer is returned
///   to the caller as an owned [`String`] for downstream parsing
///   that must not lose the psql output's trailing newline structure).
/// - Two sibling sites on the integration-tests / cargo-test-suite
///   output-concatenation path (`commands/integration_tests.rs:1401`
///   + `:1402` — `stdout + &stderr` merged into a single owned
///   [`String`] fed to [`parse_test_counts`], which counts newline-
///   delimited PASS/FAIL lines from `cargo test`'s combined output).
/// - One site on the migration-job log-fetch path
///   (`services/migration_service.rs:337` — the whole `stdout` buffer
///   from `kubectl logs job/<name>` returned to the caller as an
///   owned [`String`] so the operator sees the migration-job log
///   verbatim, blank lines and all).
///
/// # Why a separate primitive from `utf8_lossy_trim_owned`
///
/// The sibling [`utf8_lossy_trim_owned`] projects into an owned
/// [`String`] and ALSO strips leading and trailing whitespace, which
/// its consumers rely on for equality gates, substring searches, and
/// prefix slices that would silently drift off-by-one on a stray
/// closing `\n`. The eight consumers here have the opposite
/// requirement: trailing whitespace is load-bearing (a psql `stdout`
/// with its trailing blank line; a cargo-test output whose PASS/FAIL
/// line count depends on the newline structure; a migration-job log
/// whose blank continuation lines carry stack-frame context). A
/// lift onto [`utf8_lossy_trim_owned`] would silently strip that
/// tail at every one of the eight sites — a distinct projection
/// masquerading as the same shape.
///
/// # Behavior
///
/// - **Invalid UTF-8** — replaced by [`U+FFFD REPLACEMENT CHARACTER`]
///   via [`String::from_utf8_lossy`]. A non-UTF-8 byte in the child's
///   captured output never fails the projection; the operator sees a
///   diagnostic with `\u{FFFD}` markers rather than a swallowed error.
/// - **Whitespace** — leading, trailing, and internal whitespace all
///   preserved byte-for-byte. This is the load-bearing difference
///   from [`utf8_lossy_trim_owned`].
/// - **Empty input** — returns [`String::new`]. The exact result every
///   pre-lift `<x>.stdout.is_empty()` short-circuit relied on.
///
/// # Peer
///
/// Sibling to [`utf8_lossy_trim_owned`] on the byte-slice-receiving
/// surface, keyed by the tail projection: `_trim_owned` strips
/// whitespace, `_owned` preserves it. Together they cover the two
/// canonical `<captured-bytes> → <owned-String>` projections the
/// `crate::repo::*` surface owns; a future third variant would name
/// its tail explicitly (a `_borrow` variant returning `&str`, a
/// `_stderr_trim` variant that also applies an ANSI-code stripper)
/// rather than overload one primitive.
pub fn utf8_lossy_owned(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// Project a captured byte stream through [`String::from_utf8_lossy`],
/// returning a borrowed [`std::borrow::Cow`] without materializing an
/// owned [`String`] on the fully-valid-UTF-8 path.
///
/// # Duplication lift (the single-stream borrow-projection discipline)
///
/// The `let <name> = String::from_utf8_lossy(&<X>.<stream>);` bare
/// borrow-projection recurred inline at forty-plus sibling consumer
/// sites across the `commands/*.rs` surface, each spelling the identical
/// one-line projection: a captured [`std::process::Output`] stream (or a
/// hand-rolled `Vec<u8>` capture in an equivalent shape) bound as a
/// borrowed [`std::borrow::Cow<str>`] and immediately consumed by a
/// single downstream call (a [`str::contains`] gate, a
/// [`str::lines`] walk, a `format!` interpolation, a bail! message).
/// Each pre-lift site read the raw [`String::from_utf8_lossy`] name;
/// none read the family label. Post-lift the primitive stands as the
/// fourth sibling of the `crate::repo::utf8_lossy_*` surface, and
/// consumer sites route through the single named entry point that
/// pins the family membership.
///
/// # Why a separate primitive from `utf8_lossy_owned` and `utf8_lossy_streams`
///
/// The sibling [`utf8_lossy_owned`] materializes an owned [`String`]
/// via a two-alloc `.to_string()` tail — its consumers need the owned
/// buffer to outlive the source bytes (a return value, a struct field,
/// a downstream parser that binds the result across scopes). This
/// primitive's consumers do the opposite: they bind the projection into
/// a local `let` and consume it in the same block, so an owned tail
/// would allocate at every site without benefit. The sibling
/// [`utf8_lossy_streams`] projects BOTH streams from a single
/// [`std::process::Output`] receiver as a paired `(Cow, Cow)` tuple;
/// its shield refuses adjacent same-receiver borrow-projection pairs
/// to keep the "diagnostic dump both streams" surface uniform, but
/// deliberately leaves single-stream borrows (a `stderr`-only bail
/// arm, a `stdout`-only capture path) untouched — that is the class
/// this primitive owns.
///
/// # Behavior
///
/// - **Zero-alloc on valid UTF-8** — returns [`std::borrow::Cow::Borrowed`]
///   pointing directly into `bytes`. The lifetime elision binds the
///   returned [`std::borrow::Cow`]'s borrow to the input slice, so the
///   caller's `let` binding keeps the source alive across use.
/// - **Invalid UTF-8** — invalid byte sequences replaced by
///   [`U+FFFD REPLACEMENT CHARACTER`] via the same
///   [`String::from_utf8_lossy`] repair the sibling primitives use;
///   returns [`std::borrow::Cow::Owned`] carrying the repaired string.
///   A non-lossy [`str::from_utf8`] projection would fail on the first
///   invalid byte and drop the diagnostic the operator needs.
/// - **Whitespace** — leading, trailing, and internal whitespace all
///   preserved byte-for-byte. Consumers that need trimming spell
///   `utf8_lossy_borrow(&<x>.stream).trim()` explicitly at the call
///   site — the primitive does not silently apply a trim the operator
///   did not ask for.
/// - **Empty input** — returns [`std::borrow::Cow::Borrowed`] of the
///   empty string. The exact shape every `<x>.<stream>.is_empty()`
///   short-circuit relied on.
///
/// # Peer
///
/// Sibling to [`utf8_lossy_owned`], [`utf8_lossy_trim_owned`], and
/// [`utf8_lossy_streams`] on the byte-projection surface, keyed by
/// the shape of the return value and the receiver:
///
/// | Primitive               | Receiver                      | Return                                | Tail             |
/// |-------------------------|-------------------------------|---------------------------------------|------------------|
/// | `utf8_lossy_borrow`     | `&[u8]`                       | [`std::borrow::Cow<'_, str>`]         | none             |
/// | `utf8_lossy_owned`      | `&[u8]`                       | [`String`]                            | `.to_string()`   |
/// | `utf8_lossy_trim_owned` | `&[u8]`                       | [`String`]                            | `.trim()` + `.to_string()` |
/// | `utf8_lossy_streams`    | `&`[`std::process::Output`]   | `(`[`Cow<'_, str>`][`std::borrow::Cow`]`, Cow<'_, str>)` | none (paired) |
///
/// Together the four discharge the
/// `<captured-bytes> → <lossy-UTF-8-repair>` family the
/// `crate::repo::*` surface owns.
pub fn utf8_lossy_borrow(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

/// Project both captured streams of a [`std::process::Output`] through
/// [`String::from_utf8_lossy`] in one call, returning
/// `(stdout, stderr)` as a paired tuple of borrowed [`std::borrow::Cow`]
/// values.
///
/// # Duplication lift (the paired-projection discipline)
///
/// The pre-lift shape recurred at ten sibling consumer sites across six
/// files, each spelling the same two adjacent
/// `String::from_utf8_lossy(&<x>.<stream>)` borrow projections inline
/// against the SAME `Output` receiver — a failure-branch dump of both
/// pipes for the operator's diagnostic:
///
/// - `commands/codegen.rs:157-158` (graphql-codegen failure — both
///   streams piped into a single `anyhow::bail!` message).
/// - `commands/codegen_validation.rs:166-167` (graphql-codegen drift
///   detection — both streams concatenated for `drift_indicators`
///   substring search) and `:364-365` ("nothing to commit" gate on
///   `git commit` failure — both streams searched for the marker).
/// - `commands/frontend_validation.rs:181-182` (TypeScript type-check
///   failure — both streams counted for `error TS` occurrences),
///   `:250-251` (ESLint failure — both streams concatenated for the
///   summary), `:339-340` (biome-check failure — both streams merged
///   for error/warning counting), `:391-392` (unit-test failure — both
///   streams merged for the vitest parser).
/// - `commands/prerelease.rs:888-889` (integration-tests failure —
///   both streams walked for `FAILED`/`panicked` lines) and
///   `:1075-1076` (e2e-tests failure — both streams re-printed to the
///   operator).
/// - `commands/seed.rs:119-120` (psql failure — both streams piped
///   into a single `anyhow::bail!` message).
///
/// Every one of those sites bound BOTH streams (never only one) into
/// borrowed [`std::borrow::Cow`] values from the same `Output`
/// receiver, then read them for `.contains` / `.matches` / `.lines` /
/// `format!` interpolation. Nine of the ten spellings bound `stderr`
/// first and `stdout` second; one (`frontend_validation.rs:391-392`)
/// bound `stdout` first. The paired projection was invisible to the
/// borrow-checker: a helpful "let's also strip ANSI codes at the
/// diagnostic dump" cleanup at any one site would quietly fork one
/// consumer at a time from its nine siblings. Lifting to a single
/// paired-return primitive with one owner keeps the two projections
/// uniform against the same receiver and refuses drift by construction.
///
/// # Behavior
///
/// - Returns `(stdout, stderr)` — the natural [`std::process::Output`]
///   field order. Callers destructure into whichever names they read
///   (nine sites use `let (stdout, stderr) = ...`; the tenth used
///   the same order pre-lift).
/// - **Borrow shape** — the returned tuple carries two
///   [`std::borrow::Cow`] values borrowed from the argument's stream
///   buffers. Every consumer reads them via `.contains` / `.matches` /
///   `.lines` / `format!` interpolation and never needs the owned tail
///   the sibling [`utf8_lossy_owned`] applies — a `.to_string()` here
///   would allocate at every failure branch and drop the borrow shape
///   the pre-lift sites already relied on.
/// - **Invalid UTF-8** — each stream's invalid bytes replaced by
///   [`U+FFFD REPLACEMENT CHARACTER`] via the same
///   [`String::from_utf8_lossy`] repair the sibling primitives use.
///   A non-lossy [`str::from_utf8`] projection would fail on the first
///   invalid byte and drop the diagnostic the operator needs.
/// - **Whitespace** — leading, trailing, and internal whitespace all
///   preserved byte-for-byte on each stream. The failure-branch
///   consumers walk full lines (`\n`-delimited splits, `.lines()`
///   iteration) and cannot afford a trim step that would silently
///   glue the last line of one stream to the first of a `format!`
///   concatenation.
///
/// # Peer
///
/// Sibling to [`utf8_lossy_owned`] and [`utf8_lossy_trim_owned`] on
/// the `Output`-projection surface, keyed by the receiver shape and
/// the tail: `_owned` / `_trim_owned` take a single `&[u8]` byte slice
/// and return an owned [`String`] (with or without a trim tail); this
/// primitive takes an `&Output` and returns a paired
/// borrow-shape tuple covering BOTH streams in one call. Together
/// they discharge the `<captured-process-output> → <lossy-UTF-8-repair>`
/// primitive family the `crate::repo::*` surface owns.
pub fn utf8_lossy_streams(
    output: &std::process::Output,
) -> (std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>) {
    (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// Lossy-project both captured streams of a [`std::process::Output`]
/// and return a single owned [`String`] carrying
/// `<stderr>\n<stdout>` — the "combined diagnostic corpus" four
/// failure-branch consumer sites build to grep-match error / warning
/// tokens that a tool may route to either stream.
///
/// # Duplication lift (the stderr-first joined-corpus discipline)
///
/// Four sibling consumer sites past THEORY §VI.1's three-times-is-a-
/// law threshold each spelled the same two-line stanza inline:
///
/// ```text
/// let (stdout, stderr) = crate::repo::utf8_lossy_streams(&<output>);
/// let <name> = format!("{}\n{}", stderr, stdout);
/// ```
///
/// - `commands/codegen_validation.rs:166-169` (graphql-codegen drift
///   detection — `let error_msg = format!(...)` searched with
///   `.contains(indicator)` against a fixed drift-indicator list).
/// - `commands/frontend_validation.rs:249-250` (ESLint failure — `let
///   combined = format!(...)` walked with `.matches(" error").count()`
///   / `.matches(" warning").count()` and re-iterated by `.lines()`
///   for the summary).
/// - `commands/frontend_validation.rs:337-338` (biome-check failure —
///   `let combined = format!(...)` walked with `.matches("error")` /
///   line-filter `.contains("✖")` for the error/warning counts).
/// - `commands/frontend_validation.rs:388-389` (vitest unit-test run
///   — `let combined = format!(...)` fed into `parse_test_count`
///   and used for `.contains("FAIL")` / `.contains("No test files
///   found")` classifiers).
///
/// Two related sites route the paired projection into a bail!
/// message inline instead of naming the joined string
/// (`commands/codegen.rs:157-158` and `commands/seed.rs:118-120`);
/// they are OUT OF SCOPE of this primitive because the pre-lift
/// stanza there fuses the projection and the bail wording into one
/// call (`anyhow::bail!("...:\n{}\n{}", stderr, stdout)`) and lifting
/// only the joined string half would leave a trailing bail! that
/// carries the same operator wording split across two lines. The
/// four in-scope sites all name the joined `String` locally and
/// consume it via `.contains` / `.matches` / `.lines` / parser
/// helpers, so a single-owner primitive at that boundary is the
/// tightest fit.
///
/// # Behavior
///
/// - Returns `<stderr>\n<stdout>` — stderr FIRST, stdout SECOND.
///   Operator-facing diagnostic tools (ESLint, TypeScript, biome,
///   vitest, graphql-codegen) route human-readable error prose to
///   stderr and machine-parseable summary counts to stdout; putting
///   stderr first makes the first line of a truncated display carry
///   the most actionable signal. The single-line-per-primitive body
///   pins this order at ONE place; a future consumer that respells
///   the same two-line stanza and typos the order (stdout first)
///   would be caught by the sibling shield test rather than compiling
///   into a wrong-looking diagnostic.
/// - **Invalid UTF-8** — each stream's invalid bytes replaced by
///   [`U+FFFD REPLACEMENT CHARACTER`] via the same
///   [`String::from_utf8_lossy`] repair the sibling primitives use.
/// - **Whitespace** — leading, trailing, and internal whitespace all
///   preserved byte-for-byte on each stream; only the single
///   `\n` separator between the two is added by construction. A
///   `.trim()` here would silently glue the last line of stderr to
///   the first of stdout for the `.lines()` iteration the four
///   consumer sites drive.
/// - **Allocation** — one owned [`String`] allocation (the [`format!`]
///   output). The pre-lift stanza did two [`Cow`] projections plus
///   one [`format!`] allocation for a total of one owned allocation;
///   post-lift matches the pre-lift allocation shape.
///
/// # Peer
///
/// Sibling to [`utf8_lossy_streams`] on the `Output`-projection
/// surface: where the pair-tuple primitive returns two borrowed
/// [`Cow`] values for callers that need each stream independently,
/// this primitive returns a single owned [`String`] for callers that
/// need only the joined corpus. A consumer that needs BOTH the tuple
/// AND the joined corpus (the `run_type_check` site in
/// `commands/frontend_validation.rs:181-194`, which counts
/// `error TS` on each stream independently before joining) keeps
/// the tuple call and does not route through this primitive — the
/// joined-only shape is the specific well this primitive fills.
pub fn utf8_lossy_streams_joined(output: &std::process::Output) -> String {
    let (stdout, stderr) = utf8_lossy_streams(output);
    format!("{}\n{}", stderr, stdout)
}

/// Canonical wall-clock timestamp for machine-parseable emissions:
/// RFC-3339, UTC, no per-caller precision choice.
///
/// Lifts the one-liner
/// ```text
/// chrono::Utc::now().to_rfc3339()
/// ```
/// (or its post-`use chrono::Utc;` spelling `Utc::now().to_rfc3339()`)
/// that five sibling sites in forge carry verbatim:
/// - `commands/rollback.rs::execute` — `now` for artifact-json tag swaps
/// - `commands/dashboards.rs::generate_metadata` — `generated_at` on
///   the dashboard-catalog JSON record
/// - `commands/product_release.rs::write_artifact_tags` — `now` for
///   per-service `{service}.artifact.json` timestamps
/// - `commands/supergraph_verification.rs` — `composed_at` on the
///   supergraph-composition manifest record
/// - `observability.rs::EventMetadata::new` — `timestamp` on every
///   [`crate::observability::ReleaseEvent`] envelope emitted to Vector
///
/// Five identically-shaped bodies past THEORY §VI.1's three-times-is-a-
/// law threshold (PRIME DIRECTIVE: duplication budget is zero) consolidate
/// onto this typed primitive. Load-bearing properties this primitive owns
/// that the pre-lift one-liner dropped:
///
/// 1. **Time source pinned to UTC, not local.** A hypothetical future
///    consumer respelling the pre-lift stanza as
///    `chrono::Local::now().to_rfc3339()` (a single-token drift) would
///    compile and emit a locale-relative timestamp that Vector, the
///    artifact-catalog reader, and the dashboard-metadata consumer all
///    silently mis-interpret as UTC — no runtime error, no lint, no
///    grep pattern flags the drift. The primitive owns the time-source
///    choice at ONE code line, closing that drift path by construction.
/// 2. **Format pinned to RFC-3339.** Chrono exposes a `.to_string()` that
///    renders the same underlying `DateTime<Utc>` in a slightly different
///    grammar (`2026-09-02 15:30:00 UTC` — space separator, `UTC` suffix
///    rather than `+00:00`), which downstream JSON consumers parsing per
///    RFC-3339 refuse. The pre-lift sites all chose `.to_rfc3339()`
///    deliberately; the primitive pins that choice.
/// 3. **Fleet-wide grep-anchor for a future refinement.** A future
///    decision to trim the sub-second precision (`.to_rfc3339_opts(
///    SecondsFormat::Secs, true)` — the shape `commands/tool.rs:471`
///    already carries for the ATTIC_TOKEN JWT `iat` claim), swap in a
///    monotonic clock for test hermeticity (`#[cfg(test)]` injection
///    of a fixed instant), or route through a telemetry sigil that
///    stamps a build-time OTLP trace ID lands in ONE place, not five.
///
/// # Return value
///
/// A newly-allocated `String` per call — the pre-lift one-liner
/// composed `chrono::Utc::now().to_rfc3339()` which returns
/// `String` already, so the primitive body just forwards the same
/// owned-String shape. Every consumer site both assigned to a
/// `let now = ...;` local and consumed the value once (as a struct
/// field, JSON literal, or in-loop borrow into `format!(...)`), so
/// the owned-String surface is what every caller wants without a
/// `.to_owned()` bridge.
///
/// # Non-goals
///
/// This primitive is deliberately NOT the home for:
/// - `to_rfc3339_opts(SecondsFormat::<X>, use_z)` — the fixed-precision
///   variant (`commands/tool.rs:471` for the JWT `iat` grammar, which
///   the JWT spec rejects at sub-second precision) is a distinct shape
///   with a distinct-typed caller. A `now_rfc3339_utc_secs()` sibling
///   is the natural next lift when that shape crosses the three-is-a-
///   law threshold; today it is one site.
/// - Raw `DateTime<Utc>` construction — `commands/attestation.rs:1135`
///   and `:1616` assign a `DateTime<Utc>` directly to a struct field
///   (the serde envelope on the record type owns the render), so the
///   `.to_rfc3339()` step never happens. The `.timestamp()` integer
///   variant (`commands/migrations.rs:390`) is likewise a distinct
///   projection.
pub fn now_rfc3339_utc() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Run a command in a specific directory, restoring the original directory afterward
///
/// # Arguments
///
/// * `dir` - Directory to run the command in
/// * `f` - Async function to execute
///
/// # Errors
///
/// Returns an error if changing directories fails or if the function returns an error.
pub async fn in_directory<F, Fut, T>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let original_dir = current_dir()?;

    std::env::set_current_dir(dir)
        .with_context(|| format!("Failed to change to directory: {}", dir.display()))?;

    // Use scopeguard to ensure we restore the directory even on panic
    let _guard = scopeguard::guard((), |_| {
        let _ = std::env::set_current_dir(&original_dir);
    });

    f().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tool_path_with_env() {
        std::env::set_var("TEST_TOOL_PATH", "/custom/path/to/tool");
        assert_eq!(
            get_tool_path("TEST_TOOL_PATH", "default"),
            "/custom/path/to/tool"
        );
        std::env::remove_var("TEST_TOOL_PATH");
    }

    #[test]
    fn test_get_tool_path_fallback() {
        std::env::remove_var("NONEXISTENT_TOOL");
        assert_eq!(
            get_tool_path("NONEXISTENT_TOOL", "fallback-tool"),
            "fallback-tool"
        );
    }

    /// [`path_from_env`] surfaces `miss_context` verbatim through the
    /// `.context(...)` chain on a `env_var`-unset environment. Pins the
    /// contract every per-module `service_path_from_env()` sigil
    /// (`commands/developer_tools.rs`, `commands/schema_validation.rs`)
    /// delegates through: a future refactor that reshapes the primitive
    /// (a swap from `.context()` to a `bail!` with drifted wording, a
    /// lift to a typed error variant, a canonicalize prefix landed in
    /// front of the context) cannot silently drift the operator-facing
    /// wording every consumer's caller has been coached to grep for.
    #[test]
    fn test_path_from_env_surfaces_miss_context_when_unset() {
        let env_var = "TEST_PATH_FROM_ENV_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        let err = path_from_env(env_var, "sentinel miss wording for shield").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sentinel miss wording for shield"),
            "path_from_env() must forward `miss_context` verbatim on \
             the unset case — that is the contract every per-module \
             `service_path_from_env()` sigil delegates through. \
             Got: {msg}"
        );
    }

    /// [`path_from_env`] returns `PathBuf::from(env_var_value)` when the
    /// env var is set. Pins the `env::var → PathBuf` projection at ONE
    /// body so a future refinement (canonicalize hook, must-exist check,
    /// typed newtype) is caught here rather than at each consumer's
    /// downstream `.join(...)` / `.display()` call.
    #[test]
    fn test_path_from_env_returns_path_of_set_env_var() {
        let env_var = "TEST_PATH_FROM_ENV_SET_SIGIL_SHIELD";
        let sentinel = "/tmp/forge-path-from-env-sigil-shield";
        std::env::set_var(env_var, sentinel);
        let result = path_from_env(env_var, "unused-context-since-var-is-set");
        std::env::remove_var(env_var);
        let path = result.expect("path_from_env must succeed when env var is set");
        assert_eq!(
            path,
            PathBuf::from(sentinel),
            "path_from_env() must return `PathBuf::from(<env_var_value>)` \
             verbatim — the projection every pre-lift per-module \
             `service_path_from_env()` sigil spelled inline via \
             `Path::new(&service_dir)` / `PathBuf::from(service_dir)`."
        );
    }

    #[test]
    fn test_get_environment_default() {
        std::env::remove_var("FORGE_ENV");
        assert_eq!(get_environment(), "staging");
    }

    #[test]
    fn test_get_environment_custom() {
        std::env::set_var("FORGE_ENV", "production");
        assert_eq!(get_environment(), "production");
        std::env::remove_var("FORGE_ENV");
    }

    /// [`env_var_or_default`] returns the caller-supplied `default`
    /// verbatim when the env var is unset. Pins the shape every
    /// per-module sigil delegates through — [`get_environment`]
    /// (`FORGE_ENV`/`"staging"`), the `attic_server_alias` sigil
    /// (`ATTIC_SERVER_NAME`/`"default"`), the `default_cluster` sigil
    /// (`FORGE_CLUSTER`/`"default"`), the `SERVICE_REGISTRY_BASE`
    /// sigil, the `PANGEA_REGISTRY` sigil — depends on. A future
    /// refactor that reshaped the primitive (a swap from
    /// `unwrap_or_else(|_| _.to_string())` to a bail, a lift to a
    /// closed-enum of known values, a canonicalize prefix landed in
    /// front of the fallback) cannot silently drift the fallback
    /// wording every consumer's docstring pins verbatim.
    #[test]
    fn env_var_or_default_returns_default_when_env_var_unset() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            env_var_or_default(env_var, "sentinel-fallback"),
            "sentinel-fallback",
            "env_var_or_default() must return `default.to_string()` \
             verbatim on the unset case — that is the contract every \
             per-module env-var-with-`String`-fallback sigil (get_environment, \
             attic_server_alias, default_cluster, get_registry_base) \
             delegates through."
        );
    }

    /// [`env_var_or_default`] returns the env var's value verbatim
    /// when it IS set — the primitive's set-path projection. Pins the
    /// `env::var → String` shape at ONE body so a future refinement
    /// (canonicalize hook, must-not-be-empty check, typed newtype) is
    /// caught here rather than at each consumer's downstream `format!`
    /// call. Sibling shield to
    /// [`env_var_or_default_returns_default_when_env_var_unset`] on
    /// the set path.
    #[test]
    fn env_var_or_default_returns_env_var_value_when_set() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_SET_SIGIL_SHIELD";
        let sentinel = "explicit-value-not-the-fallback";
        std::env::set_var(env_var, sentinel);
        let result = env_var_or_default(env_var, "unused-fallback-should-not-appear");
        std::env::remove_var(env_var);
        assert_eq!(
            result, sentinel,
            "env_var_or_default() must return `env::var(env_var)` \
             verbatim when set — the projection every pre-lift \
             per-module `env::var(NAME).unwrap_or_else(|_| \
             DEFAULT.to_string())` sigil spelled inline. A silent \
             precedence flip that returned the fallback even when the \
             env var was set would misroute every downstream `format!` \
             at the sigils' consumers to the wrong registry / cluster \
             / server alias / environment."
        );
    }

    /// [`get_tool_path`] treats an explicit empty-string `env::var`
    /// value as a set env var and returns it verbatim — NOT the
    /// fallback. Pins the delegation onto [`env_var_or_default`]:
    /// post-lift the sigil's body is a single-line forward to the
    /// primitive, so the `.unwrap_or_else(|_| ...)` empty-string-parity
    /// semantics come from the primitive by construction. A future
    /// refactor of the primitive that swapped `.unwrap_or_else` for
    /// `.ok().filter(|s| !s.is_empty())` would silently reroute a
    /// shell-exported `CARGO_BIN=""` / `CRATE2NIX_BIN=""` from
    /// empty-string to the caller-supplied tool-name fallback, and
    /// every consumer's downstream spawn would then invoke a bare
    /// `cargo` / `crate2nix` off `PATH` where pre-lift the operator's
    /// explicit empty override told it not to. Sibling shield to
    /// [`env_var_or_default_returns_empty_string_when_env_var_set_empty`]
    /// on the tool-name surface.
    #[test]
    fn get_tool_path_returns_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_GET_TOOL_PATH_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = get_tool_path(env_var, "the-fallback-must-not-fire");
        std::env::remove_var(env_var);
        assert_eq!(
            result, "",
            "get_tool_path() must return the empty string verbatim \
             when the env var is set to \"\" — matches the primitive \
             [`env_var_or_default`]'s `.unwrap_or_else(|_| ...)` \
             semantics, which the sigil delegates through post-lift."
        );
    }

    /// The post-lift body of [`get_tool_path`] is a single-line forward
    /// to [`env_var_or_default`] — the sigil no longer spells
    /// `env::var(...)` inline. Structural regression shield: without
    /// it, a future refactor could silently re-inline the shape (e.g.
    /// a helpful "just call `std::env::var` directly, it's shorter"
    /// cleanup) and reopen the duplication class this lift closed.
    /// Pre-lift the sigil's body carried the inline
    /// `std::env::var(env_var).unwrap_or_else(|_| fallback.to_string())`
    /// spelling; post-lift the body must contain the
    /// `env_var_or_default(env_var, fallback)` call site AND NOT the
    /// inline `env::var(env_var)` needle.
    #[test]
    fn get_tool_path_body_delegates_to_env_var_or_default_sigil() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "pub fn get_tool_path(env_var: &str, fallback: &str) -> String {",
            "\n}",
        );
        assert!(
            body.contains("env_var_or_default(env_var, fallback)"),
            "get_tool_path() body must forward to \
             `env_var_or_default(env_var, fallback)` — the primitive \
             body every env-var-with-`String`-fallback sigil in the \
             crate now delegates through. Post-lift body: {body}"
        );
        assert!(
            !body.contains("std::env::var(env_var)") && !body.contains("env::var(env_var)"),
            "get_tool_path() body must NOT spell the inline \
             `env::var(env_var).unwrap_or_else(|_| \
             fallback.to_string())` shape — that duplication was lifted \
             onto [`env_var_or_default`]. A re-inline would silently \
             reopen the class this shield exists to close. \
             Post-lift body: {body}"
        );
    }

    /// [`env_var_or_default`] treats an explicit empty-string
    /// `env::var` value as a set env var and returns it verbatim —
    /// NOT the fallback. Pins the shape's parity with the pre-lift
    /// per-module sigils, each of which used `.unwrap_or_else(|_|
    /// ...)` (fallback fires only on the `Err` case, not on
    /// `Ok(String::new())`). A future refactor that swapped
    /// `.unwrap_or_else` for `.ok().filter(|s| !s.is_empty())` +
    /// fallback would silently reroute a shell-exported
    /// `FORGE_ENV=""` / `ATTIC_SERVER_NAME=""` /
    /// `SERVICE_REGISTRY_BASE=""` from empty-string to the
    /// caller-supplied default, and every consumer's downstream
    /// `format!("{}/...", ...)` would then compose against the
    /// default host name where pre-lift it composed against the empty
    /// leading segment. Explicit non-parity so the invariant survives
    /// a future primitive refinement.
    #[test]
    fn env_var_or_default_returns_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_ENV_VAR_OR_DEFAULT_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = env_var_or_default(env_var, "the-fallback-must-not-fire");
        std::env::remove_var(env_var);
        assert_eq!(
            result, "",
            "env_var_or_default() must return the empty string \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift sigil's `.unwrap_or_else(|_| ...)` semantics, \
             where the fallback fires only on the `Err` case."
        );
    }

    /// Serial-safe guard for tests that mutate the `SAFE` process env
    /// var. [`safe_mode_from_env`] reads it once per call; concurrent
    /// tests that set / remove it would race the resolved value observed
    /// by any test asserting on the primitive's return. Same
    /// `unwrap_or_else(|p| p.into_inner())` recovery shape as the
    /// sibling [`crate::git::tests::RELEASE_GIT_SHA_ENV_LOCK`] and
    /// [`crate::test_support::GIT_BIN_ENV_LOCK`] so a prior panicking
    /// test that poisoned the mutex does not chain-fail every subsequent
    /// test sharing the lock.
    static SAFE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// [`safe_mode_from_env`] returns `true` when the `SAFE` env var
    /// is unset. Pins the default-TRUE half of the contract every
    /// pre-lift consumer (`main.rs::main`'s `Commands::Rollout` arm,
    /// `commands/github_runner_ci.rs::is_safe_mode`) spelled inline
    /// as `.unwrap_or(true)` — an accidental default flip to `false`
    /// would silently disable rollout retries and Attic-login/push
    /// retries on every direct-CLI call where the operator did not
    /// explicitly export `SAFE`, the exact scenario the wrapper
    /// entrypoints treat as "retries on".
    #[test]
    fn safe_mode_from_env_defaults_to_true_when_unset() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::remove_var("SAFE");
        assert!(
            safe_mode_from_env(),
            "safe_mode_from_env() must default to `true` when `SAFE` \
             is unset — matches every pre-lift consumer's \
             `.unwrap_or(true)` on the `Err` case."
        );
    }

    /// [`safe_mode_from_env`] returns `false` when `SAFE=false`.
    /// Pins the disable-with-`false` half; a drop of the `!= \"false\"`
    /// clause would silently keep retries on even when the operator
    /// explicitly disabled them.
    #[test]
    fn safe_mode_from_env_is_false_for_literal_false() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "false");
        assert!(
            !safe_mode_from_env(),
            "safe_mode_from_env() must return `false` for `SAFE=false` \
             — the disable-with-`false` half of the contract every \
             pre-lift consumer spelled inline as `val != \"false\"`."
        );
    }

    /// [`safe_mode_from_env`] returns `false` when `SAFE=0`. Pins the
    /// disable-with-`0` half; a drop of the `!= \"0\"` clause would
    /// silently keep retries on for operators who spell the disable as
    /// the numeric zero.
    #[test]
    fn safe_mode_from_env_is_false_for_literal_zero() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "0");
        assert!(
            !safe_mode_from_env(),
            "safe_mode_from_env() must return `false` for `SAFE=0` \
             — the disable-with-`0` half of the contract every \
             pre-lift consumer spelled inline as `val != \"0\"`."
        );
    }

    /// [`safe_mode_from_env`] returns `false` for `SAFE=FALSE`,
    /// `SAFE=False`, and every other mixed-case spelling of `false`.
    /// Pins the `to_lowercase()` normalization step every pre-lift
    /// consumer spelled inline as `let val = v.to_lowercase();` — a
    /// drop of the normalizer would silently keep retries on for
    /// operators who capitalize the disable value.
    #[test]
    fn safe_mode_from_env_is_false_case_insensitive() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        for spelling in ["FALSE", "False", "fAlSe", "FALSe"] {
            std::env::set_var("SAFE", spelling);
            assert!(
                !safe_mode_from_env(),
                "safe_mode_from_env() must return `false` for \
                 `SAFE={spelling}` — the `to_lowercase()` normalization \
                 step every pre-lift consumer spelled inline via `let \
                 val = v.to_lowercase();`.",
            );
        }
    }

    /// [`safe_mode_from_env`] returns `true` when `SAFE=""` (an
    /// operator's explicit-empty export). Pins the empty-is-truthy
    /// parity: `"".to_lowercase()` is `""`, which satisfies both `!=
    /// "false"` and `!= "0"`, so the empty-string case lands on the
    /// default-true branch alongside an unset env var. A future
    /// primitive refinement that swapped the shape for a
    /// `.ok().filter(|s| !s.is_empty()).map(...).unwrap_or(true)`
    /// preserves this semantic; a swap to
    /// `.ok().is_some_and(...)`-style dispatch would flip it and
    /// silently misroute every `SAFE=""` export.
    #[test]
    fn safe_mode_from_env_is_true_for_empty_string() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        std::env::set_var("SAFE", "");
        assert!(
            safe_mode_from_env(),
            "safe_mode_from_env() must return `true` for `SAFE=\"\"` \
             — an empty string is neither `\"false\"` nor `\"0\"`, so \
             the empty-string case must land on the default-true branch."
        );
    }

    /// [`safe_mode_from_env`] returns `true` for any value that is
    /// neither `false` (any case) nor `0`. Pins the closed-set
    /// disable contract: only the two literal disable values flip
    /// retries off, and every other value (including plausible
    /// alternate spellings like `no`, `off`, `disable`, or a raw `1`)
    /// leaves retries ON. A future widening of the disable set to
    /// include e.g. `no` / `off` must land at the primitive body and
    /// break this shield, forcing an explicit contract update — not
    /// drift silently at one consumer only.
    #[test]
    fn safe_mode_from_env_is_true_for_unknown_value() {
        let _guard = SAFE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _snapshot = crate::test_support::EnvVarSnapshot::capture("SAFE");
        for spelling in ["no", "off", "disable", "1", "true", "yes"] {
            std::env::set_var("SAFE", spelling);
            assert!(
                safe_mode_from_env(),
                "safe_mode_from_env() must return `true` for \
                 `SAFE={spelling}` — only literal `false` (any case) \
                 and literal `0` flip retries off; every other value \
                 leaves the default-true branch selected.",
            );
        }
    }

    /// [`truthy_flag_from_env`] returns `false` when the env var is unset.
    /// Pins the DEFAULT-FALSE half of the contract every pre-lift consumer
    /// (`commands/helm.rs::republish_enabled`,
    /// `commands/prerelease.rs::SKIP_INTEGRATION`,
    /// `commands/prerelease.rs::SKIP_E2E`) spelled inline as
    /// `.is_ok_and(...)` / `.unwrap_or(false)` on the `Err` case. An
    /// accidental default flip to `true` would silently re-enable Helm
    /// republish (destroying the immutability invariant of the shared
    /// `oci://ghcr.io/pleme-io/charts` registry) and silently skip G13 /
    /// G14 on every direct-CLI call where the operator did not
    /// explicitly opt in.
    #[test]
    fn truthy_flag_from_env_defaults_to_false_when_unset() {
        let env_var = "TEST_TRUTHY_FLAG_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert!(
            !truthy_flag_from_env(env_var),
            "truthy_flag_from_env() must default to `false` when the env \
             var is unset — matches every pre-lift consumer's \
             `.is_ok_and(...)` / `.unwrap_or(false)` on the `Err` case."
        );
    }

    /// [`truthy_flag_from_env`] returns `true` for the literal `"1"` —
    /// the enable-with-`1` half of the contract every pre-lift consumer
    /// spelled inline as `v == "1"`. A drop of the `"1"` clause would
    /// silently disable the `FORGE_HELM_REPUBLISH=1` shape documented in
    /// `helm.rs::republish_enabled`.
    #[test]
    fn truthy_flag_from_env_is_true_for_literal_one() {
        let env_var = "TEST_TRUTHY_FLAG_ONE_SIGIL_SHIELD";
        std::env::set_var(env_var, "1");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            result,
            "truthy_flag_from_env() must return `true` for value `\"1\"` \
             — the enable-with-`1` half of the contract."
        );
    }

    /// [`truthy_flag_from_env`] returns `true` for the literal lowercase
    /// `"true"` — the enable-with-`true` half of the contract every
    /// pre-lift consumer spelled inline (case-sensitively in the two
    /// `prerelease.rs` sites, case-insensitively in `helm.rs`). Pins the
    /// primary spelling the operator-facing docs `commands/prerelease.rs`
    /// carry (`Skip with SKIP_INTEGRATION=true`,
    /// `Skip with SKIP_E2E=true`).
    #[test]
    fn truthy_flag_from_env_is_true_for_literal_lowercase_true() {
        let env_var = "TEST_TRUTHY_FLAG_TRUE_SIGIL_SHIELD";
        std::env::set_var(env_var, "true");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            result,
            "truthy_flag_from_env() must return `true` for value \
             `\"true\"` — the enable-with-`true` half of the contract."
        );
    }

    /// [`truthy_flag_from_env`] is case-insensitive on `"true"` — every
    /// mixed-case spelling (`TRUE`, `True`, `TrUe`, `tRuE`) enables the
    /// flag. Load-bearing: pre-lift the two `commands/prerelease.rs`
    /// consumers used case-sensitive `v == "true"` and silently ignored
    /// `SKIP_INTEGRATION=TRUE` / `SKIP_E2E=TRUE` from operators who
    /// capitalized the value; `commands/helm.rs::republish_enabled` used
    /// `.eq_ignore_ascii_case("true")` and fired for the same input.
    /// Post-lift the primitive fires for both, closing that inter-file
    /// drift — a shield that fails if a future refactor of the primitive
    /// reverts to case-sensitive comparison.
    #[test]
    fn truthy_flag_from_env_is_true_case_insensitive_on_true() {
        let env_var = "TEST_TRUTHY_FLAG_CASE_SIGIL_SHIELD";
        for spelling in ["TRUE", "True", "TrUe", "tRuE", "TRUe"] {
            std::env::set_var(env_var, spelling);
            let result = truthy_flag_from_env(env_var);
            assert!(
                result,
                "truthy_flag_from_env() must return `true` for \
                 `env_var={spelling}` — `.eq_ignore_ascii_case(\"true\")` \
                 accepts every mixed-case spelling of the letters t-r-u-e."
            );
        }
        std::env::remove_var(env_var);
    }

    /// [`truthy_flag_from_env`] returns `false` when the env var is set
    /// to the empty string. Pins the empty-is-falsy parity: `"" == "1"`
    /// is false, and `"".eq_ignore_ascii_case("true")` is false (lengths
    /// differ), so an operator's explicit-empty export lands on the
    /// default-false branch alongside an unset env var. Sibling to
    /// [`safe_mode_from_env_is_true_for_empty_string`] on the opt-in
    /// mirror — a swap to `.ok().filter(|s| !s.is_empty())`-style
    /// dispatch would preserve this semantic; a hypothetical widen to
    /// "empty means enable" would flip it.
    #[test]
    fn truthy_flag_from_env_is_false_for_empty_string() {
        let env_var = "TEST_TRUTHY_FLAG_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = truthy_flag_from_env(env_var);
        std::env::remove_var(env_var);
        assert!(
            !result,
            "truthy_flag_from_env() must return `false` for value `\"\"` \
             — neither `\"1\"` nor `eq_ignore_ascii_case(\"true\")` \
             accepts the empty string."
        );
    }

    /// [`truthy_flag_from_env`] returns `false` for every value outside
    /// the closed `{1, true (any case)}` enable set. Pins the closed-set
    /// enable contract: only the two literal enable values flip the flag
    /// on, and every other value (`"0"`, `"false"`, `"yes"`, `"on"`,
    /// `"disable"`, `"2"`, a plausible `"y"`) leaves it OFF. A future
    /// widening of the enable set to include `yes` / `on` must land at
    /// the primitive body and break this shield, forcing an explicit
    /// contract update — not drift silently at one consumer only.
    #[test]
    fn truthy_flag_from_env_is_false_for_non_enable_values() {
        let env_var = "TEST_TRUTHY_FLAG_NON_ENABLE_SIGIL_SHIELD";
        for spelling in [
            "0", "false", "FALSE", "no", "off", "yes", "on", "disable", "2", "y",
        ] {
            std::env::set_var(env_var, spelling);
            let result = truthy_flag_from_env(env_var);
            assert!(
                !result,
                "truthy_flag_from_env() must return `false` for \
                 `env_var={spelling}` — only literal `\"1\"` and \
                 `\"true\"` (case-insensitive) flip the flag on; every \
                 other value leaves the default-false branch selected."
            );
        }
        std::env::remove_var(env_var);
    }

    /// The monorepo terminal fires at the `{product}` node when its parent
    /// is `products` and its grandparent is `pkgs`. Pins the returned path
    /// to the `{product}` component itself — i.e. `.../pkgs/products/foo`
    /// walked up from a nested `services/bar` child, NOT the `services`
    /// sub-node or the `pkgs` root. Same shape every pre-lift consumer
    /// spelled: the walk-up returns the FIRST ancestor whose parent is
    /// `products` and grandparent is `pkgs`, so a deep service subtree
    /// resolves to its owning product directory.
    #[test]
    fn find_product_dir_monorepo_returns_product_dir_from_nested_service() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        let service = product.join("services").join("bar");
        std::fs::create_dir_all(&service).expect("create nested service dir");

        assert_eq!(
            find_product_dir(&service, ProductDirLayout::Monorepo),
            Some(product)
        );
    }

    /// A path with no `pkgs/products/{product}` ancestor and no
    /// `deploy.yaml`+`.git` marker under [`ProductDirLayout::Monorepo`]
    /// returns `None` at the filesystem-root terminal. Guards the walker's
    /// termination shape — the pre-lift `loop {}` returned `None` only
    /// when `current.parent()` was `None` at the outermost climb, and this
    /// post-lift shape must match. A silent `Some(root)` return here
    /// (e.g. a mis-refactored "any path counts" acceptance rule) would
    /// silently reroute every consumer's `deploy.yaml` lookup to the
    /// filesystem root.
    #[test]
    fn find_product_dir_monorepo_returns_none_when_no_pkgs_products_ancestor() {
        let root = tempfile::tempdir().expect("root tempdir");
        let unrelated = root.path().join("some").join("other").join("place");
        std::fs::create_dir_all(&unrelated).expect("create unrelated dir");

        assert!(find_product_dir(&unrelated, ProductDirLayout::Monorepo).is_none());
    }

    /// Under [`ProductDirLayout::MonorepoOrStandalone`], a directory
    /// carrying BOTH `deploy.yaml` and `.git` at the current node terminates
    /// the walk at that node — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape. The
    /// walk starts from a nested subdirectory to prove the standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_standalone_terminal_matches_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::Monorepo`], the standalone terminal is
    /// NOT checked — a `deploy.yaml`+`.git` directory outside a
    /// `pkgs/products/{product}` layout returns `None`. Pins the layout
    /// enum's semantics at the terminal boundary: a caller passing
    /// [`ProductDirLayout::Monorepo`] gets exactly the pre-lift
    /// monorepo-only shape, not a superset. Without this a future
    /// refactor could silently widen the `Monorepo` variant to also fire
    /// the standalone check and misroute `commands/status.rs` /
    /// `commands/integration_tests.rs` / `commands/test.rs`.
    #[test]
    fn find_product_dir_monorepo_ignores_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("standalone-product");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// A `deploy.yaml` alone (no `.git`) does NOT satisfy the standalone
    /// terminal — the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` shape
    /// required BOTH markers via `&&`. Prevents a bare-`deploy.yaml`
    /// intermediary directory in the walk (e.g. a `deploy/` folder holding
    /// per-service YAMLs) from being misidentified as a product root.
    #[test]
    fn find_product_dir_standalone_requires_both_deploy_yaml_and_git() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("half-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");

        assert!(find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone).is_none());
    }

    /// Monorepo terminal wins over standalone terminal when both fire at
    /// the same node. A `pkgs/products/{product}` directory that also
    /// carries `deploy.yaml`+`.git` returns via the monorepo branch, not
    /// the standalone one — preserves the pre-lift
    /// `commands/rust_service.rs::find_product_dir_from_path` precedence
    /// (monorepo check first, standalone check second, per iteration).
    /// Load-bearing because the return value shape is identical either way
    /// (`Some(current)`), so the branch that fires isn't observable at
    /// the return, only at the walker's internal ordering — and a
    /// reordering that silently checked standalone first would still
    /// return `Some(current)` at this test's node but would diverge at a
    /// hypothetical layout that terminated on a lower-precedence rule
    /// first.
    #[test]
    fn find_product_dir_monorepo_terminal_wins_when_both_fire() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "kind: deploy\n").expect("write deploy.yaml");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrStandalone),
            Some(product)
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a directory
    /// carrying `.git` + `deploy.yaml` whose YAML exposes a top-level
    /// string `name:` field terminates the walk at that node. Mirrors the
    /// pre-lift `config::DeployConfig::find_product_directory` shape: the
    /// walk starts from a nested subdirectory to prove the named-standalone
    /// terminal is checked at every level of the parent climb, not only at
    /// `start`.
    #[test]
    fn find_product_dir_named_standalone_terminal_matches_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let nested = repo_root.join("crates").join("worker");
        std::fs::create_dir_all(&nested).expect("create nested crate dir");

        assert_eq!(
            find_product_dir(&nested, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(repo_root)
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` node whose YAML lacks a top-level `name:`
    /// field CONTINUES the climb rather than terminating. Load-bearing:
    /// the pre-lift `config::DeployConfig::find_product_directory` used
    /// this to distinguish a genuine product-repo root (carries a
    /// product `name:`) from any other repo whose `deploy.yaml` fragment
    /// happens to describe something else (e.g. only environment
    /// settings, or a top-level manifest for a non-product artifact).
    /// Without this rule the loader would silently mis-terminate at the
    /// wrong `.git` and resolve a wrong product name.
    #[test]
    fn find_product_dir_named_standalone_ignores_yaml_without_name_field() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], a
    /// `.git`+`deploy.yaml` whose CONTENT is unparseable YAML CONTINUES
    /// the climb, matching the pre-lift
    /// `config::DeployConfig::find_product_directory` tolerate-parse-
    /// failures shape (`if let Ok(yaml) = serde_yaml::from_str::<...>(...)`).
    /// A parse error propagating out of the walker would be a hard
    /// regression: today a stray malformed `deploy.yaml` at a wrong
    /// ancestor still lets the walker reach a valid deeper product root;
    /// after the port that must remain true.
    #[test]
    fn find_product_dir_named_standalone_tolerates_unparseable_yaml() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("broken");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        // Intentionally malformed YAML: unbalanced braces + tab where a
        // key is expected.
        std::fs::write(repo_root.join("deploy.yaml"), "\t{{\n")
            .expect("write malformed deploy.yaml");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// Post-lift the body of [`standalone_deploy_yaml_has_name`] forwards
    /// the fs-read + serde-parse prefix to [`try_read_yaml_sync`] — the
    /// sibling silent-probe primitive one function up in this module.
    /// Structural regression shield: without it, a future refactor could
    /// silently re-inline the pre-lift
    /// `let Ok(content) = std::fs::read_to_string(...) + let Ok(yaml)
    /// = serde_yaml::from_str::<serde_yaml::Value>(...)` pair (e.g. a
    /// helpful "just call read_to_string + from_str directly, it's
    /// shorter" cleanup) and reopen the duplication class this lift
    /// closed — a class that lived one function down from the primitive
    /// body, so a maintainer editing either shape would need to hold
    /// both in working memory to keep them in sync. Post-lift only the
    /// primitive body spells the silent-probe shell; the sibling
    /// consumer delegates through the primitive's `Option<T>` return
    /// via `is_some_and`.
    ///
    /// Sibling to [`get_tool_path_body_delegates_to_env_var_or_default_sigil`]
    /// on the structural regression shield discipline. The delegation
    /// call literal (`try_read_yaml_sync::<serde_yaml::Value>(`) is
    /// spelled explicitly against a `body.contains` needle so a future
    /// rename of the primitive (a swap to `try_load_yaml`, a plural
    /// `try_read_yaml_sync_all`) breaks the shield and forces the
    /// rename to reach the sibling caller in the same commit rather
    /// than drifting silently at one code point only.
    #[test]
    fn standalone_deploy_yaml_has_name_body_delegates_to_try_read_yaml_sync() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "fn standalone_deploy_yaml_has_name(dir: &Path) -> bool {",
            "\n}",
        );
        assert!(
            body.contains("try_read_yaml_sync::<serde_yaml::Value>("),
            "standalone_deploy_yaml_has_name() body must forward to \
             `try_read_yaml_sync::<serde_yaml::Value>(...)` — the \
             silent-probe primitive body every fs-read + serde-parse \
             pair in the crate now delegates through. Post-lift body: \
             {body}"
        );
        assert!(
            !body.contains("std::fs::read_to_string(") && !body.contains("fs::read_to_string("),
            "standalone_deploy_yaml_has_name() body must NOT spell the \
             inline `std::fs::read_to_string(...)` needle — that fs-read \
             half of the silent-probe pair was lifted onto \
             `try_read_yaml_sync`. A re-inline would silently reopen the \
             duplication class this shield exists to close. Post-lift \
             body: {body}"
        );
        assert!(
            !body.contains("serde_yaml::from_str"),
            "standalone_deploy_yaml_has_name() body must NOT spell the \
             inline `serde_yaml::from_str::<...>(...)` needle — that \
             parse half of the silent-probe pair was lifted onto \
             `try_read_yaml_sync`. A re-inline would silently reopen the \
             duplication class this shield exists to close. Post-lift \
             body: {body}"
        );
    }

    /// [`standalone_deploy_yaml_has_name`] preserves the pre-lift
    /// `bool`-return semantics at every branch of the silent-probe
    /// contract — the three branches the pre-lift body's twin
    /// `let Ok(_) = ... else { return false; }` scaffold spelled
    /// explicitly. Load-bearing: `find_product_dir`'s named-standalone
    /// terminal calls this function once per parent-climb iteration,
    /// and a silent branch flip (unreadable → true, unparseable → true,
    /// missing-name → true) would silently mis-terminate the walker at
    /// the wrong ancestor and misroute product-dir discovery at the
    /// `config::DeployConfig` loader. The four branches:
    ///
    /// 1. Missing file → `false` (walker CONTINUES).
    /// 2. Unparseable YAML → `false` (walker CONTINUES) — the primitive's
    ///    `Option::None` on the parse arm folds through `is_some_and`
    ///    to `false` by construction.
    /// 3. Parseable YAML without top-level `name:` → `false` (walker
    ///    CONTINUES) — the `.get("name").and_then(|n| n.as_str())`
    ///    inner chain returns `None`, so `is_some()` is `false`.
    /// 4. Parseable YAML with top-level string `name:` → `true` (walker
    ///    TERMINATES at this node).
    #[test]
    fn standalone_deploy_yaml_has_name_branches_match_pre_lift_contract() {
        let root = tempfile::tempdir().expect("root tempdir");

        // (1) Missing file: dir exists, but no deploy.yaml.
        let missing_dir = root.path().join("missing");
        std::fs::create_dir_all(&missing_dir).expect("create missing dir");
        assert!(
            !standalone_deploy_yaml_has_name(&missing_dir),
            "missing deploy.yaml must return false — the primitive's \
             `None` on the read arm folds through `is_some_and`."
        );

        // (2) Unparseable YAML: file exists but content is garbage.
        let unparseable_dir = root.path().join("unparseable");
        std::fs::create_dir_all(&unparseable_dir).expect("create unparseable dir");
        std::fs::write(unparseable_dir.join("deploy.yaml"), "\t{{\n")
            .expect("write malformed deploy.yaml");
        assert!(
            !standalone_deploy_yaml_has_name(&unparseable_dir),
            "unparseable deploy.yaml must return false — the primitive's \
             `None` on the parse arm folds through `is_some_and`."
        );

        // (3) Parseable YAML without `name:` field.
        let nameless_dir = root.path().join("nameless");
        std::fs::create_dir_all(&nameless_dir).expect("create nameless dir");
        std::fs::write(nameless_dir.join("deploy.yaml"), "kind: deploy\n")
            .expect("write nameless deploy.yaml");
        assert!(
            !standalone_deploy_yaml_has_name(&nameless_dir),
            "deploy.yaml without top-level `name:` must return false — \
             `.get(\"name\").and_then(...)` returns `None`."
        );

        // (4) Parseable YAML with top-level string `name:` — the ONLY
        // branch that returns true.
        let named_dir = root.path().join("named");
        std::fs::create_dir_all(&named_dir).expect("create named dir");
        std::fs::write(named_dir.join("deploy.yaml"), "name: my-product\n")
            .expect("write named deploy.yaml");
        assert!(
            standalone_deploy_yaml_has_name(&named_dir),
            "deploy.yaml with top-level string `name:` must return \
             true — the only branch of the closed silent-probe contract \
             that satisfies the walker's terminal."
        );

        // (Corner) Parseable YAML with `name:` that is NOT a string —
        // e.g. `name: 42` — the pre-lift `.as_str().is_some()` returned
        // false there, matching the "genuine product-repo" gate. Pins
        // the non-string-name branch on the falsy side.
        let non_string_name_dir = root.path().join("non-string-name");
        std::fs::create_dir_all(&non_string_name_dir).expect("create non-string-name dir");
        std::fs::write(non_string_name_dir.join("deploy.yaml"), "name: 42\n")
            .expect("write non-string-name deploy.yaml");
        assert!(
            !standalone_deploy_yaml_has_name(&non_string_name_dir),
            "deploy.yaml with a non-string `name:` (e.g. `name: 42`) \
             must return false — `.as_str()` yields `None`, matching \
             the pre-lift `find_product_directory` acceptance rule."
        );
    }

    /// Under [`ProductDirLayout::MonorepoOrNamedStandalone`], the
    /// monorepo terminal STILL fires (and takes precedence) at a
    /// `pkgs/products/{product}` node even when that node ALSO carries a
    /// named standalone `.git`+`deploy.yaml`. Pins the precedence rule
    /// per (4) of `find_product_dir`'s doc: the closed enum adds only an
    /// alternative terminal, never redirects the monorepo one. Without
    /// this a well-formed monorepo product that additionally happens to
    /// carry a nested `.git` (e.g. a submodule root, a dev-only
    /// scratch git init) would silently return via the named-standalone
    /// branch instead of the monorepo branch — the pre-lift consumers'
    /// documented shape.
    #[test]
    fn find_product_dir_named_standalone_monorepo_terminal_still_wins() {
        let root = tempfile::tempdir().expect("root tempdir");
        let product = root.path().join("pkgs").join("products").join("foo");
        std::fs::create_dir_all(&product).expect("create product dir");
        std::fs::write(product.join("deploy.yaml"), "name: foo\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(product.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&product, ProductDirLayout::MonorepoOrNamedStandalone),
            Some(product)
        );
    }

    /// The `Monorepo` variant IGNORES the named-standalone marker (a
    /// `.git`+`deploy.yaml` whose YAML carries `name:`) — sibling of the
    /// existing `find_product_dir_monorepo_ignores_standalone_marker`
    /// test for the plain standalone marker. Guards the closed enum
    /// against a future refactor that silently widens `Monorepo` to also
    /// fire either standalone check.
    #[test]
    fn find_product_dir_monorepo_ignores_named_standalone_marker() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("named-standalone");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "name: my-product\n")
            .expect("write deploy.yaml with name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert!(find_product_dir(&repo_root, ProductDirLayout::Monorepo).is_none());
    }

    /// [`activate_root_flake`] publishes `REPO_ROOT` to the process
    /// environment as its FIRST side-effect, matching the pre-lift
    /// ordering at all three consumers (`main::setup_service_directory`,
    /// `commands/status::execute`, `commands/integration_tests::execute_manual`).
    /// A downstream `repo::find_repo_root` / `git::get_repo_root` /
    /// `PathBuilder::new` reading `REPO_ROOT` after the call sees the
    /// caller-supplied path, regardless of the chdir outcome.
    #[test]
    fn activate_root_flake_publishes_repo_root_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(repo_root.as_path())
        );
    }

    /// [`activate_root_flake`] publishes `SERVICE_DIR` to the process
    /// environment. Load-bearing: `DeployConfig::load_for_service`,
    /// `commands/developer_tools`, `commands/schema_validation`,
    /// `commands/bootstrap`, and `commands/rust_service` all read
    /// `SERVICE_DIR` — a caller that set `REPO_ROOT` but forgot
    /// `SERVICE_DIR` would silently misroute service discovery to
    /// whatever `SERVICE_DIR` the calling shell inherited. Pins the
    /// invariant that the primitive's contract makes the omission
    /// structurally impossible.
    #[test]
    fn activate_root_flake_publishes_service_dir_env_var() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = dir.path().join("repo").join("services").join("worker");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );
    }

    /// [`activate_root_flake`] changes the process working directory to
    /// `repo_root` — NOT `service_dir`. Load-bearing: the root-flake
    /// pattern (documented at `main::setup_service_directory`) runs
    /// `nix build` from the repo root, and every subsequent
    /// path-relative read in the CLI presupposes that root is the cwd.
    /// A migration that silently reversed the chdir target to
    /// `service_dir` would break every `nix flake` invocation
    /// downstream, so the test asserts the equality against `repo_root`
    /// canonicalized to match `set_current_dir`'s canonicalization.
    #[test]
    fn activate_root_flake_chdirs_to_repo_root_not_service_dir() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("services").join("api");
        std::fs::create_dir_all(&service_dir).expect("create service dir");

        activate_root_flake(&repo_root, &service_dir).expect("activate");
        let observed = std::env::current_dir().expect("cwd after activate");
        // Both sides go through canonicalize so a `/private/var/...` vs
        // `/var/...` symlink prefix at the tempdir root does not flake
        // the equality reading.
        let expected = repo_root.canonicalize().expect("canonicalize repo_root");
        let observed = observed.canonicalize().expect("canonicalize observed");
        assert_eq!(observed, expected);
    }

    /// [`activate_root_flake`] sets both env vars BEFORE attempting the
    /// chdir. Load-bearing: if the chdir fails (a caller passing a
    /// nonexistent path, a permission drop mid-pipeline), the env vars
    /// remain populated so a downstream `?`-propagated error handler
    /// can still read `REPO_ROOT` for its own diagnostics. Every
    /// pre-lift consumer had this property by accident of source-order
    /// (the two `set_var` lines preceded the `?` on `set_current_dir`);
    /// the primitive preserves it by construction, and this test pins
    /// it so a future rewrite that reordered the primitive's body
    /// cannot silently regress the invariant.
    #[test]
    fn activate_root_flake_publishes_env_vars_even_when_chdir_fails() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        // Point repo_root at a path that DOES NOT exist so
        // set_current_dir fails; service_dir can still be any path.
        let nonexistent_repo_root = dir.path().join("does-not-exist");
        let service_dir = dir.path().join("service");
        assert!(!nonexistent_repo_root.exists());

        let result = activate_root_flake(&nonexistent_repo_root, &service_dir);
        assert!(result.is_err(), "chdir to nonexistent path should fail");
        // Env vars remain published despite the chdir failure.
        assert_eq!(
            std::env::var("REPO_ROOT")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(nonexistent_repo_root.as_path())
        );
        assert_eq!(
            std::env::var("SERVICE_DIR")
                .ok()
                .map(PathBuf::from)
                .as_deref(),
            Some(service_dir.as_path())
        );
    }

    /// The chdir-failure error surfaces `repo_root`'s path in its
    /// context, so a `?`-propagated error the CLI prints to the
    /// operator names the exact directory that could not be entered.
    /// Pre-lift each consumer got a bare `std::io::Error` from
    /// `set_current_dir` with no path context; post-lift the primitive
    /// attaches `with_context` naming the offending path — a small
    /// diagnostic upgrade at every consumer by construction.
    #[test]
    fn activate_root_flake_error_context_names_the_repo_root_path() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_repo_root = dir.path().join("nope");
        let service_dir = dir.path().join("service");

        let err = activate_root_flake(&nonexistent_repo_root, &service_dir).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&nonexistent_repo_root.display().to_string()),
            "error should name the repo_root path; got: {msg}"
        );
    }

    /// The primitive accepts the caller's argument shape verbatim
    /// (`&str`, `String`, `&Path`, `PathBuf`) via `AsRef<Path>` bounds
    /// on both parameters. Load-bearing: the three pre-lift consumers
    /// each spelled the arguments differently (`main` passed
    /// `&String` from an `Option<String>` binding, `status` and
    /// `integration_tests` passed `&str` from their `&str`
    /// parameters). A single-type signature (e.g. `&str`-only) would
    /// have forced boilerplate at the `main` site; the `AsRef<Path>`
    /// bound makes every caller-shape pass by construction.
    #[test]
    fn activate_root_flake_accepts_str_and_string_and_path_args() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_root = dir.path().join("repo");
        let service_dir = repo_root.join("s");
        std::fs::create_dir_all(&service_dir).expect("mkdir");
        let repo_root_str: &str = repo_root.to_str().unwrap();
        let service_dir_string: String = service_dir.display().to_string();

        // &str for repo_root, String for service_dir.
        activate_root_flake(repo_root_str, service_dir_string).expect("&str + String");
        // &Path for repo_root, PathBuf for service_dir.
        activate_root_flake(repo_root.as_path(), repo_root.join("s")).expect("&Path + PathBuf");
        // &String for repo_root (matches the pre-lift main.rs shape),
        // &str for service_dir (matches the pre-lift status.rs shape).
        let repo_root_owned: String = repo_root.display().to_string();
        activate_root_flake(&repo_root_owned, "").ok();
    }

    /// The `MonorepoOrStandalone` variant does NOT verify the `name:`
    /// field — a `.git`+`deploy.yaml` node without `name:` terminates
    /// there under `MonorepoOrStandalone` (per the existing
    /// `find_product_dir_standalone_terminal_matches_deploy_yaml_and_git`
    /// test) but CONTINUES under `MonorepoOrNamedStandalone`. Pins the
    /// two standalone variants as independent branches: a shift of one
    /// variant's terminal condition must not silently reroute the other.
    #[test]
    fn find_product_dir_standalone_and_named_standalone_diverge_at_missing_name() {
        let root = tempfile::tempdir().expect("root tempdir");
        let repo_root = root.path().join("nameless");
        std::fs::create_dir_all(&repo_root).expect("create repo root");
        std::fs::write(repo_root.join("deploy.yaml"), "kind: deploy\n")
            .expect("write deploy.yaml without name");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");

        assert_eq!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrStandalone),
            Some(repo_root.clone())
        );
        assert!(
            find_product_dir(&repo_root, ProductDirLayout::MonorepoOrNamedStandalone).is_none()
        );
    }

    /// [`env_var_optional`] returns `None` when the env var is unset.
    /// Pins the `Err → None` half every pre-lift `env::var(NAME).ok()`
    /// stanza depended on — the six `Option<String>` gate / enrichment
    /// sites in `commands/sync.rs`, `observability.rs`, and
    /// `infrastructure/registry.rs` all treated the unset case as
    /// "absent" (return `Ok(false)` early, omit the field from the
    /// event, fall through to the next `.or_else` arm). A silent flip
    /// to `Some(String::new())` on the unset case would misroute every
    /// consumer's `.is_none()` / `.or_else` dispatch.
    #[test]
    fn env_var_optional_returns_none_when_env_var_unset() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            env_var_optional(env_var),
            None,
            "env_var_optional() must return `None` on the unset case — \
             matches every pre-lift `env::var(NAME).ok()` sigil's \
             `Err → None` projection, the projection consumers gate on."
        );
    }

    /// [`env_var_optional`] returns the env var's value inside `Some`
    /// verbatim when it IS set. Pins the `Ok(v) → Some(v)` set-path
    /// projection so a future refinement (a canonicalize prefix, a
    /// closed-enum canonicalization, a `.map(str::trim)` fold) is
    /// caught here rather than at each consumer's downstream unwrap.
    #[test]
    fn env_var_optional_returns_some_value_when_env_var_set() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_SET_SIGIL_SHIELD";
        let sentinel = "explicit-value-not-none";
        std::env::set_var(env_var, sentinel);
        let result = env_var_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(sentinel.to_string()),
            "env_var_optional() must return `Some(env::var(env_var))` \
             verbatim when set — the projection every pre-lift \
             `env::var(NAME).ok()` sigil spelled inline."
        );
    }

    /// [`env_var_optional`] returns `Some(String::new())` — NOT `None`
    /// — when the env var is set to `""`. Pins the empty-string-is-a-
    /// VALUE half of the split against
    /// [`crate::git::release_git_sha_from_env`]'s empty-string-is-MISS
    /// mirror. A future primitive refactor that swapped `.ok()` for
    /// `.ok().filter(|s| !s.is_empty())` would silently reroute a
    /// shell-exported `PUSHGATEWAY_URL=""` / `HOSTNAME=""` /
    /// `DATABASE_URL=""` from `Some("")` to `None`, collapsing the two
    /// peers onto one body and defeating the split the two sibling
    /// primitives close on. Sibling shield to
    /// [`crate::git::tests`]'s empty-string-is-miss assertions on the
    /// mirror.
    #[test]
    fn env_var_optional_returns_some_empty_string_when_env_var_set_empty() {
        let env_var = "TEST_ENV_VAR_OPTIONAL_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = env_var_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(String::new()),
            "env_var_optional() must return `Some(String::new())` \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift `env::var(NAME).ok()` sigil's semantics, where \
             `Ok(String::new())` folds to `Some(String::new())`, NOT \
             `None`. That parity is what splits this primitive from \
             the sibling empty-is-miss `release_git_sha_from_env`."
        );
    }

    /// Post-lift the callers migrated onto [`env_var_optional`] no
    /// longer spell the `std::env::var(<NAME>).ok()` shape inline.
    /// Structural regression shield — without it, a future refactor
    /// could silently re-inline the shape (e.g. a helpful "just call
    /// `std::env::var` directly, it's shorter" cleanup) and reopen the
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield.
    #[test]
    fn env_var_optional_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, &[&str])] = &[
            (
                include_str!("commands/sync.rs"),
                "commands/sync.rs",
                &["DATABASE_URL"],
            ),
            (
                include_str!("observability.rs"),
                "observability.rs",
                &["HOSTNAME", "GITHUB_RUN_ID", "CI_JOB_ID", "PUSHGATEWAY_URL"],
            ),
            (
                include_str!("infrastructure/registry.rs"),
                "infrastructure/registry.rs",
                &["GHCR_TOKEN", "GITHUB_TOKEN"],
            ),
        ];
        for (source, module_path, names) in CALLERS {
            let body = crate::test_support::module_body_before_tests(source, module_path);
            for name in *names {
                let raw = format!("std::env::var(\"{name}\").ok()");
                let short = format!("env::var(\"{name}\").ok()");
                assert!(
                    !body.contains(&raw) && !body.contains(&short),
                    "{module_path} body must NOT spell the inline \
                     `env::var(\"{name}\").ok()` shape — that \
                     `Option<String>` duplication was lifted onto \
                     `crate::repo::env_var_optional`. A re-inline would \
                     silently reopen the class this shield exists to \
                     close."
                );
                let call = format!("env_var_optional(\"{name}\")");
                assert!(
                    body.contains(&call),
                    "{module_path} body must forward to \
                     `crate::repo::env_var_optional(\"{name}\")` — the \
                     primitive body every `Option<String>` env-var \
                     sigil in the crate now delegates through."
                );
            }
        }
    }

    /// [`path_from_env_optional`] returns `None` when the env var is
    /// unset. Pins the `Err → None` half every pre-lift
    /// `if let Ok(v) = env::var(NAME) { PathBuf::from(v) }` inline
    /// stanza depended on — the six `Option<PathBuf>` env-var-first
    /// shortcut sites in `find_repo_root`, `git::get_repo_root`,
    /// `path_builder::PathBuilder::new`, `commands/bootstrap.rs`,
    /// `commands/pangea.rs`, and `nix_hooks.rs` all treated the
    /// unset case as "absent" (skip the arm and fall through to the
    /// non-env fallback: walk parents, `git rev-parse`, `find_repo_root`,
    /// standard `$HOME/code` locations, `nix build .#nix-hooks`). A
    /// silent flip to `Some(PathBuf::new())` on the unset case would
    /// misroute every consumer's fall-through arm into treating the
    /// current working directory as the substrate root.
    #[test]
    fn path_from_env_optional_returns_none_when_env_var_unset() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_UNSET_SIGIL_SHIELD";
        std::env::remove_var(env_var);
        assert_eq!(
            path_from_env_optional(env_var),
            None,
            "path_from_env_optional() must return `None` on the unset \
             case — matches every pre-lift `if let Ok(v) = \
             env::var(NAME) {{ PathBuf::from(v) }}` stanza's `Err → \
             None` projection, the projection consumers gate on."
        );
    }

    /// [`path_from_env_optional`] returns the env var's value inside
    /// `Some(PathBuf::from(v))` verbatim when it IS set. Pins the
    /// `Ok(v) → Some(PathBuf::from(v))` set-path projection so a
    /// future refinement (canonicalize via `std::fs::canonicalize`, a
    /// must-exist filter, an absolutize hook against CWD) is caught
    /// here rather than at each consumer's downstream `.join(...)`
    /// / `.exists()` composition.
    #[test]
    fn path_from_env_optional_returns_some_path_when_env_var_set() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_SET_SIGIL_SHIELD";
        let sentinel = "/tmp/explicit-path-not-none";
        std::env::set_var(env_var, sentinel);
        let result = path_from_env_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(PathBuf::from(sentinel)),
            "path_from_env_optional() must return \
             `Some(PathBuf::from(env::var(env_var)))` verbatim when \
             set — the projection every pre-lift `if let Ok(v) = \
             env::var(NAME) {{ PathBuf::from(v) }}` stanza spelled \
             inline."
        );
    }

    /// [`path_from_env_optional`] returns `Some(PathBuf::new())` —
    /// NOT `None` — when the env var is set to `""`. Pins the
    /// empty-string-is-a-VALUE half inherited from
    /// [`env_var_optional`] (which itself splits against
    /// [`crate::git::release_git_sha_from_env`]'s empty-string-is-MISS
    /// mirror). A future primitive refactor that composed on
    /// `release_git_sha_from_env`-style
    /// `.ok().filter(|s| !s.is_empty())` semantics instead of
    /// [`env_var_optional`] would silently reroute a shell-exported
    /// `REPO_ROOT=""` / `SERVICE_DIR=""` / `NIX_HOOKS_PATH=""` from
    /// `Some(PathBuf::new())` to `None` and collapse the split the two
    /// sibling primitives close on. Parity with the pre-lift
    /// `if let Ok(v) = env::var(NAME)` shape, where `Ok(String::new())`
    /// matched the arm and flowed into `PathBuf::from("")`.
    #[test]
    fn path_from_env_optional_returns_some_empty_path_when_env_var_set_empty() {
        let env_var = "TEST_PATH_FROM_ENV_OPTIONAL_EMPTY_SIGIL_SHIELD";
        std::env::set_var(env_var, "");
        let result = path_from_env_optional(env_var);
        std::env::remove_var(env_var);
        assert_eq!(
            result,
            Some(PathBuf::new()),
            "path_from_env_optional() must return `Some(PathBuf::new())` \
             verbatim when the env var is set to \"\" — matches every \
             pre-lift `if let Ok(v) = env::var(NAME) {{ PathBuf::from(v) \
             }}` stanza's semantics, where `Ok(String::new())` matched \
             the arm and flowed into `PathBuf::from(\"\")`. That parity \
             is what inherits the split from the sibling \
             `env_var_optional` primitive against the empty-is-miss \
             `release_git_sha_from_env`."
        );
    }

    /// Post-lift the callers migrated onto [`path_from_env_optional`]
    /// no longer spell the `if let Ok(v) = env::var(NAME) { ...
    /// PathBuf::from(v) ... }` shape inline. Structural regression
    /// shield — without it, a future refactor could silently re-inline
    /// the two-line stanza (e.g. a "just call `env::var` directly,
    /// then `PathBuf::from`, it's shorter" cleanup) and reopen the
    /// duplication class this lift closed. Enforced at the module
    /// bodies before their `#[cfg(test)]` regions so a test-support
    /// mention of the raw shape does not defeat the shield. The
    /// two-line adjacency (line N `env::var(NAME)`, line N+1
    /// `PathBuf::from(v)`) uniquely identifies the pre-lift shape;
    /// bare `if let Ok(_) = env::var(NAME)` reads whose next line does
    /// NOT hand the value to `PathBuf::from` (e.g. the
    /// `env_var_optional`-shaped `.ok()` sigils, the truthy-flag
    /// consumers, the boolean gates) stay unshielded — morally-
    /// adjacent shapes with their own lift target, not this one.
    #[test]
    fn path_from_env_optional_callers_delegate_through_primitive() {
        const CALLERS: &[(&str, &str, &[&str])] = &[
            (include_str!("git.rs"), "git.rs", &["REPO_ROOT"]),
            (
                include_str!("path_builder.rs"),
                "path_builder.rs",
                &["REPO_ROOT"],
            ),
            (
                include_str!("commands/bootstrap.rs"),
                "commands/bootstrap.rs",
                &["SERVICE_DIR"],
            ),
            (
                include_str!("nix_hooks.rs"),
                "nix_hooks.rs",
                &["NIX_HOOKS_PATH"],
            ),
        ];
        for (source, module_path, names) in CALLERS {
            let body = crate::test_support::module_body_before_tests(source, module_path);
            for name in *names {
                let raw = format!("std::env::var(\"{name}\")");
                let short = format!("env::var(\"{name}\")");
                assert!(
                    !body.contains(&raw) && !body.contains(&short),
                    "{module_path} body must NOT spell the inline \
                     `env::var(\"{name}\")` read — that \
                     `Option<PathBuf>` env-var-first shortcut was \
                     lifted onto `crate::repo::path_from_env_optional`. \
                     A re-inline would silently reopen the class this \
                     shield exists to close."
                );
                let call = format!("path_from_env_optional(\"{name}\")");
                assert!(
                    body.contains(&call),
                    "{module_path} body must forward to \
                     `crate::repo::path_from_env_optional(\"{name}\")` \
                     — the primitive body every `Option<PathBuf>` \
                     env-var-first shortcut in the crate now delegates \
                     through."
                );
            }
        }
        // `commands/pangea.rs::find_external_repo` composes the env-var
        // name dynamically as `format!("{}_DIR", name.to_uppercase())`
        // rather than hand-spelling a literal — its delegation is
        // shielded by needle-matching the primitive call site
        // instead of a per-name literal, so a re-inline that dropped
        // the dynamic-name arg would still fail the shield loudly.
        let pangea_body = crate::test_support::module_body_before_tests(
            include_str!("commands/pangea.rs"),
            "commands/pangea.rs",
        );
        assert!(
            pangea_body.contains("path_from_env_optional(&env_var)"),
            "commands/pangea.rs body must forward to \
             `crate::repo::path_from_env_optional(&env_var)` for the \
             dynamic `<NAME>_DIR` env-var arm — the primitive body \
             every `Option<PathBuf>` env-var-first shortcut in the \
             crate now delegates through."
        );
    }

    /// [`read_yaml_sync`] deserializes a well-formed YAML file at the
    /// caller's target type. Pins the round-trip: a regression that
    /// swapped the `serde_yaml::from_str` call for `serde_json::from_str`
    /// (or that returned the raw content string instead of the parsed
    /// value) fails here.
    #[test]
    fn read_yaml_sync_deserializes_well_formed_yaml_into_typed_target() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Fixture {
            name: String,
            count: u32,
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("fixture.yaml");
        std::fs::write(&path, "name: hive-router\ncount: 42\n").expect("seed write");

        let value: Fixture = read_yaml_sync(&path).expect("well-formed YAML must parse");

        assert_eq!(
            value,
            Fixture {
                name: "hive-router".to_string(),
                count: 42,
            }
        );
    }

    /// [`read_yaml_sync`]'s read arm must surface the offending
    /// `path.display()` alongside a `"Failed to read"` classifier so the
    /// operator's next step is `ls` on the exact path. Pins the
    /// canonical envelope every consumer inherits: the pre-lift
    /// per-consumer role labels (`"product config"`, `"service config"`)
    /// decoupled the diagnostic wording from the offending path, and
    /// this envelope closes that drift by construction.
    #[test]
    fn read_yaml_sync_missing_file_errors_carry_path_and_read_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.yaml");

        let err = read_yaml_sync::<serde_yaml::Value>(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "read arm's envelope must carry `path.display()` so the \
             operator can `ls` the offending path directly. Got: {msg}"
        );
        assert!(
            msg.contains("Failed to read"),
            "read arm's envelope must carry the `Failed to read` \
             classifier so the operator's next step is `ls`, not \
             `yamllint`. Got: {msg}"
        );
    }

    /// [`read_yaml_sync`]'s parse arm must surface the offending
    /// `path.display()` alongside a `"Failed to parse ... as YAML"`
    /// classifier so the operator's next step is `yamllint` on the exact
    /// path, not `ls` (which would find a syntactically-broken file, a
    /// dead end). Pins the parse-failure envelope every consumer
    /// inherits.
    #[test]
    fn read_yaml_sync_invalid_yaml_errors_carry_path_and_parse_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("broken.yaml");
        std::fs::write(&path, "key: [unterminated\n").expect("seed write");

        let err = read_yaml_sync::<serde_yaml::Value>(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "parse arm's envelope must carry `path.display()` so the \
             operator can `yamllint` the offending path directly. \
             Got: {msg}"
        );
        assert!(
            msg.contains("Failed to parse") && msg.contains("as YAML"),
            "parse arm's envelope must carry `Failed to parse ... as \
             YAML` so the operator's next step is `yamllint`, not `ls` \
             (which would find a syntactically-broken file, a dead \
             end). Got: {msg}"
        );
    }

    /// [`read_yaml_sync_hinted`]'s read arm must surface the offending
    /// `path.display()`, the `hints.role` label (so an operator can
    /// tell WHICH of service/product/global config failed without
    /// cross-referencing the offending path against the loader
    /// source), AND the `hints.read_hint` remediation prose. Pins the
    /// canonical hinted envelope every consumer inherits.
    #[test]
    fn read_yaml_sync_hinted_missing_file_carries_path_role_and_read_hint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.yaml");
        let hints = YamlLoadHints {
            role: "service config",
            read_hint: "Ensure the file is readable and not corrupted.",
            parse_hint: "Check YAML syntax (see CONFIGURATION.md)",
        };

        let err = read_yaml_sync_hinted::<serde_yaml::Value>(&path, &hints).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "hinted read arm's envelope must carry `path.display()` \
             so the operator can `ls` the offending path directly. \
             Got: {msg}"
        );
        assert!(
            msg.contains("service config"),
            "hinted read arm's envelope must carry `hints.role` so an \
             operator can tell which of service/product/global failed \
             without reading the loader source. Got: {msg}"
        );
        assert!(
            msg.contains("Failed to read"),
            "hinted read arm's envelope must carry the `Failed to \
             read` classifier so the operator's next step is `ls`, \
             not `yamllint`. Got: {msg}"
        );
        assert!(
            msg.contains("Ensure the file is readable and not corrupted."),
            "hinted read arm's envelope must carry `hints.read_hint` \
             remediation prose verbatim — the load-bearing signal the \
             canonical envelope would have erased. Got: {msg}"
        );
    }

    /// [`read_yaml_sync_hinted`]'s parse arm must surface the
    /// offending `path.display()`, the `hints.role` label, AND the
    /// `hints.parse_hint` remediation prose. The parse-arm hint at
    /// the three consumer sites lists common YAML-syntax pitfalls, so
    /// its verbatim survival in the failure envelope is what tells
    /// the operator `yamllint` is the next tool.
    #[test]
    fn read_yaml_sync_hinted_invalid_yaml_carries_path_role_and_parse_hint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("broken.yaml");
        std::fs::write(&path, "key: [unterminated\n").expect("seed write");
        let hints = YamlLoadHints {
            role: "product config",
            read_hint: "Ensure the file is readable.",
            parse_hint: "Check YAML syntax (see CONFIGURATION.md)",
        };

        let err = read_yaml_sync_hinted::<serde_yaml::Value>(&path, &hints).unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains(&path.display().to_string()),
            "hinted parse arm's envelope must carry `path.display()` \
             so the operator can `yamllint` the offending path \
             directly. Got: {msg}"
        );
        assert!(
            msg.contains("product config"),
            "hinted parse arm's envelope must carry `hints.role` so \
             an operator can tell which of service/product/global \
             failed to parse without reading the loader source. Got: \
             {msg}"
        );
        assert!(
            msg.contains("Failed to parse"),
            "hinted parse arm's envelope must carry the `Failed to \
             parse` classifier. Got: {msg}"
        );
        assert!(
            msg.contains("Check YAML syntax (see CONFIGURATION.md)"),
            "hinted parse arm's envelope must carry `hints.parse_hint` \
             remediation prose verbatim — this is what tells the \
             operator `yamllint` is the next tool, since the canonical \
             `as YAML` classifier suffix is delegated to the hint. \
             Got: {msg}"
        );
    }

    /// [`read_yaml_sync_hinted`] deserializes a well-formed YAML file
    /// at the caller's target type on the happy path — no hints appear
    /// in the returned value, only in the failure envelopes. Pins that
    /// the hint-threading does NOT contaminate the success path (a
    /// regression that folded the hint prose into the parsed content
    /// would fail here).
    #[test]
    fn read_yaml_sync_hinted_happy_path_returns_typed_target_with_no_hint_leakage() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Fixture {
            name: String,
            replicas: u32,
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("service.yaml");
        std::fs::write(&path, "name: hive-router\nreplicas: 3\n").expect("seed write");
        let hints = YamlLoadHints {
            role: "service config",
            read_hint: "Ensure the file is readable and not corrupted.",
            parse_hint: "Check YAML syntax (see CONFIGURATION.md)",
        };

        let value: Fixture =
            read_yaml_sync_hinted(&path, &hints).expect("well-formed YAML must parse");

        assert_eq!(
            value,
            Fixture {
                name: "hive-router".to_string(),
                replicas: 3,
            }
        );
    }

    /// [`read_yaml_sync`] parses at the OPEN [`serde_yaml::Value`]
    /// target when the caller navigates via `.get(...)` chains rather
    /// than deserializing into a closed struct. Pins that ONE primitive
    /// body serves both the typed-struct target (e.g. `ProductConfig`
    /// at `config::mod::load_product_config_from_dir`) and the
    /// open-value target (e.g. `serde_yaml::Value` at
    /// `config::mod::load_service_namespace`) — a regression that
    /// specialized the primitive to a closed T would silently break the
    /// four open-value consumer sites.
    #[test]
    fn read_yaml_sync_parses_at_open_serde_yaml_value_for_get_chain_consumers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nested.yaml");
        std::fs::write(
            &path,
            "environments:\n  production:\n    namespace: hive-prod\n",
        )
        .expect("seed write");

        let value: serde_yaml::Value = read_yaml_sync(&path).expect("open-value target must parse");

        let namespace = value
            .get("environments")
            .and_then(|e| e.get("production"))
            .and_then(|p| p.get("namespace"))
            .and_then(|n| n.as_str());
        assert_eq!(namespace, Some("hive-prod"));
    }

    /// [`try_read_yaml_sync`] returns `Some(T)` on the happy path
    /// against a well-formed YAML document, so the caller's
    /// `if let Some(yaml) = try_read_yaml_sync(&path) { ... }`
    /// shape enters the success branch and can navigate the document
    /// tree. A regression that hard-coded a `None` return on the parse
    /// arm (or that returned `Some(Default::default())` instead of the
    /// actual parsed value) would fail here.
    #[test]
    fn try_read_yaml_sync_returns_some_on_well_formed_yaml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("probe.yaml");
        std::fs::write(&path, "name: hive-router\nreplicas: 3\n").expect("seed write");

        let value: Option<serde_yaml::Value> = try_read_yaml_sync(&path);

        let value = value.expect("well-formed YAML must probe as Some");
        assert_eq!(
            value.get("name").and_then(|n| n.as_str()),
            Some("hive-router")
        );
        assert_eq!(value.get("replicas").and_then(|r| r.as_u64()), Some(3));
    }

    /// [`try_read_yaml_sync`] returns `None` for a missing path
    /// WITHOUT propagating the underlying `std::io::Error` — the
    /// caller uses this shape when a missing file is a legitimate
    /// fall-through (a probe, a backward-compatibility fallback, an
    /// optional-config load whose absence means "use defaults"), so
    /// the primitive must ABSORB the ENOENT rather than propagate a
    /// classifier. Pins the silent-probe contract on the read arm.
    #[test]
    fn try_read_yaml_sync_returns_none_on_missing_file_without_propagating() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.yaml");

        let value: Option<serde_yaml::Value> = try_read_yaml_sync(&path);

        assert!(
            value.is_none(),
            "missing file must probe as None; got Some — the silent-probe \
             contract on the read arm is broken"
        );
    }

    /// [`try_read_yaml_sync`] returns `None` for a syntactically-
    /// broken YAML file WITHOUT propagating the underlying
    /// `serde_yaml::Error` — same silent-probe contract as the
    /// missing-file arm, on the parse side. The caller has committed
    /// to a fall-through and does not want a runner log to surface
    /// this as an operator-visible error. Pins the parse-arm branch.
    #[test]
    fn try_read_yaml_sync_returns_none_on_invalid_yaml_without_propagating() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("broken.yaml");
        std::fs::write(&path, "key: [unterminated\n").expect("seed write");

        let value: Option<serde_yaml::Value> = try_read_yaml_sync(&path);

        assert!(
            value.is_none(),
            "syntactically-broken YAML must probe as None; got Some — the \
             silent-probe contract on the parse arm is broken"
        );
    }

    /// [`try_read_yaml_sync`] parses at a closed target when the
    /// caller wants an `Option<Config>`-shaped probe rather than an
    /// `Option<serde_yaml::Value>` navigation. Pins that the primitive
    /// is generic over `T: DeserializeOwned` — a regression that
    /// specialized it to `serde_yaml::Value` would silently break any
    /// future consumer that probes into a closed struct.
    #[test]
    fn try_read_yaml_sync_parses_at_closed_struct_target_when_caller_asks() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Fixture {
            name: String,
            replicas: u32,
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("closed.yaml");
        std::fs::write(&path, "name: hive-router\nreplicas: 3\n").expect("seed write");

        let value: Option<Fixture> = try_read_yaml_sync(&path);

        assert_eq!(
            value,
            Some(Fixture {
                name: "hive-router".to_string(),
                replicas: 3,
            })
        );
    }

    /// [`read_yaml_async`]'s read arm must surface the offending
    /// `path.display()` AND classify the failure as a READ error, so
    /// the operator's next step is `ls` on the exact path, not
    /// `yamllint`. Pins the async sibling to the same envelope
    /// discipline the sync sibling [`read_yaml_sync`] carries — one
    /// primitive per fs-read surface, same canonical operator-next-
    /// step contract.
    #[tokio::test]
    async fn read_yaml_async_missing_file_errors_carry_path_and_read_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("missing.yaml");

        let err = read_yaml_async::<serde_yaml::Value>(&path)
            .await
            .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read"),
            "read-arm classifier must be 'Failed to read'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "read-arm envelope must carry the offending path; got: {msg}"
        );
        assert!(
            !msg.contains("Failed to parse"),
            "no parse attempted on read-Err path; got: {msg}"
        );
    }

    /// [`read_yaml_async`]'s parse arm must surface the offending
    /// `path.display()` AND classify the failure as a PARSE error, so
    /// the operator's next step is `yamllint` on the exact path, not
    /// `ls`. Pins that the read succeeded (a good file on disk) and
    /// the parse is what failed — a diagnostic a pre-lift consumer
    /// that dropped the path from the parse arm (github_runner_ci.rs,
    /// deploy.rs) could not deliver.
    #[tokio::test]
    async fn read_yaml_async_invalid_yaml_errors_carry_path_and_parse_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("broken.yaml");
        tokio::fs::write(&path, "key: [unterminated\n")
            .await
            .expect("seed write");

        let err = read_yaml_async::<serde_yaml::Value>(&path)
            .await
            .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to parse"),
            "parse-arm classifier must be 'Failed to parse'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "parse-arm envelope must carry the offending path; got: {msg}"
        );
        assert!(
            msg.contains("as YAML"),
            "parse-arm classifier must name the format as YAML so the \
             operator reaches for yamllint, not jq; got: {msg}"
        );
    }

    /// [`read_yaml_async`] deserializes a well-formed YAML file at
    /// the caller's target type. Pins the async round-trip so a
    /// regression that swapped [`serde_yaml::from_str`] for
    /// [`serde_json::from_str`] (or hard-coded a `Default::default()`
    /// return) fails here at the closed-struct target the four
    /// present-day consumer sites (github_runner_ci.rs → Value,
    /// deploy.rs → Value, migration_validation.rs → MigrationManifest
    /// x2) collectively span.
    #[tokio::test]
    async fn read_yaml_async_happy_path_returns_typed_target() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Fixture {
            name: String,
            replicas: u32,
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("fixture.yaml");
        tokio::fs::write(&path, "name: hive-router\nreplicas: 3\n")
            .await
            .expect("seed write");

        let value: Fixture = read_yaml_async(&path)
            .await
            .expect("well-formed YAML must parse");

        assert_eq!(
            value,
            Fixture {
                name: "hive-router".to_string(),
                replicas: 3,
            }
        );
    }

    /// [`read_yaml_async`] parses at the OPEN [`serde_yaml::Value`]
    /// target when the caller navigates via `.get(...)` chains
    /// rather than deserializing into a closed struct — the shape
    /// both async-side consumers (`commands/deploy.rs`,
    /// `commands/github_runner_ci.rs`) pick today for their
    /// `images[0].newTag` sniff. A regression that specialized the
    /// primitive to a closed T would silently break both open-value
    /// consumer sites.
    #[tokio::test]
    async fn read_yaml_async_parses_at_open_serde_yaml_value_for_get_chain_consumers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        tokio::fs::write(
            &path,
            "images:\n  - name: ghcr.io/pleme-io/github-runner\n    newTag: abcdef0\n",
        )
        .await
        .expect("seed write");

        let value: serde_yaml::Value = read_yaml_async(&path)
            .await
            .expect("open-value target must parse");

        let new_tag = value
            .get("images")
            .and_then(|images| images.as_sequence())
            .and_then(|seq| seq.first())
            .and_then(|img| img.get("newTag"))
            .and_then(|tag| tag.as_str());
        assert_eq!(new_tag, Some("abcdef0"));
    }

    /// [`read_text_async`] returns the file's full contents verbatim,
    /// so line-oriented consumers ([`crate::commands::push::
    /// update_kustomization`] and its nine peers across
    /// `commands/{kenshi,kenshi_agent,nix_builder,bootstrap,rust_service,
    /// developer_tools}.rs`) receive the same byte-for-byte payload the
    /// pre-lift inline `tokio::fs::read_to_string(path).await` did.
    /// Pins that the primitive is a text-mode read — NOT a parse or a
    /// trim — so YAML comments, trailing newlines, and CRLF sequences
    /// (which each of the ten consumers relies on to preserve source
    /// formatting through its splice-and-write mutator) survive the
    /// round-trip.
    #[tokio::test]
    async fn read_text_async_returns_contents_verbatim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        let payload = "# preserved comment\n\
                       images:\n  \
                       - name: ghcr.io/pleme-io/nix-builder\n    \
                         newTag: amd64-abcdef0\n";
        tokio::fs::write(&path, payload).await.expect("seed write");

        let content = read_text_async(&path)
            .await
            .expect("well-formed file must read");

        assert_eq!(
            content, payload,
            "read_text_async() must return the file bytes verbatim so \
             every line-oriented text-splice consumer sees the same \
             payload it did pre-lift"
        );
    }

    /// [`read_text_async`]'s read arm must surface the offending
    /// `path.display()` AND classify the failure as a READ error, so
    /// the operator's next step is `ls` on the exact path. Pins the
    /// primitive to the same envelope discipline the async YAML
    /// sibling [`read_yaml_async`] and the sync sibling
    /// [`read_yaml_sync`] carry — one primitive per fs-read surface,
    /// same canonical operator-next-step contract. Pre-lift ten
    /// consumer sites carried their own per-site literal
    /// (`"Failed to read kustomization.yaml"`,
    /// `"Failed to read builder-pool.yaml"`,
    /// `"Failed to read Cargo.toml"`, `"Failed to read manifest"`)
    /// that (a) hard-coded a filename that could drift from the actual
    /// `path` argument silently and (b) DROPPED the offending
    /// `path.display()` from the failure classifier entirely, so an
    /// operator reading a runner log could not tell which of several
    /// candidate paths tripped the read. This shield forbids that
    /// regression.
    #[tokio::test]
    async fn read_text_async_missing_file_errors_carry_path_and_read_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("missing.yaml");

        let err = read_text_async(&path).await.unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read"),
            "read-arm classifier must be 'Failed to read'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "read-arm envelope must carry the offending path; got: {msg}"
        );
    }

    /// Post-lift [`read_yaml_async`]'s body must delegate its read arm
    /// to [`read_text_async`] rather than re-spelling the inline
    /// `tokio::fs::read_to_string(path).await` composition — the shape
    /// this lift closed for the ten straggler consumer sites. Without
    /// this shield a future refactor could silently re-inline the
    /// shape (e.g. a helpful "just call `tokio::fs::read_to_string`
    /// directly, it's shorter" cleanup) and reopen the duplication
    /// class this lift closed, leaving [`read_yaml_async`]'s read arm
    /// diverged from the ten sibling text-mode consumers that now
    /// route through [`read_text_async`].
    #[test]
    fn read_yaml_async_body_delegates_to_read_text_async_on_read_arm() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "pub async fn read_yaml_async<T: DeserializeOwned>(path: &Path) -> Result<T> {",
            "\n}",
        );
        assert!(
            body.contains("read_text_async(path)"),
            "read_yaml_async() body must forward its read arm to \
             `read_text_async(path)` — the primitive body every \
             async text-mode read in the crate now delegates through. \
             Post-lift body: {body}"
        );
        assert!(
            !body.contains("tokio::fs::read_to_string(path)"),
            "read_yaml_async() body must NOT spell the inline \
             `tokio::fs::read_to_string(path).await` shape — that \
             duplication was lifted onto `read_text_async`. A \
             re-inline would silently diverge the read arm from the \
             ten sibling text-mode consumers routing through the \
             primitive. Post-lift body: {body}"
        );
    }

    /// Post-lift the seven sibling
    /// `fs::read_to_string(<path>).await?` bare-await bail stanzas
    /// across `commands/{rebac_validation (×5), sync (×1),
    /// supergraph_verification (×1)}.rs` migrated onto
    /// [`read_text_async`], gaining by construction the canonical
    /// `"Failed to read {path.display()}"` failure envelope every peer
    /// on the async text-mode read arm already carries. Pre-lift each
    /// site's `.await?` propagated a bare [`std::io::Error`] that
    /// dropped the offending path from the operator log — an operator
    /// bounced by a missing `security-rebac.md` doc, a missing
    /// `supergraph.graphql`, or a bad path in `count_lines` saw a
    /// stream-classifier `"No such file or directory (os error 2)"`
    /// with no way to tell which of several candidate paths tripped
    /// the read. Post-lift every failure branch surfaces the
    /// `path.display()` at the classifier layer, matching the ten
    /// pre-existing consumer sites on this same primitive
    /// (`commands/{kenshi, kenshi_agent, nix_builder (×3), bootstrap,
    /// rust_service, developer_tools, push}.rs`).
    ///
    /// Structural regression shield — negative half asserts the
    /// pre-lift bare shape `fs::read_to_string(<any>).await?;`
    /// (whitespace-tolerated, single-line) reappears in NONE of the
    /// three files; positive half asserts each file forwards through
    /// the primitive at exactly the per-file count the lift landed
    /// (5 / 1 / 1). Without this shield a future refactor could
    /// silently re-inline the bare-await shape and reopen the
    /// envelope-dropping class this lift closed. The shape only
    /// forbids the BARE `.await?` bail; the peer sites that thread
    /// their own `.await.context(...)?` / `.await.with_context(...)?`
    /// envelope (`federation.rs`, `supergraph_verification.rs::load`,
    /// `migration_validation.rs`, `attestation.rs`) already carry a
    /// classifier and stay put.
    #[test]
    fn bare_fs_read_to_string_await_bail_sibling_class_closed() {
        // (path, per-file post-lift forwarding count)
        const CONSUMERS: &[(&str, &str, usize)] = &[
            (
                "commands/rebac_validation.rs",
                include_str!("commands/rebac_validation.rs"),
                5,
            ),
            ("commands/sync.rs", include_str!("commands/sync.rs"), 1),
            (
                "commands/supergraph_verification.rs",
                include_str!("commands/supergraph_verification.rs"),
                1,
            ),
        ];
        for (path, src, expected_forwards) in CONSUMERS {
            // Negative half — no line spells the pre-lift single-line
            // bare-await bail `fs::read_to_string(<expr>).await?;`.
            // Anchoring the needle to end-of-line rules out the peer
            // sites that carry a `.context(...)?` / `.with_context(...)?`
            // envelope split across two lines (`fs::read_to_string(x)\n
            //     .await\n    .context("...")?;`).
            let inline_hits = src
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_end();
                    trimmed.contains("fs::read_to_string(")
                        && (trimmed.ends_with(".await?;") || trimmed.ends_with(".await?"))
                })
                .count();
            assert_eq!(
                inline_hits, 0,
                "{path} must NOT spell the pre-lift bare \
                 `fs::read_to_string(<path>).await?;` — that seven-\
                 site duplication class was lifted onto \
                 `crate::repo::read_text_async` so every failure \
                 branch carries the canonical \
                 `\"Failed to read {{path}}\"` envelope. A re-inline \
                 would silently reopen the envelope-dropping class \
                 this shield closes. Found {inline_hits} inline \
                 occurrences."
            );
            // Positive half — the file forwards through the primitive
            // at exactly the count this lift landed. A fusion that
            // folds one of the sites back to inline fs::read_to_string
            // fails here (the negative half above would still pass,
            // but this positive count would fall by one).
            let forward_hits = src.matches("crate::repo::read_text_async(").count();
            assert_eq!(
                forward_hits, *expected_forwards,
                "{path} must forward through \
                 `crate::repo::read_text_async(<path>).await?` at \
                 exactly {expected_forwards} sites — one per pre-lift \
                 bare-await bail this shield replaces. A fusion or an \
                 additional lift that changes the count without \
                 updating this shield fails here. Found {forward_hits} \
                 forwarding hits."
            );
        }
    }

    /// [`read_text_sync`] returns the file's full contents verbatim,
    /// so line-oriented consumers (the three shell primitives inside
    /// [`crate::version`] — `apply_version_write`,
    /// `read_version_by_span`, `apply_optional_dep_write` — plus four
    /// straggler sites at `commands/{helm,gem,seed,migration_new}.rs`)
    /// receive the same byte-for-byte payload the pre-lift inline
    /// `std::fs::read_to_string(path)` did. Pins that the primitive is
    /// a text-mode read — NOT a parse or a trim — so TOML comments,
    /// Chart.yaml `file://` dep entries, `VERSION = %(...).freeze`
    /// literals, and trailing newlines (which every consumer relies on
    /// to preserve source formatting through its splice-and-write
    /// mutator) survive the round-trip.
    #[test]
    fn read_text_sync_returns_contents_verbatim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("Cargo.toml");
        let payload = "# preserved comment\n\
                       [package]\n\
                       name = \"pleme-forge\"\n\
                       version = \"0.1.0\"\n";
        std::fs::write(&path, payload).expect("seed write");

        let content = read_text_sync(&path).expect("well-formed file must read");

        assert_eq!(
            content, payload,
            "read_text_sync() must return the file bytes verbatim so \
             every line-oriented text-splice consumer sees the same \
             payload it did pre-lift"
        );
    }

    /// [`read_text_sync`]'s read arm must surface the offending
    /// `path.display()` AND classify the failure as a READ error, so
    /// the operator's next step is `ls` on the exact path. Pins the
    /// primitive to the same envelope discipline the sync YAML sibling
    /// [`read_yaml_sync`] and the async sibling [`read_text_async`]
    /// carry — one primitive per fs-read surface, same canonical
    /// operator-next-step contract. Pre-lift seven consumer sites each
    /// re-derived the primitive's envelope by hand, and a future
    /// straggler that mis-spells the classifier (`"cannot read"` vs.
    /// `"Failed to read"`) would divorce the runner log from every
    /// other read-arm envelope in the crate. This shield forbids that
    /// regression at the primitive body.
    #[test]
    fn read_text_sync_missing_file_errors_carry_path_and_read_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("missing.toml");

        let err = read_text_sync(&path).unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read"),
            "read-arm classifier must be 'Failed to read'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "read-arm envelope must carry the offending path; got: {msg}"
        );
    }

    /// Post-lift [`read_yaml_sync`]'s body must delegate its read arm
    /// to [`read_text_sync`] rather than re-spelling the inline
    /// `std::fs::read_to_string(path).with_context(...)` composition —
    /// the shape this lift closed for the seven straggler consumer
    /// sites. Without this shield a future refactor could silently
    /// re-inline the shape (e.g. a helpful "just call
    /// `std::fs::read_to_string` directly, it's shorter" cleanup) and
    /// reopen the duplication class this lift closed, leaving
    /// [`read_yaml_sync`]'s read arm diverged from the seven sibling
    /// text-mode consumers that now route through [`read_text_sync`].
    ///
    /// Sync sibling of
    /// [`read_yaml_async_body_delegates_to_read_text_async_on_read_arm`]
    /// on the delegation-shield frontier — same structural discipline,
    /// same body-slice source scan.
    #[test]
    fn read_yaml_sync_body_delegates_to_read_text_sync_on_read_arm() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "pub fn read_yaml_sync<T: DeserializeOwned>(path: &Path) -> Result<T> {",
            "\n}",
        );
        assert!(
            body.contains("read_text_sync(path)"),
            "read_yaml_sync() body must forward its read arm to \
             `read_text_sync(path)` — the primitive body every sync \
             text-mode read in the crate now delegates through. \
             Post-lift body: {body}"
        );
        assert!(
            !body.contains("std::fs::read_to_string(path)"),
            "read_yaml_sync() body must NOT spell the inline \
             `std::fs::read_to_string(path)` shape — that duplication \
             was lifted onto `read_text_sync`. A re-inline would \
             silently diverge the read arm from the seven sibling \
             text-mode consumers routing through the primitive. \
             Post-lift body: {body}"
        );
    }

    /// [`write_text_sync`] writes the caller's bytes verbatim, so a
    /// consumer that hands in a spliced [`crate::version`] output, a
    /// `format!("{}\n", json)` render, or a scaffold `String` gets the
    /// same byte-for-byte payload persisted the pre-lift inline
    /// `std::fs::write(path, content)` did. Pins that the primitive is
    /// a byte-mode write — NOT a serialize or a re-encode — so trailing
    /// newlines, embedded NULs, and `\r\n` line endings survive the
    /// round-trip.
    #[test]
    fn write_text_sync_persists_bytes_verbatim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("Cargo.toml");
        let payload = "# preserved comment\n\
                       [package]\n\
                       name = \"pleme-forge\"\n\
                       version = \"0.1.0\"\n";

        write_text_sync(&path, payload).expect("well-formed write must succeed");

        let round_trip = std::fs::read(&path).expect("post-write read");
        assert_eq!(
            round_trip,
            payload.as_bytes(),
            "write_text_sync() must persist the caller's bytes verbatim \
             so every text-splice consumer sees the same payload it \
             handed in"
        );
    }

    /// [`write_text_sync`]'s write arm must surface the offending
    /// `path.display()` AND classify the failure as a WRITE error, so
    /// an operator reading the runner log can tell one bounce
    /// (`"Failed to write"` → `ls -la` on the parent dir, `df -h`) from
    /// a read-arm bounce (`"Failed to read"` → `ls` on the exact path)
    /// without cross-referencing the caller. Pins the primitive to the
    /// same envelope discipline the sync read sibling [`read_text_sync`]
    /// carries — one primitive per fs-op surface, same canonical
    /// operator-next-step contract. Pre-lift six consumer sites each
    /// re-derived the primitive's envelope by hand, and a future
    /// straggler that mis-spells the classifier (`"cannot write"` vs.
    /// `"Failed to write"`) would divorce the runner log from every
    /// other write-arm envelope in the crate. This shield forbids that
    /// regression at the primitive body.
    #[test]
    fn write_text_sync_missing_parent_dir_errors_carry_path_and_write_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nonexistent-dir").join("out.toml");

        let err = write_text_sync(&path, "payload").unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to write"),
            "write-arm classifier must be 'Failed to write'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "write-arm envelope must carry the offending path; got: {msg}"
        );
    }

    /// Post-lift the seven straggler consumer sites lifted onto
    /// [`write_text_sync`] must not silently re-inline the primitive's
    /// shape at their call points — a re-inline would reopen the class
    /// this lift closed. This source-scan shield walks every hand-lifted
    /// consumer file and refuses the raw `std::fs::write(<path>,
    /// <content>).with_context(|| format!("Failed to write {}",
    /// <path>.display()))?` composition inside its consumer body
    /// window (`commands/rollback.rs`, `commands/product_release.rs`,
    /// `commands/gem.rs`, `commands/migration_new.rs`).
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The two `commands/migration_new.rs` sites that stay unlifted
    /// (`"Failed to update {}"` on the append branch, `"Failed to
    /// create {}"` on the initial-write branch) legitimately carry
    /// per-branch verb signal the canonical envelope would erase; this
    /// shield matches only the canonical `"Failed to write"` classifier
    /// so the two `"update"` / `"create"` sites survive it by
    /// construction.
    #[test]
    fn write_text_sync_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/rollback.rs", include_str!("commands/rollback.rs")),
            (
                "commands/product_release.rs",
                include_str!("commands/product_release.rs"),
            ),
            ("commands/gem.rs", include_str!("commands/gem.rs")),
            (
                "commands/migration_new.rs",
                include_str!("commands/migration_new.rs"),
            ),
        ] {
            assert!(
                !source.contains("Failed to write {}\", "),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write {{}}` — that duplication was lifted \
                 onto `crate::repo::write_text_sync`. A re-inline would \
                 silently diverge the write arm from the seven sibling \
                 write-mode consumers routing through the primitive.",
            );
        }
    }

    /// Post-lift [`crate::version::apply_version_write`]'s body must
    /// delegate its write arm to [`write_text_sync`] rather than re-
    /// spelling the inline `std::fs::write(path,
    /// &updated).with_context(...)` composition — the shape this lift
    /// closed for the six straggler consumer sites. Without this shield
    /// a future refactor could silently re-inline the shape (e.g. a
    /// helpful "just call `std::fs::write` directly, it's shorter"
    /// cleanup) and reopen the duplication class this lift closed,
    /// leaving [`crate::version::apply_version_write`]'s write arm
    /// diverged from the sibling text-mode consumers that now route
    /// through [`write_text_sync`].
    ///
    /// Sync sibling of [`read_yaml_sync_body_delegates_to_read_text_sync_on_read_arm`]
    /// on the delegation-shield frontier — same structural discipline,
    /// same body-slice source scan, applied to the write-arm peer.
    #[test]
    fn apply_version_write_body_delegates_to_write_text_sync_on_write_arm() {
        const SOURCE: &str = include_str!("version.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "version.rs",
            "fn apply_version_write<F>(path: &Path, new_version: &str, plan: F) -> Result<()>",
            "\n}",
        );
        assert!(
            body.contains("write_text_sync(path"),
            "apply_version_write() body must forward its write arm to \
             `crate::repo::write_text_sync(path, …)` — the primitive \
             body every sync text-mode write in the crate now \
             delegates through. Post-lift body: {body}"
        );
        assert!(
            !body.contains("std::fs::write(path"),
            "apply_version_write() body must NOT spell the inline \
             `std::fs::write(path, …)` shape — that duplication was \
             lifted onto `write_text_sync`. A re-inline would silently \
             diverge the write arm from the six sibling text-mode \
             consumers routing through the primitive. Post-lift body: {body}"
        );
    }

    /// [`write_text_async`] writes the caller's bytes verbatim, so the
    /// ten line-oriented text-splice consumers across
    /// `commands/{kenshi,kenshi_agent,nix_builder,push,bootstrap,
    /// migrations,rust_service}.rs` plus the async YAML round-trip's
    /// final write arm at [`crate::git::yaml_read_modify_write_async`]
    /// each receive the same byte-for-byte payload persisted the
    /// pre-lift inline `tokio::fs::write(path, content).await` did. Pins
    /// that the primitive is a byte-mode write — NOT a serialize or a
    /// re-encode — so YAML comments, trailing newlines, and CRLF
    /// sequences (which each consumer's splice-and-write mutator relies
    /// on to preserve source formatting) survive the round-trip.
    #[tokio::test]
    async fn write_text_async_persists_bytes_verbatim() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kustomization.yaml");
        let payload = "# preserved comment\n\
                       images:\n  \
                       - name: ghcr.io/pleme-io/nix-builder\n    \
                         newTag: amd64-abcdef0\n";

        write_text_async(&path, payload)
            .await
            .expect("well-formed write must succeed");

        let round_trip = tokio::fs::read(&path).await.expect("post-write read");
        assert_eq!(
            round_trip,
            payload.as_bytes(),
            "write_text_async() must persist the caller's bytes verbatim \
             so every line-oriented text-splice consumer sees the same \
             payload it did pre-lift"
        );
    }

    /// [`write_text_async`]'s write arm must surface the offending
    /// `path.display()` AND classify the failure as a WRITE error, so
    /// an operator reading the runner log can tell one bounce
    /// (`"Failed to write"` → `ls -la` on the parent dir, `df -h`) from
    /// a read-arm bounce (`"Failed to read"` → `ls` on the exact path)
    /// without cross-referencing the caller. Pins the primitive to the
    /// same envelope discipline the sync sibling [`write_text_sync`]
    /// and the async read peer [`read_text_async`] carry — one
    /// primitive per fs-op surface, same canonical operator-next-step
    /// contract. Pre-lift ten consumer sites each hard-coded a
    /// filename literal (`"Failed to write kustomization.yaml"`,
    /// `"Failed to write builder-pool.yaml"`, `"Failed to write
    /// migration job manifest"`, `"Failed to write updated manifest"`)
    /// that (a) could drift from the actual `path` argument silently
    /// and (b) DROPPED the offending `path.display()` from the failure
    /// classifier entirely. This shield forbids that regression.
    #[tokio::test]
    async fn write_text_async_missing_parent_dir_errors_carry_path_and_write_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("nonexistent-dir").join("out.yaml");

        let err = write_text_async(&path, "payload").await.unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to write"),
            "write-arm classifier must be 'Failed to write'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "write-arm envelope must carry the offending path; got: {msg}"
        );
    }

    /// Post-lift the ten straggler consumer sites lifted onto
    /// [`write_text_async`] must not silently re-inline the primitive's
    /// shape at their call points — a re-inline would reopen the class
    /// this lift closed. This source-scan shield walks every hand-lifted
    /// consumer file and refuses the raw `tokio::fs::write(<path>,
    /// <content>).await.context("Failed to write <literal>")?` shape
    /// (matched via the classifier string `"Failed to write"`) inside
    /// its consumer body window.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// Two sites stay unlifted (`commands/codegen_validation.rs`'s
    /// `"Failed to write schema to {path}"` and `commands/rust_service.rs`'s
    /// `"Failed to write .version file to {path}"`) — each legitimately
    /// tags a role (staged codegen input, deploy-metadata file) the
    /// canonical envelope would erase. Neither carries the bare `"Failed
    /// to write"` needle because both interpose a role phrase (`"schema
    /// to"`, `".version file to"`) between the classifier verb and the
    /// path, so the substring `"Failed to write "` (with the trailing
    /// space matching the canonical envelope's own separator) does not
    /// occur at either site — they survive this shield by construction.
    #[test]
    fn write_text_async_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/kenshi.rs", include_str!("commands/kenshi.rs")),
            (
                "commands/kenshi_agent.rs",
                include_str!("commands/kenshi_agent.rs"),
            ),
            (
                "commands/nix_builder.rs",
                include_str!("commands/nix_builder.rs"),
            ),
            ("commands/push.rs", include_str!("commands/push.rs")),
            (
                "commands/bootstrap.rs",
                include_str!("commands/bootstrap.rs"),
            ),
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
            ),
            (
                "commands/rust_service.rs",
                include_str!("commands/rust_service.rs"),
            ),
            // Three sibling stragglers from `commands/federation.rs`,
            // lifted in a later pass onto the same
            // `write_text_async(<path>, <content>)` body. The 866d9ed
            // pass caught ten across seven consumers; these three
            // completed the sweep at the supergraph-composition arm —
            // one write of the temporary `supergraph-config.yaml` seed,
            // one write of the composed `supergraph.graphql` output,
            // one write of the mutated `hive-router` deployment
            // manifest — each pre-lift spelled the same
            // filename-literal `.context("Failed to write <literal>")`
            // shape that dropped `path.display()` from the operator log
            // and could drift from the actual `path` argument silently.
            (
                "commands/federation.rs",
                include_str!("commands/federation.rs"),
            ),
        ] {
            assert!(
                !source.contains("Failed to write kustomization"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write kustomization.yaml` — that duplication \
                 was lifted onto `crate::repo::write_text_async`. A \
                 re-inline would silently diverge the write arm from the \
                 sibling text-mode consumers routing through the \
                 primitive.",
            );
            assert!(
                !source.contains("Failed to write builder-pool"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write builder-pool.yaml` — that duplication \
                 was lifted onto `crate::repo::write_text_async`.",
            );
            assert!(
                !source.contains("Failed to write migration job manifest"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write migration job manifest` — that \
                 duplication was lifted onto `crate::repo::write_text_async`.",
            );
            assert!(
                !source.contains("Failed to write updated manifest"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write updated manifest` — that duplication \
                 was lifted onto `crate::repo::write_text_async`.",
            );
            assert!(
                !source.contains("Failed to write supergraph config"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write supergraph config` — that duplication \
                 was lifted onto `crate::repo::write_text_async` in a \
                 follow-up sweep that closed three federation-arm \
                 stragglers of the class 866d9ed opened.",
            );
            assert!(
                !source.contains("Failed to write supergraph schema"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write supergraph schema` — that duplication \
                 was lifted onto `crate::repo::write_text_async` in the \
                 same follow-up sweep.",
            );
            assert!(
                !source.contains("Failed to write updated hive-router deployment"),
                "{name} must NOT spell the inline write-arm envelope \
                 `Failed to write updated hive-router deployment` — that \
                 duplication was lifted onto `crate::repo::write_text_async` \
                 in the same follow-up sweep.",
            );
        }
    }

    /// Post-lift [`crate::git::yaml_read_modify_write_async`]'s body
    /// must delegate its write arm to [`write_text_async`] rather than
    /// re-spelling the inline `tokio::fs::write(path, updated).await`
    /// composition — the shape this lift closed for the ten straggler
    /// consumer sites plus this eleventh in-shell site. Without this
    /// shield a future refactor could silently re-inline the shape
    /// (e.g. a helpful "just call `tokio::fs::write` directly, it's
    /// shorter" cleanup) and reopen the duplication class this lift
    /// closed, leaving [`crate::git::yaml_read_modify_write_async`]'s
    /// write arm diverged from the ten sibling text-mode consumers that
    /// now route through [`write_text_async`].
    ///
    /// Async sibling of
    /// [`apply_version_write_body_delegates_to_write_text_sync_on_write_arm`]
    /// on the delegation-shield frontier — same structural discipline,
    /// same body-slice source scan, applied to the async write-arm peer.
    #[test]
    fn yaml_read_modify_write_async_body_delegates_to_write_text_async_on_write_arm() {
        const SOURCE: &str = include_str!("git.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "git.rs",
            "async fn yaml_read_modify_write_async<F>(path: &Path, mutator: F) -> Result<()>",
            "\n}",
        );
        assert!(
            body.contains("write_text_async(path"),
            "yaml_read_modify_write_async() body must forward its write \
             arm to `crate::repo::write_text_async(path, …)` — the \
             primitive body every async text-mode write in the crate \
             now delegates through. Post-lift body: {body}"
        );
        assert!(
            !body.contains("tokio::fs::write(path"),
            "yaml_read_modify_write_async() body must NOT spell the \
             inline `tokio::fs::write(path, …)` shape — that duplication \
             was lifted onto `write_text_async`. A re-inline would \
             silently diverge the write arm from the ten sibling \
             text-mode consumers routing through the primitive. \
             Post-lift body: {body}"
        );
    }

    /// [`require_existing_working_dir`] returns a lifetime-borrowed
    /// [`Path`] pointing at the `working_dir: &str` input verbatim on
    /// the exists-hit case — the primitive's zero-alloc success return.
    /// Pins the structural contract every one of the ten pre-lift
    /// command-entry-point sites relied on inline: the returned `&Path`
    /// must be usable exactly where the pre-lift `let dir =
    /// Path::new(working_dir);` was, with no owned-`PathBuf` allocation
    /// and no path-normalization drift.
    #[test]
    fn require_existing_working_dir_returns_borrowed_path_on_exists_hit() {
        let dir = std::env::temp_dir();
        let dir_str = dir.to_str().expect("temp_dir must be UTF-8");
        let result = require_existing_working_dir(dir_str)
            .expect("require_existing_working_dir must succeed on an existing directory");
        assert_eq!(
            result,
            Path::new(dir_str),
            "require_existing_working_dir() must return `Path::new(working_dir)` \
             verbatim on the exists-hit case — no owned-PathBuf allocation, \
             no `.canonicalize()` normalization, structurally identical to \
             the pre-lift `let dir = Path::new(working_dir);` idiom the ten \
             consumer sites relied on."
        );
    }

    /// [`require_existing_working_dir`] bails with the exact wording
    /// `"Working directory not found: {working_dir}"` interpolating the
    /// `working_dir: &str` VERBATIM (NOT
    /// `Path::new(working_dir).display()`) — pre-lift every consumer
    /// bailed with the raw string, so the operator sees the value they
    /// passed on the CLI without a trailing-slash normalization or a
    /// redundant re-projection through [`Path::display`]. A drift that
    /// swapped the interpolation to `dir.display()` would silently
    /// change the operator-facing wording for every one of the ten
    /// consumers, so the shield pins the raw-string interpolation at
    /// the primitive body.
    #[test]
    fn require_existing_working_dir_bails_with_working_dir_str_verbatim_on_miss() {
        let sentinel =
            "/tmp/forge-require-existing-working-dir-sigil-shield-nonexistent-path-1234567890";
        assert!(
            !Path::new(sentinel).exists(),
            "test sentinel must not exist for the shield to be meaningful"
        );
        let err = require_existing_working_dir(sentinel)
            .expect_err("require_existing_working_dir must bail on a nonexistent directory");
        let msg = format!("{err:#}");
        assert_eq!(
            msg,
            format!("Working directory not found: {sentinel}"),
            "require_existing_working_dir() must bail with the EXACT wording \
             `\"Working directory not found: {{working_dir}}\"` interpolating \
             the raw `working_dir: &str` verbatim — pre-lift every consumer \
             spelled `bail!(\"Working directory not found: {{}}\", working_dir);`, \
             so a drift that swapped to `dir.display()` (or reworded the \
             prefix) would silently change the operator-facing message for \
             every one of the ten consumer sites. Got: {msg}"
        );
    }

    /// [`require_existing_labeled`] returns a lifetime-borrowed [`Path`]
    /// pointing at the `path: &str` input verbatim on the exists-hit case
    /// — the primitive's zero-alloc success return, structurally identical
    /// to the pre-lift `let path = Path::new(<str>);` idiom every one of
    /// the nine command-module consumer sites relied on. A drift that
    /// swapped the return to an owned `PathBuf` (via `.to_path_buf()` /
    /// `.canonicalize()`) would silently allocate at every one of the
    /// nine call sites, breaking the borrow-only discipline the pre-lift
    /// sites carried and forcing a downstream `read_text_async(&path)`
    /// through an unnecessary indirection.
    #[test]
    fn require_existing_labeled_returns_borrowed_path_on_exists_hit() {
        let dir = std::env::temp_dir();
        let dir_str = dir.to_str().expect("temp_dir must be UTF-8");
        let result = require_existing_labeled(dir_str, "Scratch dir")
            .expect("require_existing_labeled must succeed on an existing path");
        assert_eq!(
            result,
            Path::new(dir_str),
            "require_existing_labeled() must return `Path::new(path)` \
             verbatim on the exists-hit case — no owned-PathBuf allocation, \
             no `.canonicalize()` normalization, structurally identical to \
             the pre-lift `let path = Path::new(<str>);` idiom the nine \
             consumer sites relied on."
        );
    }

    /// [`require_existing_labeled`] bails with the exact wording
    /// `"{label} not found: {path}"` interpolating BOTH the caller-supplied
    /// `label` prefix AND the raw `path: &str` VERBATIM (NOT
    /// `Path::new(path).display()`) — pre-lift every consumer bailed with
    /// the raw string, so the operator sees the value they passed on the
    /// CLI without a trailing-slash normalization or a redundant
    /// re-projection through [`Path::display`]. A drift that swapped the
    /// interpolation to `p.display()` (or reordered the wording to
    /// `"not found: {path} ({label})"`) would silently change the
    /// operator-facing message for every one of the nine consumer sites,
    /// so this shield pins both the label-then-path ordering and the
    /// raw-string interpolation at the primitive body.
    ///
    /// Two label spellings are exercised: `"Kustomization file"` (the
    /// most frequent consumer noun, five sites) and `"runtime image
    /// tarball"` (a lowercase-noun consumer, one site) — the two shapes
    /// prove the primitive interpolates the label VERBATIM without a
    /// hidden capitalization or trim pass.
    #[test]
    fn require_existing_labeled_bails_with_label_and_path_verbatim_on_miss() {
        let sentinel =
            "/tmp/forge-require-existing-labeled-sigil-shield-nonexistent-path-9876543210";
        assert!(
            !Path::new(sentinel).exists(),
            "test sentinel must not exist for the shield to be meaningful"
        );
        for label in ["Kustomization file", "runtime image tarball"] {
            let err = require_existing_labeled(sentinel, label)
                .expect_err("require_existing_labeled must bail on a nonexistent path");
            let msg = format!("{err:#}");
            assert_eq!(
                msg,
                format!("{label} not found: {sentinel}"),
                "require_existing_labeled() must bail with the EXACT \
                 wording `\"{{label}} not found: {{path}}\"` interpolating \
                 the caller-supplied label and the raw path verbatim — \
                 pre-lift every consumer spelled \
                 `bail!(\"<Label> not found: {{}}\", <path>);` with the \
                 label baked in as a fixed literal, so a drift that \
                 lowercased/uppercased/normalized the label or \
                 re-projected the path through `Path::display` would \
                 silently change the operator-facing message for every \
                 one of the nine consumer sites. Got: {msg}"
            );
        }
    }

    /// [`require_existing_path`] returns `Ok(())` on the exists-hit case
    /// — the primitive's `&Path + &str → Result<()>` success arm carries
    /// no side effect and no allocated return, structurally identical to
    /// the pre-lift `if !<path>.exists() { bail!(...); }` idiom every one
    /// of the seven consumer sites relied on. A drift that swapped the
    /// return to an owned `PathBuf` (via `.to_path_buf()` /
    /// `.canonicalize()`) or `&Path` (echoing the input) would silently
    /// allocate or introduce a redundant identity binding at every call
    /// site, breaking the "caller already owns the path" invariant the
    /// pre-lift `PathBuf`-typed consumers carried.
    #[test]
    fn require_existing_path_returns_unit_on_exists_hit() {
        let dir = std::env::temp_dir();
        require_existing_path(&dir, "Scratch dir")
            .expect("require_existing_path must succeed on an existing PathBuf");
    }

    /// [`require_existing_path`] bails with the exact wording
    /// `"{label} not found: {path.display()}"` interpolating BOTH the
    /// caller-supplied `label` prefix AND the [`Path::display`] projection
    /// of the caller-owned path — where the [`&str`]-taking peer
    /// [`require_existing_labeled`] interpolates the raw string verbatim,
    /// this variant projects via `.display()` because pre-lift every one
    /// of the seven `PathBuf`-typed consumers already spelled `.display()`
    /// (the caller-owned [`PathBuf`] has no raw-`&str` form). A drift that
    /// swapped the interpolation to `path.to_string_lossy()` or a debug-
    /// format `{:?}` variant would silently change the operator-facing
    /// message for every one of the seven consumer sites, so this shield
    /// pins both the label-then-path ordering and the `.display()`
    /// projection at the primitive body.
    #[test]
    fn require_existing_path_bails_with_label_and_display_verbatim_on_miss() {
        let sentinel =
            Path::new("/tmp/forge-require-existing-path-sigil-shield-nonexistent-path-5432109876");
        assert!(
            !sentinel.exists(),
            "test sentinel must not exist for the shield to be meaningful"
        );
        for label in ["Gemspec", "SeaORM migrations directory", "index.html"] {
            let err = require_existing_path(sentinel, label)
                .expect_err("require_existing_path must bail on a nonexistent path");
            let msg = format!("{err:#}");
            assert_eq!(
                msg,
                format!("{label} not found: {}", sentinel.display()),
                "require_existing_path() must bail with the EXACT wording \
                 `\"{{label}} not found: {{path.display()}}\"` interpolating \
                 the caller-supplied label and the caller-owned `Path::display()` \
                 verbatim — pre-lift every consumer spelled \
                 `bail!(\"<Label> not found: {{}}\", <pathbuf>.display());` \
                 with the label baked in as a fixed literal, so a drift that \
                 lowercased/uppercased the label or projected the path through \
                 `.to_string_lossy()` / `{{:?}}` would silently change the \
                 operator-facing message for every one of the seven consumer \
                 sites. Got: {msg}"
            );
        }
    }

    /// Post-lift the seven consumer sites lifted onto
    /// [`require_existing_path`] must not silently re-inline the
    /// `if !<pathbuf>.exists() { bail!("<Label> not found: {}",
    /// <pathbuf>.display()); }` shape at their call points — a re-inline
    /// would reopen the class this lift closed. This source-scan shield
    /// walks every hand-lifted consumer file and refuses the label-and-
    /// display bail wordings the pre-lift sites carried.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The primitive body and its doc-comment code blocks legitimately
    /// spell the shape at their own body; this shield does NOT scan
    /// `repo.rs` so the sibling primitive survives it by construction,
    /// mirroring the discipline every sibling shield test in this module
    /// already carries.
    #[test]
    fn require_existing_path_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/gem.rs", include_str!("commands/gem.rs")),
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            (
                "commands/web_build_verify.rs",
                include_str!("commands/web_build_verify.rs"),
            ),
            (
                "commands/federation.rs",
                include_str!("commands/federation.rs"),
            ),
            (
                "commands/migration_new.rs",
                include_str!("commands/migration_new.rs"),
            ),
            (
                "commands/federation_tests.rs",
                include_str!("commands/federation_tests.rs"),
            ),
        ] {
            for needle in [
                "Gemspec not found:",
                "Library chart not found:",
                "Assets directory not found:",
                "index.html not found:",
                "Federation directory not found:",
                "SeaORM migrations directory not found:",
                "Federation tests deploy.yaml not found:",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` bail \
                     wording — that duplication was lifted onto \
                     `crate::repo::require_existing_path(&<pathbuf>, <label>)`. \
                     A re-inline would silently diverge the label-and-`.display()` \
                     envelope from the sibling consumers routing through \
                     the primitive, and fork the bail wording into a \
                     hand-typed literal that could drift from the \
                     primitive one consumer at a time."
                );
            }
        }
    }

    /// [`require_existing_working_dir`] must delegate its body through
    /// [`require_existing_labeled`] with `label = "Working directory"`
    /// rather than re-spelling the `Path::new + .exists() + bail!` shape
    /// inline. Pins the "one body per shape" discipline every sibling
    /// primitive in this module already carries: post-lift the
    /// [`Path::new`] construction, the [`Path::exists`] gate, and the
    /// bail-envelope wording live at ONE code line, so a future refinement
    /// (canonicalize, a must-be-a-dir check, a symlink-resolution branch)
    /// lands at the peer and reaches the working-dir consumers by
    /// construction. A re-inline of the three-line shape at
    /// [`require_existing_working_dir`]'s body would silently fork the
    /// working-dir specialization from the nine sibling stringly-key
    /// consumers routing through [`require_existing_labeled`], and drift
    /// the bail wording one specialization at a time.
    #[test]
    fn require_existing_working_dir_body_delegates_to_require_existing_labeled() {
        const SOURCE: &str = include_str!("repo.rs");
        let body = crate::test_support::fn_body_slice_between_markers(
            SOURCE,
            "repo.rs",
            "pub fn require_existing_working_dir(working_dir: &str) -> Result<&Path> {",
            "\n}",
        );
        assert!(
            body.contains("require_existing_labeled(working_dir, \"Working directory\")"),
            "require_existing_working_dir() body must forward through \
             `require_existing_labeled(working_dir, \"Working directory\")` — \
             the primitive body every `<str> + <role-noun> → Result<&Path>` \
             existence gate in the crate now delegates through. \
             Post-lift body: {body}"
        );
        assert!(
            !body.contains("Path::new(working_dir)"),
            "require_existing_working_dir() body must NOT spell the inline \
             `Path::new(working_dir)` construction — that duplication was \
             lifted onto `require_existing_labeled`. A re-inline would \
             silently diverge the working-dir specialization from the nine \
             sibling stringly-key consumers routing through the peer. \
             Post-lift body: {body}"
        );
        assert!(
            !body.contains("Working directory not found"),
            "require_existing_working_dir() body must NOT spell the inline \
             `\"Working directory not found: {{}}\"` bail wording — the \
             `\"{{label}} not found: {{path}}\"` envelope now lives at the \
             `require_existing_labeled` body and reaches this specialization \
             through the delegated `label = \"Working directory\"` argument. \
             Post-lift body: {body}"
        );
    }

    /// Post-lift the nine consumer sites lifted onto
    /// [`require_existing_labeled`] must not silently re-inline the
    /// `Path::new(<str>) + .exists() + bail!("<Label> not found: {}",
    /// <str>)` shape at their call points — a re-inline would reopen the
    /// class this lift closed. This source-scan shield walks every
    /// hand-lifted consumer file and refuses the raw label-and-path bail
    /// wordings the pre-lift sites carried, as well as the two-line
    /// `let path = Path::new(<str>); if !path.exists() { … }` scaffold
    /// they used to build up to it.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The primitive body and its doc-comment code blocks legitimately
    /// spell the shape at their own body; this shield does NOT scan
    /// `repo.rs` so the sibling primitive survives it by construction,
    /// mirroring the discipline every sibling shield test in this module
    /// already carries.
    #[test]
    fn require_existing_labeled_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            (
                "commands/kenshi_agent.rs",
                include_str!("commands/kenshi_agent.rs"),
            ),
            ("commands/kenshi.rs", include_str!("commands/kenshi.rs")),
            ("commands/push.rs", include_str!("commands/push.rs")),
            (
                "commands/nix_builder.rs",
                include_str!("commands/nix_builder.rs"),
            ),
            (
                "commands/crossplane.rs",
                include_str!("commands/crossplane.rs"),
            ),
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            (
                "commands/typescript.rs",
                include_str!("commands/typescript.rs"),
            ),
            ("commands/pangea.rs", include_str!("commands/pangea.rs")),
        ] {
            for needle in [
                "Kustomization file not found:",
                "Builder pool file not found:",
                "runtime image tarball not found:",
                "Chart tarball not found:",
                // Ten sibling stragglers from `commands/{helm,typescript,
                // pangea,crossplane}.rs`, lifted in a later pass onto the
                // same `require_existing_labeled(<path>, <label>)` body.
                // The 653592b pass caught nine, these ten completed the
                // sweep — six in helm.rs (chart_dir + k8s_repo + charts_dir
                // callers), one in typescript.rs (project loop), one in
                // pangea.rs (provider_dir), two in crossplane.rs (render +
                // validate input loops routed via a `format!`-built label).
                "Chart directory not found:",
                "K8s repo not found:",
                "Charts directory not found:",
                "Project directory not found:",
                "Provider directory not found:",
                "crossplane render: {} file not found:",
                "crossplane validate: {} path not found:",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` bail \
                     wording — that duplication was lifted onto \
                     `crate::repo::require_existing_labeled(<path>, <label>)`. \
                     A re-inline would silently diverge the label-and-path \
                     envelope from the sibling consumers routing through \
                     the primitive, and fork the bail wording into a \
                     hand-typed literal that could drift from the \
                     primitive one consumer at a time."
                );
            }
        }
    }

    /// [`create_dir_all_sync`] scaffolds a nested output directory that
    /// does not exist pre-call and every missing ancestor along the way.
    /// Pins the primitive's success arm to the same shape every pre-lift
    /// `std::fs::create_dir_all(<path>)?` consumer relied on — the
    /// underlying [`std::fs::create_dir_all`] is idempotent and
    /// ancestor-covering, and this shield fires if a future refactor
    /// swapped it to a single-level [`std::fs::create_dir`] (which
    /// would refuse a two-deep target with ENOENT) or added a
    /// pre-existence probe that skipped the mkdir on the "dir already
    /// there" branch (which would silently change the error semantics
    /// on a race with a concurrent scaffolder).
    #[test]
    fn create_dir_all_sync_materializes_nested_missing_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a").join("b").join("c");

        create_dir_all_sync(&nested).expect("well-formed create must succeed");

        assert!(
            nested.is_dir(),
            "create_dir_all_sync() must scaffold every missing ancestor and \
             the leaf, so a caller that then writes into the leaf sees a \
             directory ready to receive its bytes"
        );
    }

    /// [`create_dir_all_sync`]'s create-arm must surface the offending
    /// `path.display()` AND classify the failure as a CREATE-DIRECTORY
    /// error, so an operator reading the runner log can tell one bounce
    /// (`"Failed to create directory"` → `ls -la` on the parent and a
    /// permissions probe) from a write-arm bounce (`"Failed to write"`
    /// → `df -h` and `ls -la` on the file's ancestor) without cross-
    /// referencing the caller. Pins the primitive to the same envelope
    /// discipline the sync write sibling [`write_text_sync`] carries —
    /// one primitive per fs-op surface, same canonical operator-next-
    /// step contract. Pre-lift seven consumer sites carried a bare
    /// `std::fs::create_dir_all(<path>)?` shape whose failure surfaced
    /// only the underlying `io::Error` classifier with no offending
    /// path, and a future straggler that mis-spells the envelope
    /// (`"cannot create dir"` vs. `"Failed to create directory"`) would
    /// divorce the runner log from every other create-arm envelope in
    /// the crate. This shield forbids that regression at the primitive
    /// body.
    ///
    /// Failure is triggered by handing the primitive a path whose
    /// second-to-last component is a regular file — a `create_dir_all`
    /// under such a component surfaces `ENOTDIR` deterministically on
    /// every Unix filesystem without depending on process EUID or a
    /// pre-mounted read-only branch.
    #[test]
    fn create_dir_all_sync_missing_parent_dir_errors_carry_path_and_create_classifier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file_component = tmp.path().join("i-am-a-file");
        std::fs::write(&file_component, b"sentinel").expect("seed the file component");
        let path = file_component.join("nested-dir-under-a-file");

        let err = create_dir_all_sync(&path).unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to create directory"),
            "create-arm classifier must be 'Failed to create directory'; got: {msg}"
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "create-arm envelope must carry the offending path; got: {msg}"
        );
    }

    /// Post-lift the seven straggler consumer sites lifted onto
    /// [`create_dir_all_sync`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline would
    /// reopen the class this lift closed. This source-scan shield
    /// walks every hand-lifted consumer file and refuses the raw
    /// `std::fs::create_dir_all(<path>)?;` or
    /// `fs::create_dir_all(<path>)?;` composition — the exact
    /// bare-`?` shape the seven lifted sites carried pre-lift, which
    /// dropped the offending `path.display()` from every failure
    /// classifier — inside its consumer body window
    /// (`commands/helm.rs`, `commands/dashboards.rs`,
    /// `commands/pangea.rs`, `commands/gem.rs`).
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The `commands/tool.rs` and `commands/schema_validation.rs` sites
    /// that stay unlifted (`"Failed to create locks directory: {}"` on
    /// the per-tool-lock scaffold, `"Failed to create subgraph
    /// directory: {}"` on the codegen-input scaffold) legitimately
    /// carry per-role verb signal the canonical envelope would erase;
    /// this shield matches only the canonical
    /// `"Failed to create directory"` classifier so the two role-tagged
    /// sites survive it by construction — their inline shape is
    /// `create_dir_all(<x>).with_context(…)?`, NOT the bare
    /// `create_dir_all(<x>)?;` this shield forbids.
    ///
    /// Test-only tempdir scaffolding (`.unwrap()` / `.expect(…)`) is
    /// out of scope by construction: this shield matches the literal
    /// bare-`?;` suffix, and test bodies never spell `?;` at their
    /// call point (they either panic on failure via `.unwrap()` /
    /// `.expect(…)`, or thread `Result` up through a test that returns
    /// `Result` and threads its own contextual anyhow envelope, which
    /// carves them out from this pattern).
    #[test]
    fn create_dir_all_sync_consumers_do_not_reinline_the_primitive_shape() {
        // Bare-`?;` shape only: matches production sites the lift closed,
        // NOT `.unwrap()` / `.expect(…)` test scaffolds, NOT `.await` async
        // arms, NOT `.with_context(…)?` role-tagged sites.
        //
        // Two prefix spellings cover the pre-lift call-site vocabulary:
        // `std::fs::create_dir_all(…)?;` (helm.rs / pangea.rs / gem.rs) and
        // the `use std::fs;` shorthand `fs::create_dir_all(…)?;`
        // (dashboards.rs).
        for (name, source) in [
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            (
                "commands/dashboards.rs",
                include_str!("commands/dashboards.rs"),
            ),
            ("commands/pangea.rs", include_str!("commands/pangea.rs")),
            ("commands/gem.rs", include_str!("commands/gem.rs")),
        ] {
            for line in source.lines() {
                let trimmed = line.trim_start();
                let is_bare_create = (trimmed.starts_with("std::fs::create_dir_all(")
                    || trimmed.starts_with("fs::create_dir_all("))
                    && trimmed.ends_with(")?;");
                assert!(
                    !is_bare_create,
                    "{name} must NOT spell the inline bare-`?;` create-arm \
                     shape `{trimmed}` — that duplication was lifted onto \
                     `crate::repo::create_dir_all_sync`. A re-inline would \
                     silently diverge the create arm from the seven sibling \
                     create-dir consumers routing through the primitive."
                );
            }
        }
    }

    /// [`replace_symlink_async`] stages a symlink at a well-known
    /// `link_name` whose slot is empty pre-call and threads the caller's
    /// `target` verbatim into the on-disk symlink. Pins the primitive's
    /// success arm to the same shape every pre-lift `tokio::fs::symlink(&
    /// target, &link_name).await.context(...)` consumer relied on —
    /// [`tokio::fs::symlink`] IS the underlying primitive, so a future
    /// refactor that swapped the symlink direction (`(&link_name,
    /// &target)`) or re-encoded `target` through a normalization pass
    /// (which would silently canonicalize a relative
    /// `nix-store/…-derivation` path into an absolute one) would flip
    /// the on-disk semantics beneath every one of the three consumer
    /// sites, and this shield refuses that regression.
    #[tokio::test]
    async fn replace_symlink_async_stages_link_pointing_at_target() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("result-store-path");
        std::fs::write(&target, b"sentinel derivation output").expect("seed target");
        let link_name = tmp.path().join("result-runner");

        replace_symlink_async(&target, &link_name)
            .await
            .expect("well-formed replace must succeed");

        let read_back = tokio::fs::read_link(&link_name)
            .await
            .expect("post-replace read_link");
        assert_eq!(
            read_back, target,
            "replace_symlink_async() must persist the caller's `target` \
             verbatim into the on-disk symlink, so every consumer that \
             stages a build-output symlink sees the same target it did \
             pre-lift"
        );
    }

    /// [`replace_symlink_async`]'s remove-arm must silently drop an
    /// existing symlink at `link_name` before the create — the exact
    /// semantics every pre-lift consumer relied on via
    /// `tokio::fs::remove_file(&link).await.ok();` (or the `let _ = …`
    /// spelling). Pre-lift the three consumer sites each staged the
    /// build-output symlink at a slot that MAY already carry an old
    /// symlink from a prior run (a stale `result-runner` from the last
    /// CI build, a stale `result` at the repo root from the last
    /// deploy) — the pre-existence sweep is what makes the primitive
    /// idempotent across reruns. A future refactor that dropped the
    /// remove (or upgraded it to an errorful `remove_file(…)?`) would
    /// surface `EEXIST` on every rerun and break the CI's
    /// build-then-deploy loop at the second iteration.
    #[tokio::test]
    async fn replace_symlink_async_replaces_pre_existing_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let stale_target = tmp.path().join("stale-store-path");
        let fresh_target = tmp.path().join("fresh-store-path");
        std::fs::write(&stale_target, b"stale").expect("seed stale");
        std::fs::write(&fresh_target, b"fresh").expect("seed fresh");
        let link_name = tmp.path().join("result");

        tokio::fs::symlink(&stale_target, &link_name)
            .await
            .expect("seed the pre-existing symlink");

        replace_symlink_async(&fresh_target, &link_name)
            .await
            .expect("replace over a pre-existing symlink must succeed");

        let read_back = tokio::fs::read_link(&link_name)
            .await
            .expect("post-replace read_link");
        assert_eq!(
            read_back, fresh_target,
            "replace_symlink_async() must drop the stale symlink and \
             stage a fresh one pointing at the new target — the exact \
             idempotence contract every rerun-tolerant build-output \
             consumer relies on"
        );
    }

    /// [`replace_symlink_async`]'s create-arm must surface BOTH the
    /// offending `link_name.display()` AND the intended
    /// `target.display()` on the failure envelope, so an operator
    /// reading the runner log can tell one bounce
    /// (`"Failed to create symlink"`) from other fs-op bounces
    /// (`"Failed to write"` on a file, `"Failed to create directory"` on
    /// a mkdir) without cross-referencing the caller, and can tell
    /// which link and which target were involved without re-deriving
    /// the site's call context. Pins the primitive to the same envelope
    /// discipline every sibling fs-op primitive on the sync / async
    /// surfaces already carries — one primitive per fs-op surface,
    /// same canonical operator-next-step contract. Pre-lift the three
    /// consumer sites carried bare `.context("Failed to create
    /// symlink")` / `.context("Failed to create result symlink")` /
    /// `.context("Failed to create result-runner symlink")` strings
    /// with NO path in the envelope; this shield forbids that
    /// regression.
    ///
    /// Failure is triggered by pointing `link_name` at a slot whose
    /// parent does not exist — a `tokio::fs::symlink(target, link_name)`
    /// under such a missing parent surfaces `ENOENT` deterministically
    /// without depending on process EUID or a pre-mounted read-only
    /// branch.
    #[tokio::test]
    async fn replace_symlink_async_missing_parent_dir_errors_carry_both_paths_and_symlink_classifier(
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("some-target");
        let link_name = tmp.path().join("does-not-exist-dir").join("result");

        let err = replace_symlink_async(&target, &link_name)
            .await
            .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to create symlink"),
            "symlink-arm classifier must be 'Failed to create symlink'; got: {msg}"
        );
        assert!(
            msg.contains(&link_name.display().to_string()),
            "symlink-arm envelope must carry the offending link_name; got: {msg}"
        );
        assert!(
            msg.contains(&target.display().to_string()),
            "symlink-arm envelope must carry the intended target; got: {msg}"
        );
    }

    /// Post-lift the three straggler consumer sites lifted onto
    /// [`replace_symlink_async`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline would
    /// reopen the class this lift closed. This source-scan shield
    /// walks every hand-lifted consumer file and refuses the raw
    /// `tokio::fs::symlink(…)` composition inside its consumer body
    /// window (`commands/build.rs`, `commands/comprehensive_release.rs`,
    /// `commands/github_runner_ci.rs`) — the exact shape the three
    /// lifted sites carried pre-lift, which dropped both the offending
    /// `link_name.display()` and the intended `target.display()` from
    /// every failure classifier.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces
    /// every other consumer to divorce from the primitive one edit at
    /// a time.
    #[test]
    fn replace_symlink_async_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/build.rs", include_str!("commands/build.rs")),
            (
                "commands/comprehensive_release.rs",
                include_str!("commands/comprehensive_release.rs"),
            ),
            (
                "commands/github_runner_ci.rs",
                include_str!("commands/github_runner_ci.rs"),
            ),
        ] {
            assert!(
                !source.contains("tokio::fs::symlink("),
                "{name} must NOT spell the inline `tokio::fs::symlink(…)` \
                 create-arm — that duplication was lifted onto \
                 `crate::repo::replace_symlink_async`. A re-inline would \
                 silently diverge the create arm from the three sibling \
                 symlink-staging consumers routing through the primitive, \
                 and drop both the offending `link_name.display()` and \
                 the intended `target.display()` from the failure envelope."
            );
        }
    }

    /// [`set_current_dir_labeled`] pivots the process cwd to the caller-
    /// supplied `dir` and returns Ok on success — pins the primitive's
    /// happy path to the same observable-cwd shape every pre-lift
    /// `env::set_current_dir(<path>).context("Failed to change to <label>
    /// directory")?;` consumer relied on. A future refactor that dropped
    /// the [`std::env::set_current_dir`] call (or replaced it with a
    /// no-op stub returning Ok) would break every one of the five
    /// consumer sites at their next `Command` spawn — subsequent argv
    /// would spawn from the pre-lift cwd rather than the pivoted-to
    /// workspace / service / federation directory — and this test would
    /// fail HERE by observing an unchanged cwd. Cwd is a process-global
    /// singleton so the test acquires [`crate::test_support::
    /// ROOT_FLAKE_ENV_LOCK`] and captures a
    /// [`crate::test_support::RootFlakeEnvSnapshot`] to restore cwd on
    /// drop (both normal exit and panic), matching the discipline every
    /// sibling `activate_root_flake_*` test in this module already
    /// carries.
    #[test]
    fn set_current_dir_labeled_pivots_cwd_to_target_dir() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _env = crate::test_support::RootFlakeEnvSnapshot::capture();
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target-workspace");
        std::fs::create_dir_all(&target).expect("create target dir");

        set_current_dir_labeled(&target, "workspace").expect("well-formed pivot must succeed");

        let observed = std::env::current_dir().expect("cwd after pivot");
        // Both sides go through canonicalize so a `/private/var/...` vs
        // `/var/...` symlink prefix at the tempdir root does not flake
        // the equality reading — same discipline as the
        // `activate_root_flake_chdirs_to_repo_root_not_service_dir` peer.
        let expected = target.canonicalize().expect("canonicalize target");
        let observed = observed.canonicalize().expect("canonicalize observed");
        assert_eq!(
            observed, expected,
            "set_current_dir_labeled() must pivot the process cwd to the \
             caller-supplied `dir` — the exact shape every pre-lift \
             `env::set_current_dir(<path>).context(...)?` consumer \
             relied on for its subsequent `Command` spawns"
        );
    }

    /// [`set_current_dir_labeled`]'s failure arm must surface the
    /// caller-supplied `label` VERBATIM in the classifier — pins the
    /// envelope to the same `"Failed to change to <label> directory"`
    /// shape every pre-lift consumer relied on, so a runner log that
    /// grep-matched `"Failed to change to workspace directory"` keeps
    /// matching post-lift. A drift that swapped the interpolation to
    /// `dir.display()`, dropped the trailing `" directory"` token, or
    /// changed the leading `"Failed to change to "` prefix would break
    /// operator-facing prose at every one of the five consumer sites
    /// without a compile error, and this shield refuses that regression.
    ///
    /// Failure is triggered by pointing `dir` at a slot that does not
    /// exist under a hermetic tempdir — a
    /// [`std::env::set_current_dir`] to such a path surfaces `ENOENT`
    /// deterministically without depending on process EUID or a
    /// pre-mounted read-only branch. Cwd is not mutated on the failure
    /// arm (the underlying [`std::env::set_current_dir`] call errors
    /// before the process cwd is touched), so the test needs no
    /// cwd-restore guard.
    #[test]
    fn set_current_dir_labeled_missing_target_envelope_carries_label() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist-workspace-dir");

        let err = set_current_dir_labeled(&missing, "federation").unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains("Failed to change to federation directory"),
            "chdir-arm envelope must carry the caller-supplied label \
             verbatim in a `Failed to change to <label> directory` \
             classifier; got: {msg}"
        );
    }

    /// Post-lift the five consumer sites lifted onto
    /// [`set_current_dir_labeled`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline would
    /// reopen the class this lift closed. This source-scan shield walks
    /// every hand-lifted consumer file and refuses the raw
    /// `"Failed to change to "` classifier substring inside its consumer
    /// body window (`commands/federation.rs`,
    /// `commands/developer_tools.rs`) — the exact shape the five lifted
    /// sites carried pre-lift, whose per-site `.context(...)` string
    /// baked the role label into a hand-typed literal that could drift
    /// from the actual role the pivot served silently.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The [`in_directory`] primitive body in `repo.rs` legitimately
    /// carries `"Failed to change to directory: {path}"` (path-tagged,
    /// not label-tagged) at its own body; this shield does NOT scan
    /// `repo.rs` so the sibling primitive survives it by construction,
    /// mirroring the discipline sibling shield tests already carry.
    ///
    /// [`activate_root_flake`]'s `"Failed to change working directory to
    /// repo root: {path}"` envelope legitimately carries the raw path
    /// (not a label) because the load-bearing operator-facing signal at
    /// that ONE consumer is which repo-root path failed to activate,
    /// not the role; this shield's `"Failed to change to "` needle does
    /// NOT match `"Failed to change working directory"` (different
    /// substring), so the primitive survives it by construction.
    #[test]
    fn set_current_dir_labeled_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            (
                "commands/federation.rs",
                include_str!("commands/federation.rs"),
            ),
            (
                "commands/developer_tools.rs",
                include_str!("commands/developer_tools.rs"),
            ),
        ] {
            assert!(
                !source.contains("Failed to change to "),
                "{name} must NOT spell the inline \
                 `.context(\"Failed to change to <label> directory\")` \
                 classifier — that duplication was lifted onto \
                 `crate::repo::set_current_dir_labeled`. A re-inline \
                 would silently diverge the chdir arm from the five \
                 sibling cwd-pivoting consumers routing through the \
                 primitive, and reopen the drift class where a hand-typed \
                 `<label>` literal could diverge from the role the pivot \
                 served."
            );
        }
    }

    /// [`current_dir`] projects the underlying
    /// [`std::env::current_dir`] return value verbatim on the Ok arm —
    /// pins the primitive to a byte-identical projection of the
    /// stdlib read plus the anyhow envelope, so a
    /// `find_repo_root(&current_dir()?)` lookup that pre-lift resolved
    /// against `X` still resolves against `X` post-lift. A future
    /// refactor that swapped the underlying read for a hard-coded
    /// literal (or a call through a caching layer that would
    /// stale-read a prior chdir) would break every one of the five
    /// consumer sites at their next `find_repo_root(&cwd)` lookup, and
    /// this test fails HERE by observing a value that does not match
    /// the direct stdlib read.
    ///
    /// Test is read-only on the cwd surface (does NOT chdir): the two
    /// reads must observe the same value at the same instant, so the
    /// test acquires [`crate::test_support::ROOT_FLAKE_ENV_LOCK`] to
    /// serialize with sibling cwd-touching tests and captures no
    /// [`crate::test_support::RootFlakeEnvSnapshot`] because no
    /// mutation happens under the lock — the sibling
    /// `set_current_dir_labeled_pivots_cwd_to_target_dir` peer covers
    /// the write path on its own primitive.
    #[test]
    fn current_dir_returns_process_cwd() {
        let _guard = crate::test_support::ROOT_FLAKE_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let observed = current_dir().expect("current_dir must succeed on a live process cwd");
        let direct = std::env::current_dir().expect("direct stdlib read must also succeed");
        assert_eq!(
            observed, direct,
            "current_dir() must project the underlying \
             `std::env::current_dir()` return value verbatim on the Ok \
             arm — the exact shape every pre-lift consumer relied on \
             for its subsequent `find_repo_root(&cwd)` / \
             `set_current_dir(original_dir)` operations, so a lookup \
             that pre-lift resolved against `X` still resolves against \
             `X` post-lift"
        );
    }

    /// Post-lift the five consumer sites lifted onto [`current_dir`]
    /// must not silently re-inline the primitive's shape at their call
    /// points — a re-inline would reopen the class this lift closed.
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses the raw `env::current_dir(` composition inside its
    /// consumer body window (`commands/e2e.rs`, `commands/federation.rs`,
    /// `path_builder.rs`) — the exact shape the pre-lift sites carried,
    /// which either dropped the classifier entirely
    /// (`federation.rs`, bare `env::current_dir()?`) or spelled a
    /// hand-typed `"Failed to get current directory"` string that would
    /// silently drift away from the primitive's canonical envelope one
    /// consumer at a time.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The primitive body in `repo.rs` legitimately carries
    /// `std::env::current_dir()` at its own body; this shield does NOT
    /// scan `repo.rs` so the sibling primitive survives it by
    /// construction, mirroring the discipline every sibling shield test
    /// in this module already carries.
    ///
    /// Test-only cwd-reading callers (`commands/attestation.rs`'s
    /// `std::env::current_dir().expect("cwd")` in per-test setup,
    /// `test_support.rs`'s `RootFlakeEnvSnapshot::capture` /
    /// `CwdRestoreGuard`) legitimately spell the raw call under a
    /// `#[cfg(test)]` gate because a panic-on-failure semantics
    /// (`.expect(…)`) is what the test scaffold wants, not an anyhow
    /// envelope — this shield does NOT scan those files so the test-
    /// only carve-out survives it by construction.
    #[test]
    fn current_dir_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/e2e.rs", include_str!("commands/e2e.rs")),
            (
                "commands/federation.rs",
                include_str!("commands/federation.rs"),
            ),
            ("path_builder.rs", include_str!("path_builder.rs")),
        ] {
            assert!(
                !source.contains("env::current_dir("),
                "{name} must NOT spell the inline `env::current_dir(…)` \
                 read — that duplication was lifted onto \
                 `crate::repo::current_dir`. A re-inline would silently \
                 diverge the cwd-read from the five sibling consumers \
                 routing through the primitive, and either drop the \
                 canonical `\"Failed to get current directory\"` \
                 classifier from the envelope (`federation.rs`'s pre-lift \
                 naked shape) or fork a hand-typed copy that could drift \
                 from the primitive's wording one consumer at a time \
                 (`e2e.rs` / `path_builder.rs`'s pre-lift shape)."
            );
        }
    }

    /// [`file_name_str`] projects the file-name segment of `path` as a
    /// borrowed `&str` on the well-formed UTF-8 case — pins the
    /// primitive to the byte-identical projection every one of the ten
    /// pre-lift consumer sites relied on. The returned `&str` must
    /// alias the input path's bytes (no owned-`String` allocation), so
    /// a downstream [`str::starts_with`] / [`str::trim_end_matches`] /
    /// [`regex::Regex::is_match`] can consume it without an
    /// intermediate copy — the exact zero-alloc discipline the pre-lift
    /// sigil silently carried and this shield keeps.
    #[test]
    fn file_name_str_returns_file_name_segment_on_utf8_hit() {
        let path = Path::new("/tmp/forge-workspace/pleme-linker-cli/src/main.rs");
        let name = file_name_str(path);
        assert_eq!(
            name, "main.rs",
            "file_name_str() must project the file-name segment of the \
             input path verbatim on the UTF-8 hit case — the exact shape \
             every pre-lift consumer relied on for its downstream string \
             predicate (a `.starts_with(...)`, a `.trim_end_matches(...)`, \
             a regex `.is_match(...)`). Got: {name:?}"
        );
    }

    /// [`file_name_str`] returns `""` on the missing-file-name arm
    /// (root `/`, a path ending in `..`). Pins the primitive's canonical
    /// miss-arm unit to the exact `""` literal every pre-lift consumer
    /// relied on: a downstream `.starts_with("pleme-")`,
    /// `.trim_end_matches(".rs")`, `regex.is_match(&filename)`, or
    /// equality against a fixed sentinel like `"test_support.rs"`
    /// all propagate the "no match" verdict through the empty-string
    /// unit by construction, so no consumer needs a separate
    /// [`Option`]-shaped short-circuit branch. A drift that swapped the
    /// miss-arm unit to `"?"` / `"unknown"` / any non-empty sentinel
    /// would silently trigger downstream predicates that the pre-lift
    /// sites did NOT want triggered.
    #[test]
    fn file_name_str_returns_empty_string_on_root_path_miss() {
        let root = Path::new("/");
        assert_eq!(
            file_name_str(root),
            "",
            "file_name_str() must return `\"\"` on a path with no \
             file-name component (root `/`) — the exact miss-arm unit \
             every pre-lift consumer relied on to propagate the \
             `no match` verdict through its downstream string predicate."
        );
    }

    /// Post-lift the ten consumer sites lifted onto [`file_name_str`]
    /// must not silently re-inline the primitive's shape at their call
    /// points — a re-inline would reopen the class this lift closed.
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses the raw
    /// `<ident>.file_name().and_then(|<x>| <x>.to_str()).unwrap_or("")`
    /// composition — the exact shape the ten lifted sites carried
    /// pre-lift, which fanned the triple-projection out as ten
    /// hand-typed spellings the borrow-checker could not cross-check.
    ///
    /// A helpful "just inline it, it's shorter" cleanup at any one site
    /// re-opens the duplication class this lift closed and forces every
    /// other consumer to divorce from the primitive one edit at a time.
    ///
    /// The `.parent().and_then(|p| p.file_name()).and_then(|s| s.
    /// to_str()).unwrap_or("")` parent-directory-name variant at
    /// `test_support.rs:7164` is a multi-line composition whose tail
    /// (`.and_then(|s| s.to_str()).unwrap_or("")`) lives on subsequent
    /// lines; the file-name-of-path shape this shield guards is a
    /// single-line composition, so the two-arm `.contains(...)` needles
    /// below match the single-line shape only and the multi-line parent
    /// variant survives them by construction.
    ///
    /// The primitive body in `repo.rs` legitimately spells the shape at
    /// its own body (inside a doc-comment code block and inside the
    /// primitive body itself); this shield does NOT scan `repo.rs` so
    /// the sibling primitive survives it by construction, mirroring the
    /// discipline every sibling shield test in this module already
    /// carries.
    #[test]
    fn file_name_str_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            (
                "commands/workspace_deps.rs",
                include_str!("commands/workspace_deps.rs"),
            ),
            (
                "commands/migration_validation.rs",
                include_str!("commands/migration_validation.rs"),
            ),
            (
                "commands/web_build_verify.rs",
                include_str!("commands/web_build_verify.rs"),
            ),
            ("test_support.rs", include_str!("test_support.rs")),
        ] {
            for needle in [
                ".file_name().and_then(|n| n.to_str()).unwrap_or(\"\")",
                ".file_name().and_then(|s| s.to_str()).unwrap_or(\"\")",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` \
                     triple-projection — that duplication was lifted \
                     onto `crate::repo::file_name_str`. A re-inline \
                     would silently diverge the file-name-read from the \
                     ten sibling stringly-key consumers routing through \
                     the primitive, and fork the miss-arm unit (`\"\"`) \
                     into a hand-typed literal that could drift from \
                     the primitive one consumer at a time."
                );
            }
        }
    }

    /// [`dir_entry_name_lossy`] projects the file-name segment of a
    /// [`std::fs::DirEntry`] into an owned [`String`] verbatim through
    /// the lossy UTF-8 repair on the well-formed UTF-8 case — pins the
    /// primitive to the byte-identical projection every one of the five
    /// pre-lift consumer sites relied on. On a directory containing an
    /// ASCII-named entry the returned [`String`] carries the entry's
    /// file-name bytes byte-for-byte, so a downstream
    /// [`str::starts_with`] / [`str::ends_with`] / [`str::contains`] /
    /// [`Path::join`] receives the same bytes the pre-lift
    /// `<entry>.file_name().to_string_lossy().to_string()` spelling
    /// handed it.
    #[test]
    fn dir_entry_name_lossy_returns_file_name_byte_identical_on_utf8_hit() {
        let tmp = tempfile::tempdir().expect("mk tempdir");
        std::fs::write(tmp.path().join("m20260209_000001_seed.rs"), b"//! seed\n")
            .expect("write seed file");
        let entry = std::fs::read_dir(tmp.path())
            .expect("read_dir tempdir")
            .filter_map(std::result::Result::ok)
            .next()
            .expect("one entry in tempdir");
        let projected = dir_entry_name_lossy(&entry);
        assert_eq!(
            projected, "m20260209_000001_seed.rs",
            "dir_entry_name_lossy() must project the DirEntry's file-name \
             segment byte-identical on the UTF-8 hit arm — the exact shape \
             every pre-lift consumer relied on for its downstream \
             `.starts_with(&date_prefix)` / `.ends_with(\".rs\")` / \
             `.contains('_')` / `Path::join(&name)` / \
             `info!(\"Skipping {{}}\", name)` predicate. Got: {projected:?}"
        );
    }

    /// [`dir_entry_name_lossy`] uses [`std::borrow::Cow::into_owned`]
    /// at its tail rather than the pre-lift `.to_string()` spelling —
    /// see the primitive body's doc-comment for the one-alloc vs
    /// two-alloc distinction on the [`std::borrow::Cow::Owned`] arm.
    /// Mirrors [`path_to_string_lossy_body_ends_with_into_owned_not_to_string`]
    /// on the [`std::fs::DirEntry`]-receiving sibling — a body-slice
    /// source-scan shield keeps future drift on the tail (a helpful
    /// "let's be consistent with `.to_string()` everywhere" cleanup
    /// would silently reintroduce the double-alloc the primitive
    /// discharges).
    #[test]
    fn dir_entry_name_lossy_body_ends_with_into_owned_not_to_string() {
        let source = include_str!("repo.rs");
        let signature = "pub fn dir_entry_name_lossy(entry: &std::fs::DirEntry) -> String {";
        let start = source
            .find(signature)
            .expect("dir_entry_name_lossy signature must appear in repo.rs");
        let body_slice = &source[start..start + 200];
        assert!(
            body_slice.contains(".into_owned()"),
            "dir_entry_name_lossy body must end with `.into_owned()` \
             to keep the one-alloc discipline on the \
             `Cow::Owned` (non-UTF-8) arm — a drift to `.to_string()` \
             reintroduces the silent double-alloc every pre-lift site \
             carried and this primitive was lifted to discharge. \
             Body slice: {body_slice}"
        );
        assert!(
            !body_slice.contains(".to_string_lossy().to_string()"),
            "dir_entry_name_lossy body must NOT respell the pre-lift \
             `.to_string_lossy().to_string()` two-alloc shape at its \
             own body — that is the exact shape the five consumer \
             sites were lifted to escape. Body slice: {body_slice}"
        );
    }

    /// Post-lift the five consumer sites lifted onto
    /// [`dir_entry_name_lossy`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline would
    /// reopen the class this lift closed. This source-scan shield walks
    /// every hand-lifted consumer file and refuses the raw
    /// `<ident>.file_name().to_string_lossy().to_string()` composition
    /// keyed by the concrete identifier every consumer bound (the two
    /// `pangea.rs` closures bind `e` and `entry`, `helm.rs` binds
    /// `entry`, `migration_new.rs` binds `entry`, `gem.rs`'s `.map(|e|
    /// ...)` closure binds `e`).
    ///
    /// The `pangea.rs:640` `Some(r) => e.file_name().to_string_lossy() == r`
    /// site is legitimately a different shape from the identifier-plus-
    /// `.to_string()` form this lift consolidated: it compares the
    /// [`std::borrow::Cow<str>`] directly against a `&String` without
    /// allocating the owned tail, so it survives the identifier-keyed
    /// needle below by construction (the `.to_string()` suffix is
    /// absent from that expression).
    ///
    /// The primitive body in `repo.rs` legitimately spells the shape at
    /// its own body (inside a doc-comment code block and inside the
    /// primitive body itself); this shield does NOT scan `repo.rs` so
    /// the sibling primitive survives it by construction, mirroring the
    /// discipline every sibling shield test in this module already
    /// carries.
    #[test]
    fn dir_entry_name_lossy_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/pangea.rs", include_str!("commands/pangea.rs")),
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            (
                "commands/migration_new.rs",
                include_str!("commands/migration_new.rs"),
            ),
            ("commands/gem.rs", include_str!("commands/gem.rs")),
        ] {
            for needle in [
                "e.file_name().to_string_lossy().to_string()",
                "entry.file_name().to_string_lossy().to_string()",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` \
                     triple-projection — that duplication was lifted \
                     onto `crate::repo::dir_entry_name_lossy`. A re-inline \
                     would silently diverge the DirEntry file-name read \
                     from the five sibling stringly-key consumers routing \
                     through the primitive, and re-fork the \
                     `.to_string()` tail one consumer at a time from \
                     the primitive's `.into_owned()` one-alloc \
                     discipline."
                );
            }
        }
    }

    /// [`sort_dir_entries_by_mtime_desc`] orders three entries whose
    /// modification times were written in ascending order so the newest
    /// lands at index 0 and the oldest at the tail — pins the newest-
    /// first ordering both `find_latest_tgz` (`commands/helm.rs`) and
    /// `find_gem_file` (`commands/gem.rs`) rely on when they call
    /// `entries.first()` after the sort to pick the freshly-packaged
    /// artifact. A silent flip to ascending-by-mtime would return the
    /// STALE tarball / gem — the exact class of bug the primitive
    /// exists to close.
    #[test]
    fn sort_dir_entries_by_mtime_desc_orders_newest_first() {
        let tmp = tempfile::tempdir().expect("mk tempdir");
        for name in ["oldest.tgz", "middle.tgz", "newest.tgz"] {
            let path = tmp.path().join(name);
            std::fs::write(&path, name.as_bytes()).expect("write fixture");
            // Space each file's mtime a full second apart so the sort
            // never sees ties on a filesystem with 1-second mtime
            // granularity (ext4, HFS+ on some setups). Sleeping is
            // cheap and the test runs once.
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(tmp.path())
            .expect("read_dir tempdir")
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 3, "fixture must produce three entries");

        sort_dir_entries_by_mtime_desc(&mut entries);

        let names: Vec<String> = entries.iter().map(dir_entry_name_lossy).collect();
        assert_eq!(
            names,
            vec![
                "newest.tgz".to_string(),
                "middle.tgz".to_string(),
                "oldest.tgz".to_string(),
            ],
            "sort_dir_entries_by_mtime_desc must place the most-recently \
             modified entry at index 0 so the two `find_latest_<artifact>` \
             selectors' `entries.first()` yields the freshly-packaged \
             tarball / gem — a swap to ascending order would silently \
             return the stale artifact one release at a time."
        );
    }

    /// [`sort_dir_entries_by_mtime_desc`] treats an entry whose metadata
    /// cannot be resolved as ancient ([`std::time::SystemTime::UNIX_EPOCH`])
    /// rather than propagating the error, so a foreign-owned file, an
    /// ACL denial, or a file removed between `read_dir` and the sort
    /// pass sorts to the TAIL without failing the selector. Every
    /// readable entry still lands ahead of every unreadable one, so the
    /// caller's `entries.first()` continues to pick a valid artifact.
    ///
    /// Simulated here by capturing a [`std::fs::DirEntry`] and then
    /// deleting the file the entry points at before the sort runs, so
    /// [`std::fs::DirEntry::metadata`] surfaces
    /// [`std::io::ErrorKind::NotFound`] — reliably reproducible in a
    /// unit test without depending on symlink-follow semantics (which
    /// differ across platforms) or on file permissions (which don't
    /// survive `sudo`-less test runners).
    #[test]
    fn sort_dir_entries_by_mtime_desc_treats_unreadable_metadata_as_epoch() {
        let tmp = tempfile::tempdir().expect("mk tempdir");
        // Two real files with real mtimes, so both start with valid
        // metadata at the moment `read_dir` enumerates them.
        std::fs::write(tmp.path().join("readable.tgz"), b"x").expect("write readable");
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(tmp.path().join("vanishes.tgz"), b"y").expect("write vanishes");

        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(tmp.path())
            .expect("read_dir tempdir")
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(entries.len(), 2, "fixture must produce two entries");

        // Delete the newer file AFTER capturing its DirEntry: the
        // DirEntry still points at the (now missing) path, so
        // `entry.metadata()` returns ENOENT and the primitive's
        // `.and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH)` chain
        // treats the entry as ancient.
        std::fs::remove_file(tmp.path().join("vanishes.tgz")).expect("remove vanishes");

        sort_dir_entries_by_mtime_desc(&mut entries);

        let names: Vec<String> = entries.iter().map(dir_entry_name_lossy).collect();
        assert_eq!(
            names,
            vec!["readable.tgz".to_string(), "vanishes.tgz".to_string()],
            "sort_dir_entries_by_mtime_desc must sort the entry \
             whose metadata cannot be resolved (deleted file → \
             UNIX_EPOCH fallback) to the tail — a `map_err`-style \
             rewrite that let the metadata failure bubble as `Err` \
             would silently fail the entire selector on a directory \
             that also contains a perfectly readable artifact."
        );
    }

    /// Post-lift the two `find_latest_<artifact>` selectors lifted onto
    /// [`sort_dir_entries_by_mtime_desc`] must not silently re-inline
    /// the primitive's shape at their call sites — a re-inline would
    /// reopen the comparator-direction and unreadable-metadata-
    /// fallback drift the primitive was lifted to close. The source-
    /// scan shield refuses either half of the pre-lift `b.metadata().
    /// and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::
    /// UNIX_EPOCH)` chain (the closure body is the load-bearing
    /// half; the `.unwrap_or(UNIX_EPOCH)` tail is the fallback
    /// half). Restatement at any call site is a re-fork one
    /// consumer at a time from the primitive's owner-frozen contract.
    #[test]
    fn sort_dir_entries_by_mtime_desc_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            ("commands/gem.rs", include_str!("commands/gem.rs")),
        ] {
            for needle in [
                ".and_then(|m| m.modified())",
                "std::time::SystemTime::UNIX_EPOCH",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` — that \
                     duplication was lifted onto \
                     `crate::repo::sort_dir_entries_by_mtime_desc`. A \
                     re-inline would silently reopen the comparator- \
                     direction bug (a b/a → a/b swap returns the STALE \
                     artifact one release at a time) and the \
                     unreadable-metadata fallback bug (an unreadable \
                     entry fails the whole selector instead of sorting \
                     to the tail) the primitive discharges."
                );
            }
        }
    }

    /// [`path_to_string_lossy`] projects a path into an owned
    /// [`String`] verbatim through the lossy UTF-8 repair: an
    /// ASCII-only path passes through byte-identical, so the output
    /// aliases the input segment-for-segment and no consumer needs
    /// a separate short-circuit for the "trivially UTF-8" arm.
    ///
    /// Pinning the byte-identity on the ASCII arm is the load-bearing
    /// half of the contract: every one of the eleven lifted consumer
    /// sites feeds the returned [`String`] into a downstream
    /// [`std::process::Command::current_dir`], a
    /// `git add <path>` argv slot, a `--working-dir <path>` CLI flag
    /// forwarded through [`run_forge_subcommand`], or a `serde_json`
    /// `modified_files` list eventually surfaced to the operator —
    /// every one of them relies on the path bytes surviving the round
    /// trip through the primitive verbatim. A drift to a
    /// [`Path::display`]-normalized shape (which collapses trailing
    /// slashes and canonicalizes empty segments) would silently walk
    /// one of those spawn-time paths off the caller-supplied argv.
    #[test]
    fn path_to_string_lossy_returns_owned_string_byte_identical_on_utf8_hit() {
        let path = std::path::Path::new("/tmp/forge-workspace/pleme-linker-cli/src/main.rs");
        let projected = path_to_string_lossy(path);
        assert_eq!(
            projected, "/tmp/forge-workspace/pleme-linker-cli/src/main.rs",
            "path_to_string_lossy() must project the ASCII input path \
             byte-identical on the UTF-8 hit arm — the exact shape \
             every pre-lift consumer relied on for its downstream \
             argv slot / `current_dir` / `--working-dir` flag / \
             `modified_files` push. Got: {projected:?}"
        );
    }

    /// [`path_to_string_lossy`] uses [`std::borrow::Cow::into_owned`]
    /// at its tail rather than the pre-lift `.to_string()` spelling —
    /// see the primitive body's doc-comment for the one-alloc vs
    /// two-alloc distinction on the [`std::borrow::Cow::Owned`] arm.
    /// A body-slice source-scan shield keeps future drift on the tail
    /// (a helpful "let's be consistent with `.to_string()` everywhere"
    /// cleanup would silently reintroduce the double-alloc the
    /// primitive discharges).
    #[test]
    fn path_to_string_lossy_body_ends_with_into_owned_not_to_string() {
        let source = include_str!("repo.rs");
        let signature = "pub fn path_to_string_lossy(path: &Path) -> String {";
        let start = source
            .find(signature)
            .expect("path_to_string_lossy signature must appear in repo.rs");
        let body_slice = &source[start..start + 200];
        assert!(
            body_slice.contains(".into_owned()"),
            "path_to_string_lossy body must end with `.into_owned()` \
             to keep the one-alloc discipline on the \
             `Cow::Owned` (non-UTF-8) arm — a drift to `.to_string()` \
             reintroduces the silent double-alloc every pre-lift site \
             carried and this primitive was lifted to discharge. \
             Body slice: {body_slice}"
        );
        assert!(
            !body_slice.contains(".to_string_lossy().to_string()"),
            "path_to_string_lossy body must NOT respell the pre-lift \
             `.to_string_lossy().to_string()` two-alloc shape at its \
             own body — that is the exact shape the eleven consumer \
             sites were lifted to escape. Body slice: {body_slice}"
        );
    }

    /// Post-lift the fifteen consumer sites lifted onto
    /// [`path_to_string_lossy`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline reopens
    /// the class this lift closed. This source-scan shield walks
    /// every hand-lifted consumer file and refuses the exact
    /// `<ident>.to_string_lossy().to_string()` and
    /// `<ident>.to_string_lossy().into_owned()` compositions each
    /// site carried pre-lift, keyed by the concrete identifier every
    /// consumer bound.
    ///
    /// The two pre-lift spellings project identically through the
    /// primitive's `.into_owned()` tail: on the
    /// [`std::borrow::Cow::Borrowed`] (UTF-8) arm both allocate one
    /// fresh [`String`] and are bytewise indistinguishable; on the
    /// [`std::borrow::Cow::Owned`] (non-UTF-8) arm the primitive
    /// unwraps the already-owned [`String`] in place while both
    /// pre-lift spellings — the double-`.to_string()` variant and
    /// the `.into_owned()` variant that already saved one alloc —
    /// belong to the same "path-to-owned-string via lossy repair"
    /// projection. Consolidating both into one primitive keeps the
    /// projection uniform and refuses drift by construction, no
    /// matter which of the two pre-lift spellings a future cleanup
    /// tried to re-inline.
    ///
    /// The chained-receiver variants that survive by construction
    /// (`product_dir.join(&svc.path).to_string_lossy().to_string()`
    /// at `commands/product_release.rs:708` and
    /// `commands/rollback.rs:238`, `entry.file_name().to_string_lossy()
    /// .to_string()` at `commands/helm.rs:1841`,
    /// `e.path().to_string_lossy().to_string()` at
    /// `commands/helm.rs:2930`) are legitimately different in shape
    /// from the identifier-single form this lift consolidated: the
    /// receiver is an inline expression whose result type
    /// ([`std::ffi::OsString`], the returned [`std::path::PathBuf`] of
    /// [`Path::join`], etc.) differs from the caller-owned `PathBuf`
    /// / `&Path` binding the primitive takes. Those sites are
    /// out-of-scope for this lift; the identifier-keyed needles below
    /// leave them untouched.
    ///
    /// The one chained-receiver class explicitly closed by a
    /// follow-up lift is the `<tempfile-binding>.path()
    /// .to_string_lossy().to_string()` shape (seven sites across
    /// `commands/image_release.rs` ×5, `commands/helm.rs` ×1,
    /// `infrastructure/git.rs` ×1) — see the sibling
    /// [`path_to_string_lossy_tempfile_receiver_consumers_do_not_reinline_the_primitive_shape`]
    /// shield for the chained-receiver needles those consumers were
    /// lifted to escape.
    #[test]
    fn path_to_string_lossy_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source, needles) in [
            (
                "commands/product_release.rs",
                include_str!("commands/product_release.rs"),
                &[
                    "json_path.to_string_lossy().to_string()",
                    "product_dir.to_string_lossy().to_string()",
                ][..],
            ),
            (
                "commands/helm.rs",
                include_str!("commands/helm.rs"),
                &[
                    "repo_root.to_string_lossy().to_string()",
                    "lib_path.to_string_lossy().to_string()",
                    "dst_chart.to_string_lossy().to_string()",
                    "ci_values.to_string_lossy().into_owned()",
                ][..],
            ),
            (
                "commands/rust_service.rs",
                include_str!("commands/rust_service.rs"),
                &[
                    "full_manifest_path.to_string_lossy().to_string()",
                    "manifest_path.to_string_lossy().to_string()",
                ][..],
            ),
            (
                "commands/rollback.rs",
                include_str!("commands/rollback.rs"),
                &["json_path.to_string_lossy().to_string()"][..],
            ),
            (
                "commands/dashboards.rs",
                include_str!("commands/dashboards.rs"),
                &["path.to_string_lossy().to_string()"][..],
            ),
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
                &["manifest_path.to_string_lossy().into_owned()"][..],
            ),
            (
                "commands/federation_tests.rs",
                include_str!("commands/federation_tests.rs"),
                &["manifest_path.to_string_lossy().into_owned()"][..],
            ),
            (
                "commands/e2e.rs",
                include_str!("commands/e2e.rs"),
                &["output_path.to_string_lossy().into_owned()"][..],
            ),
        ] {
            for needle in needles {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` \
                     two-step projection — that duplication was \
                     lifted onto `crate::repo::path_to_string_lossy`. \
                     A re-inline would silently diverge the \
                     path-to-owned-string projection from the fifteen \
                     sibling consumers routing through the primitive, \
                     and re-fork the two pre-lift spellings \
                     (`.to_string()` and `.into_owned()`) into two \
                     hand-typed shapes that could drift from each \
                     other one consumer at a time."
                );
            }
        }
    }

    /// Post-lift the seven `<tempfile-binding>.path()
    /// .to_string_lossy().to_string()` chained-receiver consumer sites
    /// lifted onto [`path_to_string_lossy`] — a class the earlier
    /// identifier-keyed shield left open by construction because its
    /// needle-keying skipped chained receivers — must not silently
    /// re-inline the primitive's shape at their call points.
    ///
    /// The seven sites route through the primitive by handing it the
    /// tempfile binding's [`Path`] reference directly (`tmp.path()`,
    /// `dir.path()`) rather than binding an owned copy first. The
    /// shielded shape is therefore keyed by the concrete tempfile
    /// identifier every consumer bound: `tmp` at the five
    /// `commands/image_release.rs` test sites and the one
    /// `commands/helm.rs:1163` `helm pull -d` mirror-tempdir
    /// production site, and `dir` at the one
    /// `infrastructure/git.rs:675` `GitBinScope::set(&shim)` fixture
    /// tempdir test site.
    ///
    /// The chained-receiver form is legitimately a different shape
    /// from the identifier-single form the primary shield walks: the
    /// receiver is an inline `<TempFile>::path()` / `<TempDir>::path()`
    /// call whose `&Path` return is fed straight into the primitive
    /// without an intermediate binding. A re-inline would silently
    /// diverge the tempfile-path-to-owned-string projection from the
    /// primary-shield consumers routing through the same primitive,
    /// and re-fork the `.to_string()` tail one tempfile site at a
    /// time from the primitive's `.into_owned()` one-alloc
    /// discipline. Anchoring the needle to the `<ident>.path()` chain
    /// (rather than either `.path()` alone or the trailing
    /// `.to_string_lossy().to_string()` alone) keeps the shield from
    /// matching legitimately different chained-receiver shapes that
    /// use `.path()` on non-tempfile receivers (a
    /// [`std::fs::DirEntry`], say) or the trailing two-step over a
    /// receiver whose type is not `&Path`.
    #[test]
    fn path_to_string_lossy_tempfile_receiver_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source) in [
            (
                "commands/image_release.rs",
                include_str!("commands/image_release.rs"),
            ),
            ("commands/helm.rs", include_str!("commands/helm.rs")),
            (
                "infrastructure/git.rs",
                include_str!("infrastructure/git.rs"),
            ),
        ] {
            for needle in [
                "tmp.path().to_string_lossy().to_string()",
                "dir.path().to_string_lossy().to_string()",
            ] {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` \
                     chained-receiver two-step projection — that \
                     duplication was lifted onto \
                     `crate::repo::path_to_string_lossy(<tempfile>.path())`. \
                     A re-inline reopens the class this follow-up lift \
                     closed (the seven tempfile-receiver stragglers the \
                     primary identifier-keyed shield left open by \
                     construction) and re-forks the `.to_string()` tail \
                     from the primitive's `.into_owned()` one-alloc \
                     discipline."
                );
            }
        }
    }

    /// Post-lift the eleven chained-receiver
    /// `<pathbuf-expr>.to_string_lossy().to_string()` consumer sites
    /// across ten files (nine `commands/*.rs` + one
    /// `infrastructure/git.rs` test helper + one `nix_hooks.rs`
    /// production site) lifted onto [`path_to_string_lossy`] — a
    /// class the two earlier shields
    /// ([`path_to_string_lossy_consumers_do_not_reinline_the_primitive_shape`]
    /// keyed by identifiers, and
    /// [`path_to_string_lossy_tempfile_receiver_consumers_do_not_reinline_the_primitive_shape`]
    /// keyed by `<tempfile>.path()` chained receivers) left open by
    /// construction because their needle-keying skipped the
    /// non-tempfile chained-receiver shape — must not silently
    /// re-inline the primitive's shape at their call points.
    ///
    /// The eleven sites route through the primitive by handing it a
    /// reference to whatever `PathBuf`-shaped expression the pre-lift
    /// callsite chained `.to_string_lossy().to_string()` onto: a
    /// [`PathBuf::join`] product (`product_release.rs`,
    /// `rollback.rs`), an already-bound `PathBuf` local (`e2e.rs`'s
    /// `root`, `sync.rs`'s `path`, `tool.rs`'s `dest`, `infra.rs`'s
    /// `compose_file`, `bootstrap.rs`'s `repo_root`, `nix_hooks.rs`'s
    /// `hook_path`), a fallible [`Result<PathBuf>`] projection unwrapped
    /// inline (`e2e.rs`'s `crate::repo::current_dir()?`), a
    /// [`Cow<Path>`] from a `tar::Entry::path()` (`image_release.rs`),
    /// a [`std::fs::DirEntry::path`] inside a `.map(|e| ...)` closure
    /// (`helm.rs`'s `find_latest_tgz`), or a `&Path` parameter fed
    /// directly (`infrastructure/git.rs`'s
    /// `git_client_in_dir_path_git` test helper). Anchoring each
    /// needle to the concrete pre-lift *expression* (the identifier
    /// or method chain that immediately preceded
    /// `.to_string_lossy().to_string()`) keeps the shield from
    /// matching legitimately different chained-receiver shapes the
    /// primitive owns elsewhere in the crate.
    #[test]
    fn path_to_string_lossy_pathbuf_chained_receiver_consumers_do_not_reinline_the_primitive_shape()
    {
        for (name, source, needles) in [
            (
                "commands/product_release.rs",
                include_str!("commands/product_release.rs"),
                &["product_dir.join(&svc.path).to_string_lossy().to_string()"][..],
            ),
            (
                "commands/rollback.rs",
                include_str!("commands/rollback.rs"),
                &["product_dir.join(&entry.path).to_string_lossy().to_string()"][..],
            ),
            (
                "commands/e2e.rs",
                include_str!("commands/e2e.rs"),
                &[
                    "root.to_string_lossy().to_string()",
                    "crate::repo::current_dir()?.to_string_lossy().to_string()",
                ][..],
            ),
            (
                "commands/sync.rs",
                include_str!("commands/sync.rs"),
                &["path.to_string_lossy().to_string()"][..],
            ),
            (
                "commands/image_release.rs",
                include_str!("commands/image_release.rs"),
                &[
                    "Ok(p) => p.to_string_lossy().to_string()",
                    ".map(|p| p.to_string_lossy().to_string())",
                    "entry.path()?.to_string_lossy().to_string()",
                ][..],
            ),
            (
                "commands/tool.rs",
                include_str!("commands/tool.rs"),
                &["dest.to_string_lossy().to_string()"][..],
            ),
            (
                "commands/helm.rs",
                include_str!("commands/helm.rs"),
                &[".map(|e| e.path().to_string_lossy().to_string())"][..],
            ),
            (
                "commands/infra.rs",
                include_str!("commands/infra.rs"),
                &["compose_file.to_string_lossy().to_string()"][..],
            ),
            (
                "commands/bootstrap.rs",
                include_str!("commands/bootstrap.rs"),
                &["repo_root.to_string_lossy().to_string()"][..],
            ),
            (
                "infrastructure/git.rs",
                include_str!("infrastructure/git.rs"),
                &["dir.to_string_lossy().to_string()"][..],
            ),
            (
                "nix_hooks.rs",
                include_str!("nix_hooks.rs"),
                &["hook_path.to_string_lossy().to_string()"][..],
            ),
        ] {
            for needle in needles {
                assert!(
                    !source.contains(needle),
                    "{name} must NOT spell the inline `{needle}` \
                     chained-receiver two-step projection — that \
                     duplication was lifted onto \
                     `crate::repo::path_to_string_lossy(&<expr>)`. \
                     A re-inline reopens the class this follow-up \
                     lift closed (the eleven \
                     `PathBuf`-shaped chained-receiver stragglers the \
                     identifier-keyed and tempfile-`.path()`-keyed \
                     shields left open by construction) and re-forks \
                     the `.to_string()` tail one site at a time from \
                     the primitive's `.into_owned()` one-alloc \
                     discipline."
                );
            }
        }
    }

    /// [`path_to_string_lossy`] projects a caller-owned [`Path`]
    /// bytewise-equal to the pre-lift `.to_string_lossy().into_owned()`
    /// spelling on a UTF-8 input path — the exact spelling the four
    /// alternate-spelling consumers lifted in the current commit
    /// (`commands/migrations.rs`, `commands/federation_tests.rs`,
    /// `commands/e2e.rs`, `commands/helm.rs`'s `ci_values` site)
    /// carried. Pins the substitution to be a no-op at those sites,
    /// so a future refinement that tightened the primitive's
    /// projection cannot silently diverge from the pre-lift shape
    /// the four alternate-spelling consumers relied on.
    ///
    /// The peer test
    /// [`path_to_string_lossy_returns_owned_string_byte_identical_on_utf8_hit`]
    /// pins byte-identity against the input path literal; this test
    /// pins byte-identity against the second pre-lift *spelling* of
    /// the projection (`.into_owned()`), so a drift where the
    /// primitive body's tail changed one of the two arms of
    /// [`std::borrow::Cow::into_owned`] out from under the pre-lift
    /// `.into_owned()` sites — a hypothetical tail like
    /// `.to_string_lossy().to_string().trim().to_string()` — would
    /// fail here even though it would still pass the ASCII-literal
    /// pin.
    #[test]
    fn path_to_string_lossy_matches_pre_lift_into_owned_spelling_byte_for_byte() {
        for input in [
            "/tmp/forge/manifest.yaml",
            "/nix/store/deadbeef-hash/output-symlink",
            "./chart/ci/lint-values.yaml",
        ] {
            let path = std::path::Path::new(input);
            let via_primitive = path_to_string_lossy(path);
            let via_pre_lift_spelling: String = path.to_string_lossy().into_owned();
            assert_eq!(
                via_primitive, via_pre_lift_spelling,
                "path_to_string_lossy() must project byte-for-byte \
                 equal to the pre-lift `.to_string_lossy().into_owned()` \
                 spelling — the four alternate-spelling consumer sites \
                 lifted in this commit depend on the substitution \
                 being a no-op. Input: {input:?}"
            );
        }
    }

    /// [`utf8_lossy_trim_owned`] projects a byte slice through
    /// [`String::from_utf8_lossy`] + [`str::trim`] + [`ToString::to_string`]
    /// byte-for-byte identically to the pre-lift inline spelling every
    /// one of the eight consumer sites carried
    /// (`String::from_utf8_lossy(&<bytes>).trim().to_string()`). Pins
    /// the substitution to be a no-op across the four canonical
    /// shapes the pre-lift sites exercised:
    ///
    /// - ASCII stdout with a trailing newline (`kubectl -o jsonpath`,
    ///   `crane digest`) — the trim strips the newline, the payload
    ///   passes through byte-identical.
    /// - Empty stdout (`kubectl` returning no data) — projects to
    ///   [`String::new`], the same value every pre-lift
    ///   `<x>.is_empty()` short-circuit at
    ///   `commands/rust_service.rs:759` relied on.
    /// - Multi-line stderr with mixed leading and trailing whitespace
    ///   (`docker push` diagnostic) — leading and trailing whitespace
    ///   is stripped, internal newlines and spacing are preserved so
    ///   the operator sees the full diagnostic line-for-line.
    /// - A byte slice carrying invalid UTF-8 (a `0xFF` in the middle
    ///   of a stdout buffer, structurally what a rogue subprocess can
    ///   emit) — the invalid byte is replaced by `\u{FFFD}` via the
    ///   [`String::from_utf8_lossy`] repair every pre-lift consumer
    ///   relied on. A non-lossy [`str::from_utf8`] projection would
    ///   have [`Result::Err`]-ed here and swallowed the surrounding
    ///   diagnostic.
    ///
    /// A future refinement that tightened the primitive's projection
    /// out from under any one of the eight consumer sites — a
    /// [`std::borrow::Cow`]-returning variant, a
    /// [`str::trim_ascii`] specialization, a
    /// [`char::is_ascii_whitespace`] classifier — surfaces here as a
    /// byte-mismatch against the pre-lift spelling on the shape the
    /// refinement missed, before it reaches production.
    #[test]
    fn utf8_lossy_trim_owned_matches_pre_lift_spelling_byte_for_byte() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "ascii kubectl-jsonpath phase with trailing newline",
                b"Running\n",
                "Running",
            ),
            ("empty stdout", b"", ""),
            (
                "multi-line stderr with leading+trailing whitespace",
                b"\n  push failed: unauthorized\n  retry the login\n\n",
                "push failed: unauthorized\n  retry the login",
            ),
            (
                "invalid utf-8 byte in stdout buffer",
                b"sha256:abc\xffdef\n",
                "sha256:abc\u{FFFD}def",
            ),
        ];
        for (label, bytes, expected) in cases {
            let via_primitive = utf8_lossy_trim_owned(bytes);
            let via_pre_lift_spelling: String = String::from_utf8_lossy(bytes).trim().to_string();
            assert_eq!(
                via_primitive, via_pre_lift_spelling,
                "utf8_lossy_trim_owned() must project byte-for-byte \
                 equal to the pre-lift \
                 `String::from_utf8_lossy(&<bytes>).trim().to_string()` \
                 spelling — the eight lifted consumer sites depend on \
                 the substitution being a no-op. Case: {label}"
            );
            assert_eq!(
                via_primitive, *expected,
                "utf8_lossy_trim_owned() must produce the expected \
                 canonical payload on the four load-bearing shapes the \
                 pre-lift sites exercise. Case: {label}"
            );
        }
    }

    /// Post-lift the eight consumer sites routing through
    /// [`utf8_lossy_trim_owned`] must not silently re-inline the
    /// primitive's shape at their call points — a re-inline reopens
    /// the class this lift closed and forks one consumer at a time
    /// from its seven siblings.
    ///
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses the exact
    /// `String::from_utf8_lossy(&<bytes>).trim().to_string()`
    /// three-step projection, keyed by the concrete `.stdout` or
    /// `.stderr` receiver every consumer bound. The needles pair each
    /// consumer with the specific identifier it carried pre-lift
    /// (`output.stdout` at the three command sites and
    /// `infrastructure/attic.rs`; `out.stderr` / `out.stdout` at the
    /// three [`crate::retry`] sites; `output.stderr` at the
    /// [`crate::retry::CapturedFailure::from_output`] site).
    ///
    /// Other spellings of the same projection survive by construction:
    /// `String::from_utf8_lossy(&<x>).trim()` (no owned tail — returns
    /// `&str` for a `format!` interpolation, e.g.
    /// `commands/github_runner_ci.rs:838`) is a distinct
    /// zero-alloc-borrow projection and is not routed through this
    /// primitive; `String::from_utf8_lossy(&<x>).to_string()` (no
    /// trim — the `commands/migrations.rs`, `commands/seed.rs`,
    /// `services/migration_service.rs` sites) preserves trailing
    /// whitespace intentionally and is a different projection. This
    /// shield's needles pin the three-step
    /// `.from_utf8_lossy(_).trim().to_string()` shape only.
    ///
    /// The primitive body in `repo.rs` legitimately spells the
    /// three-step shape at its own body; this shield does NOT scan
    /// `repo.rs`, mirroring the sibling shield discipline.
    #[test]
    fn utf8_lossy_trim_owned_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source, needles) in [
            (
                "commands/product_release.rs",
                include_str!("commands/product_release.rs"),
                &["String::from_utf8_lossy(&output.stdout).trim().to_string()"][..],
            ),
            (
                "commands/rust_service.rs",
                include_str!("commands/rust_service.rs"),
                &["String::from_utf8_lossy(&output.stdout).trim().to_string()"][..],
            ),
            (
                "commands/github_runner_ci.rs",
                include_str!("commands/github_runner_ci.rs"),
                &["String::from_utf8_lossy(&output.stdout).trim().to_string()"][..],
            ),
            (
                "infrastructure/attic.rs",
                include_str!("infrastructure/attic.rs"),
                &["String::from_utf8_lossy(&output.stderr).trim().to_string()"][..],
            ),
            (
                "retry.rs",
                include_str!("retry.rs"),
                &[
                    "String::from_utf8_lossy(&output.stderr).trim().to_string()",
                    "String::from_utf8_lossy(&out.stderr).trim().to_string()",
                    "String::from_utf8_lossy(&out.stdout).trim().to_string()",
                ][..],
            ),
        ] {
            // Scan executable lines only — doc-comment (`///`) prose
            // that legitimately spells the three-step shape in prior-
            // commit historical narrative (`retry.rs`'s
            // [`CapturedFailure`] doc block naming the pre-lift
            // "verbatim two-line incantation", the
            // [`classify_capture_query_anyhow`] doc's example code
            // fence) is not executable and would spuriously trip the
            // shield. Filtering by leading-`///` (after trimming
            // ambient indentation) keeps the shield checking what it
            // was written to check: the primitive body of every
            // caller, not the prose above it.
            for needle in needles {
                for (line_no, line) in source.lines().enumerate() {
                    if line.trim_start().starts_with("///") {
                        continue;
                    }
                    assert!(
                        !line.contains(needle),
                        "{name}:{line_no} must NOT spell the inline \
                         `{needle}` three-step projection — that \
                         duplication was lifted onto \
                         `crate::repo::utf8_lossy_trim_owned`. A re-\
                         inline would silently diverge the Output-\
                         bytes-to-trimmed-owned-String projection from \
                         the eight sibling consumers routing through \
                         the primitive, and re-fork the shape into \
                         hand-typed literals that could drift from the \
                         primitive one consumer at a time (a helpful \
                         `Cow`-return / `trim_ascii` / \
                         `is_ascii_whitespace` refinement at the \
                         primitive would silently miss the re-inlined \
                         site). Offending line: {line}"
                    );
                }
            }
        }
    }

    /// [`utf8_lossy_owned`] projects a byte slice through
    /// [`String::from_utf8_lossy`] + [`ToString::to_string`]
    /// byte-for-byte identically to the pre-lift inline spelling every
    /// one of the eight consumer sites carried
    /// (`String::from_utf8_lossy(&<bytes>).to_string()`, WITHOUT the
    /// `.trim()` step the sibling [`utf8_lossy_trim_owned`] applies).
    /// Pins the substitution to be a no-op across the four canonical
    /// shapes the pre-lift sites exercised — and pins the load-bearing
    /// difference from the sibling by asserting the trailing whitespace
    /// SURVIVES the projection:
    ///
    /// - psql `stdout` with trailing newline (`commands/seed.rs:124`,
    ///   returned to the caller for downstream parsing that must see
    ///   the closing `\n`).
    /// - Multi-line `stderr` diagnostic (a migration-job log the
    ///   operator reads verbatim — `services/migration_service.rs:337`
    ///   — where blank continuation lines carry stack-frame context).
    /// - Empty stdout (`kubectl` returning no data —
    ///   `commands/migrations.rs:852`'s [`String::is_empty`] gate) —
    ///   projects to [`String::new`], the value the pre-lift shape
    ///   produced.
    /// - A byte slice carrying invalid UTF-8 (structurally what a
    ///   rogue subprocess can emit) — the invalid byte is replaced by
    ///   `\u{FFFD}` via the same [`String::from_utf8_lossy`] repair
    ///   the sibling primitive uses.
    ///
    /// The trailing-whitespace-survives assertion is the load-bearing
    /// contract: a future "helpful" cleanup that routed
    /// [`utf8_lossy_owned`] through [`utf8_lossy_trim_owned`] would
    /// silently strip the closing `\n` at every one of the eight
    /// consumer sites and surface here as an equality mismatch
    /// against the pre-lift spelling.
    #[test]
    fn utf8_lossy_owned_matches_pre_lift_spelling_byte_for_byte() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "psql stdout with trailing newline (must survive)",
                b"SELECT 1\n",
                "SELECT 1\n",
            ),
            ("empty stdout", b"", ""),
            (
                "multi-line stderr diagnostic (internal + trailing \
                 whitespace must survive)",
                b"\n  migration failed: constraint violated\n  at row 42\n\n",
                "\n  migration failed: constraint violated\n  at row 42\n\n",
            ),
            (
                "invalid utf-8 byte in stdout buffer",
                b"NOTICE: log line\xffwith byte\n",
                "NOTICE: log line\u{FFFD}with byte\n",
            ),
        ];
        for (label, bytes, expected) in cases {
            let via_primitive = utf8_lossy_owned(bytes);
            let via_pre_lift_spelling: String = String::from_utf8_lossy(bytes).to_string();
            assert_eq!(
                via_primitive, via_pre_lift_spelling,
                "utf8_lossy_owned() must project byte-for-byte equal to \
                 the pre-lift `String::from_utf8_lossy(&<bytes>).to_string()` \
                 spelling — the eight lifted consumer sites depend on the \
                 substitution being a no-op. Case: {label}"
            );
            assert_eq!(
                via_primitive, *expected,
                "utf8_lossy_owned() must produce the expected canonical \
                 payload on the four load-bearing shapes the pre-lift \
                 sites exercise. Case: {label}"
            );
        }
    }

    /// [`utf8_lossy_owned`] MUST NOT be lifted onto
    /// [`utf8_lossy_trim_owned`] — the two are distinct projections
    /// keyed by whether trailing whitespace is stripped or preserved,
    /// and the eight consumers here rely on the trailing whitespace
    /// SURVIVING. This body-slice source-scan pins the primitive to
    /// its own two-step `.from_utf8_lossy(_).to_string()` composition
    /// and refuses a "cleanup" that routed it through the trimming
    /// sibling.
    #[test]
    fn utf8_lossy_owned_body_does_not_trim_the_payload() {
        let with_trailing_newline = utf8_lossy_owned(b"payload\n");
        assert_eq!(
            with_trailing_newline, "payload\n",
            "utf8_lossy_owned() must preserve trailing whitespace \
             byte-for-byte — the load-bearing difference from the \
             sibling `utf8_lossy_trim_owned`. A lift onto the \
             trimming sibling would silently strip the closing `\\n` \
             at every one of the eight consumer sites (psql stdout, \
             cargo-test stdout+stderr concat, migration-job logs, \
             kubectl pod-logs tail) whose downstream parsing depends \
             on the newline structure."
        );
    }

    /// Post-lift the eight consumer sites routing through
    /// [`utf8_lossy_owned`] must not silently re-inline the primitive's
    /// shape at their call points — a re-inline reopens the class this
    /// lift closed and forks one consumer at a time from its seven
    /// siblings.
    ///
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses the exact
    /// `String::from_utf8_lossy(&<bytes>).to_string()`
    /// two-step projection, keyed by the concrete `.stdout` or
    /// `.stderr` receiver every consumer bound (`o.stdout` at the
    /// [`Option::map`] closure in `commands/migrations.rs:678`,
    /// `output.stdout` at the three other migration polling sites plus
    /// `commands/seed.rs` and `services/migration_service.rs`,
    /// `check.stdout` and `list_jobs.stdout` at the remaining migration
    /// sites, and `output.stdout` + `output.stderr` at the
    /// integration-tests concat site).
    ///
    /// Other spellings of the same-input, different-projection surface
    /// survive by construction: the trimming sibling
    /// `String::from_utf8_lossy(&<x>).trim().to_string()` is the
    /// distinct load-bearing projection lifted onto
    /// [`utf8_lossy_trim_owned`] and pinned by its own shield;
    /// `String::from_utf8_lossy(&<x>).into_owned()` (`retry.rs`) uses
    /// the one-alloc `Cow::into_owned` tail rather than the two-alloc
    /// `.to_string()` tail — a different projection this shield leaves
    /// untouched. `String::from_utf8_lossy(&<x>)` without either owned
    /// tail (a borrowed `Cow<str>` fed directly to `format!()`) is a
    /// distinct zero-alloc-borrow projection also untouched. This
    /// shield's needles pin the two-step `.from_utf8_lossy(_).to_string()`
    /// shape only.
    ///
    /// The primitive body in `repo.rs` legitimately spells the two-step
    /// shape at its own body; this shield does NOT scan `repo.rs`,
    /// mirroring the sibling shield discipline.
    #[test]
    fn utf8_lossy_owned_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source, needles) in [
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
                &[
                    "String::from_utf8_lossy(&o.stdout).to_string()",
                    "String::from_utf8_lossy(&output.stdout).to_string()",
                    "String::from_utf8_lossy(&check.stdout).to_string()",
                    "String::from_utf8_lossy(&list_jobs.stdout).to_string()",
                ][..],
            ),
            (
                "commands/seed.rs",
                include_str!("commands/seed.rs"),
                &["String::from_utf8_lossy(&output.stdout).to_string()"][..],
            ),
            (
                "commands/integration_tests.rs",
                include_str!("commands/integration_tests.rs"),
                &[
                    "String::from_utf8_lossy(&output.stdout).to_string()",
                    "String::from_utf8_lossy(&output.stderr).to_string()",
                ][..],
            ),
            (
                "services/migration_service.rs",
                include_str!("services/migration_service.rs"),
                &["String::from_utf8_lossy(&output.stdout).to_string()"][..],
            ),
        ] {
            for needle in needles {
                for (line_no, line) in source.lines().enumerate() {
                    if line.trim_start().starts_with("///") {
                        continue;
                    }
                    assert!(
                        !line.contains(needle),
                        "{name}:{line_no} must NOT spell the inline \
                         `{needle}` two-step projection — that \
                         duplication was lifted onto \
                         `crate::repo::utf8_lossy_owned`. A re-inline \
                         would silently diverge the Output-bytes-to-\
                         owned-String projection from the eight sibling \
                         consumers routing through the primitive, and \
                         re-fork the shape into hand-typed literals that \
                         could drift from the primitive one consumer at \
                         a time (a helpful `Cow`-return, an ANSI-strip \
                         refinement, or a metrics-hook counting the \
                         non-UTF-8 repair frequency at the primitive \
                         would silently miss the re-inlined site). \
                         Offending line: {line}"
                    );
                }
            }
        }
    }

    /// [`utf8_lossy_streams`] projects both streams of an
    /// [`std::process::Output`] through [`String::from_utf8_lossy`]
    /// byte-for-byte identically to the pre-lift inline spelling every
    /// one of the ten consumer sites carried
    /// (`String::from_utf8_lossy(&<x>.stderr)` + adjacent
    /// `String::from_utf8_lossy(&<x>.stdout)`). Pins the substitution
    /// to be a no-op across the four canonical shapes the pre-lift
    /// failure-branch dumps exercise:
    ///
    /// - Both streams non-empty ASCII with a trailing newline
    ///   (typical `bun run test` / `graphql-codegen` failure) — each
    ///   stream projects to the borrow-shape [`std::borrow::Cow`] the
    ///   pre-lift sites bound.
    /// - Empty stdout, populated stderr (typical `psql` failure —
    ///   `commands/seed.rs`) — the stdout borrow is `""` and the
    ///   diagnostic stderr survives byte-for-byte.
    /// - Populated stdout, empty stderr (typical `tsc` type-check
    ///   failure — `commands/frontend_validation.rs`) — the stderr
    ///   borrow is `""` and the diagnostic stdout survives.
    /// - A stream carrying invalid UTF-8 (a `0xFF` byte in captured
    ///   output, structurally what a rogue subprocess can emit) — the
    ///   invalid byte is replaced by `\u{FFFD}` via the same
    ///   [`String::from_utf8_lossy`] repair the sibling primitives use.
    #[test]
    fn utf8_lossy_streams_matches_pre_lift_spelling_byte_for_byte() {
        use std::os::unix::process::ExitStatusExt;
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "both streams populated ASCII with trailing newline",
                b"codegen: 3 files written\n",
                b"error: schema drift\n",
            ),
            (
                "empty stdout, populated stderr (psql failure)",
                b"",
                b"ERROR: relation does not exist\n",
            ),
            (
                "populated stdout, empty stderr (tsc failure)",
                b"src/foo.ts(12,3): error TS2322\n",
                b"",
            ),
            ("both streams empty", b"", b""),
            (
                "invalid utf-8 byte in stdout, ascii stderr",
                b"junk\xffbyte in payload\n",
                b"error diagnostic\n",
            ),
        ];
        for (label, stdout_bytes, stderr_bytes) in cases {
            let output = std::process::Output {
                status: std::process::ExitStatus::from_raw(1 << 8),
                stdout: stdout_bytes.to_vec(),
                stderr: stderr_bytes.to_vec(),
            };
            let (stdout, stderr) = utf8_lossy_streams(&output);
            let stdout_pre_lift = String::from_utf8_lossy(&output.stdout);
            let stderr_pre_lift = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                stdout, stdout_pre_lift,
                "utf8_lossy_streams()'s stdout half must project \
                 byte-for-byte equal to the pre-lift \
                 `String::from_utf8_lossy(&<x>.stdout)` spelling — the \
                 ten lifted consumer sites depend on the substitution \
                 being a no-op. Case: {label}"
            );
            assert_eq!(
                stderr, stderr_pre_lift,
                "utf8_lossy_streams()'s stderr half must project \
                 byte-for-byte equal to the pre-lift \
                 `String::from_utf8_lossy(&<x>.stderr)` spelling — the \
                 ten lifted consumer sites depend on the substitution \
                 being a no-op. Case: {label}"
            );
        }
    }

    /// [`utf8_lossy_streams`] MUST return `(stdout, stderr)` — the
    /// natural [`std::process::Output`] field order — and the two
    /// projections MUST map to the corresponding stream, not the
    /// opposite one. A stream-swap regression at the primitive would
    /// silently misroute every one of the ten consumer sites' error
    /// diagnostic (a `psql failed: stdout: <ERROR ...>` message with
    /// stderr's payload in the stdout slot, a `format!("{}\n{}",
    /// stderr, stdout)` concatenation with the two halves swapped).
    /// This shape test pins the ordering contract with distinguishable
    /// non-empty payloads on each stream.
    #[test]
    fn utf8_lossy_streams_returns_stdout_first_stderr_second() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"THIS-IS-STDOUT".to_vec(),
            stderr: b"THIS-IS-STDERR".to_vec(),
        };
        let (stdout, stderr) = utf8_lossy_streams(&output);
        assert_eq!(
            stdout, "THIS-IS-STDOUT",
            "utf8_lossy_streams() must return the stdout projection in \
             the first tuple slot — the ten consumer sites destructure \
             `let (stdout, stderr) = ...` and a stream-swap would \
             silently misroute every failure-branch diagnostic."
        );
        assert_eq!(
            stderr, "THIS-IS-STDERR",
            "utf8_lossy_streams() must return the stderr projection in \
             the second tuple slot — the ten consumer sites destructure \
             `let (stdout, stderr) = ...` and a stream-swap would \
             silently misroute every failure-branch diagnostic."
        );
    }

    /// Post-lift the ten consumer sites routing through
    /// [`utf8_lossy_streams`] must not silently re-inline the paired
    /// projection at their call points — a re-inline reopens the
    /// class this lift closed and forks one consumer at a time from
    /// its nine siblings.
    ///
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses ADJACENT `String::from_utf8_lossy(&<X>.stderr)` +
    /// `String::from_utf8_lossy(&<X>.stdout)` borrow projections on
    /// the SAME receiver identifier (in either order). Only the
    /// paired failure-branch spelling is pinned; single-stream borrow
    /// projections (a `stderr`-only diagnostic on a spawn error that
    /// never bound `stdout`, a `stdout`-only capture path that never
    /// bound `stderr`) are a distinct projection not routed through
    /// this primitive and survive by construction — the shield keys
    /// on the same-receiver adjacency, not the projection shape
    /// alone.
    ///
    /// The primitive body in `repo.rs` legitimately spells the two
    /// borrow projections at its own body; this shield does NOT scan
    /// `repo.rs`, mirroring the sibling shield discipline.
    #[test]
    fn utf8_lossy_streams_consumers_do_not_reinline_the_primitive_shape() {
        fn extract_receiver<'a>(line: &'a str, stream: &str) -> Option<&'a str> {
            let prefix = "String::from_utf8_lossy(&";
            let suffix = if stream == "stderr" {
                ".stderr)"
            } else {
                ".stdout)"
            };
            let start = line.find(prefix)? + prefix.len();
            let rest = line.get(start..)?;
            let end = rest.find(suffix)?;
            let ident = &rest[..end];
            // A receiver identifier is Rust-lexical only — no whitespace,
            // no punctuation. This guards against a needle appearing in
            // an unrelated context (a `format!` string, a comment).
            if ident.is_empty()
                || ident
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            {
                return None;
            }
            Some(ident)
        }
        for (name, source) in [
            ("commands/codegen.rs", include_str!("commands/codegen.rs")),
            (
                "commands/codegen_validation.rs",
                include_str!("commands/codegen_validation.rs"),
            ),
            (
                "commands/frontend_validation.rs",
                include_str!("commands/frontend_validation.rs"),
            ),
            (
                "commands/prerelease.rs",
                include_str!("commands/prerelease.rs"),
            ),
            ("commands/seed.rs", include_str!("commands/seed.rs")),
        ] {
            let lines: Vec<&str> = source.lines().collect();
            for i in 0..lines.len().saturating_sub(1) {
                let a = lines[i];
                let b = lines[i + 1];
                let a_trim = a.trim_start();
                let b_trim = b.trim_start();
                if a_trim.starts_with("///")
                    || a_trim.starts_with("//!")
                    || a_trim.starts_with("//")
                {
                    continue;
                }
                if b_trim.starts_with("///")
                    || b_trim.starts_with("//!")
                    || b_trim.starts_with("//")
                {
                    continue;
                }
                let a_stderr = extract_receiver(a, "stderr");
                let a_stdout = extract_receiver(a, "stdout");
                let b_stderr = extract_receiver(b, "stderr");
                let b_stdout = extract_receiver(b, "stdout");
                let paired_same_receiver =
                    (a_stderr.is_some() && b_stdout.is_some() && a_stderr == b_stdout)
                        || (a_stdout.is_some() && b_stderr.is_some() && a_stdout == b_stderr);
                assert!(
                    !paired_same_receiver,
                    "{name}:{}-{} must NOT spell adjacent \
                     `String::from_utf8_lossy(&<X>.stderr)` + \
                     `String::from_utf8_lossy(&<X>.stdout)` borrow \
                     projections on the same `<X>` receiver — that \
                     paired failure-branch duplication was lifted onto \
                     `crate::repo::utf8_lossy_streams`. A re-inline \
                     would silently diverge the Output-both-streams-to-\
                     borrowed-Cow projection from the ten sibling \
                     consumers routing through the primitive, and re-\
                     fork the shape into hand-typed literals that could \
                     drift one consumer at a time (a helpful ANSI-strip, \
                     `Cow::into_owned`, or `.trim()` refinement at the \
                     primitive would silently miss the re-inlined \
                     site). Offending pair:\n  {a}\n  {b}",
                    i + 1,
                    i + 2,
                );
            }
        }
    }

    /// [`utf8_lossy_streams_joined`] returns the joined
    /// `<stderr>\n<stdout>` corpus byte-for-byte identically to the
    /// pre-lift inline stanza every one of the four consumer sites
    /// carried:
    ///
    /// ```text
    /// let (stdout, stderr) = crate::repo::utf8_lossy_streams(&<output>);
    /// let <name> = format!("{}\n{}", stderr, stdout);
    /// ```
    ///
    /// Pins the substitution to be a no-op across the four canonical
    /// shapes the pre-lift failure-branch dumps exercise:
    ///
    /// - Both streams non-empty ASCII with a trailing newline (typical
    ///   `bun run test` / `graphql-codegen` failure) — the joined
    ///   corpus is `<stderr-with-trailing-newline>\n<stdout-with-\
    ///   trailing-newline>`, which the pre-lift `format!` produced
    ///   verbatim.
    /// - Empty stdout, populated stderr (typical `psql`-shaped failure)
    ///   — the joined corpus is `<stderr>\n` (stdout's empty projection
    ///   contributes nothing but the `\n` separator survives).
    /// - Populated stdout, empty stderr (typical `tsc` type-check
    ///   failure with all diagnostics on stdout) — the joined corpus
    ///   is `\n<stdout>` (stderr's empty projection leaves the
    ///   leading `\n` from the separator).
    /// - A stream carrying invalid UTF-8 (a `0xFF` byte in captured
    ///   output) — the invalid byte is replaced by `\u{FFFD}` via the
    ///   same [`String::from_utf8_lossy`] repair the sibling primitives
    ///   use.
    #[test]
    fn utf8_lossy_streams_joined_matches_pre_lift_spelling_byte_for_byte() {
        use std::os::unix::process::ExitStatusExt;
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "both streams populated ASCII with trailing newline",
                b"codegen: 3 files written\n",
                b"error: schema drift\n",
            ),
            (
                "empty stdout, populated stderr (psql failure)",
                b"",
                b"ERROR: relation does not exist\n",
            ),
            (
                "populated stdout, empty stderr (tsc failure)",
                b"src/foo.ts(12,3): error TS2322\n",
                b"",
            ),
            ("both streams empty", b"", b""),
            (
                "invalid utf-8 byte in stdout, ascii stderr",
                b"junk\xffbyte in payload\n",
                b"error diagnostic\n",
            ),
            (
                "invalid utf-8 byte in stderr, ascii stdout",
                b"stdout summary\n",
                b"error \xff diagnostic\n",
            ),
        ];
        for (label, stdout_bytes, stderr_bytes) in cases {
            let output = std::process::Output {
                status: std::process::ExitStatus::from_raw(1 << 8),
                stdout: stdout_bytes.to_vec(),
                stderr: stderr_bytes.to_vec(),
            };
            let via_primitive = utf8_lossy_streams_joined(&output);
            let stdout_pre_lift = String::from_utf8_lossy(&output.stdout);
            let stderr_pre_lift = String::from_utf8_lossy(&output.stderr);
            let via_pre_lift = format!("{}\n{}", stderr_pre_lift, stdout_pre_lift);
            assert_eq!(
                via_primitive, via_pre_lift,
                "utf8_lossy_streams_joined() must return the joined \
                 corpus byte-for-byte equal to the pre-lift \
                 `format!(\"{{}}\\n{{}}\", stderr, stdout)` spelling — \
                 the four lifted consumer sites depend on the \
                 substitution being a no-op. Case: {label}"
            );
        }
    }

    /// [`utf8_lossy_streams_joined`] MUST place `stderr` FIRST and
    /// `stdout` SECOND in the joined corpus — operator-facing
    /// diagnostic tools (ESLint, TypeScript, biome, vitest,
    /// graphql-codegen) route human-readable error prose to stderr
    /// and machine-parseable summary counts to stdout; a stderr-\
    /// second regression at the primitive would silently misroute
    /// every one of the four consumer sites' `.contains(...)` /
    /// `.matches(...)` / `.lines().take(N)` grep by putting the
    /// summary-count noise ahead of the actionable error prose. This
    /// shape test pins the ordering contract with distinguishable
    /// non-empty payloads on each stream.
    #[test]
    fn utf8_lossy_streams_joined_places_stderr_first_stdout_second() {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"THIS-IS-STDOUT".to_vec(),
            stderr: b"THIS-IS-STDERR".to_vec(),
        };
        let joined = utf8_lossy_streams_joined(&output);
        assert_eq!(
            joined, "THIS-IS-STDERR\nTHIS-IS-STDOUT",
            "utf8_lossy_streams_joined() must render \
             `<stderr>\\n<stdout>` — the four consumer sites' \
             `.contains(...)` / `.matches(...)` / `.lines().take(N)` \
             grep against the joined corpus depends on the \
             human-readable error prose (stderr) appearing FIRST so \
             the first N lines of a truncated display carry the most \
             actionable signal. A stream-swap regression would \
             silently surface the summary-count noise (stdout) \
             ahead of the error prose."
        );
    }

    /// Post-lift the four consumer sites routing through
    /// [`utf8_lossy_streams_joined`] must not silently re-inline the
    /// two-line stanza at their call points — a re-inline reopens the
    /// class this lift closed and forks one consumer at a time from
    /// its three siblings.
    ///
    /// This source-scan shield walks every hand-lifted consumer file
    /// and refuses the pre-lift ADJACENT two-line stanza
    /// (`let (stdout, stderr) = crate::repo::utf8_lossy_streams(&<X>);`
    /// followed by `let <name> = format!("{}\n{}", stderr, stdout);`)
    /// on the same-receiver identifier. The primitive body in
    /// `repo.rs` legitimately spells the two-line composition inside
    /// its own body; this shield does NOT scan `repo.rs`, mirroring
    /// the sibling [`utf8_lossy_streams`] shield discipline. Two
    /// related sites (`commands/codegen.rs` and `commands/seed.rs`)
    /// fuse the paired projection into an inline `anyhow::bail!`
    /// message and are OUT OF SCOPE (see the primitive's docstring)
    /// — they are also skipped by this shield.
    ///
    /// A consumer that needs BOTH the tuple AND the joined corpus
    /// (the `run_type_check` site in
    /// `commands/frontend_validation.rs`, which counts `error TS`
    /// on each stream independently before joining) keeps the tuple
    /// call spelled inline and does not match the two-line stanza
    /// this shield refuses — the shield keys on the ADJACENT two
    /// lines, not the tuple call in isolation.
    #[test]
    fn utf8_lossy_streams_joined_consumers_do_not_reinline_the_primitive_shape() {
        fn extract_streams_receiver(line: &str) -> Option<&str> {
            let prefix = "= crate::repo::utf8_lossy_streams(&";
            let start = line.find(prefix)? + prefix.len();
            let rest = line.get(start..)?;
            let end = rest.find(')')?;
            let ident = &rest[..end];
            if ident.is_empty()
                || ident
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            {
                return None;
            }
            Some(ident)
        }
        fn line_binds_stderr_stdout_format(line: &str) -> bool {
            // Matches `let <name> = format!("{}\n{}", stderr, stdout);`
            // — the pre-lift stanza's second half. Note the exact
            // `stderr, stdout` argument order the primitive enforces.
            let trimmed = line.trim_start();
            trimmed.starts_with("let ")
                && trimmed.contains("= format!(\"{}\\n{}\", stderr, stdout)")
        }
        for (name, source) in [
            (
                "commands/codegen_validation.rs",
                include_str!("commands/codegen_validation.rs"),
            ),
            (
                "commands/frontend_validation.rs",
                include_str!("commands/frontend_validation.rs"),
            ),
        ] {
            let lines: Vec<&str> = source.lines().collect();
            for i in 0..lines.len().saturating_sub(1) {
                let a = lines[i];
                let b = lines[i + 1];
                let a_trim = a.trim_start();
                let b_trim = b.trim_start();
                if a_trim.starts_with("///")
                    || a_trim.starts_with("//!")
                    || a_trim.starts_with("//")
                {
                    continue;
                }
                if b_trim.starts_with("///")
                    || b_trim.starts_with("//!")
                    || b_trim.starts_with("//")
                {
                    continue;
                }
                let paired_stanza =
                    extract_streams_receiver(a).is_some() && line_binds_stderr_stdout_format(b);
                assert!(
                    !paired_stanza,
                    "{name}:{}-{} must NOT spell the pre-lift adjacent \
                     `let (stdout, stderr) = crate::repo::\
                     utf8_lossy_streams(&<X>);` + `let <name> = \
                     format!(\"{{}}\\n{{}}\", stderr, stdout);` \
                     two-line stanza — that stderr-first joined-corpus \
                     duplication was lifted onto \
                     `crate::repo::utf8_lossy_streams_joined`. A \
                     re-inline would silently diverge the joined-corpus \
                     shape from the four sibling consumers routing \
                     through the primitive, and re-fork the shape into \
                     hand-typed literals that could drift one consumer \
                     at a time (a helpful ANSI-strip, a stderr-second \
                     regression, or a metrics-hook counting the joined \
                     corpus's post-repair length at the primitive would \
                     silently miss the re-inlined site). Offending \
                     pair:\n  {a}\n  {b}",
                    i + 1,
                    i + 2,
                );
            }
        }
    }

    /// [`utf8_lossy_borrow`] projects a byte slice through
    /// [`String::from_utf8_lossy`] byte-for-byte identically to the
    /// pre-lift inline spelling every one of the forty-plus consumer
    /// sites carried (`let <name> = String::from_utf8_lossy(&<X>.stream);`).
    /// Pins the substitution to be a no-op across the four canonical
    /// shapes the pre-lift borrow-projections exercise:
    ///
    /// - Empty input — projects to the empty [`std::borrow::Cow::Borrowed`]
    ///   `""` the `<x>.stream.is_empty()` short-circuits relied on.
    /// - Valid ASCII with a trailing newline (typical `kubectl` /
    ///   `helm` / `cargo` stdout capture) — projects to a
    ///   [`std::borrow::Cow::Borrowed`] pointing at the source bytes
    ///   without allocating.
    /// - Valid multi-byte UTF-8 (a subprocess emitting `→` /
    ///   `✅` in a diagnostic) — projects to a [`std::borrow::Cow::Borrowed`]
    ///   containing the same code points.
    /// - Invalid UTF-8 (a rogue `0xFF` byte in captured output) — projects
    ///   to a [`std::borrow::Cow::Owned`] with the invalid byte replaced
    ///   by `\u{FFFD}` via the same [`String::from_utf8_lossy`] repair
    ///   the sibling primitives use.
    #[test]
    fn utf8_lossy_borrow_matches_pre_lift_spelling_byte_for_byte() {
        let cases: &[(&str, &[u8])] = &[
            ("empty input", b""),
            (
                "ascii with trailing newline (kubectl stdout)",
                b"pod-abc123   Running   0   3m\n",
            ),
            (
                "multi-byte utf-8 (diagnostic with unicode arrows)",
                "→ 3 files updated ✅\n".as_bytes(),
            ),
            (
                "invalid utf-8 byte in payload (rogue subprocess)",
                b"partial\xff\xfeoutput\n",
            ),
        ];
        for (label, bytes) in cases {
            let via_primitive = utf8_lossy_borrow(bytes);
            let via_pre_lift_spelling = String::from_utf8_lossy(bytes);
            assert_eq!(
                via_primitive, via_pre_lift_spelling,
                "utf8_lossy_borrow() must project byte-for-byte \
                 identically to the pre-lift inline \
                 `String::from_utf8_lossy(&<bytes>)` spelling — the \
                 shape every one of the forty-plus consumer sites \
                 across `commands/*.rs` carried. Case `{label}` \
                 diverged: primitive={via_primitive:?}, \
                 pre-lift={via_pre_lift_spelling:?}"
            );
        }
    }

    /// [`utf8_lossy_borrow`] must NOT allocate on the fully-valid-UTF-8
    /// path — the whole point of the borrow-shape return is that a
    /// caller who binds `let s = utf8_lossy_borrow(&<x>.stream)` and
    /// consumes `s` via a [`str::contains`] / [`str::lines`] /
    /// `format!` interpolation pays zero allocations, whereas the
    /// sibling [`utf8_lossy_owned`] always materializes an owned
    /// [`String`]. A future primitive body that silently applied a
    /// `.to_string()` tail (a "convenient" refactor onto the owned
    /// sibling) would silently reintroduce a per-site allocation at
    /// every one of the forty-plus consumer sites. This shield pins
    /// the borrow discipline at the primitive's own body by asserting
    /// the returned [`std::borrow::Cow`] discriminant is `Borrowed`
    /// on the valid-UTF-8 branch and `Owned` on the invalid-UTF-8
    /// branch — the exact discriminant behavior [`String::from_utf8_lossy`]
    /// itself specifies.
    #[test]
    fn utf8_lossy_borrow_returns_borrowed_on_valid_utf8_owned_on_invalid() {
        let valid = utf8_lossy_borrow(b"pod-abc123   Running   0   3m\n");
        assert!(
            matches!(valid, std::borrow::Cow::Borrowed(_)),
            "utf8_lossy_borrow() must return `Cow::Borrowed` on \
             fully-valid UTF-8 input — the zero-allocation guarantee \
             that separates this primitive from the sibling \
             `utf8_lossy_owned`. A `.to_string()` tail at the primitive \
             body would silently reintroduce a per-site allocation at \
             every consumer routing through it."
        );
        let empty = utf8_lossy_borrow(b"");
        assert!(
            matches!(empty, std::borrow::Cow::Borrowed(_)),
            "utf8_lossy_borrow() must return `Cow::Borrowed` on empty \
             input — the exact shape every `<x>.stream.is_empty()` \
             short-circuit relied on."
        );
        let invalid = utf8_lossy_borrow(b"partial\xffoutput");
        assert!(
            matches!(invalid, std::borrow::Cow::Owned(_)),
            "utf8_lossy_borrow() must return `Cow::Owned` when the \
             input carries invalid UTF-8 — the repair path where \
             `\\u{{FFFD}}` replacements are stamped into a fresh \
             buffer. A pre-lift consumer that bound the projection \
             into a `let` and expected `.contains(\"\\u{{FFFD}}\")` \
             to succeed relies on this branch."
        );
    }

    /// Post-lift the nine hand-lifted consumer files routing through
    /// [`utf8_lossy_borrow`] must not silently re-inline the
    /// bare-borrow projection at their call points — a re-inline
    /// reopens the class this lift closed and forks one consumer at a
    /// time from its siblings.
    ///
    /// This source-scan shield walks each lifted file and refuses the
    /// specific pre-lift needles: any `String::from_utf8_lossy(&<X>.stream)`
    /// borrow projection where the following character is neither
    /// `.` (a further method call — a distinct projection like
    /// `.trim().to_string()` [→ `utf8_lossy_trim_owned`] or
    /// `.to_string()` [→ `utf8_lossy_owned`] or `.into_owned()`) nor
    /// a closing token of a paired dump (which [`utf8_lossy_streams`]
    /// owns). The shield keys on the exact needle each file's lifted
    /// site carried pre-lift; other spellings survive by construction.
    ///
    /// The primitive body in `repo.rs` legitimately spells the shape
    /// at its own body; this shield does NOT scan `repo.rs`, mirroring
    /// the sibling shield discipline.
    #[test]
    fn utf8_lossy_borrow_consumers_do_not_reinline_the_primitive_shape() {
        for (name, source, needles) in [
            (
                "commands/prerelease.rs",
                include_str!("commands/prerelease.rs"),
                &[
                    "let stderr = String::from_utf8_lossy(&output.stderr);",
                    "let stderr = String::from_utf8_lossy(&fix_output.stderr);",
                    "let stdout = String::from_utf8_lossy(&check_output.stdout);",
                    "let stdout = String::from_utf8_lossy(&output.stdout);",
                ][..],
            ),
            (
                "commands/federation_tests.rs",
                include_str!("commands/federation_tests.rs"),
                &[
                    "let logs = String::from_utf8_lossy(&output.stdout);",
                    "let stderr = String::from_utf8_lossy(&output.stderr);",
                    "let status = String::from_utf8_lossy(&output.stdout);",
                    "let succeeded = String::from_utf8_lossy(&output.stdout);",
                ][..],
            ),
            (
                "commands/migrations.rs",
                include_str!("commands/migrations.rs"),
                &[
                    "let names = String::from_utf8_lossy(&output.stdout);",
                    "let stderr = String::from_utf8_lossy(&patch_result.stderr);",
                    "let output = String::from_utf8_lossy(&cleanup_pods.stdout);",
                    "let stderr = String::from_utf8_lossy(&o.stderr);",
                ][..],
            ),
            (
                "commands/nix_builder.rs",
                include_str!("commands/nix_builder.rs"),
                &[
                    "let output = String::from_utf8_lossy(&nix_build.stdout);",
                    "let stderr = String::from_utf8_lossy(&nc_check.stderr);",
                    "let ip = String::from_utf8_lossy(&dig_output.stdout);",
                ][..],
            ),
            (
                "commands/e2e.rs",
                include_str!("commands/e2e.rs"),
                &[
                    "let stdout = String::from_utf8_lossy(&output.stdout);",
                    "let ryuk_stdout = String::from_utf8_lossy(&ryuk_output.stdout);",
                ][..],
            ),
            (
                "commands/supergraph_verification.rs",
                include_str!("commands/supergraph_verification.rs"),
                &[
                    "let version = String::from_utf8_lossy(&output.stdout);",
                    "let health_response = String::from_utf8_lossy(&output.stdout);",
                    "let actual_hash = String::from_utf8_lossy(&output.stdout);",
                    "let text = String::from_utf8_lossy(content);",
                ][..],
            ),
            (
                "commands/codegen_validation.rs",
                include_str!("commands/codegen_validation.rs"),
                &[
                    "let stderr = String::from_utf8_lossy(&install_output.stderr);",
                    "let stderr = String::from_utf8_lossy(&status_output.stderr);",
                    "let changes = String::from_utf8_lossy(&status_output.stdout);",
                    "let stderr = String::from_utf8_lossy(&add_output.stderr);",
                ][..],
            ),
            (
                "commands/rust_service.rs",
                include_str!("commands/rust_service.rs"),
                &[
                    "let config = String::from_utf8_lossy(&output.stdout);",
                    "let stderr = String::from_utf8_lossy(&output.stderr);",
                    "let phase = String::from_utf8_lossy(&status_output.stdout);",
                    "let image = String::from_utf8_lossy(&image_output.stdout);",
                ][..],
            ),
            (
                "commands/frontend_validation.rs",
                include_str!("commands/frontend_validation.rs"),
                &[
                    "let stderr = String::from_utf8_lossy(&fix_output.stderr);",
                    "let stderr = String::from_utf8_lossy(&install.stderr);",
                ][..],
            ),
            (
                "commands/federation.rs",
                include_str!("commands/federation.rs"),
                &["let stderr = String::from_utf8_lossy(&output.stderr);"][..],
            ),
            (
                "commands/status.rs",
                include_str!("commands/status.rs"),
                &["let stderr = String::from_utf8_lossy(&output.stderr);"][..],
            ),
            (
                "commands/dashboards.rs",
                include_str!("commands/dashboards.rs"),
                &["let stdout = String::from_utf8_lossy(&output.stdout);"][..],
            ),
            (
                "commands/flux.rs",
                include_str!("commands/flux.rs"),
                &["let stdout = String::from_utf8_lossy(&output.stdout);"][..],
            ),
            (
                "commands/github_runner_ci.rs",
                include_str!("commands/github_runner_ci.rs"),
                &[
                    "let pod_json = String::from_utf8_lossy(&output.stdout);",
                    "let logs = String::from_utf8_lossy(&log_output.stdout);",
                ][..],
            ),
            (
                "commands/comprehensive_release.rs",
                include_str!("commands/comprehensive_release.rs"),
                &[
                    "let load_output = String::from_utf8_lossy(&load_result.stdout);",
                    "let ps_output = String::from_utf8_lossy(&ps_result.stdout);",
                ][..],
            ),
            (
                "commands/codegen_validation.rs",
                include_str!("commands/codegen_validation.rs"),
                &["let schema = String::from_utf8_lossy(&schema_bytes);"][..],
            ),
            (
                "commands/helm.rs",
                include_str!("commands/helm.rs"),
                &[
                    "let stderr = String::from_utf8_lossy(stderr);",
                    "let stdout = String::from_utf8_lossy(stdout);",
                ][..],
            ),
            (
                "commands/schema_validation.rs",
                include_str!("commands/schema_validation.rs"),
                &["let schema_text = String::from_utf8_lossy(schema_bytes);"][..],
            ),
            (
                "flux_get.rs",
                include_str!("flux_get.rs"),
                &["let stdout = String::from_utf8_lossy(&output.stdout);"][..],
            ),
            (
                "services/migration_service.rs",
                include_str!("services/migration_service.rs"),
                &[
                    "let status = String::from_utf8_lossy(&output.stdout);",
                    "let failed = String::from_utf8_lossy(&output.stdout);",
                ][..],
            ),
            (
                "git.rs",
                include_str!("git.rs"),
                &[
                    "let s = String::from_utf8_lossy(&stdout);",
                    "let listing = String::from_utf8_lossy(&stdout);",
                    "let files = String::from_utf8_lossy(&files_out.stdout);",
                ][..],
            ),
            (
                "retry.rs",
                include_str!("retry.rs"),
                &[
                    "let stderr = String::from_utf8_lossy(&output.stderr);",
                    "let stdout = String::from_utf8_lossy(&out.stdout);",
                    "let stderr = String::from_utf8_lossy(&out.stderr);",
                ][..],
            ),
        ] {
            for needle in needles {
                for (line_no, line) in source.lines().enumerate() {
                    if line.trim_start().starts_with("///")
                        || line.trim_start().starts_with("//!")
                        || line.trim_start().starts_with("//")
                    {
                        continue;
                    }
                    assert!(
                        !line.contains(needle),
                        "{name}:{} must NOT spell the inline \
                         `{needle}` bare-borrow projection — that \
                         duplication was lifted onto \
                         `crate::repo::utf8_lossy_borrow`. A re-inline \
                         would silently diverge the captured-bytes-to-\
                         borrowed-Cow projection from its siblings \
                         routing through the primitive, and re-fork the \
                         shape into hand-typed literals that could drift \
                         one consumer at a time (a helpful ANSI-strip, \
                         `.trim()`, or metrics-hook counting the \
                         non-UTF-8 repair frequency at the primitive \
                         would silently miss the re-inlined site). \
                         Offending line: {line}",
                        line_no + 1,
                    );
                }
            }
        }
    }

    /// [`utf8_lossy_borrow`] does NOT trim its payload — leading and
    /// trailing whitespace survives byte-for-byte because consumers
    /// that need trimming spell `.trim()` explicitly at the call site,
    /// and consumers that DON'T trim (a `stdout` walked line-by-line,
    /// a `stderr` re-emitted to the operator verbatim) rely on the
    /// preserved bytes. A future primitive body that silently applied
    /// a `.trim()` tail would silently drift the projection from the
    /// callers who never asked for it — the same discipline
    /// [`utf8_lossy_owned`]'s own shield enforces against the sibling
    /// [`utf8_lossy_trim_owned`].
    #[test]
    fn utf8_lossy_borrow_body_does_not_trim_the_payload() {
        let with_trailing_newline = utf8_lossy_borrow(b"payload\n");
        assert_eq!(
            with_trailing_newline, "payload\n",
            "utf8_lossy_borrow() must preserve trailing whitespace \
             byte-for-byte — trimming is a distinct projection at the \
             sibling `utf8_lossy_trim_owned`, and a silent trim tail \
             here would drop the newline forty-plus consumers walk \
             lines against."
        );
        let with_leading_whitespace = utf8_lossy_borrow(b"  indent\n");
        assert_eq!(
            with_leading_whitespace, "  indent\n",
            "utf8_lossy_borrow() must preserve leading whitespace \
             byte-for-byte — a `stderr` re-emitted verbatim relies \
             on the indent structure."
        );
    }

    /// [`now_rfc3339_utc`] must project the current wall-clock time via
    /// the same `chrono::Utc::now().to_rfc3339()` grammar every one of
    /// the five pre-lift consumer sites carried inline. Byte-for-byte
    /// equivalence is not testable directly (two calls on either side
    /// straddle a clock tick, so their sub-second precision drifts), so
    /// this test pins the SHAPE that grammar produces: an RFC-3339
    /// date-time with a `T` separator, a UTC offset suffix, and a
    /// digit-run at least covering the `YYYY-MM-DDTHH:MM:SS` prefix.
    /// A future primitive body that respells the projection as
    /// `chrono::Local::now().to_rfc3339()` (a one-token drift that
    /// still compiles and returns an RFC-3339 string, but with a
    /// non-`+00:00` offset the downstream JSON consumers silently
    /// mis-interpret as UTC) fails the offset-suffix assertion. A
    /// respell to `.to_string()` (which renders `2026-09-02 15:30:00
    /// UTC` — space separator, `UTC` suffix rather than `+00:00`)
    /// fails the `T` separator assertion.
    #[test]
    fn now_rfc3339_utc_projects_the_pre_lift_utc_rfc3339_grammar() {
        let stamp = now_rfc3339_utc();

        // T-separator: `YYYY-MM-DDTHH:MM:SS...` — `chrono::to_string()`
        // renders a space separator, `chrono::to_rfc3339()` renders `T`.
        // Pin the RFC-3339 spelling here so a `.to_string()` respell
        // fails loud.
        assert!(
            stamp.as_bytes().get(10) == Some(&b'T'),
            "now_rfc3339_utc() must place `T` at byte index 10 (the \
             `YYYY-MM-DD` / `HH:MM:SS...` separator RFC-3339 mandates) \
             — a `chrono::to_string()` respell renders a space \
             separator that downstream JSON consumers parsing per \
             RFC-3339 refuse. Got: {stamp}"
        );

        // UTC offset suffix: `+00:00`. Chrono's `Utc::now().to_rfc3339()`
        // renders the offset verbatim as `+00:00` (never `Z`), so a
        // silent `chrono::Local::now()` respell — which emits the
        // machine's local offset (`-04:00`, `+02:00`, ...) — fails this
        // assertion, catching the drift at the primitive body.
        assert!(
            stamp.ends_with("+00:00"),
            "now_rfc3339_utc() must end with the UTC offset suffix \
             `+00:00` — a `chrono::Local::now()` respell emits the \
             machine's local offset instead, silently mis-representing \
             the timestamp to every downstream JSON consumer. Got: \
             {stamp}"
        );

        // YYYY-MM-DDTHH:MM:SS prefix — 19 bytes, digits at fixed
        // positions with `-` / `T` / `:` at the RFC-3339-mandated slots.
        // A drifting body that returned `Utc::now().timestamp().
        // to_string()` (an epoch-seconds integer) would fail this
        // structural check even though the string LOOKS numeric.
        assert!(
            stamp.len() >= 25,
            "now_rfc3339_utc() must return an RFC-3339 date-time at \
             least `YYYY-MM-DDTHH:MM:SS+00:00` long (25 bytes). A \
             respell to `.timestamp().to_string()` would return a \
             bare epoch-seconds integer that fails this shape. Got: \
             {stamp} (len={})",
            stamp.len()
        );
        let prefix = &stamp[..19];
        for (i, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
            assert_eq!(
                prefix.as_bytes()[i],
                expected,
                "now_rfc3339_utc() must place `{}` at prefix byte {} \
                 (RFC-3339 date-time layout). Got: {stamp}",
                expected as char,
                i
            );
        }
    }

    /// [`now_rfc3339_utc`] must project the SAME timestamp shape as the
    /// pre-lift `chrono::Utc::now().to_rfc3339()` one-liner. Byte-for-
    /// byte equality is unreachable across a clock tick, but a tight
    /// wall-clock window between two back-to-back calls lets us pin
    /// that the primitive's output PARSES back to the same
    /// `DateTime<FixedOffset>` domain the pre-lift spelling did, and
    /// resolves to a UTC offset (`+00:00`) — the strongest oracle
    /// available without freezing the clock.
    #[test]
    fn now_rfc3339_utc_parses_back_to_the_pre_lift_utc_datetime_domain() {
        let via_primitive = now_rfc3339_utc();
        let via_pre_lift_spelling = chrono::Utc::now().to_rfc3339();

        // Both project as parseable RFC-3339 date-times. If the
        // primitive body drifted onto `.to_string()` (space separator,
        // `UTC` suffix) or `.format(<other-strftime-spec>)`, chrono's
        // own RFC-3339 parser refuses the output and this assertion
        // fires.
        let parsed_primitive = chrono::DateTime::parse_from_rfc3339(&via_primitive).expect(
            "now_rfc3339_utc() must return a string chrono's own \
                 RFC-3339 parser accepts — the same round-trip \
                 discipline every pre-lift consumer's downstream JSON \
                 consumer applies.",
        );
        let parsed_pre_lift = chrono::DateTime::parse_from_rfc3339(&via_pre_lift_spelling)
            .expect("pre-lift `Utc::now().to_rfc3339()` must round-trip");

        // Both parse to a `FixedOffset::east(0)` — the UTC zero-offset.
        // A drifted primitive body that quietly returned
        // `Local::now().to_rfc3339()` would parse successfully but
        // land at the machine's local offset (`-04:00` on us-east,
        // `+02:00` on eu-central, ...), catching the timezone drift
        // that the SHAPE-only check above cannot see when the runner
        // happens to be in a `+00:00` locale (a CI container with
        // `TZ=UTC` set — where a `Local` and `Utc` respell would
        // render identically). Compare offsets, not instants
        // (the two calls straddle a clock tick).
        assert_eq!(
            parsed_primitive.offset(),
            &chrono::FixedOffset::east_opt(0).unwrap(),
            "now_rfc3339_utc() must resolve to UTC (`+00:00`) — a \
             `chrono::Local::now()` respell drifts to the machine's \
             local offset and silently mis-represents the timestamp. \
             Got offset: {}",
            parsed_primitive.offset()
        );
        assert_eq!(
            parsed_pre_lift.offset(),
            parsed_primitive.offset(),
            "primitive and pre-lift spelling must agree on the UTC \
             offset — a divergence here means the primitive body drifted \
             from the pre-lift consumer contract."
        );
    }

    /// Post-lift the five hand-lifted consumer files routing through
    /// [`now_rfc3339_utc`] must not silently re-inline the pre-lift
    /// `chrono::Utc::now().to_rfc3339()` (or its post-`use` shorthand
    /// `Utc::now().to_rfc3339()`) one-liner. Every consumer that emits
    /// a UTC RFC-3339 timestamp for a machine-parseable JSON record
    /// (artifact tag record, dashboard metadata, supergraph composition
    /// manifest, `ReleaseEvent` envelope) routes through this
    /// primitive, so a re-inline is a lift-regression by construction.
    ///
    /// The shield walks each of the five lifted files and refuses
    /// any occurrence of the pre-lift spellings — locking in the lift
    /// with the same discipline the sibling `utf8_lossy_borrow` /
    /// `utf8_lossy_streams_joined` shields enforce.
    ///
    /// The `observability.rs` file uses the post-`use chrono::Utc;`
    /// spelling `Utc::now().to_rfc3339()` pre-lift, so the shield
    /// probes for both spellings on every file.
    ///
    /// Files not in the fleet map are ALLOWED to spell either form —
    /// a hypothetical future single-site consumer that needs a
    /// non-`.to_rfc3339()` variant (a `.to_rfc3339_opts(SecondsFormat::
    /// Secs, true)` for a JWT `iat` claim; `commands/tool.rs:471`
    /// carries this shape today) chooses its own projection; the shield
    /// governs only the five sibling call sites this lift closes.
    #[test]
    fn now_rfc3339_utc_consumers_do_not_reinline_the_primitive_shape() {
        let fleet: &[&str] = &[
            "src/commands/rollback.rs",
            "src/commands/dashboards.rs",
            "src/commands/product_release.rs",
            "src/commands/supergraph_verification.rs",
            "src/observability.rs",
        ];
        for path in fleet {
            let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!(
                    "shield must read `{path}` to walk it for re-inlines — \
                     the five-file fleet map was frozen at the lift boundary. \
                     Read error: {e}"
                )
            });
            assert!(
                !content.contains("chrono::Utc::now().to_rfc3339()"),
                "shield refuses re-inline: `{path}` contains the \
                 pre-lift `chrono::Utc::now().to_rfc3339()` one-liner \
                 the lift replaced with a `crate::repo::now_rfc3339_utc()` \
                 call. A silent re-inline would silently reopen the \
                 timezone-drift path (a hand-swap to `Local::now()`) at \
                 exactly this site — route the value through the \
                 primitive instead."
            );
            assert!(
                !content.contains("Utc::now().to_rfc3339()"),
                "shield refuses re-inline: `{path}` contains the \
                 post-`use` shorthand `Utc::now().to_rfc3339()` — the \
                 pre-lift spelling `observability.rs` originally \
                 carried. Same fix: route through \
                 `crate::repo::now_rfc3339_utc()`."
            );
        }
    }
}
