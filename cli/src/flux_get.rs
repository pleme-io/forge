//! Typed primitive for `flux get kustomizations --all-namespaces`.
//!
//! This module owns the fleet-wide "list every kustomization, parse the
//! CLI's tabular stdout, partition into ready / not-ready" shape.
//!
//! # The pre-lift duplication
//!
//! Two consumer sites in `commands/flux.rs` — `health_check` (bail-on-
//! failure) and `check_health_status` (return-structured-tuple) — carried
//! the same invocation-plus-parse stanza verbatim modulo per-site failure
//! envelope. Same shell command, same column offsets, same
//! `format!("  • {} - Status: {} - {}", ...)` failure prose:
//!
//! ```text
//! let output = Command::new("flux")
//!     .args(["get", "kustomizations", "--all-namespaces"])
//!     .output().await?;
//! for line in stdout.lines().skip(1) {
//!     let columns: Vec<&str> = line.split_whitespace().collect();
//!     if columns.len() >= 5 {
//!         let name = columns[1];
//!         let ready_status = columns[4];
//!         if ready_status == "True" { ready += 1; }
//!         else {
//!             let message = columns.get(5..).map(|s| s.join(" ")).unwrap_or_default();
//!             failures.push(format!("  • {} - Status: {} - {}", name, ready_status, message));
//!         }
//!     }
//! }
//! ```
//!
//! Duplication is a bug (PRIME DIRECTIVE — `pleme-io/CLAUDE.md` §★★★ /
//! THEORY §VI.1 three-times threshold), and two literal copies past the
//! two-times floor. This module is the law-redeeming consolidation.
//!
//! # Two load-bearing properties this primitive owns
//!
//! 1. **`FLUX_BIN` env override.** Pre-lift both sites spelled
//!    `Command::new("flux")`, ignoring the env var the
//!    [`tools::get_tool_path("flux")`][crate::tools::get_tool_path] idiom
//!    resolves — the same class of bug the pre-lift `flux reconcile`
//!    sites carried (redeemed at f0dfa12 / 621f827 / d3dd199) and the
//!    pre-lift `cargo run --bin extract-graphql-schema` sites carried
//!    (redeemed at 673e4be / b02d4eb / 54a9985). A Nix-hermetic runner
//!    with a store-path `flux` would fall through to whatever `flux` was
//!    first on `PATH`.
//! 2. **Typed error dispatch.** Pre-lift, spawn failure at the
//!    `check_health_status` site fused with op failure into a single
//!    `map_err(|_| (0, 0, vec!["Failed to run flux command".to_string()]))`
//!    bag — the exit code, the offending stderr, and the missing-binary
//!    signal all collapsed into a stringly-typed vec of one. Post-lift
//!    both surface as typed [`FluxGetKustomizationsError`] variants
//!    carrying the `(exit_code, stderr)` structural record the
//!    Phase 1 attestation surface (THEORY §V.4) pattern-matches on
//!    without re-parsing the display string.
//!
//! # The typed record
//!
//! [`KustomizationRow`] carries the six columns `flux get kustomizations
//! --all-namespaces` emits — `NAMESPACE NAME REVISION SUSPENDED READY
//! MESSAGE` — as owned `String` fields. Two convenience methods encode
//! the reused per-row policy the pre-lift call sites duplicated:
//!
//! - [`KustomizationRow::is_ready`] — the `"True"` comparison both sites
//!   duplicated to partition ready from not-ready.
//! - [`KustomizationRow::render_failure_line`] — the
//!   `"  • {name} - Status: {ready} - {message}"` format string both
//!   sites emitted verbatim into their per-site failure vectors.
//!
//! THEORY §V.1 (Types → Invariants → Proofs): the "flux CLI ran, its
//! stdout parses to a well-formed table, and each row is a typed record"
//! invariant is proved once at the frontier of this module and carried
//! by the return type `Result<Vec<KustomizationRow>,
//! FluxGetKustomizationsError>`, not re-derived at two consumer sites.
//! THEORY §VI.1 (three-times rule / duplication budget zero): the
//! invocation-plus-parse shape is named here and every consumer reads
//! through it.

use thiserror::Error;
use tokio::process::Command;

use crate::retry::classify_capture;
use crate::tools::get_tool_path;

/// The column count `flux get kustomization <name> -n <namespace>
/// --no-header` emits: `NAME REVISION SUSPENDED READY MESSAGE`. Five
/// tokens minimum; MESSAGE is a free-form suffix that may span zero or
/// more additional whitespace-separated tokens. Named as a `const` so
/// [`parse_kustomization_row_no_header_scoped`]'s short-row guard and
/// the message-suffix slice index share one source of truth — a future
/// flux schema drift (say, an added `AGE` column between SUSPENDED and
/// READY) lands as a single edit here rather than as two silently-
/// drifting magic numbers.
const NO_HEADER_MIN_COLUMNS: usize = 4;

/// One row of `flux get kustomizations --all-namespaces`'s tabular
/// stdout. The columns flux emits are, in order:
///
/// ```text
/// NAMESPACE  NAME  REVISION  SUSPENDED  READY  MESSAGE
/// ```
///
/// `MESSAGE` is a free-form suffix that spans zero or more whitespace-
/// separated tokens; the parser rejoins those tokens with a single
/// space (matching the pre-lift call sites' `columns.get(5..).join(" ")`
/// verbatim). All six fields are owned `String`s so a caller can store
/// the row past the lifetime of the captured stdout without cloning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KustomizationRow {
    pub namespace: String,
    pub name: String,
    pub revision: String,
    pub suspended: String,
    pub ready: String,
    pub message: String,
}

impl KustomizationRow {
    /// `true` iff flux reported this kustomization as `READY == "True"`.
    ///
    /// The pre-lift call sites both compared the raw column string
    /// verbatim (`ready_status == "True"`), so the boundary is that
    /// exact byte sequence — not case-insensitive, not `parse::<bool>`,
    /// not "any non-`False` value" — to preserve the pre-lift semantics
    /// bit-for-bit. A future flux release that emits `"true"` /
    /// `"Ready"` / a colored string would surface here as a
    /// partitioning drift (the sites' `ready` counter would zero out)
    /// rather than as a confusing typed-error deep in the stack.
    pub fn is_ready(&self) -> bool {
        self.ready == "True"
    }

    /// Render the canonical one-line failure summary for an unready
    /// kustomization: `"  • {name} - Status: {ready} - {message}"`.
    ///
    /// This is the exact `format!` string both pre-lift call sites
    /// emitted verbatim into their per-site failure vectors. Owning
    /// the format string on the row means a future prose refresh (e.g.
    /// switching `•` to `-`, or promoting `Status:` to `Ready:`) lands
    /// at one call site instead of drifting between the two.
    pub fn render_failure_line(&self) -> String {
        format!(
            "  • {} - Status: {} - {}",
            self.name, self.ready, self.message
        )
    }
}

/// Why a `flux get kustomizations --all-namespaces` invocation failed.
/// Sibling of [`FluxReconcileError`][crate::flux_reconcile::FluxReconcileError]
/// and [`FluxSourceGitReconcileError`][crate::flux_reconcile::FluxSourceGitReconcileError]
/// for the `get` shape (no per-kustomization tuple — the operation is
/// a whole-fleet listing, so there is no offending name to attach).
#[derive(Error, Debug)]
pub enum FluxGetKustomizationsError {
    /// The `flux` binary could not be spawned. Fires when the resolved
    /// tool path (from `get_tool_path("flux")`) is missing / non-
    /// executable — distinct by construction from `Failed`, which
    /// represents a spawn that succeeded but the child exited non-zero.
    #[error("Failed to spawn flux for get kustomizations --all-namespaces: {message}")]
    SpawnFailed { message: String },

    /// `flux get kustomizations --all-namespaces` exited non-zero.
    /// Carries the exit code and the captured stderr as separate
    /// fields — same structural-record shape as
    /// `FluxReconcileError::Failed` / `SchemaExtractionError::Failed`
    /// — so downstream telemetry can pattern-match on the failure
    /// shape without re-parsing the message.
    #[error("flux get kustomizations --all-namespaces failed (exit {exit_code:?}): {stderr}")]
    Failed {
        exit_code: Option<i32>,
        stderr: String,
    },
}

/// Parse the tabular stdout of `flux get kustomizations
/// --all-namespaces` into a vector of [`KustomizationRow`].
///
/// The parse discipline mirrors the pre-lift call sites verbatim:
///
/// - The first line is skipped as a header (`lines().skip(1)`).
/// - Blank lines are skipped.
/// - Each remaining line is split on whitespace; a row is emitted only
///   if it produces at least 5 columns (matching the pre-lift `>= 5`
///   guard that dropped any malformed row rather than panicking on
///   `columns[4]` indexing).
/// - `MESSAGE` is the join of columns `5..` with a single space; if
///   fewer than 6 columns are present the message is empty.
///
/// Exposed as a pure function (no async, no I/O) so the parse contract
/// is testable without spinning up a shim: a test can hand-craft the
/// exact byte sequence flux emits and pin the row-for-row translation
/// without touching the process boundary.
pub fn parse_kustomization_rows(stdout: &str) -> Vec<KustomizationRow> {
    let mut rows = Vec::new();
    for line in stdout.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() >= 5 {
            let message = columns.get(5..).map(|s| s.join(" ")).unwrap_or_default();
            rows.push(KustomizationRow {
                namespace: columns[0].to_string(),
                name: columns[1].to_string(),
                revision: columns[2].to_string(),
                suspended: columns[3].to_string(),
                ready: columns[4].to_string(),
                message,
            });
        }
    }
    rows
}

/// List every FluxCD kustomization in the cluster by running
/// `flux get kustomizations --all-namespaces` and parsing the tabular
/// stdout into a vector of [`KustomizationRow`].
///
/// # `FLUX_BIN` env override
///
/// The `flux` binary resolves via `tools::get_tool_path("flux")` —
/// same discipline every Nix-derivation-provided tool in forge honors.
/// Pre-lift the two consumer sites spelled `Command::new("flux")`
/// bypassing the override, so a Nix-hermetic runner with a store-path
/// `flux` would fall through to whatever `flux` was first on `PATH`.
///
/// # Errors
///
/// - [`FluxGetKustomizationsError::SpawnFailed`] — the resolved flux
///   binary could not be spawned. Carries the underlying io error
///   message.
/// - [`FluxGetKustomizationsError::Failed`] — flux exited non-zero.
///   Carries `exit_code` and the trimmed UTF-8-lossy stderr.
pub async fn list_kustomizations_all_namespaces(
) -> Result<Vec<KustomizationRow>, FluxGetKustomizationsError> {
    let flux = get_tool_path("flux");
    list_kustomizations_all_namespaces_with_bin(&flux).await
}

/// Test-injection sibling of [`list_kustomizations_all_namespaces`]:
/// accepts the resolved `flux_bin` as an explicit argument so unit
/// tests can point at a hermetic shim without mutating the process-
/// wide `FLUX_BIN` environment variable — same discipline as
/// [`crate::flux_reconcile::reconcile_kustomization`]'s
/// `_with_bin` sibling, `graphql_schema::extract_graphql_schema_with_bin`,
/// and `AtticClient::with_attic_bin`. Splitting the resolution from
/// the execution keeps the test surface hermetic AND parallel-safe:
/// `#[tokio::test]` on this module can run concurrent tests without
/// racing on env-var writes.
async fn list_kustomizations_all_namespaces_with_bin(
    flux_bin: &str,
) -> Result<Vec<KustomizationRow>, FluxGetKustomizationsError> {
    let captured = Command::new(flux_bin)
        .args(["get", "kustomizations", "--all-namespaces"])
        .output()
        .await;

    let output = classify_capture(
        captured,
        |e| FluxGetKustomizationsError::SpawnFailed {
            message: e.to_string(),
        },
        |cf| FluxGetKustomizationsError::Failed {
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_kustomization_rows(&stdout))
}

/// Why a `flux get kustomization <kustomization> -n <namespace>
/// --no-header` invocation failed. Sibling of
/// [`FluxGetKustomizationsError`] for the single-kustomization query
/// shape: one name, one namespace, no header, zero-or-one row. Carries
/// the offending `kustomization` AND `namespace` on every variant so a
/// caller can attach both to a failure record — a Phase 1 attestation,
/// a telemetry event, a structured log line — without re-parsing the
/// display string.
///
/// Only `SpawnFailed` is modeled: on this query shape a non-zero exit
/// structurally means "the kustomization does not exist", which
/// [`get_kustomization_scoped`] surfaces as `Ok(None)` rather than as
/// an error. The pre-lift call site at
/// `commands/flux.rs::reconcile_product_chain` collapsed both
/// spawn-failure AND non-zero-exit into a single `_ => continue` arm;
/// splitting them here keeps the operator-visible signal ("flux binary
/// missing / broken", a load-bearing failure) recoverable at the API
/// boundary even though the pre-lift consumer preserves the collapsed
/// silent-skip semantic.
#[derive(Error, Debug)]
pub enum FluxGetKustomizationError {
    /// The `flux` binary could not be spawned. Fires when the resolved
    /// tool path (from `get_tool_path("flux")`) is missing / non-
    /// executable.
    #[error(
        "Failed to spawn flux for get kustomization {kustomization} -n {namespace} --no-header: {message}"
    )]
    SpawnFailed {
        kustomization: String,
        namespace: String,
        message: String,
    },
}

/// Parse the tabular stdout of `flux get kustomization <name> -n
/// <namespace> --no-header` into an optional [`KustomizationRow`]. The
/// invocation targets exactly one kustomization, so at most one row is
/// emitted — the return type is `Option`, not `Vec`.
///
/// Because `-n <namespace>` scopes the query and `--no-header`
/// suppresses the header, the emitted columns are:
///
/// ```text
/// NAME  REVISION  SUSPENDED  READY  MESSAGE
/// ```
///
/// Five columns without a NAMESPACE prefix. The caller already knows
/// the namespace it queried, so the parser accepts it as an argument
/// and stamps it onto the returned row — [`KustomizationRow`]'s
/// `namespace` field stays populated across both the
/// `--all-namespaces` and the scoped `-n <namespace>` shapes, and
/// downstream policy (e.g. [`KustomizationRow::is_ready`],
/// [`KustomizationRow::render_failure_line`]) reads the exact same
/// record type from either producer.
///
/// The parse discipline mirrors the sibling
/// [`parse_kustomization_rows`] verbatim modulo the header-skip:
///
/// - Blank lines are skipped.
/// - Each remaining line is split on whitespace; a row is emitted only
///   if it produces at least [`NO_HEADER_MIN_COLUMNS`] tokens (the
///   post-lift equivalent of the pre-lift `columns.get(3)` guard that
///   would `unwrap_or(false)` on a shorter row rather than panicking).
/// - `MESSAGE` is the join of columns `4..` with a single space; if
///   fewer than 5 columns are present the message is empty — matching
///   the sibling parser's `columns.get(5..).map(...).unwrap_or_default()`.
/// - Only the first well-formed line yields a row; any trailing lines
///   are ignored (flux never emits more than one, but defending against
///   an appended warning line keeps the parse total across future flux
///   diagnostic-line drift).
///
/// Exposed as a pure function (no async, no I/O) so the parse contract
/// is testable without spinning up a shim: a test can hand-craft the
/// exact byte sequence flux emits and pin the row-for-row translation
/// without touching the process boundary — same discipline as
/// [`parse_kustomization_rows`].
pub fn parse_kustomization_row_no_header_scoped(
    namespace: &str,
    stdout: &str,
) -> Option<KustomizationRow> {
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() >= NO_HEADER_MIN_COLUMNS {
            let message = columns.get(4..).map(|s| s.join(" ")).unwrap_or_default();
            return Some(KustomizationRow {
                namespace: namespace.to_string(),
                name: columns[0].to_string(),
                revision: columns[1].to_string(),
                suspended: columns[2].to_string(),
                ready: columns[3].to_string(),
                message,
            });
        }
    }
    None
}

/// Parse the tabular stdout of `flux get kustomizations -n <namespace>`
/// (with header, WITHOUT `--all-namespaces`, WITHOUT `--no-header`) into
/// a vector of [`KustomizationRow`]. The invocation targets every
/// kustomization in one namespace, so zero or more rows are emitted.
///
/// Because `-n <namespace>` scopes the query, the emitted columns match
/// the single-row scoped shape exactly:
///
/// ```text
/// NAME  REVISION  SUSPENDED  READY  MESSAGE
/// ```
///
/// Five columns without a NAMESPACE prefix. The caller already knows
/// the namespace it queried, so the parser accepts it as an argument
/// and stamps it onto every returned row — [`KustomizationRow`]'s
/// `namespace` field stays populated across all three producers
/// (`--all-namespaces`, `-n <ns>` with header, `-n <ns> --no-header`
/// scoped-to-one), and downstream policy
/// ([`KustomizationRow::is_ready`], [`KustomizationRow::render_failure_line`])
/// reads the exact same record type from any producer.
///
/// The parse discipline mirrors [`parse_kustomization_rows`] (header
/// skip, blank skip, short-row skip) modulo the column count — the
/// short-row guard uses [`NO_HEADER_MIN_COLUMNS`] (four tokens) rather
/// than the 5-column `--all-namespaces` guard, matching
/// [`parse_kustomization_row_no_header_scoped`] verbatim so a row that
/// clears one scoped parser clears the other.
///
/// Exposed as a pure function (no async, no I/O) so the parse contract
/// is testable without spinning up a shim — same discipline as
/// [`parse_kustomization_rows`] and
/// [`parse_kustomization_row_no_header_scoped`].
pub fn parse_kustomization_rows_in_namespace(
    namespace: &str,
    stdout: &str,
) -> Vec<KustomizationRow> {
    let mut rows = Vec::new();
    for line in stdout.lines().skip(1) {
        if let Some(row) = parse_kustomization_row_no_header_scoped(namespace, line) {
            rows.push(row);
        }
    }
    rows
}

/// List every FluxCD kustomization in one namespace by running
/// `flux get kustomizations -n <namespace>` and parsing the tabular
/// stdout into a vector of [`KustomizationRow`]. Positioned between the
/// fleet-wide sibling [`list_kustomizations_all_namespaces`] and the
/// single-row sibling [`get_kustomization_scoped`]: same
/// invocation-plus-parse discipline, same `FLUX_BIN` env override, same
/// typed failure envelope ([`FluxGetKustomizationsError`]), scoped to
/// one namespace and returning every row it emits.
///
/// # `FLUX_BIN` env override
///
/// The `flux` binary resolves via `tools::get_tool_path("flux")` —
/// same discipline every Nix-derivation-provided tool in forge honors,
/// and the same discipline the two sibling primitives observe. Pre-lift
/// the `commands/flux.rs::gather_deployment_diagnostics` site — the
/// last raw `Command::new("flux")` stanza in forge — spelled the
/// literal so a Nix-hermetic runner with a store-path `flux` would fall
/// through to whatever `flux` was first on `PATH`.
///
/// # Errors
///
/// Same shape as [`list_kustomizations_all_namespaces`]: `SpawnFailed`
/// carries the underlying io error message, `Failed` carries
/// `(exit_code, stderr)`. Reused envelope (rather than a scoped
/// per-namespace variant) because the failure signal is structurally
/// identical — flux either ran or it didn't, and if it ran either it
/// exited zero or it didn't — and adding a per-scoped-namespace tuple
/// would just double the enum's cardinality for a record the caller
/// already threads through argv.
pub async fn list_kustomizations_in_namespace(
    namespace: &str,
) -> Result<Vec<KustomizationRow>, FluxGetKustomizationsError> {
    let flux = get_tool_path("flux");
    list_kustomizations_in_namespace_with_bin(&flux, namespace).await
}

/// Test-injection sibling of [`list_kustomizations_in_namespace`]:
/// accepts the resolved `flux_bin` as an explicit argument so unit
/// tests can point at a hermetic shim without mutating the process-
/// wide `FLUX_BIN` environment variable — same discipline as
/// [`list_kustomizations_all_namespaces_with_bin`] and
/// [`get_kustomization_scoped_with_bin`].
///
/// `namespace` is spliced verbatim into flux's argv (no escaping / no
/// shell interpretation — `Command::args` owns argv-vector delivery).
async fn list_kustomizations_in_namespace_with_bin(
    flux_bin: &str,
    namespace: &str,
) -> Result<Vec<KustomizationRow>, FluxGetKustomizationsError> {
    let captured = Command::new(flux_bin)
        .args(["get", "kustomizations", "-n", namespace])
        .output()
        .await;

    let output = classify_capture(
        captured,
        |e| FluxGetKustomizationsError::SpawnFailed {
            message: e.to_string(),
        },
        |cf| FluxGetKustomizationsError::Failed {
            exit_code: cf.exit_code,
            stderr: cf.stderr,
        },
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_kustomization_rows_in_namespace(namespace, &stdout))
}

/// Look up a single FluxCD kustomization by name and namespace by
/// running `flux get kustomization <kustomization> -n <namespace>
/// --no-header` and parsing the tabular stdout into an optional
/// [`KustomizationRow`].
///
/// # Return contract
///
/// - `Ok(Some(row))` — the kustomization exists; the returned row's
///   `namespace` is the argument passed in (stamped by
///   [`parse_kustomization_row_no_header_scoped`]), and `is_ready()` /
///   `render_failure_line()` behave identically to a row from
///   [`list_kustomizations_all_namespaces`].
/// - `Ok(None)` — the kustomization does not exist (flux exited
///   non-zero) OR flux exited zero with an empty stdout. Both shapes
///   collapse to `None` because the pre-lift call site treated a
///   non-successful exit as "silently skip this phase", and there is
///   no structural way to tell "not found" from "flux couldn't answer"
///   from the exit code alone. A consumer that DOES need to distinguish
///   the two would have to inspect flux's stderr, which is out of scope
///   for the pre-lift semantic this primitive preserves.
/// - `Err(SpawnFailed)` — the resolved flux binary could not be
///   spawned. The pre-lift call site collapsed this into the same
///   silent-skip arm as non-zero exit; splitting it out here means a
///   future consumer that wants to fail-fast on missing `flux` can do
///   so at the API boundary without regex-parsing the display string.
///
/// # `FLUX_BIN` env override
///
/// The `flux` binary resolves via `tools::get_tool_path("flux")` —
/// same discipline every Nix-derivation-provided tool in forge honors,
/// and the same discipline the sibling
/// [`list_kustomizations_all_namespaces`] observes. Pre-lift the
/// `commands/flux.rs::reconcile_product_chain` site spelled
/// `Command::new("flux")` bypassing the override, so a Nix-hermetic
/// runner with a store-path `flux` would fall through to whatever
/// `flux` was first on `PATH`.
pub async fn get_kustomization_scoped(
    kustomization: &str,
    namespace: &str,
) -> Result<Option<KustomizationRow>, FluxGetKustomizationError> {
    let flux = get_tool_path("flux");
    get_kustomization_scoped_with_bin(&flux, kustomization, namespace).await
}

/// Test-injection sibling of [`get_kustomization_scoped`]: accepts the
/// resolved `flux_bin` as an explicit argument so unit tests can point
/// at a hermetic shim without mutating the process-wide `FLUX_BIN`
/// environment variable — same discipline as
/// [`list_kustomizations_all_namespaces_with_bin`],
/// [`crate::flux_reconcile::reconcile_kustomization`]'s `_with_bin`
/// sibling, `graphql_schema::extract_graphql_schema_with_bin`, and
/// `AtticClient::with_attic_bin`.
///
/// `kustomization` and `namespace` are spliced verbatim into flux's
/// argv (no escaping / no shell interpretation — `Command::args`
/// owns argv-vector delivery so a user-controlled name cannot inject
/// additional flux args).
async fn get_kustomization_scoped_with_bin(
    flux_bin: &str,
    kustomization: &str,
    namespace: &str,
) -> Result<Option<KustomizationRow>, FluxGetKustomizationError> {
    let captured = Command::new(flux_bin)
        .args([
            "get",
            "kustomization",
            kustomization,
            "-n",
            namespace,
            "--no-header",
        ])
        .output()
        .await;

    let output = match captured {
        Ok(o) => o,
        Err(e) => {
            return Err(FluxGetKustomizationError::SpawnFailed {
                kustomization: kustomization.to_string(),
                namespace: namespace.to_string(),
                message: e.to_string(),
            });
        }
    };

    // Non-zero exit on this query shape structurally means "the
    // kustomization does not exist" — the pre-lift call site treated it
    // as a silent-skip arm, and we preserve that semantic here by
    // returning `Ok(None)` rather than an error variant. A future
    // consumer that wants richer failure-vs-not-found discrimination
    // can inspect flux's stderr via a sibling primitive.
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_kustomization_row_no_header_scoped(namespace, &stdout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_executable_shim;

    /// The canonical `flux get kustomizations --all-namespaces` output
    /// parses to one [`KustomizationRow`] per non-header, non-blank
    /// line. Pins the row-for-row translation the two consumer sites
    /// depend on — a regression that swapped `columns[1]` for
    /// `columns[0]` (name for namespace) would surface here as a
    /// name/namespace transpose rather than as a confusing "wrong
    /// kustomization reported unready" downstream.
    #[test]
    fn parse_kustomization_rows_canonical_output_yields_typed_rows() {
        let stdout = "\
NAMESPACE   NAME         REVISION       SUSPENDED  READY  MESSAGE
flux-system flux-system  main@sha1:abc  False      True   Applied revision: main@sha1:abc
alpha       svc-alpha    main@sha1:def  False      False  dependency 'flux-system/init' is not ready
";
        let rows = parse_kustomization_rows(stdout);
        assert_eq!(
            rows.len(),
            2,
            "two non-header non-blank lines parse to two rows"
        );
        assert_eq!(
            rows[0],
            KustomizationRow {
                namespace: "flux-system".to_string(),
                name: "flux-system".to_string(),
                revision: "main@sha1:abc".to_string(),
                suspended: "False".to_string(),
                ready: "True".to_string(),
                message: "Applied revision: main@sha1:abc".to_string(),
            }
        );
        assert_eq!(
            rows[1],
            KustomizationRow {
                namespace: "alpha".to_string(),
                name: "svc-alpha".to_string(),
                revision: "main@sha1:def".to_string(),
                suspended: "False".to_string(),
                ready: "False".to_string(),
                message: "dependency 'flux-system/init' is not ready".to_string(),
            }
        );
    }

    /// `parse_kustomization_rows` skips the header line unconditionally
    /// (`lines().skip(1)`), skips blank lines, and drops any row that
    /// produces fewer than 5 whitespace-separated columns rather than
    /// panicking on `columns[4]` indexing. Pins the three defensive
    /// guards the pre-lift call sites carried verbatim — a regression
    /// that dropped the header-skip would silently emit the header as
    /// a phantom kustomization named "NAME"; a regression that
    /// panicked on a short row would take down the whole health check
    /// on any transient flux output shape drift.
    #[test]
    fn parse_kustomization_rows_skips_header_blanks_and_short_rows() {
        let stdout = "\
NAMESPACE NAME REVISION SUSPENDED READY MESSAGE

flux-system ks-one main@sha1 False True

only three cols here

alpha ks-two main@sha1 False False bad message here
";
        let rows = parse_kustomization_rows(stdout);
        assert_eq!(
            rows.len(),
            2,
            "header, blanks, and the 3-column malformed row must all be skipped"
        );
        assert_eq!(rows[0].name, "ks-one");
        assert_eq!(
            rows[0].message, "",
            "6-column-less row parses to empty message"
        );
        assert_eq!(rows[1].name, "ks-two");
        assert_eq!(rows[1].message, "bad message here");
    }

    /// Empty stdout parses to an empty row vector — no header to skip,
    /// no rows to emit, no panic. Pins the vacuous-case behavior a
    /// caller that consumed the returned `Vec` via `.len()` /
    /// `.is_empty()` relies on for its "no kustomizations installed"
    /// branch. Pre-lift both call sites handled the empty-stdout case
    /// by walking `.lines().skip(1)` over the empty iterator — same
    /// no-op shape this test pins.
    #[test]
    fn parse_kustomization_rows_empty_stdout_is_empty_vec() {
        assert!(parse_kustomization_rows("").is_empty());
        assert!(parse_kustomization_rows("\n\n\n").is_empty());
    }

    /// `KustomizationRow::is_ready` returns `true` iff the raw column
    /// string equals `"True"` verbatim — not `"true"`, not `"Ready"`,
    /// not any-non-`False` value. Pins the boundary the pre-lift call
    /// sites depended on (both compared `ready_status == "True"`) so
    /// a future flux release that emits a differently-cased string
    /// surfaces here as a partitioning drift rather than a confusing
    /// unready-counted-as-ready silent failure downstream.
    #[test]
    fn is_ready_is_exact_string_match_on_true_verbatim() {
        let row = |ready: &str| KustomizationRow {
            namespace: "ns".to_string(),
            name: "ks".to_string(),
            revision: "rev".to_string(),
            suspended: "False".to_string(),
            ready: ready.to_string(),
            message: "".to_string(),
        };
        assert!(row("True").is_ready());
        assert!(!row("true").is_ready());
        assert!(!row("False").is_ready());
        assert!(!row("Ready").is_ready());
        assert!(!row("Unknown").is_ready());
        assert!(!row("").is_ready());
    }

    /// `KustomizationRow::render_failure_line` emits the exact prose
    /// both pre-lift call sites duplicated: `"  • {name} - Status:
    /// {ready} - {message}"`. Pins the format string once so a future
    /// prose refresh lands at this method rather than drifting between
    /// the two consumer sites. A regression that changed the bullet
    /// glyph, the separator, or the field order would surface here
    /// rather than as an operator-visible cosmetic drift only at one
    /// site.
    #[test]
    fn render_failure_line_matches_pre_lift_prose_verbatim() {
        let row = KustomizationRow {
            namespace: "alpha".to_string(),
            name: "svc-alpha".to_string(),
            revision: "main@sha1:def".to_string(),
            suspended: "False".to_string(),
            ready: "False".to_string(),
            message: "dependency 'flux-system/init' is not ready".to_string(),
        };
        assert_eq!(
            row.render_failure_line(),
            "  • svc-alpha - Status: False - dependency 'flux-system/init' is not ready"
        );
    }

    /// When the resolved flux binary cannot be spawned,
    /// `list_kustomizations_all_namespaces_with_bin` must surface
    /// `SpawnFailed` carrying the underlying io error message — never
    /// a fused stringly bag that collapses spawn-failure with op-
    /// failure. Uses an absolute path that does not exist so
    /// Command::spawn fails deterministically without touching global
    /// PATH state — same discipline as
    /// `reconcile_kustomization_with_bin`'s spawn-failed test.
    #[tokio::test]
    async fn spawn_failed_carries_io_error_message() {
        let result = list_kustomizations_all_namespaces_with_bin(
            "/nonexistent/path/to/flux-binary-that-does-not-exist",
        )
        .await;
        let err = result.expect_err("missing flux binary must fail");
        match err {
            FluxGetKustomizationsError::SpawnFailed { message } => {
                assert!(
                    !message.is_empty(),
                    "spawn-failure message must not be empty"
                );
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A flux invocation that exits non-zero must produce `Failed`
    /// carrying the exit code and captured stderr — never a fused
    /// stringly bag. Uses a shim invoked by absolute path so the test
    /// is hermetic and parallel-safe against PATH.
    #[tokio::test]
    async fn failed_carries_structured_exit_code_and_stderr() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\necho 'no flux controller' 1>&2\nexit 2\n",
        );
        let result = list_kustomizations_all_namespaces_with_bin(&shim).await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            FluxGetKustomizationsError::Failed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(2));
                assert!(
                    stderr.contains("no flux controller"),
                    "stderr must capture the flux stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    /// On the success path, `list_kustomizations_all_namespaces_with_bin`
    /// must return the parsed rows the shim's stdout describes. Pins
    /// the end-to-end capture-and-parse round-trip: a caller that
    /// consumes the returned `Vec` gets the same rows a direct
    /// `parse_kustomization_rows` on the shim's stdout would produce.
    #[tokio::test]
    async fn success_returns_parsed_rows() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\ncat <<'EOF'\n\
NAMESPACE   NAME         REVISION       SUSPENDED  READY  MESSAGE\n\
flux-system flux-system  main@sha1:abc  False      True   Applied revision: main@sha1:abc\n\
alpha       svc-alpha    main@sha1:def  False      False  reconciliation in progress\n\
EOF\n\
exit 0\n",
        );
        let rows = list_kustomizations_all_namespaces_with_bin(&shim)
            .await
            .expect("success path");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "flux-system");
        assert!(rows[0].is_ready());
        assert_eq!(rows[1].name, "svc-alpha");
        assert!(!rows[1].is_ready());
        assert_eq!(rows[1].message, "reconciliation in progress");
    }

    /// `list_kustomizations_all_namespaces_with_bin` must splice the
    /// canonical argv `["get", "kustomizations", "--all-namespaces"]`
    /// verbatim, unshelled, unquoted. Pinned with a shim that copies
    /// its full argv to a marker file so a future regression that
    /// silently reordered args (or dropped `--all-namespaces` and
    /// scoped the listing to the current namespace) surfaces here
    /// rather than as a "half the fleet missing" downstream failure.
    #[tokio::test]
    async fn honors_canonical_argv() {
        let observed = tempfile::tempdir().expect("observed tempdir");
        let observed_path = observed.path().join("observed-argv");
        let shim_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_path.display()
        );
        let (_shim_dir, shim) = make_executable_shim("flux", &shim_body);
        list_kustomizations_all_namespaces_with_bin(&shim)
            .await
            .expect("success path");
        let raw = std::fs::read_to_string(&observed_path).expect("shim must have written argv");
        let args: Vec<&str> = raw.lines().collect();
        assert_eq!(
            args,
            vec!["get", "kustomizations", "--all-namespaces"],
            "flux argv must be exactly [get, kustomizations, --all-namespaces]"
        );
    }

    /// Every failure variant's `Display` must render the structural
    /// fields verbatim so a caller that collapses the typed error into
    /// a `bail!("{}", err)` or a stringly-downstream vector surfaces
    /// the exit-code / stderr signal to the operator as-is. A
    /// regression that dropped either field from the `#[error(...)]`
    /// attribute would silently degrade the operator prose at every
    /// stringly-downstream site.
    #[test]
    fn display_carries_structural_fields_on_every_variant() {
        let spawn = FluxGetKustomizationsError::SpawnFailed {
            message: "No such file or directory (os error 2)".to_string(),
        };
        assert!(
            spawn
                .to_string()
                .contains("No such file or directory (os error 2)"),
            "SpawnFailed must render the io error message; got: {}",
            spawn
        );

        let failed = FluxGetKustomizationsError::Failed {
            exit_code: Some(2),
            stderr: "no flux controller reachable".to_string(),
        };
        let rendered = failed.to_string();
        assert!(
            rendered.contains("2"),
            "Failed must render exit_code verbatim; got: {rendered}"
        );
        assert!(
            rendered.contains("no flux controller reachable"),
            "Failed must render stderr verbatim; got: {rendered}"
        );

        // The signal-terminated shape (`exit_code: None`) must ALSO
        // carry stderr so a killed-flux failure still surfaces its
        // exit output.
        let killed = FluxGetKustomizationsError::Failed {
            exit_code: None,
            stderr: "signal 9 while listing".to_string(),
        };
        assert!(
            killed.to_string().contains("signal 9 while listing"),
            "signal-killed Failed display must render stderr verbatim; got: {}",
            killed
        );
    }

    /// A caller that wraps `FluxGetKustomizationsError` via
    /// `anyhow::Error::new(e)` must be able to recover the typed
    /// variant across the anyhow boundary via `downcast_ref`. Pins the
    /// programmatic-recovery promise (matches
    /// `flux_reconcile::FluxReconcileError`'s
    /// `anyhow_boundary_preserves_typed_downcast` test) — without which
    /// downstream telemetry would be forced to regex-parse the display
    /// string to partition failures by exit_code. A regression that
    /// swapped the typed error for a `String` (or dropped the
    /// `#[derive(Error, Debug)]`) would break every consumer that
    /// expects to pattern-match on the structural tuple; that break
    /// would surface here rather than as a silent downgrade to
    /// stringly-typed telemetry.
    #[test]
    fn anyhow_boundary_preserves_typed_downcast() {
        let typed = FluxGetKustomizationsError::Failed {
            exit_code: Some(7),
            stderr: "context deadline exceeded".to_string(),
        };
        let wrapped: anyhow::Error =
            anyhow::Error::new(typed).context("Failed to get FluxCD status");
        let recovered = wrapped
            .downcast_ref::<FluxGetKustomizationsError>()
            .expect("typed FluxGetKustomizationsError must survive anyhow wrapping");
        match recovered {
            FluxGetKustomizationsError::Failed { exit_code, stderr } => {
                assert_eq!(*exit_code, Some(7));
                assert_eq!(stderr, "context deadline exceeded");
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    // ─── scoped no-header primitive (`get_kustomization_scoped`) ────

    /// The canonical `flux get kustomization <name> -n <namespace>
    /// --no-header` output parses to one [`KustomizationRow`] with the
    /// argument-provided `namespace` stamped on it. Pins the
    /// column-for-column translation the `reconcile_product_chain`
    /// consumer depends on — a regression that swapped `columns[3]`
    /// (READY) for `columns[4]` (which would land in MESSAGE without
    /// the header) would surface here as a mis-partition of
    /// ready-vs-unready rather than as a silent "already-ready phase
    /// counted as unready" downstream re-reconcile storm.
    #[test]
    fn parse_no_header_scoped_canonical_output_yields_typed_row() {
        let stdout = "svc-alpha  main@sha1:abc  False  True   Applied revision: main@sha1:abc\n";
        let row = parse_kustomization_row_no_header_scoped("alpha", stdout)
            .expect("well-formed no-header row must parse");
        assert_eq!(
            row,
            KustomizationRow {
                namespace: "alpha".to_string(),
                name: "svc-alpha".to_string(),
                revision: "main@sha1:abc".to_string(),
                suspended: "False".to_string(),
                ready: "True".to_string(),
                message: "Applied revision: main@sha1:abc".to_string(),
            }
        );
    }

    /// `parse_kustomization_row_no_header_scoped` returns `None` on
    /// empty stdout, all-blank stdout, and short rows (fewer than 4
    /// columns) — matching the pre-lift call site's
    /// `columns.get(3).map(|s| *s == "True").unwrap_or(false)` guard
    /// that never panicked on a short row. Pins the vacuous-case
    /// discipline the `reconcile_product_chain` loop relies on for its
    /// "silently skip this phase" arm.
    #[test]
    fn parse_no_header_scoped_returns_none_on_empty_blank_or_short() {
        assert_eq!(parse_kustomization_row_no_header_scoped("ns", ""), None);
        assert_eq!(
            parse_kustomization_row_no_header_scoped("ns", "\n\n\n"),
            None
        );
        assert_eq!(
            parse_kustomization_row_no_header_scoped("ns", "only two cols\n"),
            None
        );
        assert_eq!(
            parse_kustomization_row_no_header_scoped("ns", "three cols here\n"),
            None
        );
    }

    /// A row with exactly 4 columns (no MESSAGE) parses to a row with
    /// an empty message string — matching the sibling
    /// `parse_kustomization_rows`'s `columns.get(5..).unwrap_or_default()`
    /// discipline verbatim. Pins the exactly-at-the-guard case that a
    /// future regression tightening the guard from `>= 4` to `>= 5`
    /// would silently drop rather than pass.
    #[test]
    fn parse_no_header_scoped_four_col_row_parses_to_empty_message() {
        let row = parse_kustomization_row_no_header_scoped("ns", "svc main@sha1 False True\n")
            .expect("four-column row must parse with empty message");
        assert_eq!(row.message, "");
        assert!(row.is_ready());
    }

    /// The parser returns the FIRST well-formed line and ignores
    /// trailing lines. Pins the tolerance against an appended warning /
    /// diagnostic line a future flux release might add: pre-lift the
    /// call site did `stdout.split_whitespace()` on the entire stdout,
    /// which would linearize a trailing diagnostic into the same token
    /// vector; the primitive's line-by-line parse is strictly more
    /// robust and this test pins the behavior.
    #[test]
    fn parse_no_header_scoped_takes_first_row_and_ignores_trailing_lines() {
        let stdout = "\
svc-alpha  main@sha1  False  True   Applied\n\
warning: rate-limited by upstream\n";
        let row = parse_kustomization_row_no_header_scoped("alpha", stdout)
            .expect("first line must parse");
        assert_eq!(row.name, "svc-alpha");
        assert_eq!(row.ready, "True");
        assert_eq!(row.message, "Applied");
    }

    /// When the resolved flux binary cannot be spawned,
    /// `get_kustomization_scoped_with_bin` must surface `SpawnFailed`
    /// carrying the offending `(kustomization, namespace)` tuple AND
    /// the underlying io error message — never a bare `Ok(None)` that
    /// collapses spawn-failure into "kustomization doesn't exist".
    /// Uses an absolute path that does not exist so `Command::spawn`
    /// fails deterministically without touching global PATH state —
    /// same discipline as
    /// [`list_kustomizations_all_namespaces_with_bin`]'s spawn-failed
    /// test.
    #[tokio::test]
    async fn scoped_spawn_failed_carries_tuple_and_message() {
        let result = get_kustomization_scoped_with_bin(
            "/nonexistent/path/to/flux-binary-that-does-not-exist",
            "svc-alpha",
            "alpha",
        )
        .await;
        let err = result.expect_err("missing flux binary must fail");
        match err {
            FluxGetKustomizationError::SpawnFailed {
                kustomization,
                namespace,
                message,
            } => {
                assert_eq!(kustomization, "svc-alpha");
                assert_eq!(namespace, "alpha");
                assert!(!message.is_empty(), "io error message must not be empty");
            }
        }
    }

    /// A flux invocation that exits non-zero must produce `Ok(None)` —
    /// the pre-lift call site treats "flux exited non-zero on a
    /// scoped get" as "kustomization doesn't exist, silently skip
    /// this phase", and the primitive preserves that semantic
    /// verbatim. A regression that flipped this to
    /// `Err(FluxGetKustomizationError::...)` would fail the loop at
    /// the first missing phase (init / secrets / …) that a product
    /// legitimately doesn't have, breaking every partially-populated
    /// deployment.
    #[tokio::test]
    async fn scoped_nonzero_exit_is_ok_none() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\necho 'kustomization not found' 1>&2\nexit 1\n",
        );
        let result = get_kustomization_scoped_with_bin(&shim, "missing-ks", "flux-system")
            .await
            .expect("nonzero exit must not error");
        assert_eq!(result, None);
    }

    /// On the success path, `get_kustomization_scoped_with_bin` must
    /// return the parsed row the shim's stdout describes AND stamp the
    /// argument-provided `namespace` on it. Pins the end-to-end
    /// capture-and-parse round-trip: a caller that consumes the
    /// returned `Some(row)` gets the exact record `KustomizationRow`
    /// downstream policy (`is_ready`, `render_failure_line`) reads,
    /// with `namespace` populated from the argument rather than
    /// dropped as an empty string.
    #[tokio::test]
    async fn scoped_success_returns_some_row_with_stamped_namespace() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\ncat <<'EOF'\n\
svc-alpha  main@sha1:abc  False  True   Applied revision: main@sha1:abc\n\
EOF\n\
exit 0\n",
        );
        let row = get_kustomization_scoped_with_bin(&shim, "svc-alpha", "alpha")
            .await
            .expect("success path must not error")
            .expect("well-formed shim stdout must parse to Some");
        assert_eq!(row.namespace, "alpha", "namespace must be stamped from arg");
        assert_eq!(row.name, "svc-alpha");
        assert!(row.is_ready());
        assert_eq!(row.message, "Applied revision: main@sha1:abc");
    }

    /// A success invocation with empty stdout (e.g. flux exited 0 but
    /// produced no rows) must yield `Ok(None)` rather than
    /// `Ok(Some(default))`. Pins the vacuous-success case so a future
    /// consumer that pattern-matches `Ok(Some(_))` for "kustomization
    /// exists" reliably distinguishes it from "flux answered but
    /// found nothing" — both structurally mean "not there" in this
    /// query shape.
    #[tokio::test]
    async fn scoped_success_with_empty_stdout_is_ok_none() {
        let (_shim_dir, shim) = make_executable_shim("flux", "#!/bin/sh\nexit 0\n");
        let result = get_kustomization_scoped_with_bin(&shim, "svc", "flux-system")
            .await
            .expect("success path must not error");
        assert_eq!(result, None);
    }

    /// `get_kustomization_scoped_with_bin` must splice the canonical
    /// argv `["get", "kustomization", <name>, "-n", <namespace>,
    /// "--no-header"]` verbatim, unshelled, unquoted. Pinned with a
    /// shim that copies its full argv to a marker file so a future
    /// regression that silently swapped `kustomization` for
    /// `kustomizations` (which would list the whole namespace rather
    /// than the targeted one) surfaces here rather than as a "flux
    /// gets rate-limited under load" downstream failure.
    #[tokio::test]
    async fn scoped_honors_canonical_argv() {
        let observed = tempfile::tempdir().expect("observed tempdir");
        let observed_path = observed.path().join("observed-argv");
        let shim_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_path.display()
        );
        let (_shim_dir, shim) = make_executable_shim("flux", &shim_body);
        get_kustomization_scoped_with_bin(&shim, "svc-alpha", "alpha")
            .await
            .expect("success path");
        let raw = std::fs::read_to_string(&observed_path).expect("shim must have written argv");
        let args: Vec<&str> = raw.lines().collect();
        assert_eq!(
            args,
            vec![
                "get",
                "kustomization",
                "svc-alpha",
                "-n",
                "alpha",
                "--no-header",
            ],
            "flux argv must be exactly [get, kustomization, <name>, -n, <namespace>, --no-header]"
        );
    }

    /// `FluxGetKustomizationError::SpawnFailed`'s `Display` must render
    /// the offending `(kustomization, namespace)` tuple AND the io
    /// error message so a caller that collapses the typed error into a
    /// `bail!("{}", err)` surfaces all three to the operator. A
    /// regression that dropped any field from the `#[error(...)]`
    /// attribute would silently degrade the operator prose at every
    /// stringly-downstream site.
    #[test]
    fn scoped_display_carries_kustomization_namespace_and_message() {
        let err = FluxGetKustomizationError::SpawnFailed {
            kustomization: "svc-alpha".to_string(),
            namespace: "alpha".to_string(),
            message: "No such file or directory (os error 2)".to_string(),
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("svc-alpha"),
            "SpawnFailed display must render kustomization; got: {rendered}"
        );
        assert!(
            rendered.contains("alpha"),
            "SpawnFailed display must render namespace; got: {rendered}"
        );
        assert!(
            rendered.contains("No such file or directory (os error 2)"),
            "SpawnFailed display must render io error message; got: {rendered}"
        );
    }

    // ─── namespace-scoped listing (`list_kustomizations_in_namespace`) ───

    /// The canonical `flux get kustomizations -n <namespace>` output
    /// parses to one [`KustomizationRow`] per non-header, non-blank
    /// line, with the argument-provided `namespace` stamped on every
    /// row. Pins the row-for-row translation the
    /// `gather_deployment_diagnostics` consumer depends on. A
    /// regression that failed to skip the header would silently emit a
    /// phantom row named `"NAME"` with `ready == "READY"` — which
    /// [`KustomizationRow::is_ready`] would (correctly) partition as
    /// not-ready, then render into the diagnostic table as a phantom
    /// unready kustomization.
    #[test]
    fn parse_in_namespace_canonical_output_yields_typed_rows() {
        let stdout = "\
NAME           REVISION       SUSPENDED  READY  MESSAGE
svc-alpha      main@sha1:abc  False      True   Applied revision: main@sha1:abc
svc-beta       main@sha1:def  False      False  dependency 'flux-system/init' is not ready
";
        let rows = parse_kustomization_rows_in_namespace("flux-system", stdout);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            KustomizationRow {
                namespace: "flux-system".to_string(),
                name: "svc-alpha".to_string(),
                revision: "main@sha1:abc".to_string(),
                suspended: "False".to_string(),
                ready: "True".to_string(),
                message: "Applied revision: main@sha1:abc".to_string(),
            }
        );
        assert_eq!(
            rows[1].name, "svc-beta",
            "second data row must parse to typed record"
        );
        assert_eq!(
            rows[1].namespace, "flux-system",
            "namespace must be stamped from arg on every row"
        );
        assert!(!rows[1].is_ready());
    }

    /// `parse_kustomization_rows_in_namespace` skips the header line
    /// unconditionally, skips blank lines, and drops any row that
    /// produces fewer than [`NO_HEADER_MIN_COLUMNS`] tokens. Pins the
    /// three defensive guards inherited from
    /// [`parse_kustomization_row_no_header_scoped`] — a regression that
    /// dropped the header skip would silently emit a `"NAME"`-named
    /// phantom row.
    #[test]
    fn parse_in_namespace_skips_header_blanks_and_short_rows() {
        let stdout = "\
NAME REVISION SUSPENDED READY MESSAGE

svc-alpha main@sha1 False True

only two cols

svc-beta main@sha1 False False bad message here
";
        let rows = parse_kustomization_rows_in_namespace("flux-system", stdout);
        assert_eq!(
            rows.len(),
            2,
            "header, blanks, and the 2-column malformed row must all be skipped"
        );
        assert_eq!(rows[0].name, "svc-alpha");
        assert_eq!(
            rows[0].message, "",
            "row with exactly NO_HEADER_MIN_COLUMNS parses to empty message"
        );
        assert_eq!(rows[1].name, "svc-beta");
        assert_eq!(rows[1].message, "bad message here");
    }

    /// Empty stdout parses to an empty vector — no header to skip,
    /// no rows to emit, no panic. Pins the vacuous-case shape the
    /// consumer relies on for its "no kustomizations in this
    /// namespace" arm (which suppresses the diagnostic subsection).
    #[test]
    fn parse_in_namespace_empty_stdout_is_empty_vec() {
        assert!(parse_kustomization_rows_in_namespace("flux-system", "").is_empty());
        assert!(parse_kustomization_rows_in_namespace("flux-system", "\n\n\n").is_empty());
    }

    /// When the resolved flux binary cannot be spawned,
    /// `list_kustomizations_in_namespace_with_bin` must surface
    /// `SpawnFailed` carrying the underlying io error message — never
    /// a bare empty vec that collapses spawn-failure into "no
    /// kustomizations in namespace". Uses an absolute path that does
    /// not exist so `Command::spawn` fails deterministically without
    /// touching global PATH state.
    #[tokio::test]
    async fn in_namespace_spawn_failed_carries_io_error_message() {
        let result = list_kustomizations_in_namespace_with_bin(
            "/nonexistent/path/to/flux-binary-that-does-not-exist",
            "flux-system",
        )
        .await;
        let err = result.expect_err("missing flux binary must fail");
        match err {
            FluxGetKustomizationsError::SpawnFailed { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected SpawnFailed, got: {other:?}"),
        }
    }

    /// A flux invocation that exits non-zero must produce `Failed`
    /// carrying the exit code and captured stderr — never a fused
    /// stringly bag. Distinguishes this primitive from the sibling
    /// `get_kustomization_scoped`, whose non-zero-exit contract is
    /// `Ok(None)` (silent skip for "kustomization doesn't exist");
    /// here non-zero exit is a real failure because a whole-namespace
    /// listing that fails is structurally different from a single-
    /// kustomization lookup that yields no rows.
    #[tokio::test]
    async fn in_namespace_failed_carries_structured_exit_code_and_stderr() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\necho 'no flux controller' 1>&2\nexit 3\n",
        );
        let result = list_kustomizations_in_namespace_with_bin(&shim, "flux-system").await;
        let err = result.expect_err("nonzero exit must fail");
        match err {
            FluxGetKustomizationsError::Failed { exit_code, stderr } => {
                assert_eq!(exit_code, Some(3));
                assert!(
                    stderr.contains("no flux controller"),
                    "stderr must capture flux stderr verbatim, got: {stderr:?}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    /// On the success path, `list_kustomizations_in_namespace_with_bin`
    /// must return the parsed rows the shim's stdout describes, with
    /// every row's `namespace` stamped from the argument. Pins the
    /// end-to-end capture-and-parse round-trip.
    #[tokio::test]
    async fn in_namespace_success_returns_parsed_rows_with_stamped_namespace() {
        let (_shim_dir, shim) = make_executable_shim(
            "flux",
            "#!/bin/sh\ncat <<'EOF'\n\
NAME       REVISION       SUSPENDED  READY  MESSAGE\n\
svc-alpha  main@sha1:abc  False      True   Applied revision: main@sha1:abc\n\
svc-beta   main@sha1:def  False      False  reconciliation in progress\n\
EOF\n\
exit 0\n",
        );
        let rows = list_kustomizations_in_namespace_with_bin(&shim, "flux-system")
            .await
            .expect("success path");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].namespace, "flux-system",
            "namespace must be stamped from arg"
        );
        assert_eq!(rows[0].name, "svc-alpha");
        assert!(rows[0].is_ready());
        assert_eq!(rows[1].name, "svc-beta");
        assert!(!rows[1].is_ready());
        assert_eq!(rows[1].message, "reconciliation in progress");
    }

    /// `list_kustomizations_in_namespace_with_bin` must splice the
    /// canonical argv `["get", "kustomizations", "-n", <namespace>]`
    /// verbatim, unshelled, unquoted. Pinned with a shim that copies
    /// its full argv to a marker file so a future regression that
    /// silently swapped in `--all-namespaces` (which would return the
    /// whole fleet rather than the one namespace, and would surface
    /// downstream as a 6-column parse against a 5-column expectation)
    /// surfaces here rather than as a "diagnostic table showed all of
    /// flux-system" surprise.
    #[tokio::test]
    async fn in_namespace_honors_canonical_argv() {
        let observed = tempfile::tempdir().expect("observed tempdir");
        let observed_path = observed.path().join("observed-argv");
        let shim_body = format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexit 0\n",
            observed_path.display()
        );
        let (_shim_dir, shim) = make_executable_shim("flux", &shim_body);
        list_kustomizations_in_namespace_with_bin(&shim, "flux-system")
            .await
            .expect("success path");
        let raw = std::fs::read_to_string(&observed_path).expect("shim must have written argv");
        let args: Vec<&str> = raw.lines().collect();
        assert_eq!(
            args,
            vec!["get", "kustomizations", "-n", "flux-system"],
            "flux argv must be exactly [get, kustomizations, -n, <namespace>]"
        );
    }

    /// A caller that wraps `FluxGetKustomizationError` via
    /// `anyhow::Error::new(e)` must be able to recover the typed
    /// variant across the anyhow boundary via `downcast_ref`. Pins the
    /// programmatic-recovery promise (matches
    /// [`FluxGetKustomizationsError`]'s
    /// `anyhow_boundary_preserves_typed_downcast` test) so a future
    /// consumer wrapping the error with `anyhow::Context` still
    /// exposes the structural tuple to Phase 1 attestation records
    /// (THEORY §V.4) without regex-parsing the display string.
    #[test]
    fn scoped_anyhow_boundary_preserves_typed_downcast() {
        let typed = FluxGetKustomizationError::SpawnFailed {
            kustomization: "svc-alpha".to_string(),
            namespace: "alpha".to_string(),
            message: "os error 2".to_string(),
        };
        let wrapped: anyhow::Error =
            anyhow::Error::new(typed).context("Failed to check kustomization existence");
        let recovered = wrapped
            .downcast_ref::<FluxGetKustomizationError>()
            .expect("typed FluxGetKustomizationError must survive anyhow wrapping");
        match recovered {
            FluxGetKustomizationError::SpawnFailed {
                kustomization,
                namespace,
                message,
            } => {
                assert_eq!(kustomization, "svc-alpha");
                assert_eq!(namespace, "alpha");
                assert_eq!(message, "os error 2");
            }
        }
    }
}
