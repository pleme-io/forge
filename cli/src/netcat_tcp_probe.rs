//! Netcat TCP-reachability probe primitive with typed target and
//! target-specific diagnostic — the pre-lift 2 sibling
//! `Command::new(nc_bin()).args(<argv>).output().context("Failed to
//! execute netcat check")? + if !nc_check.status.success() { let
//! stderr = crate::repo::utf8_lossy_borrow(&nc_check.stderr);
//! anyhow::bail!(<target-specific diagnostic>); }` stanzas in
//! `commands/nix_builder.rs::{verify_k8s_service, verify_external}`
//! for probing TCP reachability of a target host.
//!
//! # Pre-lift census — two sibling stanzas, one grammar
//!
//! Two consumer sites inside
//! [`crate::commands::nix_builder`] each spelled the same
//! `Command::new(nc_bin()).args(<argv>).output().context("Failed to
//! execute netcat check")? + if !status.success() { let stderr =
//! ...; anyhow::bail!(<diagnostic>); }` seven-line grammar, diverging
//! only on the argv shape and the bail diagnostic. The primitive
//! [`nc_tcp_probe_or_bail_sync`] fuses spawn + non-success extraction +
//! target-specific diagnostic composition onto ONE typed body:
//!
//! 1. [`crate::commands::nix_builder`]`::verify_k8s_service` — the
//!    in-cluster reachability probe consumed by
//!    `forge nix-builder verify --k8s-service`. Pre-lift argv
//!    `["-zv", "<service>.<namespace>.svc.cluster.local", "<port>"]`
//!    and pre-lift bail
//!    `"Service not accessible: {service}. Stderr: {stderr}"`.
//! 2. [`crate::commands::nix_builder`]`::verify_external` — the
//!    external-verification path's L4 reachability probe (from a
//!    developer machine outside the cluster). Pre-lift argv
//!    `["-zv", "-G", "5", "<hostname>", "<port>"]` with the hard-coded
//!    5-second connection-timeout via `-G 5`, and pre-lift bail
//!    `"Cannot connect to {hostname}:{port}. Stderr: {stderr}"`.
//!
//! Both consumers share the `Command::new(nc_bin())`,
//! `.context("Failed to execute netcat check")`, non-success-extract,
//! and `Stderr: {stderr}` diagnostic-suffix bytes verbatim. The only
//! pre-lift divergence is in the argv slice (K8s DNS-name vs. external
//! hostname + connect timeout) and the diagnostic prefix (service-
//! name-scoped vs. host+port-scoped). Both axes fit inside a closed
//! two-variant `NetcatTcpProbeTarget` enum whose `argv` /
//! `failure_diagnostic` accessors render the pre-lift bytes for each
//! variant.
//!
//! # Why a fused spawn-and-bail primitive, not just an argv slice
//!
//! The two consumers share not only the argv literal but the entire
//! spawn context, the extraction, the bail template's `Stderr:`
//! suffix, and the diagnostic-composition polarity. Lifting only the
//! argv (as in [`crate::attic_login_argv`]) would leave the
//! `Command::new(nc_bin()).<args>.output().context("Failed to execute
//! netcat check")?; if !X.status.success() { let stderr = ...;
//! bail!(...) }` five-line body respelled at both sites — a future
//! refinement of the spawn (a per-probe timeout via `.timeout(...)`, a
//! telemetry hook on the exit code, a switch to
//! `crate::retry::run_capture_anyhow_sync`'s
//! `(op, exit_code, stderr)` envelope) would have hit two sites in
//! lockstep or diverged. Post-lift the whole grammar lives at ONE
//! typed body and every consumer inherits the change from
//! `nc_tcp_probe_or_bail_sync(&nc_bin(), <target>)?`.
//!
//! # Distinct from the sibling `retry::run_capture_anyhow_sync` envelope
//!
//! The regression shield at
//! `commands/nix_builder.rs::test_nix_builder_test_routes_captured_output_through_classify_capture_anyhow`
//! (line 696-750 pre-migration) explicitly carves the two `nc_check`
//! bail paths OUT of the `crate::retry::run_capture_anyhow_sync`
//! migration surface, on the grounds that their pre-lift
//! `"Service not accessible: {service}. Stderr: {stderr}"` /
//! `"Cannot connect to {hostname}:{port}. Stderr: {stderr}"` diagnostics
//! carry per-call service/host/port context that does NOT fit the
//! `(op, exit_code, stderr)`-only envelope
//! `retry::classify_capture_anyhow` emits. This primitive owns the
//! target-scoped-diagnostic surface those two sites need: the closed
//! `NetcatTcpProbeTarget` enum's `failure_diagnostic` accessor renders
//! the per-target `<target-descriptor>. Stderr: {stderr}` shape at ONE
//! typed body, complementing (not colliding with) the
//! `(op, exit_code, stderr)` envelope for captured-output sites that
//! don't need target-scoped context.
//!
//! # Sigil boundary
//!
//! [`crate::commands::nix_builder`]`::nc_bin()` is the module-scoped
//! sigil that resolves the `nc` binary via the canonical two-argument
//! `crate::repo::get_tool_path("NC_BIN", "nc")` call, guarded by the
//! whole-module shield
//! `test_nix_builder_routes_nc_through_nc_bin_sigil_not_raw_resolve`.
//! This primitive takes the resolved nc-binary path as its first
//! parameter (`nc_bin: &str`) so the sigil boundary stays intact:
//! callers still route through `nc_bin()` for resolution, and the
//! `NC_BIN` env-var override, single-point-of-truth resolve, and
//! sigil-shield discipline all apply unchanged.
//!
//! # THEORY grounding
//!
//! §V.1 (Types → Invariants → Proofs → Render Anywhere): the closed
//! two-variant `NetcatTcpProbeTarget` enum expresses the target shape
//! as a type — a caller cannot spawn an nc probe against a target that
//! isn't K8s-cluster-local or external-host, and the argv and
//! diagnostic renderers are total functions from the enum onto their
//! pre-lift byte-shapes. §VI.1 (one-oracle discipline): the whole
//! spawn+extract+diagnostic grammar lives at ONE construction surface
//! so a future refinement (a per-probe telemetry hook, a switch to
//! async spawn, a migration onto the `(op, exit_code, stderr)`
//! envelope for the captured-output side) lands in one place rather
//! than at every consumer.

use anyhow::Context;

/// Typed netcat TCP-reachability probe target — closed enum of the
/// two pre-lift consumer shapes in
/// [`crate::commands::nix_builder`]`::{verify_k8s_service,
/// verify_external}`.
///
/// The enum is CLOSED: a future third probe shape (a Unix-socket
/// probe, a v6-only probe with `-6`, an ICMP `-u` probe) must add a
/// third variant here, and the `argv` / `failure_diagnostic`
/// accessors' exhaustive `match` will force the addition of the
/// corresponding argv-render / diagnostic-render arms in lockstep —
/// so a future contributor cannot silently extend the target surface
/// without touching both renderers.
pub enum NetcatTcpProbeTarget<'a> {
    /// In-cluster K8s Service probe. Renders to argv
    /// `["-zv", "<service>.<namespace>.svc.cluster.local", "<port>"]`
    /// and failure diagnostic
    /// `"Service not accessible: {service}. Stderr: {stderr}"`.
    K8sClusterLocal {
        service: &'a str,
        namespace: &'a str,
        port: u16,
    },
    /// External host probe with hard-coded 5-second connection
    /// timeout via `-G 5`. Renders to argv
    /// `["-zv", "-G", "5", "<hostname>", "<port>"]` and failure
    /// diagnostic
    /// `"Cannot connect to {hostname}:{port}. Stderr: {stderr}"`.
    ExternalHost { hostname: &'a str, port: u16 },
}

impl<'a> NetcatTcpProbeTarget<'a> {
    /// Render the pre-lift argv slice for the target variant.
    ///
    /// Byte-identical to the pre-lift `.args(&[...])` slice at the
    /// two consumer sites — pinned by
    /// [`tests::test_k8s_cluster_local_argv_bytes`] and
    /// [`tests::test_external_host_argv_bytes`].
    pub fn argv(&self) -> Vec<String> {
        match self {
            Self::K8sClusterLocal {
                service,
                namespace,
                port,
            } => vec![
                "-zv".to_string(),
                format!("{}.{}.svc.cluster.local", service, namespace),
                port.to_string(),
            ],
            Self::ExternalHost { hostname, port } => vec![
                "-zv".to_string(),
                "-G".to_string(),
                "5".to_string(),
                (*hostname).to_string(),
                port.to_string(),
            ],
        }
    }

    /// Render the pre-lift failure-diagnostic bail message for the
    /// target variant.
    ///
    /// Byte-identical to the pre-lift `anyhow::bail!(<template>, ...,
    /// stderr)` message at the two consumer sites — pinned by
    /// [`tests::test_k8s_cluster_local_failure_diagnostic_bytes`]
    /// and [`tests::test_external_host_failure_diagnostic_bytes`].
    pub fn failure_diagnostic(&self, stderr: &str) -> String {
        match self {
            Self::K8sClusterLocal { service, .. } => {
                format!("Service not accessible: {}. Stderr: {}", service, stderr)
            }
            Self::ExternalHost { hostname, port } => {
                format!(
                    "Cannot connect to {}:{}. Stderr: {}",
                    hostname, port, stderr
                )
            }
        }
    }
}

/// Fused netcat TCP-reachability probe: spawn `nc` against the typed
/// target, and on non-zero exit extract stderr and bail with the
/// target-specific diagnostic. Byte-identical semantics to the
/// pre-lift 7-line stanza the two consumer sites carried.
///
/// # Parameters
///
/// - `nc_bin` — the resolved `nc` binary path. Both current callers
///   route through the module-scoped sigil
///   [`crate::commands::nix_builder`]`::nc_bin()` (which delegates
///   to `crate::repo::get_tool_path("NC_BIN", "nc")`); the primitive
///   takes the resolved string so the sigil boundary and its shield
///   stay intact.
/// - `target` — the typed target discriminator. See
///   [`NetcatTcpProbeTarget`] for the closed variant set.
///
/// # Returns
///
/// `Ok(())` on `nc` exit 0 (target reachable). `Err(...)` on:
/// - Spawn failure (the `.context("Failed to execute netcat
///   check")?` frame carries the underlying `std::io::Error`);
/// - Non-zero exit (the target-specific
///   [`NetcatTcpProbeTarget::failure_diagnostic`] message wraps the
///   captured stderr, byte-identical to the pre-lift `bail!`).
pub fn nc_tcp_probe_or_bail_sync(
    nc_bin: &str,
    target: NetcatTcpProbeTarget<'_>,
) -> anyhow::Result<()> {
    let argv = target.argv();
    let nc_check = std::process::Command::new(nc_bin)
        .args(&argv)
        .output()
        .context("Failed to execute netcat check")?;
    if !nc_check.status.success() {
        let stderr = crate::repo::utf8_lossy_borrow(&nc_check.stderr);
        anyhow::bail!("{}", target.failure_diagnostic(&stderr));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: the `K8sClusterLocal` variant's argv is exactly
    /// the pre-lift 3-element `["-zv", "<svc>.<ns>.svc.cluster.local",
    /// "<port>"]` slice, in the pre-lift order, with the DNS-name
    /// composition `"<service>.<namespace>.svc.cluster.local"`
    /// preserved byte-for-byte (including the two literal dots and
    /// the `.svc.cluster.local` suffix). A future refactor that
    /// (a) swapped the argv-order (`<port>` before the DNS name),
    /// (b) reformatted the DNS name (`<ns>.<svc>` swap or a
    /// `.svc.<ns>.<svc>...` misspell), (c) dropped the `-z` or `-v`
    /// letter of `-zv`, or (d) inserted a leading `--` separator
    /// regresses this assertion.
    #[test]
    fn test_k8s_cluster_local_argv_bytes() {
        let argv = NetcatTcpProbeTarget::K8sClusterLocal {
            service: "my-svc",
            namespace: "prod",
            port: 5432,
        }
        .argv();
        assert_eq!(
            argv,
            vec![
                "-zv".to_string(),
                "my-svc.prod.svc.cluster.local".to_string(),
                "5432".to_string(),
            ],
            "K8sClusterLocal argv must render byte-identically to the \
             pre-lift `[\"-zv\", &format!(\"{{}}.{{}}.svc.cluster.local\", \
             service, namespace), &port.to_string()]` slice at \
             `commands/nix_builder.rs::verify_k8s_service`",
        );
    }

    /// Byte-oracle: the `ExternalHost` variant's argv is exactly the
    /// pre-lift 5-element `["-zv", "-G", "5", "<hostname>", "<port>"]`
    /// slice. The `-G 5` connection-timeout pair is FIXED at the
    /// pre-lift 5-second budget (not caller-tunable) — a change that
    /// promoted the timeout to a caller parameter, swapped it to
    /// `-w 5` (a different timeout flag with post-connection
    /// semantics), or dropped it entirely regresses this assertion.
    #[test]
    fn test_external_host_argv_bytes() {
        let argv = NetcatTcpProbeTarget::ExternalHost {
            hostname: "builder.example.com",
            port: 22,
        }
        .argv();
        assert_eq!(
            argv,
            vec![
                "-zv".to_string(),
                "-G".to_string(),
                "5".to_string(),
                "builder.example.com".to_string(),
                "22".to_string(),
            ],
            "ExternalHost argv must render byte-identically to the \
             pre-lift `[\"-zv\", \"-G\", \"5\", hostname, \
             &port.to_string()]` slice at \
             `commands/nix_builder.rs::verify_external`, including the \
             hard-coded `-G 5` connection-timeout pair",
        );
    }

    /// Byte-oracle: the `K8sClusterLocal` variant's failure
    /// diagnostic is exactly the pre-lift
    /// `"Service not accessible: {service}. Stderr: {stderr}"`
    /// template, service-name-scoped (the namespace and port DO NOT
    /// appear in the pre-lift template). A future refactor that
    /// (a) added the namespace or port to the diagnostic prefix,
    /// (b) reworded `"Service not accessible"` to a synonym, or
    /// (c) reordered the `. Stderr: {stderr}` suffix regresses this
    /// assertion.
    #[test]
    fn test_k8s_cluster_local_failure_diagnostic_bytes() {
        let msg = NetcatTcpProbeTarget::K8sClusterLocal {
            service: "my-svc",
            namespace: "prod",
            port: 5432,
        }
        .failure_diagnostic("nc: connect to my-svc port 5432 failed: Connection refused");
        assert_eq!(
            msg,
            "Service not accessible: my-svc. Stderr: nc: connect to my-svc port 5432 failed: Connection refused",
            "K8sClusterLocal failure diagnostic must render byte-identically \
             to the pre-lift `anyhow::bail!(\"Service not accessible: {{}}. \
             Stderr: {{}}\", service, stderr)` template at \
             `commands/nix_builder.rs::verify_k8s_service`",
        );
    }

    /// Byte-oracle: the `ExternalHost` variant's failure diagnostic
    /// is exactly the pre-lift `"Cannot connect to {hostname}:{port}.
    /// Stderr: {stderr}"` template — hostname and port BOTH appear
    /// in the diagnostic prefix (the K8s variant surfaces only
    /// `service`; the External variant surfaces `hostname:port`),
    /// making the two diagnostics distinguishable in operator logs.
    #[test]
    fn test_external_host_failure_diagnostic_bytes() {
        let msg = NetcatTcpProbeTarget::ExternalHost {
            hostname: "builder.example.com",
            port: 22,
        }
        .failure_diagnostic(
            "nc: connectx to builder.example.com port 22 (tcp) failed: Operation timed out",
        );
        assert_eq!(
            msg,
            "Cannot connect to builder.example.com:22. Stderr: nc: connectx to builder.example.com port 22 (tcp) failed: Operation timed out",
            "ExternalHost failure diagnostic must render byte-identically \
             to the pre-lift `anyhow::bail!(\"Cannot connect to {{}}:{{}}. \
             Stderr: {{}}\", hostname, port, stderr)` template at \
             `commands/nix_builder.rs::verify_external`",
        );
    }

    /// Interpolation-position pin (K8sClusterLocal): `service` lands
    /// at the DNS-name FIRST slot AND at the diagnostic prefix; a
    /// future swap of `service` and `namespace` in either renderer
    /// would silently probe `<ns>.<svc>...` (an unreachable DNS name)
    /// while the diagnostic still names `service` — a wire-visible
    /// / operator-visible divergence a mere length or substring
    /// check would not catch.
    #[test]
    fn test_k8s_cluster_local_service_and_namespace_positions() {
        let target = NetcatTcpProbeTarget::K8sClusterLocal {
            service: "svc-alpha",
            namespace: "ns-beta",
            port: 9000,
        };
        let argv = target.argv();
        assert_eq!(
            argv[1], "svc-alpha.ns-beta.svc.cluster.local",
            "argv[1] must render as `<service>.<namespace>.svc.cluster.local` \
             with `service` FIRST and `namespace` SECOND",
        );
        let msg = target.failure_diagnostic("<stderr>");
        assert!(
            msg.contains("Service not accessible: svc-alpha."),
            "diagnostic must scope on `service` (\"svc-alpha\"), not \
             `namespace` (\"ns-beta\") — the pre-lift diagnostic \
             template surfaces the service name only. Got: {msg}",
        );
        assert!(
            !msg.contains("ns-beta"),
            "diagnostic must NOT leak `namespace` (\"ns-beta\") — the \
             pre-lift template omits it. Got: {msg}",
        );
    }

    /// The `nc_tcp_probe_or_bail_sync` primitive returns
    /// `Err(...)` when the spawn fails (an unresolvable
    /// `nc_bin` path — a nonexistent binary that satisfies neither
    /// the `.output()` spawn nor the `.context("Failed to execute
    /// netcat check")?` frame). Pins the spawn-failure carve-out:
    /// the primitive MUST surface a `Failed to execute netcat check`
    /// context on any spawn-side error before it ever inspects the
    /// child's exit status.
    #[test]
    fn test_nc_tcp_probe_bails_with_spawn_context_on_missing_binary() {
        // A path guaranteed not to exist on any conforming host —
        // `/nonexistent-forge-nc-XXXX` under the OS temp policy
        // isn't a real binary, so the sync spawn fails at
        // `.output()` before ever reaching the exit-status check.
        let result = nc_tcp_probe_or_bail_sync(
            "/nonexistent/path/to/nc-binary-that-does-not-exist",
            NetcatTcpProbeTarget::ExternalHost {
                hostname: "example.com",
                port: 80,
            },
        );
        let err = result.expect_err(
            "spawning a nonexistent nc binary must surface an Err — the \
             `.context(\"Failed to execute netcat check\")?` frame short-\
             circuits before the exit-status inspection",
        );
        let chain: String = err
            .chain()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            chain.contains("Failed to execute netcat check"),
            "spawn-failure error chain must carry the canonical \
             `Failed to execute netcat check` context — the pre-lift \
             `.context(\"Failed to execute netcat check\")?` frame \
             the two consumer sites both spelled verbatim. Got: {chain}",
        );
    }

    /// Caller shield (positive half): the pre-lift module
    /// `commands/nix_builder.rs` MUST forward through
    /// [`nc_tcp_probe_or_bail_sync`] at least the pre-lift count of
    /// times (2), so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but this positive count still fails.
    /// Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields the crate carries against every other typed lift
    /// primitive (see `attic_login_argv.rs` and the broader family).
    #[test]
    fn every_prelift_module_forwards_through_nc_tcp_probe_or_bail_sync() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let path = crate_src.join("commands").join("nix_builder.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let needle = "nc_tcp_probe_or_bail_sync(";
        let forwards = crate::test_support::code_line_hits(&source, needle).len();
        assert!(
            forwards >= 2,
            "{} must forward at least 2 `nc` TCP-reachability probe site(s) \
             through `crate::netcat_tcp_probe::{}` (one for \
             `verify_k8s_service`, one for `verify_external`); found {}. \
             A dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
            needle.trim_end_matches('('),
            forwards,
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift
    /// `.context("Failed to execute netcat check")` spawn-context
    /// frame — the tell of the pre-lift `Command::new(nc_bin())
    /// .args(...).output().context(...)?` grammar. The two pre-lift
    /// sites migrated; any future consumer that wants the same
    /// netcat-probe grammar reaches for [`nc_tcp_probe_or_bail_sync`]
    /// on first grep, not by copy-pasting the raw spawn+context
    /// stanza from the pre-lift form.
    ///
    /// The forbidden needle is reconstructed at test time via
    /// `format!` so this shield's own source text does not
    /// false-match itself. The scan routes through
    /// [`crate::test_support::code_line_hits`] to preserve the
    /// anti-docstring-self-match discipline — existing `///` and
    /// `//!` prose in `commands/` that legitimately quotes the
    /// pre-lift shape for narrative purposes does not count against
    /// the shield.
    #[test]
    fn no_commands_module_still_spells_raw_netcat_check_spawn_context() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let commands_dir = crate_src.join("commands");
        // Reconstruct the forbidden needle via `format!` so this
        // shield's own source text does not false-match itself.
        let forbidden = format!(".context({}Failed to execute netcat check{})", "\"", "\"");

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let read = std::fs::read_dir(&commands_dir)
            .unwrap_or_else(|_| panic!("expected {} to exist", commands_dir.display()));
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("///") || t.starts_with("//!") || t.starts_with("//") {
                    continue;
                }
                if line.contains(&forbidden) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.context(\"Failed to execute netcat check\")` spawn-context \
             frame(s) survive under `commands/` — route each netcat \
             TCP-reachability probe through \
             `crate::netcat_tcp_probe::nc_tcp_probe_or_bail_sync(&nc_bin(), \
             <target>)?` instead:\n{:#?}",
            offenders,
        );
    }
}
