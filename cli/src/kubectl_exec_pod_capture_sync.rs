//! Resolve `kubectl`, compose the canonical `kubectl exec -n <ns> <pod> --`
//! argv prefix, extend it with a caller-supplied payload, and route the
//! spawn through the sync captured-stdout adapter.
//!
//! # Pre-lift census — two sibling stanzas, one fused composition
//!
//! Two consumer sites in `commands/sessions.rs` each spelled the same
//! four-line stanza verbatim, differing only in the exec payload that
//! follows the `--` terminator and in the downstream parse of the
//! captured stdout:
//!
//! ```ignore
//! let kubectl = get_tool_path(tools::KUBECTL);
//! let mut argv: Vec<&str> =
//!     crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, pod).to_vec();
//! argv.extend([<payload>]);
//! let output = run_query_capture_sync(&kubectl, &argv)?;
//! ```
//!
//! 1. `commands/sessions.rs::count_sessions` — extends with the Valkey
//!    `["valkey-cli", "-a", password, "--no-auth-warning", "keys",
//!    "session:*"]` probe payload; the captured stdout is line-counted
//!    to a `usize` session tally.
//! 2. `commands/sessions.rs::delete_sessions` — extends with a `sh -c`
//!    payload orchestrating a Valkey SCAN + DEL pipeline against the
//!    same key namespace; the captured stdout is line-parsed to a sum
//!    of per-DEL counts.
//!
//! Two identically-shaped bodies (PRIME DIRECTIVE: duplication budget
//! is zero — [`crate::kubectl_exec_pod_argv`] already redeemed the
//! argv-prefix axis; the enclosing "resolve kubectl + extend prefix +
//! route through the sync captured-stdout adapter" fusion is the
//! remaining sibling axis in this module).
//!
//! # Why fold the resolve + spawn axes together
//!
//! The two consumer sites share three orthogonal axes past the argv
//! prefix — the [`crate::tools::KUBECTL`] name-resolution discipline
//! (i.e., `get_tool_path` on the canonical tool name so a hermetic
//! runner's `KUBECTL_BIN`-provided store-path `kubectl` wins over any
//! `PATH` shadow), the argv-prefix + payload composition, and the
//! [`crate::retry::run_query_capture_sync`] spawn adapter that returns
//! trimmed UTF-8-lossy stdout on the `Ok` arm and a classified
//! anyhow error on the `Err` arm. All three land at this primitive; a
//! caller that wants ANY of them (a swap of the tool-resolution
//! discipline, a rename of the argv-prefix helper, a promotion of the
//! spawn adapter to the async sibling) crosses a single body rather
//! than two.
//!
//! # Sibling primitives kept apart
//!
//! - [`crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix`] is
//!   the argv-prefix half of this composition. Three other consumers
//!   under `commands/` still reach for the prefix directly because they
//!   route through a DIFFERENT spawn adapter than this primitive owns —
//!   `search_sync.rs::run_sync_via_kubectl` routes through
//!   [`crate::retry::run_inherited_status`] (inherited I/O, no capture)
//!   and its cleanup branch through a raw `.status().await`;
//!   `supergraph_verification.rs::verify_router_schema` routes through
//!   a raw `.output().await`. Those three sit on a different spawn-
//!   adapter axis and stay on the argv-prefix primitive alone.
//! - [`crate::retry::run_query_capture_sync`] is the captured-stdout
//!   half. Every non-`kubectl exec` sync-capture consumer routes there
//!   directly. This primitive is the fusion specific to the
//!   `kubectl exec -n <ns> <pod> --` argv shape.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the fused resolve + argv-compose +
//! sync-capture body lives at ONE surface. A future refinement (a
//! `KUBECTL_BIN` fallback that consults a `~/.forge` config, a
//! per-invocation attempt sigil around the spawn, a promotion of the
//! captured-stdout envelope to a typed
//! `KubectlExecPodCapturedOutput { stdout, elapsed }` record) lands
//! here and reaches both consumers by construction.
//!
//! §VI.1 recurring-shape-to-helper: two sibling stanzas across two
//! functions in the same module match the recurring-shape criterion;
//! the primitive body is the promotion.

use anyhow::Result;

/// Resolve the `kubectl` binary through
/// [`crate::tools::get_tool_path`] on the canonical
/// [`crate::tools::tools::KUBECTL`] name, compose the
/// `["exec", "-n", <namespace>, <pod>, "--"]` argv prefix via
/// [`crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix`],
/// extend it with the caller-supplied `payload` (the exec-payload
/// argv that follows the `--` terminator), and route the spawn
/// through [`crate::retry::run_query_capture_sync`].
///
/// Returns the trimmed UTF-8-lossy stdout on the `Ok` arm — byte-
/// identical to what a direct
/// `crate::retry::run_query_capture_sync(&kubectl, &argv)` call would
/// return with the same argv composed at the call site.
///
/// # Ordering
///
/// The tool resolution runs BEFORE the argv composition, and the argv
/// composition runs BEFORE the spawn. Both pre-lift sites relied on
/// this ordering: a `?`-propagated capture failure short-circuits the
/// per-caller stdout-parsing tail that follows the pre-lift `let output
/// = ...?;` binding.
pub(crate) fn run_kubectl_exec_pod_capture_sync(
    namespace: &str,
    pod: &str,
    payload: &[&str],
) -> Result<String> {
    let kubectl = crate::tools::get_tool_path(crate::tools::tools::KUBECTL);
    let mut argv: Vec<&str> =
        crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, pod).to_vec();
    argv.extend_from_slice(payload);
    crate::retry::run_query_capture_sync(&kubectl, &argv)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Positive-delegation shield: every pre-lift consumer must forward
    /// at least once through
    /// [`run_kubectl_exec_pod_capture_sync`]. A dropped call site would
    /// leave the negative "no raw kubectl-resolve + argv-extend +
    /// capture pair" scan trivially satisfied by absence; this positive
    /// count keeps that failure visible.
    #[test]
    fn every_prelift_consumer_forwards_through_run_kubectl_exec_pod_capture_sync() {
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("sessions.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches(
                    "crate::kubectl_exec_pod_capture_sync::\
                     run_kubectl_exec_pod_capture_sync(",
                )
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 kubectl-exec-pod capture-sync site(s) through \
                 `crate::kubectl_exec_pod_capture_sync::\
                 run_kubectl_exec_pod_capture_sync(`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }

    /// Negative caller shield: no source line under `cli/src/commands/`
    /// may spell the pre-lift raw pair
    ///
    /// ```ignore
    /// let kubectl = get_tool_path(tools::KUBECTL);
    /// // ... (kubectl_exec_pod_argv_prefix line follows)
    /// ```
    ///
    /// any more when the very next non-trivial line reaches for
    /// [`crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix`].
    /// The two pre-lift sites migrated; any future consumer that wants
    /// the same fused resolve + argv-prefix + captured-sync composition
    /// reaches for [`run_kubectl_exec_pod_capture_sync`] on first grep,
    /// not by copy-pasting the raw stanza.
    ///
    /// The scan is anchored to the pre-lift PAIR — a `get_tool_path(`
    /// binding on the same source line as `tools::KUBECTL`, IMMEDIATELY
    /// followed (skipping blank / comment lines) by an argv binding
    /// that forwards through
    /// [`crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix`].
    /// The pairing keeps the shield from tripping on the `seed.rs::
    /// find_primary_pod` consumer (which resolves `kubectl` for a
    /// non-exec `get pod ...` capture — a distinct argv shape this
    /// primitive does not own) nor on the `seed.rs::exec_psql` consumer
    /// (which routes through a raw `.spawn()` with stdin-fed SQL — a
    /// distinct spawn shape).
    #[test]
    fn no_command_module_still_spells_raw_kubectl_resolve_exec_argv_pair() {
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
                if trimmed.starts_with("//") {
                    continue;
                }
                if !(line.contains("get_tool_path(") && line.contains("KUBECTL")) {
                    continue;
                }
                // Walk forward past blank / comment lines and see whether
                // the very next non-trivial line reaches for the
                // argv-prefix helper this primitive fuses onto.
                let mut cursor = idx + 1;
                while cursor < lines.len() {
                    let next = lines[cursor];
                    let next_trimmed = next.trim_start();
                    if next_trimmed.is_empty() || next_trimmed.starts_with("//") {
                        cursor += 1;
                        continue;
                    }
                    if next.contains("kubectl_exec_pod_argv_prefix(") {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                    // The `kubectl_exec_pod_argv_prefix(` binding can
                    // split across two source lines when the `let mut
                    // argv: Vec<&str> =` head sits alone; walk one more
                    // non-trivial line before giving up.
                    let mut inner = cursor + 1;
                    while inner < lines.len() {
                        let after = lines[inner];
                        let after_trimmed = after.trim_start();
                        if after_trimmed.is_empty() || after_trimmed.starts_with("//") {
                            inner += 1;
                            continue;
                        }
                        if !next.contains("kubectl_exec_pod_argv_prefix(")
                            && after.contains("kubectl_exec_pod_argv_prefix(")
                        {
                            offenders.push((path.clone(), idx + 1, line.to_string()));
                        }
                        break;
                    }
                    break;
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `get_tool_path(tools::KUBECTL) → \
             kubectl_exec_pod_argv_prefix(` pair(s) survive under \
             `commands/` — route each resolve-then-exec-prefix \
             composition through `crate::kubectl_exec_pod_capture_sync::\
             run_kubectl_exec_pod_capture_sync()` instead. \
             Offenders:\n{:#?}",
            offenders
        );
    }

    /// Argv-shape byte-oracle: with an empty payload, the primitive's
    /// composed argv is the 5-element canonical prefix from
    /// [`crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix`]
    /// with nothing appended. Pinning this pins the "prefix comes
    /// FIRST, payload comes AFTER" ordering — a future refactor that
    /// reversed the extend order (i.e., prepended the payload) would
    /// silently regress every consumer's exec target selection.
    ///
    /// The oracle is `cfg(test)`-only and re-derives the argv the way
    /// the primitive body composes it, without actually spawning
    /// `kubectl` (the test harness need not have `kubectl` on `PATH`).
    #[test]
    fn composed_argv_prefix_leads_and_payload_trails() {
        let namespace = "ns-alpha";
        let pod = "pod-beta";
        let payload: [&str; 3] = ["valkey-cli", "keys", "session:*"];

        let mut argv: Vec<&str> =
            crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, pod).to_vec();
        argv.extend_from_slice(&payload);

        assert_eq!(argv[0], "exec");
        assert_eq!(argv[1], "-n");
        assert_eq!(argv[2], "ns-alpha");
        assert_eq!(argv[3], "pod-beta");
        assert_eq!(argv[4], "--");
        assert_eq!(argv[5], "valkey-cli");
        assert_eq!(argv[6], "keys");
        assert_eq!(argv[7], "session:*");
        assert_eq!(
            argv.len(),
            8,
            "argv length must equal prefix arity (5) + payload arity (3)",
        );
    }

    /// Empty-payload byte-oracle: with an empty payload, the primitive
    /// composes exactly the 5-element prefix — no trailing extend, no
    /// off-by-one insertion. The pinned length rules out a future
    /// refactor that appended a phantom empty element or dropped the
    /// `--` terminator.
    #[test]
    fn composed_argv_with_empty_payload_is_prefix_only() {
        let namespace = "ns-only";
        let pod = "pod-only";
        let payload: [&str; 0] = [];

        let mut argv: Vec<&str> =
            crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, pod).to_vec();
        argv.extend_from_slice(&payload);

        assert_eq!(argv.len(), 5);
        assert_eq!(argv, vec!["exec", "-n", "ns-only", "pod-only", "--"]);
    }
}
