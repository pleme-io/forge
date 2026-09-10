//! Canonical `kubectl exec -n <ns> <pod> --` argv prefix used at every
//! kubectl-exec-into-a-specific-pod spawn site.
//!
//! # Pre-lift census — five sibling stanzas, one argv prefix shape
//!
//! Five consumer sites each spelled the same 5-element argv prefix
//! literal verbatim on their `kubectl` builder, diverging only on the
//! exec payload that follows the `--` terminator:
//!
//! 1. `commands/sessions.rs::count_sessions` (Valkey `keys session:*`
//!    probe, routed through
//!    [`crate::retry::run_query_capture_sync`], spelling
//!    `&["exec", "-n", namespace, pod, "--", "valkey-cli", ...]`
//!    around line 107).
//! 2. `commands/sessions.rs::delete_sessions` (`sh -c` orchestrating a
//!    Valkey SCAN + DEL pipeline, routed through the same
//!    [`crate::retry::run_query_capture_sync`], spelling
//!    `&["exec", "-n", namespace, pod, "--", "sh", "-c", &script]`
//!    around line 138).
//! 3. `commands/search_sync.rs::run_sync_via_kubectl` (`novasearchctl
//!    sync` invocation with runtime-conditional `--dry-run` / `--prune`
//!    pushes, routed through
//!    [`crate::retry::run_inherited_status`], spelling
//!    `vec!["exec", "-n", namespace, &pod_name, "--", "novasearchctl",
//!    ...]` around line 201).
//! 4. `commands/search_sync.rs::run_sync_via_kubectl` cleanup branch
//!    (`rm -rf <remote_config_path>` post-sync cleanup, routed through
//!    a raw `.status().await` on the `kubectl_command_async` frontier,
//!    spelling `["exec", "-n", namespace, &pod_name, "--", "rm", "-rf",
//!    remote_config_path]` around line 241).
//! 5. `commands/supergraph_verification.rs::verify_router_schema`
//!    (`wget -q -O- http://localhost:4000/health` health-endpoint probe
//!    against the Hive Router pod, routed through a raw
//!    `.output().await` on the `kubectl_command_async` frontier,
//!    spelling `&["exec", &pod_name, "-n", namespace, "--", "wget",
//!    ...]` around line 279 — the pod-first drift is normalized onto
//!    the canonical `-n <ns>` before positional `<pod>` order this
//!    primitive owns).
//!
//! Five identically-shaped bodies past THEORY §VI.1's three-is-a-law
//! threshold (PRIME DIRECTIVE: duplication budget is zero). A `kubectl
//! exec` argv drift — a rename of the `-n` short form to `--namespace`,
//! an argv-order shuffle putting `<pod>` before `-n <ns>` (which
//! kubectl accepts semantically but is heterogeneous across the
//! pre-lift census, one site of five), an accidental drop of the `--`
//! terminator (which would silently route the exec payload's flags
//! through kubectl's own flag parser and produce misleading "unknown
//! flag" errors on the operator surface), or a swap of `exec` for
//! `debug` (kubectl's ephemeral-container surface) — pre-lift had to
//! hit five sites in lockstep or diverge; post-lift it hits ONE typed
//! body and every consumer inherits the change from
//! `kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix(namespace, pod)`.
//!
//! # Why an argv prefix slice, not a `Command` builder
//!
//! The five consumers differ AFTER the argv prefix on four axes:
//!
//! - **Spawn adapter.** Sites 1–2 route through
//!   [`crate::retry::run_query_capture_sync`], whose captured stdout
//!   feeds a line-count / DEL-count parser. Site 3 routes through
//!   [`crate::retry::run_inherited_status`] wrapped in a
//!   [`tokio::time::timeout`], whose inherited stdio streams the
//!   `novasearchctl` output live to the operator terminal. Site 4
//!   routes through a raw `.status().await` on the
//!   `kubectl_command_async` frontier with the result deliberately
//!   discarded through `let _ = …` (best-effort cleanup). Site 5 routes
//!   through a raw `.output().await` on the same frontier with the
//!   captured bytes fed into a hash-comparison classifier.
//! - **Exec payload arity.** Sites 1–2, 4 have fixed payload arity
//!   (7 / 3 / 3 elements respectively past `--`); site 3 has
//!   runtime-conditional arity (6 base + up to 2 conditional flags,
//!   pushed onto a `Vec<&str>` after the prefix); site 5 has fixed 4.
//! - **Payload composition surface.** Sites 1, 2, 4, 5 pass a fixed
//!   array literal. Site 3 pre-binds a `mut Vec<&str>` and mutates it
//!   through a chain of `.push` / `.extend` calls before handing it to
//!   `.args(&exec_args)`.
//! - **Post-spawn classification.** Sites 1–2 parse the captured
//!   stdout; site 3 propagates a nested `Result<Result<(), Error>,
//!   Elapsed>` through a `match` on the outer `Result`; site 4 drops
//!   the result entirely; site 5 branches on `output.status.success()`
//!   and short-circuits into a `VerificationResult { success: false,
//!   … }` on non-zero exit.
//!
//! A `Command`-builder primitive would have to expose all four axes as
//! parameters; the argv prefix slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper like
//! [`crate::retry::run_query_capture_sync`]) consume identically when
//! concatenated with the payload. Modeled on
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! and [`crate::kubectl_apply_argv::kubectl_apply_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify / stdio layers that legitimately
//! diverge downstream.
//!
//! # Deliberately disjoint from the interactive-stdin `exec_psql` site
//!
//! `commands/seed.rs::exec_psql` (line 83) spells the argv prefix
//! `["exec", "-i", "-n", <ns>, <pod>, "--", "psql", ...]` — a
//! 6-element prefix that inserts the `-i` interactive flag between
//! `exec` and the `-n <ns>` scoping pair. The `-i` flag pins kubectl to
//! keep stdin open across the exec, which is required for the seed SQL
//! payload the caller writes into the child's `Stdio::piped()` stdin.
//! Every other site in this primitive's census spawns without stdin
//! piping (their exec payload is self-contained), so folding `exec_psql`
//! into this prefix would force a second boolean parameter that only
//! ever takes `true` at one call site. The `-i` variant is therefore
//! deliberately absent from this primitive; a future consolidation that
//! unifies both surfaces would grow an `InteractiveStdin` axis in one
//! motion, not through a second half-lift.
//!
//! # Canonical argv order
//!
//! The primitive canonicalizes on `["exec", "-n", <ns>, <pod>, "--"]`.
//! kubectl accepts the pod-first ordering `["exec", <pod>, "-n", <ns>,
//! "--"]` (site 5's pre-lift form) semantically, but a single primitive
//! owning both orderings would either drop the argv-shape invariant (a
//! variant selects the order, and no consumer would benefit from
//! choosing) or splay two distinct primitives against the same intent.
//! The `-n <ns>` before positional `<pod>` order matches four of the
//! five pre-lift sites and every kubectl example in the upstream
//! reference documentation; site 5 is normalized on migration.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's namespace and pod slots interpolate the caller-supplied
//! strings under a single `'a` lifetime bound. The three static string
//! elements (`"exec"`, `"-n"`, `"--"`) are `&'static str` and coerce
//! into `'a` freely. The returned `[&'a str; 5]` binds strictly to the
//! caller strings' scope, matching the discipline in
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`] and
//! [`crate::kubectl_apply_argv::kubectl_apply_argv`].
//!
//! # Distinct from the `kubectl_command_async()` sigil family
//!
//! Every consumer resolves the `kubectl` binary via either the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil
//! (sites 3–5) or the [`crate::tools::get_tool_path`] +
//! [`crate::retry::run_query_capture_sync`] pair (sites 1–2). That
//! sigil owns *which* binary spawns; this primitive owns *which
//! arguments* it receives on the exec-into-pod phase. The two concerns
//! compose:
//! `kubectl_command_async().args(&kubectl_exec_pod_argv::
//! kubectl_exec_pod_argv_prefix(ns, pod).iter().copied().chain([…]).
//! collect::<Vec<_>>())` — or, equivalently and more idiomatically,
//! `let mut argv = kubectl_exec_pod_argv_prefix(ns, pod).to_vec();
//! argv.extend([…]);`.

/// The pre-lift 5-element `["exec", "-n", <namespace>, <pod>, "--"]`
/// argv prefix that opens every `kubectl exec` invocation targeting a
/// specific pod in a specific namespace before its `--` payload.
///
/// Callers assemble the exec payload (the tokens that follow `--`) and
/// the surrounding builder chain (`kubectl_command_async()`,
/// `.output().await` vs `.status().await` vs
/// [`crate::retry::run_query_capture_sync`] vs
/// [`crate::retry::run_inherited_status`], the timeout wrapping,
/// post-spawn classification, and the mutable-Vec vs fixed-array
/// payload composition) themselves — those axes vary across the five
/// consumers. This primitive owns ONLY the 5-element argv prefix shape.
///
/// # Element layout
///
/// - `argv[0] = "exec"` — kubectl verb.
/// - `argv[1] = "-n"` — namespace-scope short-form flag.
/// - `argv[2] = <namespace>` — caller-supplied namespace.
/// - `argv[3] = <pod>` — caller-supplied pod name.
/// - `argv[4] = "--"` — argv terminator separating kubectl's own flags
///   from the exec payload's flags. Without it, kubectl's flag parser
///   would greedily consume any leading `-<x>` tokens in the exec
///   payload (e.g., site 1's `-a <password>` for `valkey-cli`), which
///   surfaces as "unknown flag" errors that mask the underlying intent
///   at the operator surface.
///
/// # Lifetime discipline
///
/// The returned array borrows `namespace` and `pod` under a single
/// `'a` bound. Every current caller binds both strings ahead of the
/// spawn and holds them alive across the `.args(...)` call or the
/// subsequent `.to_vec() + .extend(...)` composition; the
/// `[&'a str; 5]` return type pins that requirement at the type level
/// (a caller cannot silently extend the array past either input's
/// scope). The three static string elements (`"exec"`, `"-n"`, `"--"`)
/// are `&'static str` and coerce into `'a` freely.
pub(crate) fn kubectl_exec_pod_argv_prefix<'a>(namespace: &'a str, pod: &'a str) -> [&'a str; 5] {
    ["exec", "-n", namespace, pod, "--"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`kubectl_exec_pod_argv_prefix`] returns the pre-lift
    /// 5-element slice element-for-element (`"exec"`, `"-n"`, `<ns>`,
    /// `<pod>`, `"--"`) in the canonical order, with no extra element
    /// and no rewritten value. A future refactor that (a) reordered the
    /// `-n <ns>` pair with the positional `<pod>` argument (i.e.,
    /// regressed to site 5's pre-lift pod-first form), (b) added a
    /// `--container=<name>` companion between the pod name and `--` (a
    /// legitimate future extension, but one that would drift on the
    /// current five sites), (c) swapped `-n` for `--namespace` (which
    /// kubectl accepts but no pre-lift site spelled), or (d) dropped
    /// the `--` terminator (regressing every current site into a
    /// silent-flag-consumption bug against its exec payload) regresses
    /// this assertion.
    #[test]
    fn test_kubectl_exec_pod_argv_prefix_emits_pre_lift_five_element_prefix() {
        let argv = kubectl_exec_pod_argv_prefix("ns-alpha", "pod-beta");
        assert_eq!(argv[0], "exec");
        assert_eq!(argv[1], "-n");
        assert_eq!(argv[2], "ns-alpha");
        assert_eq!(argv[3], "pod-beta");
        assert_eq!(argv[4], "--");
        assert_eq!(argv.len(), 5);
    }

    /// Interpolation-position pin: `namespace` lands at index 2, `pod`
    /// lands at index 3. A future refactor that swapped them (i.e.,
    /// regressed to site 5's pre-lift pod-first form
    /// `["exec", <pod>, "-n", <ns>, "--", …]`) would silently pass the
    /// namespace as the positional pod argument against the running
    /// cluster — kubectl would then bail with "pod <ns-name> not found
    /// in namespace <pod-name>" and the shape drift would masquerade
    /// as a targeting error. Two distinct string arguments make the
    /// swap observable at the assertion level.
    #[test]
    fn test_kubectl_exec_pod_argv_prefix_places_namespace_at_index_2_and_pod_at_index_3() {
        let argv = kubectl_exec_pod_argv_prefix("ns-alpha", "pod-beta");
        assert_eq!(
            argv[2], "ns-alpha",
            "index 2 must carry the namespace argument",
        );
        assert_eq!(argv[3], "pod-beta", "index 3 must carry the pod argument",);
        assert_ne!(argv[2], argv[3], "namespace and pod must not collide");
    }

    /// The return type is a fixed-arity `[&str; 5]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument onto the primitive's own body
    /// without touching this module; a change to a slice reference
    /// would allow an unsized-length pattern that a variadic future
    /// refactor might silently exploit. Pin the fixed arity at compile
    /// time via a destructured binding — if the returned type ever
    /// loses its `[_; 5]` shape, this line fails to type-check.
    #[test]
    fn test_kubectl_exec_pod_argv_prefix_returns_fixed_arity_five() {
        let argv: [&str; 5] = kubectl_exec_pod_argv_prefix("ns", "pod");
        let [a0, a1, a2, a3, a4] = argv;
        assert_eq!(a0, "exec");
        assert_eq!(a1, "-n");
        assert_eq!(a2, "ns");
        assert_eq!(a3, "pod");
        assert_eq!(a4, "--");
    }

    /// The three static-string elements — `"exec"` (verb), `"-n"`
    /// (namespace-scope flag), and `"--"` (argv terminator) — sit at
    /// their pre-lift positions regardless of the caller-supplied
    /// namespace and pod strings. A future refactor that (a) folded the
    /// verb and terminator into a single formatted string, (b) dropped
    /// the terminator when the payload's first element does not start
    /// with `-` (an optimization that would silently break the moment
    /// a future consumer routed a `-a <password>` valkey-cli payload
    /// through), or (c) rewrote `-n` as `--namespace` would regress
    /// this assertion.
    #[test]
    fn test_kubectl_exec_pod_argv_prefix_static_elements_are_position_stable() {
        for (ns, pod) in [
            ("default", "svc-0"),
            ("cart-prod", "cart-api-0"),
            ("", ""),
            (
                "ns-with-hyphens-and-numerics-123",
                "pod-with-hyphens-and-numerics-456",
            ),
        ] {
            let argv = kubectl_exec_pod_argv_prefix(ns, pod);
            assert_eq!(argv[0], "exec", "verb must not drift under {ns:?}/{pod:?}");
            assert_eq!(
                argv[1], "-n",
                "namespace-scope flag must not drift under {ns:?}/{pod:?}",
            );
            assert_eq!(
                argv[4], "--",
                "argv terminator must not drift under {ns:?}/{pod:?}",
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` (excluding the deliberately-deferred
    /// interactive-stdin `commands/seed.rs::exec_psql` site, which
    /// spells the `-i` prefix `["exec", "-i", "-n", <ns>, <pod>, "--",
    /// …]` and is out-of-scope per the module doc) may spell the
    /// pre-lift raw `"exec"`-immediately-followed-by-`"-n"` argv
    /// adjacency any more. The five pre-lift sites migrated; any future
    /// consumer that wants the same kubectl-exec-into-pod shape reaches
    /// for [`kubectl_exec_pod_argv_prefix`] on first grep, not by
    /// copy-pasting the raw literal from an existing module. Mirrors
    /// the negative half of the sibling shields on
    /// [`crate::kubectl_apply_argv`],
    /// [`crate::first_pod_field_argv`], and
    /// [`crate::kubectl_delete_job_argv`].
    ///
    /// Anchored on the joined pair `"exec", "-n"` — the two-adjacency
    /// is what every canonical-order pre-lift stanza carried, and no
    /// post-lift consumer will (the typed primitive owns both inside
    /// its body). A future consumer of a different kubectl verb can
    /// still spell either token alone (an `exec` on a different flag
    /// family that legitimately routes through this primitive or a
    /// sibling one, or a `-n` on a non-`exec` verb like `kubectl get
    /// -n`, `kubectl logs -n`) without tripping the shield — those
    /// live outside this primitive's scope, and every other-verb `-n
    /// <ns>` pair on this crate already routes through its own typed
    /// primitive (`kubectl_get_*_argv`, `kubectl_delete_job_argv`,
    /// `kubectl_logs_argv`, `list_resource_names_by_selector_argv`,
    /// `first_pod_field_argv`).
    ///
    /// Scans both single-line (`"exec", "-n"` as a substring) and
    /// multi-line (`"exec",` on one line, `"-n",` on the very next
    /// line, ignoring leading whitespace) pre-lift stanza forms. The
    /// multi-line form is what four of the five pre-lift sites carried
    /// (sessions.rs::count_sessions, both search_sync.rs sites, and
    /// supergraph_verification.rs); the single-line form is what
    /// sessions.rs::delete_sessions carried.
    #[test]
    fn no_command_module_still_spells_raw_kubectl_exec_pod_argv_prefix() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");
        let deferred_stem = "seed";

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_stem().and_then(|s| s.to_str()) == Some(deferred_stem) {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            let mut in_block_comment = false;
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.starts_with("/*") {
                    in_block_comment = true;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                // Single-line pre-lift form: e.g., delete_sessions'
                // `&["exec", "-n", namespace, pod, "--", …]`.
                if line.contains("\"exec\", \"-n\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                    continue;
                }
                // Multi-line pre-lift form: `"exec",` on one line, the
                // very next non-comment line trimmed to `"-n",`.
                let trimmed_this = trimmed.trim_end();
                if trimmed_this == "\"exec\"," {
                    if let Some(next) = lines.get(idx + 1) {
                        let next_trimmed = next.trim().trim_end();
                        if next_trimmed == "\"-n\"," {
                            offenders.push((path.clone(), idx + 1, line.to_string()));
                        }
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"exec\", \"-n\", <ns>, <pod>, \"--\", …]` argv prefix \
             literal(s) survive under `commands/` — route each through \
             `crate::kubectl_exec_pod_argv::kubectl_exec_pod_argv_prefix()` \
             instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the three pre-lift modules that
    /// housed the five sites MUST each forward through
    /// [`kubectl_exec_pod_argv_prefix`] at least the number of times
    /// matching their pre-lift site count, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_exec_pod_argv_prefix() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("sessions.rs"), 2),
            (crate_src.join("commands").join("search_sync.rs"), 2),
            (
                crate_src
                    .join("commands")
                    .join("supergraph_verification.rs"),
                1,
            ),
        ];
        let needle = "kubectl_exec_pod_argv_prefix(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} kubectl-exec-into-pod spawn site(s) through \
                 `{}`; found {}. A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
