//! Canonical `kubectl apply -f <manifest-path-or-stdin>` argv slice used
//! at every k8s-manifest apply spawn site.
//!
//! # Pre-lift census — three sibling stanzas, one argv shape
//!
//! Three consumer sites each spelled the same 3-element argv literal
//! verbatim on their `kubectl` builder, diverging only on the third
//! element (a caller-supplied manifest path vs the stdin `"-"` sentinel):
//!
//! 1. `commands/migrations.rs::run_migration_job` (post-write apply of
//!    the migration-Job manifest reserved via
//!    `migration_job_manifest_file`, routed through
//!    [`crate::retry::run_inherited_status`] with op label
//!    `"kubectl apply"`, spelling
//!    `apply_cmd.args(["apply", "-f", &manifest_path_str])` around
//!    line 584).
//! 2. `commands/federation_tests.rs::create_federation_test_job` (post-write
//!    apply of the federation-test Job manifest reserved via
//!    `federation_test_job_manifest_file`, routed through
//!    [`crate::retry::classify_capture_anyhow`] wrapping
//!    `.output().await`, spelling
//!    `.args(&["apply", "-f", &manifest_path_str])` around line 323).
//! 3. `services/migration_service.rs::MigrationService::create_job`
//!    (in-memory job manifest piped straight into `kubectl apply -f -`
//!    via [`std::process::Stdio::piped`] on the child's stdin, spelling
//!    `.args(["apply", "-f", "-"])` around line 255).
//!
//! Three identically-shaped bodies past THEORY §VI.1's three-is-a-law
//! threshold (PRIME DIRECTIVE: duplication budget is zero). A kubectl
//! apply argv drift — a rename of `-f` to `--filename`, an added
//! `--server-side` for the SSA rollout, a `--field-manager=<name>`
//! companion for ownership tracking, a `--dry-run=server` audit toggle,
//! a `--validate=strict` flag flip, an argv-order shuffle putting `-f`
//! before `apply`, or a rename of the stdin sentinel `"-"` — pre-lift
//! had to hit three sites in lockstep or diverge; post-lift it hits ONE
//! typed body and the enum's per-variant third-element projection, and
//! every consumer inherits the change from
//! `.args(kubectl_apply_argv::kubectl_apply_argv(KubectlApplySource::
//! ManifestPath(&manifest_path_str)))` (or
//! `.args(&kubectl_apply_argv::kubectl_apply_argv(...))` for the
//! `&[&str]`-taking sites, or
//! `.args(kubectl_apply_argv::kubectl_apply_argv(KubectlApplySource::
//! Stdin))` for the piped-stdin site).
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The three consumers differ AFTER the argv slice on three axes:
//!
//! - **Spawn adapter.** Site 1 routes through
//!   [`crate::retry::run_inherited_status`], which propagates the
//!   child's inherited stdio and classifies the wait-status as
//!   `anyhow::Result`. Site 2 routes through
//!   [`crate::retry::classify_capture_anyhow`], which captures the
//!   `.output().await` bytes and classifies both spawn and non-zero exit
//!   as `anyhow::Result` with the captured stderr surfaced. Site 3
//!   spawns the child raw via `.spawn()?` and manually writes the job
//!   manifest into the child's `Stdio::piped()` stdin before awaiting
//!   `.wait()`.
//! - **Post-spawn classification.** Site 1 propagates the
//!   `run_inherited_status` result verbatim via `?`. Site 2 discards
//!   the captured `Output` bytes through `let _output =` (the
//!   subsequent [`crate::ui::print_step_pass`] "Job created: {}" line
//!   is the observable success signal). Site 3 bails on non-success
//!   `ExitStatus` via `anyhow::bail!("Failed to create migration job")`.
//! - **Stdio arrangement.** Sites 1–2 apply from a filesystem path (the
//!   manifest was written to `<TempDir>/<name>-migration-job-<ts>.yaml`
//!   or `<TempDir>/<job_name>.yaml` before the spawn). Site 3 pipes the
//!   manifest through the child's stdin — the `"-"` third argv element
//!   is the sentinel `kubectl apply -f` reads to mean "read from
//!   stdin", and site 3's `.stdin(Stdio::piped())` + subsequent
//!   `stdin.write_all(job_manifest.as_bytes()).await` is what fills
//!   that stream.
//!
//! A `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape both
//! `tokio::process` and `std::process` `Command`s' `.args()` (and any
//! `&[&str]`-taking helper) consume identically. Modeled on
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`],
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`], and
//! [`crate::cargo_test_argv::cargo_integration_tests_argv`] — argv-slice
//! primitives that partition their tool's duplication budget without
//! collapsing the spawn / classify / stdio layers that legitimately
//! diverge downstream.
//!
//! # The enum-over-`Option<&str>` design
//!
//! [`KubectlApplySource`] is a closed enum whose
//! [`KubectlApplySource::arg_literal`] projection returns either the
//! caller-supplied manifest path or the `"-"` stdin sentinel. An
//! `Option<&str>` parameter (with `None` meaning stdin) would have
//! compressed the two variants into a single call surface but would
//! have (a) forced the caller to remember which polarity mapped to
//! which spawn shape, and (b) made the stdin-sentinel drift invisible
//! at the call site — a site that reads `kubectl_apply_argv(None)`
//! cannot be greppable-checked against "which stdio shape does this
//! apply use?" the way `KubectlApplySource::Stdin` can.
//!
//! A future extension (a `Kustomization(&str)` variant for a `-k`
//! directory apply, an `Url(&str)` variant for `-f <http://...>`)
//! lands one variant plus one match arm at
//! [`KubectlApplySource::arg_literal`], not a re-cross-multiplication
//! over the `Option` and a fresh boolean.
//!
//! # Borrows from inputs, not `&'static`
//!
//! The array's third element interpolates the caller-supplied
//! manifest path under a single `'a` lifetime bound. The stdin
//! `"-"` sentinel produced by
//! [`KubectlApplySource::arg_literal`] on the [`KubectlApplySource::Stdin`]
//! arm is a `&'static str` and coerces into `'a` freely, so a
//! `[&'a str; 3]` return type binds strictly to the caller's
//! `ManifestPath` string when that arm is chosen and to no runtime
//! input on the `Stdin` arm. This matches the discipline in
//! [`crate::kubectl_delete_job_argv::kubectl_delete_job_ignore_not_found_argv`]
//! and [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`].
//!
//! # Distinct from the `kubectl_command_async()` sigil family
//!
//! Every consumer already resolves the `kubectl` binary via the
//! module-scoped
//! [`crate::infrastructure::kubectl::kubectl_command_async`] sigil,
//! which reads `KUBECTL_BIN` from the tools registry. That sigil owns
//! *which* binary spawns; this primitive owns *which arguments* it
//! receives on the manifest-apply phase. The two concerns compose:
//! `kubectl_command_async().args(kubectl_apply_argv::
//! kubectl_apply_argv(KubectlApplySource::ManifestPath(path)))`.

/// Closed enum naming whether a `kubectl apply -f` invocation reads its
/// manifest from a caller-supplied filesystem path or from the child's
/// stdin (the `"-"` sentinel). Divergent per-variant
/// [`KubectlApplySource::arg_literal`] projections encode the exact byte
/// shape of the emitted third argv element for every current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KubectlApplySource<'a> {
    /// `-f <path>` — the caller writes the manifest to a filesystem path
    /// (typically a `TempDir`-scoped scratch slot reserved via the
    /// per-consumer `*_job_manifest_file` sigil) and hands its
    /// stringified path to this variant. Emitted as-is at argv index 2.
    ManifestPath(&'a str),
    /// `-f -` — the caller pipes the manifest through the child's stdin
    /// via `.stdin(Stdio::piped())` and a subsequent
    /// `stdin.write_all(manifest.as_bytes()).await`. Emits the literal
    /// `"-"` sentinel at argv index 2.
    ///
    /// `#[allow(dead_code)]` because the sole current constructor —
    /// `services/migration_service.rs::MigrationService::create_job` —
    /// sits inside a struct impl whose production call-graph entry is
    /// itself currently absent (the `MigrationService` type is a lifted
    /// service-layer surface with tests-only exercise on `main`, per
    /// the crate-wide dead-code baseline that includes
    /// `create_job` / `wait_for_job` / `check_job_success` /
    /// `run_federation_tests`). clippy's `dead_code` analysis treats
    /// the whole call subtree as unreachable and therefore flags this
    /// variant as never-constructed even though the constructor line
    /// `KubectlApplySource::Stdin` is spelled in that dead subtree. The
    /// variant is load-bearing to the primitive's typed shape (a
    /// future consumer that pipes a manifest into `kubectl apply -f -`
    /// reaches for this variant, not a fresh raw-argv paste), so the
    /// allow keeps the design intact rather than collapsing the enum
    /// to a single-variant shape whose next extension would have to
    /// re-lift the enum from scratch.
    #[allow(dead_code)]
    Stdin,
}

impl<'a> KubectlApplySource<'a> {
    /// The exact third-element byte sequence this variant emits on a
    /// `kubectl apply -f <arg>` spawn. `&'a str` because the
    /// [`KubectlApplySource::ManifestPath`] arm returns the borrowed
    /// caller string, and the [`KubectlApplySource::Stdin`] arm returns
    /// the compile-time `"-"` sentinel (a `&'static str` that coerces
    /// into any `'a` a caller composes over the surrounding
    /// [`kubectl_apply_argv`] array).
    pub(crate) fn arg_literal(self) -> &'a str {
        match self {
            Self::ManifestPath(p) => p,
            Self::Stdin => "-",
        }
    }
}

/// The pre-lift 3-element `apply -f <manifest-path-or-stdin>` argv slice
/// used at every k8s-manifest apply spawn site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` vs
/// [`crate::retry::run_inherited_status`] vs
/// [`crate::retry::classify_capture_anyhow`] vs a raw `.spawn()?` +
/// manual stdin write, post-spawn classification, and the stdio
/// arrangement) themselves — those axes vary across the three
/// consumers. This primitive owns ONLY the 3-element argv shape and the
/// per-variant third-element projection.
///
/// # Element layout
///
/// - `argv[0] = "apply"` — kubectl verb.
/// - `argv[1] = "-f"` — filename-input flag. The short form is what
///   every pre-lift site spelled; a future migration to `--filename`
///   lands here.
/// - `argv[2] = <source.arg_literal()>` — the caller-supplied manifest
///   path (on [`KubectlApplySource::ManifestPath`]) or the `"-"` stdin
///   sentinel (on [`KubectlApplySource::Stdin`]).
///
/// # Lifetime discipline
///
/// The returned array borrows the [`KubectlApplySource::ManifestPath`]
/// arm's caller string under the shared `'a` bound. Every current
/// caller binds the path string ahead of the spawn and holds it alive
/// across the `.args(...)` call; the `[&'a str; 3]` return type pins
/// that requirement at the type level (a caller cannot silently extend
/// the array past the input's scope). The
/// [`KubectlApplySource::Stdin`] arm's `"-"` element is a `&'static str`
/// and coerces into `'a` freely.
pub(crate) fn kubectl_apply_argv<'a>(source: KubectlApplySource<'a>) -> [&'a str; 3] {
    ["apply", "-f", source.arg_literal()]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`KubectlApplySource::ManifestPath`] projects the
    /// caller-supplied path verbatim. A drift that (a) transformed the
    /// path (e.g., through
    /// [`crate::repo::path_to_string_lossy`] a second time), (b)
    /// wrapped it in shell-quoting, or (c) collapsed it to a constant
    /// regresses this assertion.
    #[test]
    fn test_kubectl_apply_source_manifest_path_projects_caller_string_verbatim() {
        let path = "/tmp/scratch/migration-job-1699999999.yaml";
        assert_eq!(KubectlApplySource::ManifestPath(path).arg_literal(), path,);
    }

    /// Byte-oracle: [`KubectlApplySource::Stdin`] projects the exact
    /// pre-lift `"-"` byte sequence. A drift that (a) renamed the
    /// sentinel to `/dev/stdin` (which kubectl also honors on Linux but
    /// no pre-lift site spelled), (b) upper-cased it to `"STDIN"`
    /// (which kubectl does NOT honor and would fail with a
    /// "no such file or directory" error), or (c) emitted an empty
    /// string (which kubectl would reject with a "flag needs an
    /// argument" error) regresses this assertion.
    #[test]
    fn test_kubectl_apply_source_stdin_projects_pre_lift_dash_sentinel() {
        assert_eq!(KubectlApplySource::Stdin.arg_literal(), "-");
    }

    /// The two variants project distinct third-element bytes on every
    /// non-empty, non-`"-"` path. A future refactor that accidentally
    /// folded both arms of the `match` onto the same string (e.g., a
    /// copy-paste in the arm bodies) would silently route the
    /// `ManifestPath` apply onto the stdin sentinel and silently
    /// route the `Stdin` apply onto whatever path the caller happened
    /// to bind — a destructive-in-production divergence that a mere
    /// per-arm oracle would not catch. Pin the disjointness at the
    /// assertion level so a folded-arm regression is caught by name.
    #[test]
    fn test_kubectl_apply_source_variants_project_distinct_arg_literals() {
        let path = "/tmp/manifest.yaml";
        assert_ne!(
            KubectlApplySource::ManifestPath(path).arg_literal(),
            KubectlApplySource::Stdin.arg_literal(),
        );
    }

    /// Byte-oracle: [`kubectl_apply_argv`] returns the pre-lift 3-element
    /// slice element-for-element (`"apply"`, `"-f"`,
    /// `<source.arg_literal()>`) in the pre-lift order, with no extra
    /// element and no rewritten value, on the
    /// [`KubectlApplySource::ManifestPath`] arm. A future refactor that
    /// (a) reordered the flag/value pair, (b) added a `--server-side`
    /// or `--field-manager=<name>` companion, (c) swapped `-f` for
    /// `--filename`, or (d) collapsed the trailing path element into a
    /// formatted string that unfolded `-f` separately regresses this
    /// assertion.
    #[test]
    fn test_kubectl_apply_argv_emits_pre_lift_three_element_slice_manifest_path() {
        let path = "/tmp/scratch/migration-job-1699999999.yaml";
        let argv = kubectl_apply_argv(KubectlApplySource::ManifestPath(path));
        assert_eq!(argv[0], "apply");
        assert_eq!(argv[1], "-f");
        assert_eq!(argv[2], path);
        assert_eq!(argv.len(), 3);
    }

    /// Byte-oracle sibling for the [`KubectlApplySource::Stdin`]
    /// variant: the third element must carry the `"-"` stdin sentinel
    /// verbatim. Guards against a variant-dispatch regression that
    /// (a) routed every call onto `ManifestPath` regardless of the
    /// `source` argument (silently passing an empty string as the
    /// manifest path and failing with "flag needs an argument"), or
    /// (b) hard-coded the pre-lift path arm as a constant argv slot
    /// with the `source` parameter ignored.
    #[test]
    fn test_kubectl_apply_argv_dispatches_stdin_variant() {
        let argv = kubectl_apply_argv(KubectlApplySource::Stdin);
        assert_eq!(argv[0], "apply");
        assert_eq!(argv[1], "-f");
        assert_eq!(argv[2], "-");
    }

    /// The return type is a fixed-arity `[&str; 3]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this
    /// module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 3]` shape, this line fails to type-check.
    #[test]
    fn test_kubectl_apply_argv_returns_fixed_arity_three() {
        let argv: [&str; 3] = kubectl_apply_argv(KubectlApplySource::ManifestPath("m.yaml"));
        let [a0, a1, a2] = argv;
        assert_eq!(a0, "apply");
        assert_eq!(a1, "-f");
        assert_eq!(a2, "m.yaml");
    }

    /// Interpolation-position pin: the caller-supplied path lands at
    /// index 2, NOT index 0 or 1. A future refactor that swapped the
    /// verb and its filename argument (e.g., an argv-order shuffle
    /// putting `-f <path>` before `apply`) would silently pass the
    /// manifest path as the kubectl verb and the string `"apply"` as
    /// the filename against the running cluster — kubectl would then
    /// bail with "unknown command <path>" and the shape drift would
    /// masquerade as a config error. Pin the position at the
    /// assertion level so a swap is caught by name.
    #[test]
    fn test_kubectl_apply_argv_places_manifest_path_at_index_2() {
        let path = "/etc/kubernetes/manifest.yaml";
        let argv = kubectl_apply_argv(KubectlApplySource::ManifestPath(path));
        assert_eq!(
            argv[2], path,
            "index 2 must carry the manifest-path argument"
        );
        assert_ne!(
            argv[0], path,
            "index 0 must be the kubectl verb, not the path",
        );
        assert_ne!(argv[1], path, "index 1 must be the `-f` flag, not the path",);
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/services/` may spell the
    /// pre-lift raw `"apply", "-f"` argv adjacency any more. The three
    /// pre-lift sites migrated; any future consumer that wants the
    /// same k8s-manifest apply shape reaches for
    /// [`kubectl_apply_argv`] on first grep, not by copy-pasting the
    /// raw literal from an existing module.
    ///
    /// Anchored on the joined pair `"apply", "-f"` — the two-adjacency
    /// is what every pre-lift stanza carried, and no post-lift consumer
    /// will (the typed primitive owns both inside its body). Mirrors
    /// the negative half of the sibling shields on
    /// [`crate::kubectl_delete_job_argv`],
    /// [`crate::first_pod_field_argv`], and [`crate::bun_argv`].
    #[test]
    fn no_command_or_service_module_still_spells_raw_kubectl_apply_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("services")];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for dir in scan_dirs.iter() {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                let mut in_block_comment = false;
                for (idx, line) in source.lines().enumerate() {
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
                    // Anchor on the joined pair `"apply", "-f"` — the
                    // two-adjacency is what every pre-lift stanza
                    // carried. A future consumer of a different
                    // kubectl verb can still spell either token alone
                    // (an `apply` on a different flag family, or a
                    // `-f` on a non-apply verb like `kubectl create
                    // -f`, `kubectl delete -f`, `kubectl replace -f`)
                    // without tripping the shield — those live outside
                    // this primitive's scope. A future extension of
                    // this primitive to cover those siblings would add
                    // variants and reshape this shield in one motion.
                    if line.contains("\"apply\", \"-f\"") {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"apply\", \"-f\", ...]` argv literal(s) survive under \
             `commands/` or `services/` — route each through \
             `crate::kubectl_apply_argv::kubectl_apply_argv()` with a \
             `KubectlApplySource` variant instead:\n{:#?}",
            offenders,
        );
    }

    /// Caller shield (positive half): the three pre-lift modules that
    /// housed the three sites MUST each forward through
    /// [`kubectl_apply_argv`] at least the number of times matching
    /// their pre-lift site count, so a migration that dropped a call
    /// site outright leaves the negative "no raw inline shape" scan
    /// trivially satisfied by absence but the positive count still
    /// fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_apply_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("migrations.rs"), 1),
            (crate_src.join("commands").join("federation_tests.rs"), 1),
            (crate_src.join("services").join("migration_service.rs"), 1),
        ];
        let needle = "kubectl_apply_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} k8s-manifest apply spawn site(s) through \
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
