//! Fixed-arity `kubectl get databasemigration <name> -n <namespace> -o
//! <format>` argv slice used at every Shinka `DatabaseMigration` CRD
//! object-fetch site whose consumer wants the standard `-o wide` /
//! `-o name` / `-o json` renderers rather than the jsonpath phase-readout
//! that
//! [`crate::kubectl_get_databasemigration_status_phase_argv::kubectl_get_databasemigration_status_phase_argv`]
//! already owns.
//!
//! # Pre-lift census — four sibling stanzas, three distinct output formats
//!
//! Four consumer sites in `commands/migrations.rs` each spelled the
//! same 7-element argv literal verbatim on their `kubectl` builder,
//! diverging only on the trailing `-o <format>` renderer and on the
//! surrounding spawn / classify wiring:
//!
//! 1. `commands/migrations.rs::reset_migration` (verify-status
//!    post-reset display readout, `-o wide`, routed through
//!    [`crate::retry::run_inherited_status`] so the operator sees the
//!    kubectl-rendered table on stdout).
//! 2. `commands/migrations.rs::run_migration` pre-check (existence gate
//!    on the `DatabaseMigration` CRD, `-o name`, routed through
//!    [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`]
//!    with `op = "Failed to check DatabaseMigration CRD"`, gating on
//!    `check.stdout.is_empty()` to bail with a "not found in namespace"
//!    message).
//! 3. `commands/migrations.rs::fetch_shinka_status` (parsed-JSON
//!    status readout, `-o json`, routed through the raw
//!    `kubectl_command_async().args(...).output().await` shape and
//!    piping stdout into `serde_json::from_slice::<ShinkaCrdStatus>`
//!    with a `default()` fall-through on any spawn / non-success /
//!    parse failure).
//! 4. `commands/migrations.rs::set_expected_tag_if_exists` (soft
//!    existence gate before annotation, `-o name`, routed through
//!    the raw `kubectl_command_async().args(...).output().await` shape
//!    and gating on `output.status.success() && !output.stdout.is_empty()`
//!    to decide whether to fire the follow-on `annotate` spawn — a
//!    missing CRD is a no-op, not a failure).
//!
//! Four identically-shaped bodies past THEORY §VI.1's duplication
//! trigger (PRIME DIRECTIVE: duplication budget is zero). A Shinka
//! `DatabaseMigration` fetch-argv drift — a rename of the `-n` short
//! form to `--namespace`, an argv-order shuffle putting `-n <ns>`
//! before the resource name, an `-o` swap for `--output`, or a
//! rename of the singular resource kind (`databasemigration` →
//! `databasemigrations` or a fully-qualified
//! `databasemigrations.shinka.pleme.io`) — pre-lift had to hit four
//! sites in lockstep or diverge; post-lift it hits ONE typed body and
//! every consumer inherits the change from
//! `.args(kubectl_get_databasemigration_output_argv(name, namespace,
//! DatabaseMigrationGetOutputFormat::<variant>))`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The four consumers differ AFTER the argv slice on the spawn adapter
//! (`run_inherited_status` / `kubectl_output_spawn_anyhow` / raw
//! `kubectl_command_async().output()`), the post-spawn classification
//! (`Result<()>` propagation, `stdout.is_empty()` bail, `serde_json`
//! parse, ternary success / empty / other), and the `op` label on the
//! spawn-anyhow surface. A `Command`-builder primitive would have to
//! expose all three axes as parameters; the argv slice owns only the
//! shape that every `Command`-family adapter's `.args()` (and any
//! `&[&str]`-taking helper) consumes identically. Modeled on
//! [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`],
//! [`crate::kubectl_get_databasemigration_status_phase_argv::kubectl_get_databasemigration_status_phase_argv`],
//! and [`crate::kubectl_get_job_condition_status_argv`] — enum-driven
//! argv-slice primitives that partition their tool's duplication budget
//! without collapsing the spawn / classify / display layers that
//! legitimately diverge downstream.
//!
//! # Distinct from the jsonpath phase-readout primitive
//!
//! [`crate::kubectl_get_databasemigration_status_phase_argv::kubectl_get_databasemigration_status_phase_argv`]
//! reads a jsonpath projection of a single scalar field
//! (`jsonpath={.status.phase}`) whose downstream classify expects a
//! trimmed phase string. This primitive reads a whole-object rendering
//! under one of kubectl's standard `-o <format>` names (`wide` /
//! `name` / `json`) whose downstream classify runs a table display, an
//! emptiness gate, or a `serde_json::from_slice` parse. The two
//! families carry genuinely distinct downstream contracts and belong
//! at distinct typed primitives; the jsonpath primitive stays
//! parameter-less because it has exactly one caller-selectable axis
//! (name / namespace) and this primitive adds the `format` axis
//! precisely because its consumers need three of the standard
//! renderers.

/// Closed enum naming which `-o <format>` renderer the whole-object
/// `kubectl get databasemigration` argv emits. Divergent per-variant
/// [`DatabaseMigrationGetOutputFormat::format_literal`] projections
/// encode the exact byte shape of the emitted `-o` value for every
/// current consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseMigrationGetOutputFormat {
    /// `-o wide` — the human-readable table renderer with extra
    /// columns beyond the default `get`. Read at
    /// `reset_migration`'s post-reset verify-status display, whose
    /// caller pipes the kubectl-rendered table straight to stdout
    /// via [`crate::retry::run_inherited_status`].
    Wide,
    /// `-o name` — the minimal `<kind>/<name>` renderer, emitted on
    /// stdout only if the object exists. Read at the two soft /
    /// hard existence gates (`run_migration` pre-check bailing on
    /// `stdout.is_empty()`; `set_expected_tag_if_exists` gating the
    /// follow-on `annotate` spawn on `success() &&
    /// !stdout.is_empty()`).
    Name,
    /// `-o json` — the full-object JSON renderer. Read at
    /// `fetch_shinka_status`, whose caller pipes the stdout bytes
    /// into `serde_json::from_slice::<ShinkaCrdStatus>` with a
    /// `default()` fall-through on any failure.
    Json,
}

impl DatabaseMigrationGetOutputFormat {
    /// The exact `-o` value this variant emits as the seventh argv
    /// element on a `kubectl get databasemigration … -o <format>`
    /// spawn. `&'static str` because every variant's literal is a
    /// compile-time constant; coerces into any lifetime a caller
    /// composes over the surrounding
    /// [`kubectl_get_databasemigration_output_argv`] array.
    pub(crate) fn format_literal(self) -> &'static str {
        match self {
            Self::Wide => "wide",
            Self::Name => "name",
            Self::Json => "json",
        }
    }
}

/// The pre-lift 7-element `get databasemigration <name> -n <namespace>
/// -o <format>` argv slice used at every whole-object Shinka
/// `DatabaseMigration` fetch site.
///
/// Callers assemble the surrounding builder chain
/// (`kubectl_command_async()`, `.output().await` /
/// [`crate::retry::run_inherited_status`] /
/// [`crate::infrastructure::kubectl::kubectl_output_spawn_anyhow`],
/// post-spawn classification, and the `op` label on the spawn-anyhow
/// surface) themselves — those axes vary across the four consumers.
/// This primitive owns ONLY the 7-element argv shape and the per-format
/// `-o` literal.
///
/// # Element layout
///
/// - `argv[0] = "get"` — kubectl verb.
/// - `argv[1] = "databasemigration"` — the singular Shinka
///   `DatabaseMigration` CRD kind, preserved byte-for-byte to match
///   the sibling
///   [`crate::kubectl_get_databasemigration_status_phase_argv`]
///   primitive.
/// - `argv[2] = <name>` — caller-supplied `DatabaseMigration` name.
/// - `argv[3] = "-n"` — namespace-scope flag.
/// - `argv[4] = <namespace>` — caller-supplied namespace.
/// - `argv[5] = "-o"` — output-format flag.
/// - `argv[6] = <format.format_literal()>` — one of `"wide"` /
///   `"name"` / `"json"` dispatched off the
///   [`DatabaseMigrationGetOutputFormat`] variant.
///
/// # Lifetime discipline
///
/// The returned array borrows `name` and `namespace` under a single
/// `'a` bound. The `format.format_literal()` element is a
/// `&'static str` and coerces into `'a` freely, matching the
/// discipline in
/// [`crate::first_pod_field_argv::first_pod_field_get_pods_argv`]
/// and
/// [`crate::kubectl_get_databasemigration_status_phase_argv::kubectl_get_databasemigration_status_phase_argv`].
pub(crate) fn kubectl_get_databasemigration_output_argv<'a>(
    name: &'a str,
    namespace: &'a str,
    format: DatabaseMigrationGetOutputFormat,
) -> [&'a str; 7] {
    [
        "get",
        "databasemigration",
        name,
        "-n",
        namespace,
        "-o",
        format.format_literal(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`DatabaseMigrationGetOutputFormat::Wide`] projects
    /// exactly `"wide"`. A drift to a synonym kubectl also accepts
    /// (e.g., a hypothetical `"wide-table"` alias) or to a bare `""`
    /// would silently change the rendered stdout the operator sees at
    /// `reset_migration`'s verify-status display.
    #[test]
    fn test_output_format_wide_literal_matches_pre_lift_bytes() {
        assert_eq!(
            DatabaseMigrationGetOutputFormat::Wide.format_literal(),
            "wide"
        );
    }

    /// Byte-oracle: [`DatabaseMigrationGetOutputFormat::Name`] projects
    /// exactly `"name"`. A drift to a different existence-cheap
    /// renderer (`"custom-columns=NAME:.metadata.name"`) would still
    /// pass the `stdout.is_empty()` gate on `NotFound` but change the
    /// non-empty stdout shape the two consumer sites read.
    #[test]
    fn test_output_format_name_literal_matches_pre_lift_bytes() {
        assert_eq!(
            DatabaseMigrationGetOutputFormat::Name.format_literal(),
            "name"
        );
    }

    /// Byte-oracle: [`DatabaseMigrationGetOutputFormat::Json`] projects
    /// exactly `"json"`. A drift to `"yaml"` would silently break
    /// `fetch_shinka_status`'s `serde_json::from_slice::<ShinkaCrdStatus>`
    /// parse (a YAML document is not a JSON document), collapsing every
    /// call to the `default()` `ShinkaCrdStatus` fall-through.
    #[test]
    fn test_output_format_json_literal_matches_pre_lift_bytes() {
        assert_eq!(
            DatabaseMigrationGetOutputFormat::Json.format_literal(),
            "json"
        );
    }

    /// The three variants project pairwise-distinct `-o` literals. A
    /// future refactor that accidentally folded two arms of the
    /// `match` onto the same string would silently route one caller's
    /// spawn onto another's renderer — e.g., routing `Json` onto
    /// `"name"` and starving `fetch_shinka_status`'s JSON parse of
    /// its input, or routing `Name` onto `"json"` and letting a
    /// non-empty JSON document pass the `stdout.is_empty()` gate on
    /// clusters where the CRD legitimately does not exist.
    #[test]
    fn test_output_format_variants_project_distinct_literals() {
        let wide = DatabaseMigrationGetOutputFormat::Wide.format_literal();
        let name = DatabaseMigrationGetOutputFormat::Name.format_literal();
        let json = DatabaseMigrationGetOutputFormat::Json.format_literal();
        assert_ne!(wide, name);
        assert_ne!(name, json);
        assert_ne!(wide, json);
    }

    /// Byte-oracle: [`kubectl_get_databasemigration_output_argv`]
    /// returns the pre-lift 7-element slice element-for-element for
    /// every variant, in the pre-lift order, with no extra element
    /// and no rewritten value. A future refactor that (a) reordered
    /// the flag/value pairs, (b) added a `--kubeconfig <path>` or
    /// `--context <ctx>` companion, (c) swapped `-n` for
    /// `--namespace`, or (d) swapped `-o` for `--output` regresses
    /// this assertion.
    #[test]
    fn test_argv_emits_pre_lift_seven_element_slice_for_every_variant() {
        for (format, tail) in [
            (DatabaseMigrationGetOutputFormat::Wide, "wide"),
            (DatabaseMigrationGetOutputFormat::Name, "name"),
            (DatabaseMigrationGetOutputFormat::Json, "json"),
        ] {
            let argv = kubectl_get_databasemigration_output_argv("cart-api", "cart", format);
            assert_eq!(argv[0], "get");
            assert_eq!(argv[1], "databasemigration");
            assert_eq!(argv[2], "cart-api");
            assert_eq!(argv[3], "-n");
            assert_eq!(argv[4], "cart");
            assert_eq!(argv[5], "-o");
            assert_eq!(argv[6], tail);
            assert_eq!(argv.len(), 7);
        }
    }

    /// The return type is a fixed-arity `[&str; 7]`, NOT a
    /// `Vec<&str>` or a `&[&str]`. A type change to a `Vec<String>`
    /// would allow a caller to `.push` a stray argument without
    /// touching this module; a change to a slice reference would allow
    /// an unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 7]` shape, this line fails to type-check.
    #[test]
    fn test_argv_returns_fixed_arity_seven() {
        let argv: [&str; 7] = kubectl_get_databasemigration_output_argv(
            "m",
            "ns",
            DatabaseMigrationGetOutputFormat::Json,
        );
        let [a0, a1, a2, a3, a4, a5, a6] = argv;
        assert_eq!(a0, "get");
        assert_eq!(a1, "databasemigration");
        assert_eq!(a2, "m");
        assert_eq!(a3, "-n");
        assert_eq!(a4, "ns");
        assert_eq!(a5, "-o");
        assert_eq!(a6, "json");
    }

    /// Interpolation-position pin: `name` lands at index 2,
    /// `namespace` lands at index 4. A future refactor that swapped
    /// them (e.g., an argv-order shuffle putting `-n <ns>` before the
    /// resource name) would silently pass the namespace as the
    /// `DatabaseMigration` name and the name as the namespace against
    /// the running cluster. Two distinct string arguments make the
    /// swap observable at the assertion level.
    #[test]
    fn test_argv_places_name_at_index_2_and_namespace_at_index_4() {
        let argv = kubectl_get_databasemigration_output_argv(
            "name-alpha",
            "ns-beta",
            DatabaseMigrationGetOutputFormat::Wide,
        );
        assert_eq!(
            argv[2], "name-alpha",
            "index 2 must carry the DatabaseMigration name argument"
        );
        assert_eq!(
            argv[4], "ns-beta",
            "index 4 must carry the namespace argument"
        );
        assert_ne!(argv[2], argv[4], "name and namespace must not collide");
    }

    /// Variant-dispatch pin: index 6 tracks the passed `format`, NOT
    /// a hard-coded constant. Guards against a regression that
    /// ignored the `format` argument and always emitted (e.g.)
    /// `"json"`, silently routing every consumer onto the JSON
    /// renderer and collapsing `reset_migration`'s human-readable
    /// table into a raw JSON dump on stdout.
    #[test]
    fn test_argv_dispatches_each_variant_onto_its_own_tail() {
        let wide = kubectl_get_databasemigration_output_argv(
            "m",
            "ns",
            DatabaseMigrationGetOutputFormat::Wide,
        );
        let name = kubectl_get_databasemigration_output_argv(
            "m",
            "ns",
            DatabaseMigrationGetOutputFormat::Name,
        );
        let json = kubectl_get_databasemigration_output_argv(
            "m",
            "ns",
            DatabaseMigrationGetOutputFormat::Json,
        );
        assert_eq!(wide[6], "wide");
        assert_eq!(name[6], "name");
        assert_eq!(json[6], "json");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift 7-element argv
    /// literal for any of the three renderer variants inline any
    /// more. The four pre-lift sites migrated; any future consumer
    /// that wants the same whole-object Shinka `DatabaseMigration`
    /// fetch shape reaches for
    /// [`kubectl_get_databasemigration_output_argv`] on first grep,
    /// not by copy-pasting the raw literal from an existing module.
    ///
    /// Mirrors the negative half of the sibling shields on
    /// [`crate::first_pod_field_argv`] and
    /// [`crate::kubectl_get_databasemigration_status_phase_argv`].
    /// Anchored on the adjacent-line pair `"databasemigration"` +
    /// one of `"wide"` / `"name"` / `"json"` on the `-o` tail — a
    /// future consumer that reads a different renderer (a jsonpath
    /// projection, a `-o yaml` dump, a custom-columns template) is
    /// deliberately outside the shield's scope.
    #[test]
    fn no_command_module_still_spells_raw_databasemigration_get_output_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let tails = ["\"wide\"", "\"name\"", "\"json\""];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
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
                if !line.contains("\"databasemigration\"") {
                    continue;
                }
                let window_end = (idx + 8).min(lines.len());
                let window: String = lines[idx..window_end].join("\n");
                if !window.contains("\"get\"") {
                    continue;
                }
                if !window.contains("\"-n\"") {
                    continue;
                }
                if !window.contains("\"-o\"") {
                    continue;
                }
                if !tails.iter().any(|t| window.contains(t)) {
                    continue;
                }
                offenders.push((path.clone(), idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `get databasemigration … -o (wide|name|json)` argv literal(s) survive \
             under `commands/` — route each through \
             `crate::kubectl_get_databasemigration_output_argv::\
             kubectl_get_databasemigration_output_argv()` with a \
             `DatabaseMigrationGetOutputFormat` variant instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift module that
    /// housed the four sites MUST forward through
    /// [`kubectl_get_databasemigration_output_argv`] at least four
    /// times, so a migration that dropped a call site outright
    /// leaves the negative "no raw inline shape" scan trivially
    /// satisfied by absence but the positive count still fails.
    /// Mirrors the sibling `every_prelift_module_forwards_through_*`
    /// shields the crate carries against every other typed argv
    /// primitive.
    #[test]
    fn every_prelift_module_forwards_through_kubectl_get_databasemigration_output_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("commands").join("migrations.rs"), 4)];
        let needle = "kubectl_get_databasemigration_output_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} Shinka DatabaseMigration \
                 whole-object fetch site(s) through `{}`; found {}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
