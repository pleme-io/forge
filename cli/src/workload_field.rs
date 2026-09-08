//! Info-routed `"   <WorkloadKind>: <name>"` three-space-indented
//! Kubernetes-workload field-readout grammar.
//!
//! Two pre-lift sibling sites across
//! `commands/{rollout (×1: rollback branch of `execute`, immediately
//! below `crate::info_namespace_field!(namespace)` and above the
//! terminating `println!();` at the end of the rollback preamble),
//! github_runner_ci (×1: watch branch of `execute`, immediately below
//! `crate::info_namespace_field!(namespace)` and above the terminating
//! `println!();` at the end of the watch preamble)}.rs` each restated
//! the byte-identical (modulo the workload-kind label) stanza:
//!
//! ```ignore
//! // commands/rollout.rs (rollback branch)
//! info!("   Deployment: {}", name);
//!
//! // commands/github_runner_ci.rs (watch branch)
//! info!("   StatefulSet: {}", name);
//! ```
//!
//! Three ASCII spaces of indent, the workload-kind label
//! (`Deployment` or `StatefulSet`), a colon, one ASCII space, the
//! interpolated [`std::fmt::Display`]-formatted name, and an
//! `info!`-routed emission via the tracing subscriber. Post-lift the
//! sites reach for [`info_workload_field!`] and the indent width +
//! separator + tracing verbosity are decided once here; the enum
//! [`KubernetesWorkloadKind`] owns the byte-for-byte spelling of each
//! variant's label.
//!
//! # Paired with the sibling `Namespace:` readout
//!
//! Both pre-lift sites emit this stanza IMMEDIATELY BELOW the sibling
//! [`crate::info_namespace_field!`] emission, forming a two-line
//! `Namespace` / `<Workload>` sub-item pair under a parent
//! emoji-anchored header (`🔄 Performing rollback...` in `rollout.rs`,
//! `👀 Watching StatefulSet rollout...` in `github_runner_ci.rs`).
//! The two primitives are deliberately kept separate: the
//! `Namespace:` label never varies across sites and needs no enum,
//! while the workload-kind label varies per site and needs the
//! [`KubernetesWorkloadKind`] enum. Merging them would either
//! fabricate a workload-kind selector on every namespace readout
//! (there are more namespace sites than workload sites in this
//! grammar family), or drop the enum-driven kind spelling this
//! primitive owns.
//!
//! # The load-bearing three-space indent
//!
//! Both pre-lift sites spell the stanza with EXACTLY THREE ASCII
//! spaces of indent, matching the sibling three-space-indented field
//! readouts elsewhere in the same command modules — and matching the
//! immediately-preceding [`crate::info_namespace_field!`] emission on
//! the pair's first line. A future collapse to a two-space or
//! four-space grammar would misalign the whole family. Pin the
//! three-space width so a drift hits the byte-oracle test rather
//! than shipping a misaligned sub-item under the parent header.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic
//! source-location capture (`file` + `line` + `module_path`) matches
//! the pre-lift behavior byte-for-byte. A function-based wrapper
//! would collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::rollout=info` would stop matching
//! once the emission moved to `forge::workload_field`). The
//! byte-oracle writer sibling [`write_workload_field`] captures the
//! exact rendered body for the tests so the invariant is pinned
//! without racing an ambient tracing subscriber — the same split
//! [`crate::namespace_field::write_namespace_field`] carries against
//! [`crate::info_namespace_field!`].

use std::fmt;
use std::io;

/// The Kubernetes workload-kind label the caller emits as the second
/// line of the `Namespace` / `<Workload>` sub-item pair. Each variant
/// maps to a fixed byte-string label that the writer stamps between
/// the three-space indent and the trailing `: <name>` slot.
///
/// Pre-lift the label was baked into the format string at each of
/// the two consumer sites (`"Deployment"` at `commands/rollout.rs:29`
/// under the rollback branch, `"StatefulSet"` at
/// `commands/github_runner_ci.rs:517` under the watch branch);
/// post-lift the enum owns the byte-level spelling at exactly one
/// site. Adding a third workload kind (e.g. `DaemonSet`, `Job`) is
/// one new variant plus one [`KubernetesWorkloadKind::label`] arm —
/// the surrounding indent + separator grammar stays fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KubernetesWorkloadKind {
    /// A `Deployment` workload — the rollback branch in
    /// `commands/rollout.rs::execute` emits under this label
    /// immediately below the sibling namespace readout.
    Deployment,
    /// A `StatefulSet` workload — the watch branch in
    /// `commands/github_runner_ci.rs::execute` emits under this
    /// label immediately below the sibling namespace readout.
    StatefulSet,
}

impl KubernetesWorkloadKind {
    /// The fixed PascalCase workload-kind label emitted between the
    /// three-space indent and the trailing `: <name>` slot.
    ///
    /// Pre-lift the label was baked into the format string at each
    /// site; the byte-for-byte spelling matches the upstream
    /// Kubernetes API kind (`Deployment`, `StatefulSet`) and is
    /// named as a `const fn` so a future addition of a third
    /// workload cannot drift the label formatting from what
    /// `kubectl get <kind>` accepts.
    pub const fn label(self) -> &'static str {
        match self {
            KubernetesWorkloadKind::Deployment => "Deployment",
            KubernetesWorkloadKind::StatefulSet => "StatefulSet",
        }
    }
}

impl fmt::Display for KubernetesWorkloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Emits a single `"   <kind.label()>: <name>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's workload name
/// with the pre-lift three-ASCII-space indent + kind-label + `: `
/// separator prefix that two sibling sites spelled inline.
///
/// The [`crate::info_workload_field!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can
/// pin the exact emitted bytes (the three-space indent, the
/// enum-selected label literal, the single-space gap before the
/// name, the trailing newline) without capturing a tracing
/// subscriber and without racing an ambient logger — the same split
/// [`crate::namespace_field::write_namespace_field`] carries against
/// [`crate::info_namespace_field!`].
///
/// The `name` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str`, an owned `String` (both
/// pre-lift call sites' shape today, sourced from a `name: String`
/// function parameter), `Cow<str>`, and a future
/// Kubernetes-workload-name newtype (`substrate::WorkloadName(String)`)
/// all flow through the same writer without a per-caller
/// `.to_string()` intermediate.
#[allow(dead_code)] // Peer of the tracing-routed `info_workload_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_workload_field<W: io::Write>(
    w: &mut W,
    kind: KubernetesWorkloadKind,
    name: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "   {}: {}", kind.label(), name)
}

/// Emit a sub-item Kubernetes-workload field readout via
/// [`tracing::info!`] on the fleet-standard
/// `"   <kind>: <name>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at
/// the caller's location so tracing's automatic source-location
/// capture is preserved (a function wrapper would collapse every
/// emission to the wrapper's site — see the module docs for why
/// that breaks per-module filter routing). See the [module docs](self)
/// for the sibling site census, the split against
/// [`crate::info_namespace_field!`] (paired first line of the
/// two-line sub-item pair), and the compounding rationale for the
/// load-bearing three-space indent.
///
/// # Examples
///
/// ```ignore
/// use crate::workload_field::KubernetesWorkloadKind;
///
/// // Pre-lift
/// info!("   Deployment: {}", name);
///
/// // Post-lift
/// crate::info_workload_field!(KubernetesWorkloadKind::Deployment, name);
/// ```
#[macro_export]
macro_rules! info_workload_field {
    ($kind:expr, $name:expr) => {
        ::tracing::info!("   {}: {}", $kind, $name)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces (0x20 0x20 0x20),
    // the literal `Deployment:` (11 bytes), one ASCII space, the
    // interpolated name Display, then `\n`. A future refactor that
    // changes the indent width, drops the colon, changes the label
    // capitalization, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_workload_field_deployment_emits_three_space_indent_label_name_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_workload_field(&mut buf, KubernetesWorkloadKind::Deployment, &"api-server").unwrap();
        assert_eq!(buf, b"   Deployment: api-server\n");
    }

    // Same pin for the `StatefulSet` variant — the other pre-lift
    // consumer site.
    #[test]
    fn write_workload_field_statefulset_emits_three_space_indent_label_name_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_workload_field(
            &mut buf,
            KubernetesWorkloadKind::StatefulSet,
            &"github-runner",
        )
        .unwrap();
        assert_eq!(buf, b"   StatefulSet: github-runner\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_workload_field_renders_expected_grammar_for_both_kinds() {
        for (kind, name, expected) in [
            (
                KubernetesWorkloadKind::Deployment,
                "api-server",
                "   Deployment: api-server\n",
            ),
            (
                KubernetesWorkloadKind::StatefulSet,
                "github-runner",
                "   StatefulSet: github-runner\n",
            ),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_workload_field(&mut buf, kind, &name).unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), expected);
        }
    }

    // Pin the enum's `Display` impl matches `label()` byte-for-byte —
    // the macro expands to `::tracing::info!("   {}: {}", $kind, $name)`
    // and depends on the enum's Display emitting the same bytes the
    // writer stamps via `label()`. A drift between the two would
    // desynchronize the macro from the byte-oracle writer.
    #[test]
    fn kind_display_matches_label_byte_for_byte() {
        for kind in [
            KubernetesWorkloadKind::Deployment,
            KubernetesWorkloadKind::StatefulSet,
        ] {
            assert_eq!(format!("{}", kind), kind.label());
        }
    }

    // Pin the label byte-strings match the upstream Kubernetes API
    // kind names — a future rename to `deployment` or `stateful_set`
    // would break `kubectl get <kind>` invocation parity for any
    // consumer that echoed the label into a kubectl argv.
    #[test]
    fn label_matches_upstream_kubernetes_api_kind_names() {
        assert_eq!(KubernetesWorkloadKind::Deployment.label(), "Deployment");
        assert_eq!(KubernetesWorkloadKind::StatefulSet.label(), "StatefulSet");
    }

    // Guard against a two-space-indent drift: the sibling
    // `info_namespace_field!` emission that this stanza pairs with
    // carries a THREE-space indent, and the pair reads as a two-line
    // sub-item block under the parent header. Pin the three-space
    // width so a future collapse to a two-space (`  `) or four-space
    // (`    `) grammar hits the byte-oracle test rather than shipping
    // a misaligned sub-item under the parent header.
    #[test]
    fn write_workload_field_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_workload_field(&mut buf, KubernetesWorkloadKind::Deployment, &"app").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Deployment:"),
            "must start with three spaces + label; got: {s:?}"
        );
        assert!(
            !s.starts_with("  Deployment:"),
            "must NOT be two-space indent; got: {s:?}"
        );
        assert!(
            !s.starts_with("    Deployment:"),
            "must NOT be four-space indent; got: {s:?}"
        );
    }

    // No-emoji guard: the pre-lift sites carry NO glyph anchor (the
    // parent header — `🔄 Performing rollback...` /
    // `👀 Watching StatefulSet rollout...` — is emitted separately by
    // the caller). Pin that this primitive emits no leading emoji so
    // a future refactor that reached for `📦`, `🚀`, or `⚙️` on the
    // label side would break the sub-item vs top-level shape split.
    #[test]
    fn write_workload_field_emits_no_leading_emoji_glyph() {
        for kind in [
            KubernetesWorkloadKind::Deployment,
            KubernetesWorkloadKind::StatefulSet,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_workload_field(&mut buf, kind, &"app").unwrap();
            let s = String::from_utf8(buf).unwrap();
            // Every codepoint in the pre-lift render is ASCII — a
            // stray non-ASCII byte means an emoji or glyph slipped in.
            assert!(
                s.is_ascii(),
                "must emit ASCII-only bytes (no emoji); got: {s:?}"
            );
        }
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization
    // in `main.rs` deliberately sets `with_ansi(false)` so CI log
    // ingestion sees clean records. Pin that this primitive's render
    // carries no ANSI escape byte (0x1B) — a future refactor that
    // reached for `colored` on the label side would break the
    // ANSI-free contract the tracing-routed sites depend on.
    #[test]
    fn write_workload_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_workload_field(&mut buf, KubernetesWorkloadKind::Deployment, &"app").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_workload_field must emit no ANSI escape (0x1B) — \
             the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // A Kubernetes workload name is a DNS-1123 subdomain — lowercase
    // alphanumeric + hyphens + dots, 1..=253 chars. Pin that the
    // writer forwards a canonical 63-char label verbatim (no
    // truncation, no case-fold, no hyphen mangling). Guards against
    // a future helper that "sanitizes" the name at the primitive
    // layer, which the caller must have already done at input
    // validation.
    #[test]
    fn write_workload_field_forwards_max_length_dns1123_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let name = "a".repeat(63);
        write_workload_field(&mut buf, KubernetesWorkloadKind::StatefulSet, &name).unwrap();
        let expected = format!("   StatefulSet: {}\n", name);
        assert_eq!(String::from_utf8(buf).unwrap(), expected);
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro accepts the supported arg shapes by expanding it at
    // compile time — a compile-fail here would fail the crate's
    // `cargo test` build gate.
    #[test]
    fn info_workload_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (a function local of the pre-lift call sites).
        let name_str: &str = "app";
        crate::info_workload_field!(KubernetesWorkloadKind::Deployment, name_str);

        // Owned `String` via the same slot — both pre-lift call
        // sites receive a `name: String` function parameter and pass
        // it as `name` (bare Display forward of `&String`, which the
        // format machinery resolves through Deref to `&str`).
        let owned = String::from("app");
        crate::info_workload_field!(KubernetesWorkloadKind::StatefulSet, owned);

        // A `&String` reference — every pre-lift call site's actual
        // shape today: `name: String` param passed as `name` which
        // is a lvalue of type `String`, format machinery takes its
        // Display through `&String` -> `&str`.
        let borrowed = &String::from("app");
        crate::info_workload_field!(KubernetesWorkloadKind::Deployment, borrowed);

        // A future substrate::WorkloadName newtype would implement
        // Display — simulate with a Display-wrapping newtype to
        // prove the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_workload_field!(KubernetesWorkloadKind::StatefulSet, Wrap("app"));
    }

    // Caller shield (negative): no source line under
    // `cli/src/commands/` may spell the pre-lift raw
    // `info!("   Deployment: {}", <arg>);` or
    // `info!("   StatefulSet: {}", <arg>);` stanza inline any more.
    // The two pre-lift sites migrated; any future consumer that
    // wants the same grammar reaches for `crate::info_workload_field!`
    // on first grep, not by copy-pasting the raw shape from an
    // existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_workload_field_stanza() {
        use std::path::PathBuf;
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
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own reference
                // to the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"   Deployment: {}\"")
                    || line.contains("info!(\"   StatefulSet: {}\"")
                {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   <Deployment|StatefulSet>: {{}}\", <arg>);` \
             stanza(s) survive under `commands/` — route each through \
             `crate::info_workload_field!(KubernetesWorkloadKind::<Kind>, \
             <name>)` instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield (positive): the two pre-lift files MUST each
    // forward through `crate::info_workload_field!(` at least once,
    // so a migration that dropped a call site outright leaves the
    // negative "no raw inline shape" scan trivially satisfied by
    // absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_workload_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("rollout.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_workload_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} workload \
                 sub-item site(s) through `crate::info_workload_field!(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
