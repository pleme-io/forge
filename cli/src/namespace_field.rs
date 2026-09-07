//! Info-routed `   Namespace: <namespace>` three-space-indented
//! Kubernetes-namespace field-readout grammar.
//!
//! Two pre-lift sibling sites across `commands/{rollout (×1: rollback
//! branch of `execute`, immediately below `info!("🔄 Performing
//! rollback...")` and above `info!("   Deployment: {}", name)`),
//! github_runner_ci (×1: watch branch of `execute`, immediately below
//! `info!("👀 Watching StatefulSet rollout...")` and above
//! `info!("   StatefulSet: {}", name)`)}.rs` each restated the
//!
//! ```ignore
//! info!("   Namespace: {}", namespace);
//! ```
//!
//! stanza verbatim — three ASCII spaces of indent, the ten-character
//! `Namespace:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted namespace string, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_namespace_field!`] and the indent width + label + separator +
//! tracing verbosity are decided once here.
//!
//! # Distinct from every sibling emoji-labeled tag-field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>` field
//! primitives ([`crate::info_git_sha_field!`],
//! [`crate::info_registry_field!`], [`crate::info_deploy_target_field!`],
//! [`crate::info_tags_field!`]) that all emit a zero-indent
//! glyph-anchored preamble line. This primitive is deliberately **not**
//! one of them: the pre-lift stanza carries a three-ASCII-space indent
//! (it is a sub-item under the parent emoji-anchored header emitted
//! separately by the caller — `🔄 Performing rollback...` in `rollout.rs`,
//! `👀 Watching StatefulSet rollout...` in `github_runner_ci.rs`) and
//! NO emoji glyph. A merge into any `<emoji> Label:` primitive would
//! either fabricate a glyph the two pre-lift sites did not carry, or
//! force the sibling emoji primitives to drop their zero-indent anchor.
//!
//! The nearest sibling is [`crate::info_zone_id_field!`]
//! (`   Zone ID: <prefix>***`) — also three-space-indented, also
//! glyphless, also field-readout under an emoji-anchored parent header.
//! Those two primitives share a shape class (three-space-indented
//! `<Label>: <value>` field readouts under an emoji-anchored parent) but
//! carry different labels and different value shapes (a zone_id readout
//! is masked to a fixed prefix + `***` suffix; a namespace readout is
//! bare Display). A merge would either fabricate a masking suffix the
//! namespace sites did not carry, or drop the masking the zone_id sites
//! rely on for tenant-identity hygiene.
//!
//! # Distinct from the sibling `🌍 Namespace:` primitive
//!
//! `commands/comprehensive_release.rs::execute` carries a
//! `info!("🌍 Namespace: {} (staging)", namespace);` stanza at the
//! pre-workflow preamble — same `Namespace:` label, but with a `🌍`
//! GLOBE glyph anchor (top-level preamble grammar, not a sub-item under
//! a parent header) AND with a `(staging)` trailing environment marker.
//! That site emits with zero indent and a per-environment suffix; the
//! two pre-lift sites this primitive covers emit with a three-space
//! indent and no suffix. The two shapes are deliberately separate:
//!
//! - `🌍 Namespace: <ns> (staging)` — top-level workflow preamble with an
//!   environment marker; emitted once per `comprehensive_release` invocation,
//!   part of the initial `📦 Git SHA` / `🎯 Registry` / `🌍 Namespace`
//!   header trio.
//! - `   Namespace: <ns>` — sub-item field readout under a parent header
//!   (`🔄 Performing rollback...` / `👀 Watching StatefulSet rollout...`);
//!   emitted per-command, part of a `   Namespace` / `   Deployment` |
//!   `   StatefulSet` per-workload pair.
//!
//! A merge would either force the `comprehensive_release` site to lose
//! its `(staging)` marker (or drop the `🌍` anchor), or force the two
//! sub-item sites to fabricate an environment marker they have no source
//! for. Both directions erase load-bearing information.
//!
//! # The load-bearing three-space indent
//!
//! Both pre-lift sites spell the stanza with EXACTLY THREE ASCII spaces
//! of indent, matching the sibling three-space-indented field readouts
//! elsewhere in the same command modules:
//!
//! - `rollout.rs::execute` (rollback branch): the `Namespace` line at
//!   `:28` is immediately followed by `info!("   Deployment: {}", name);`
//!   at `:29`, then `println!();` at `:30` — a three-line pair-plus-break
//!   under the parent `🔄 Performing rollback...` header.
//! - `github_runner_ci.rs::execute` (watch branch): the `Namespace` line
//!   at `:517` is immediately followed by `info!("   StatefulSet: {}", name);`
//!   at `:518`, then `println!();` at `:519` — the same three-line
//!   pair-plus-break shape under the parent `👀 Watching StatefulSet
//!   rollout...` header.
//!
//! The three-space grammar aligns visually with the sibling `   URL:` /
//! `   Cache:` / `   Old tag:` / `   New tag:` / `   Total replicas:` /
//! `   Expected image tag:` field readouts scattered across the same
//! command modules. A future collapse to a two-space or four-space
//! grammar would misalign the whole family. Pin the three-space width
//! so a drift hits the byte-oracle test rather than shipping a
//! misaligned sub-item under the parent header.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift
//! behavior byte-for-byte. A function-based wrapper would collapse every
//! emission to the wrapper's own site and break structured-log
//! destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::rollout=info` would stop matching once
//! the emission moved to `forge::namespace_field`). The byte-oracle
//! writer sibling [`write_namespace_field`] captures the exact rendered
//! body for the tests (the three-space indent, the `Namespace:` label,
//! the single-space gap before the namespace, the trailing newline) so
//! the invariant is pinned without racing an ambient tracing subscriber
//! — the same split
//! [`crate::zone_id_field::write_zone_id_field`] carries against
//! [`crate::info_zone_id_field!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"   Namespace: <namespace>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's namespace with the
/// pre-lift three-ASCII-space indent + `Namespace: ` label prefix that
/// two sibling sites spelled inline.
///
/// The [`crate::info_namespace_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the three-space indent, the `Namespace:` label literal, the
/// single-space gap before the namespace, the trailing newline) without
/// capturing a tracing subscriber and without racing an ambient logger
/// — the same split
/// [`crate::zone_id_field::write_zone_id_field`] carries against
/// [`crate::info_zone_id_field!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `namespace` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (both pre-lift call sites' shape
/// today, sourced from a `String` function parameter), an owned
/// `String`, `Cow<str>`, and a future Kubernetes-namespace newtype
/// (`substrate::KubeNamespace(String)`) all flow through the same
/// writer without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // Peer of the tracing-routed `info_namespace_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_namespace_field<W: io::Write>(
    w: &mut W,
    namespace: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "   Namespace: {}", namespace)
}

/// Emit a sub-item Kubernetes-namespace field readout via
/// [`tracing::info!`] on the fleet-standard
/// `"   Namespace: <namespace>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::info_zone_id_field!`] (same
/// indent, different label, masked value), against the
/// `comprehensive_release`'s zero-indent `🌍 Namespace: <ns> (staging)`
/// shape (top-level preamble with environment marker), and the
/// compounding rationale for the load-bearing three-space indent.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("   Namespace: {}", namespace);
///
/// // Post-lift
/// crate::info_namespace_field!(namespace);
/// ```
#[macro_export]
macro_rules! info_namespace_field {
    ($namespace:expr) => {
        ::tracing::info!("   Namespace: {}", $namespace)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces (0x20 0x20 0x20),
    // the literal `Namespace:` (10 bytes), one ASCII space, the
    // interpolated namespace Display, then `\n`. A future refactor that
    // changes the indent width, drops the colon, changes the label
    // capitalization, or drops the trailing newline regresses this
    // assertion.
    #[test]
    fn write_namespace_field_emits_three_space_indent_label_namespace_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"pleme-prod").unwrap();
        assert_eq!(buf, b"   Namespace: pleme-prod\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_namespace_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"pleme-prod").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   Namespace: pleme-prod\n"
        );
    }

    // A Kubernetes namespace name is a DNS-1123 label — lowercase
    // alphanumeric + hyphens, 1..=63 chars. Pin that the writer
    // forwards a canonical 63-char label verbatim (no truncation,
    // no case-fold, no hyphen mangling). Guards against a future
    // helper that "sanitizes" the namespace at the primitive layer,
    // which the caller must have already done at input validation.
    #[test]
    fn write_namespace_field_forwards_max_length_dns1123_label_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let ns = "a".repeat(63);
        write_namespace_field(&mut buf, &ns).unwrap();
        let expected = format!("   Namespace: {}\n", ns);
        assert_eq!(String::from_utf8(buf).unwrap(), expected);
    }

    // Guard against a two-space-indent drift: adjacent tracing lines in
    // the pre-lift rollback / rollout preambles carry a THREE-space
    // indent (a sub-item under the parent `🔄 Performing rollback...` /
    // `👀 Watching StatefulSet rollout...` header). Pin the three-space
    // width so a future collapse to a two-space (`  `) or four-space
    // (`    `) grammar hits the byte-oracle test rather than shipping
    // a misaligned sub-item under the parent header.
    #[test]
    fn write_namespace_field_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"ns").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Namespace:"),
            "must start with three spaces + label; got: {s:?}"
        );
        assert!(
            !s.starts_with("  Namespace:"),
            "must NOT be two-space indent; got: {s:?}"
        );
        assert!(
            !s.starts_with("    Namespace:"),
            "must NOT be four-space indent; got: {s:?}"
        );
    }

    // Guard against the sibling `🌍 Namespace:` shape drift: the
    // top-level `comprehensive_release.rs` preamble emits with a
    // `🌍` GLOBE glyph anchor AND a `(staging)` environment marker.
    // This primitive is the SUB-ITEM shape — no glyph, no marker.
    // A future collapse of the two shapes would either invent a
    // `(staging)` suffix the sub-item sites cannot source, or drop
    // the `🌍` anchor from the top-level site.
    #[test]
    fn write_namespace_field_emits_no_globe_glyph_and_no_environment_marker() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"pleme-prod").unwrap();
        let s = String::from_utf8(buf).unwrap();
        // No `🌍` GLOBE glyph (U+1F30D, F0 9F 8C 8D).
        assert!(
            !s.contains('\u{1F30D}'),
            "must NOT emit the sibling top-level `🌍` GLOBE anchor; got: {s:?}"
        );
        // No `(staging)` marker (or `(prod)`, `(dev)`, ...).
        assert!(
            !s.contains('('),
            "must NOT emit an environment marker; got: {s:?}"
        );
    }

    // Guard against the sibling `   Zone ID: <prefix>***` shape drift:
    // the sibling `info_zone_id_field!` primitive shares this
    // primitive's three-space-indented no-glyph shape but carries a
    // fixed `***` masking suffix. Pin that this primitive emits NO
    // masking suffix — a namespace is a public identifier, not a
    // secret, and its full value is intended to render.
    #[test]
    fn write_namespace_field_emits_no_masking_suffix() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"pleme-prod").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains('*'),
            "must NOT emit any masking asterisk — namespace is a public \
             identifier, not a secret. Actual: {s:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B) — a future refactor that reached for
    // `colored` on the label side would break the ANSI-free contract
    // the tracing-routed sites depend on.
    #[test]
    fn write_namespace_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_namespace_field(&mut buf, &"pleme-prod").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_namespace_field must emit no ANSI escape (0x1B) — \
             the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing whatever
    // subscriber `main` installs. Instead, pin that the macro accepts the
    // supported arg shapes by expanding it at compile time — a compile-fail
    // here would fail the crate's `cargo test` build gate.
    #[test]
    fn info_namespace_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (a function local of the pre-lift call sites).
        let ns_str: &str = "pleme-prod";
        crate::info_namespace_field!(ns_str);

        // Owned `String` via the same slot — both pre-lift call sites
        // receive a `namespace: String` function parameter and pass it
        // as `namespace` (bare Display forward of `&String`, which the
        // format machinery resolves through Deref to `&str`).
        let owned = String::from("pleme-prod");
        crate::info_namespace_field!(owned);

        // A `&String` reference — every pre-lift call site's actual
        // shape today: `namespace: String` param passed as `namespace`
        // which is a lvalue of type `String`, format machinery takes
        // its Display through `&String` -> `&str`.
        let borrowed = &String::from("pleme-prod");
        crate::info_namespace_field!(borrowed);

        // A future substrate::KubeNamespace newtype would implement
        // Display — simulate with a Display-wrapping newtype to prove
        // the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_namespace_field!(Wrap("pleme-prod"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("   Namespace: {}", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_namespace_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_namespace_field_stanza() {
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
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"   Namespace: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   Namespace: {{}}\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_namespace_field!(<namespace>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_namespace_field!(` at least once, so
    // a migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_namespace_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[("rollout.rs", 1), ("github_runner_ci.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_namespace_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} namespace \
                 sub-item site(s) through `crate::info_namespace_field!(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
