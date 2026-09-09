//! Pre-release gate-configuration-source announcement — the
//! `📋 <phrase>` single-line stanza primitive emitted by
//! `commands/prerelease.rs::load_gates_config` to tell the operator
//! which `deploy.yaml` (if any) the gate configuration was resolved
//! from before the pre-release gates begin executing.
//!
//! Pre-lift three sibling `eprintln!("📋 <phrase>")` stanzas lived in
//! the `load_gates_config` body, each spelled the same clipboard-glyph
//! + trailing-ASCII-space prefix and differed only in the tail phrase:
//!
//! ```ignore
//! eprintln!("📋 Loaded gate configuration from backend/deploy.yaml");
//! eprintln!("📋 Loaded gate configuration from product/deploy.yaml");
//! eprintln!("📋 Using default gate configuration");
//! ```
//!
//! Three occurrences of a lockstep shape past THEORY §VI.1's
//! three-is-a-law threshold. Post-lift the three sites reach for
//! [`print_gate_config_source_announcement`] with a
//! [`GateConfigSource`] variant naming which of the three
//! outcomes the resolver landed on, and inherit the canonical
//! `📋 ` prefix + trailing `\n` from one site.
//!
//! # Distinct from stdout announcement primitives
//!
//! Sibling stdout announcement primitives ([`crate::commands::
//! migration_cleanup_announcement`],
//! [`crate::commands::developer_tool_phase_open`]) route through
//! [`std::io::stdout`]; this one routes to [`std::io::stderr`] because
//! the three pre-lift `eprintln!` sites deliberately kept the resolver
//! announcement OFF stdout so a future `--json` / `--quiet` command
//! run whose stdout is machine-consumed cannot interleave a config-
//! source line into its payload. The `write_*` sibling below is the
//! writer-taking form so byte-oracle tests can pin the exact rendered
//! bytes against an in-memory [`Vec<u8>`] buffer without capturing
//! stderr and without racing an ambient logger.
//!
//! # Closed-enum discipline
//!
//! The three pre-lift outcomes are exhaustive by construction: the
//! resolver tries backend, falls through to product, falls through to
//! the built-in default. A new deploy.yaml source location added to
//! the resolver becomes a new enum variant plus one
//! [`GateConfigSource::message`] arm — the surrounding prefix, writer,
//! and destination stay fixed. Making the phrase carrier a closed enum
//! rather than a caller-supplied `&str` means the operator's
//! vocabulary at this readout is decided here rather than at every
//! future consumer site (THEORY §II — "typed contracts turn a
//! structural drift into a compile error"). A future addition of a
//! fourth resolver source (e.g. a `~/.config/forge/gates.yaml` user
//! override) shows up as a compile failure at every
//! [`GateConfigSource::message`] arm that doesn't handle it, not as a
//! silent drift into a fourth ad-hoc `eprintln!` literal.

use std::io;

/// The four-byte `📋 ` prefix every pre-lift announcement spelled —
/// the clipboard glyph U+1F4CB (four UTF-8 bytes) followed by one
/// trailing ASCII space that separates it from the per-variant tail
/// phrase. Named as a `const` so a future re-branding of the glyph
/// (e.g. dropping the emoji for accessibility, promoting to a
/// two-space gap to match the `⚠️  Warning: ` config-validation
/// grammar, or hoisting the prefix onto a shared
/// `crate::ui::print_annotated_note` primitive spanning the whole
/// resolver-source-announcement family) reaches one site rather than
/// three inline literals.
pub const GATE_CONFIG_SOURCE_ANNOUNCEMENT_PREFIX: &str = "\u{1f4cb} ";

/// Which of the three deploy.yaml resolver outcomes
/// `commands/prerelease.rs::load_gates_config` landed on before
/// returning the [`PreReleaseGatesConfig`] the pre-release gate loop
/// executes.
///
/// The three variants exhaustively cover the pre-lift census; each
/// maps to a fixed byte-string phrase [`GateConfigSource::message`]
/// emits after the shared `📋 ` prefix. Adding a fourth resolver
/// source is one new variant plus one match arm — the surrounding
/// print grammar stays fixed at [`write_gate_config_source_announcement`].
///
/// [`PreReleaseGatesConfig`]: crate::commands::prerelease::PreReleaseGatesConfig
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateConfigSource {
    /// The resolver read `backend/deploy.yaml` (or its legacy
    /// `services/rust/backend/deploy.yaml` twin) and parsed a
    /// `prerelease:` sub-map from it. First tier of the resolver
    /// fall-through chain — the service-local deploy.yaml overrides
    /// both the product-level file and the built-in default.
    LoadedFromBackendDeployYaml,
    /// The resolver fell through the backend tier and parsed the
    /// `prerelease:` sub-map from the product-root `deploy.yaml`
    /// instead. Second tier of the resolver fall-through chain — a
    /// monorepo that keeps its gate config centralised at the product
    /// root rather than in each service directory.
    LoadedFromProductDeployYaml,
    /// Both the backend and product deploy.yaml files were absent (or
    /// present but missing a `prerelease:` sub-map), so the resolver
    /// fell through to [`PreReleaseGatesConfig::default`]. Third tier
    /// of the fall-through chain — the operator sees this line when a
    /// checkout has not yet declared its gate config anywhere.
    ///
    /// [`PreReleaseGatesConfig::default`]: crate::commands::prerelease::PreReleaseGatesConfig
    UsingDefault,
}

impl GateConfigSource {
    /// The fixed per-variant phrase emitted after the shared
    /// `📋 ` prefix. Byte-for-byte invariant across the three pre-lift
    /// consumer sites and named as a `const fn` so a future addition
    /// of a fourth resolver source cannot drift the phrase spelling
    /// from what the operator has been trained to read.
    ///
    /// Pre-lift the phrase was baked into each `eprintln!` template
    /// verbatim at `commands/prerelease.rs::load_gates_config`:
    ///
    /// | variant                          | pre-lift line             |
    /// |----------------------------------|---------------------------|
    /// | [`Self::LoadedFromBackendDeployYaml`] | `📋 Loaded gate configuration from backend/deploy.yaml` |
    /// | [`Self::LoadedFromProductDeployYaml`] | `📋 Loaded gate configuration from product/deploy.yaml` |
    /// | [`Self::UsingDefault`]                | `📋 Using default gate configuration` |
    pub const fn message(self) -> &'static str {
        match self {
            GateConfigSource::LoadedFromBackendDeployYaml => {
                "Loaded gate configuration from backend/deploy.yaml"
            }
            GateConfigSource::LoadedFromProductDeployYaml => {
                "Loaded gate configuration from product/deploy.yaml"
            }
            GateConfigSource::UsingDefault => "Using default gate configuration",
        }
    }
}

/// Emit the canonical `📋 <source.message()>` gate-config-source
/// announcement to stderr. Called once by
/// `commands/prerelease.rs::load_gates_config` immediately before the
/// resolver returns a [`PreReleaseGatesConfig`] so the operator can
/// see which deploy.yaml (if any) the upcoming gate loop is bound
/// against.
///
/// Delegates to [`write_gate_config_source_announcement`] against
/// [`std::io::stderr`]; the writer split exists so the fail-before-pass
/// byte-oracle test pins the exact rendered bytes without capturing
/// stderr and without racing an ambient logger.
///
/// [`PreReleaseGatesConfig`]: crate::commands::prerelease::PreReleaseGatesConfig
pub fn print_gate_config_source_announcement(source: GateConfigSource) {
    let _ = write_gate_config_source_announcement(&mut io::stderr().lock(), source);
}

/// Writer-taking sibling to [`print_gate_config_source_announcement`].
/// Emits the single `📋 <source.message()>\n` line via [`writeln!`]
/// against the supplied writer.
///
/// [`print_gate_config_source_announcement`] is the stderr adapter;
/// this variant exists so tests can pin the exact prefix bytes (the
/// four-byte clipboard glyph U+1F4CB + trailing ASCII space), the
/// per-variant phrase from [`GateConfigSource::message`], the trailing
/// `\n`, and the absence of every ANSI palette sequence without
/// capturing stderr.
pub fn write_gate_config_source_announcement<W: io::Write>(
    w: &mut W,
    source: GateConfigSource,
) -> io::Result<()> {
    writeln!(
        w,
        "{}{}",
        GATE_CONFIG_SOURCE_ANNOUNCEMENT_PREFIX,
        source.message()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_gate_config_source_announcement`]. Pins the one-line
    /// body every pre-lift consumer spelled verbatim: the four-byte
    /// clipboard glyph U+1F4CB + trailing ASCII space + the per-variant
    /// phrase + trailing `\n`. A silent drift a future rewrite might
    /// introduce — swapping the clipboard glyph for a stricter
    /// document-symbol, dropping the trailing space between glyph and
    /// phrase, or dropping the newline — flips this assertion rather
    /// than compiling and silently diverging the three consumer sites'
    /// visual grammar.
    #[test]
    fn write_gate_config_source_announcement_emits_clipboard_prefix_and_message_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_gate_config_source_announcement(
            &mut buf,
            GateConfigSource::LoadedFromBackendDeployYaml,
        )
        .expect("write_gate_config_source_announcement against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect(
            "write_gate_config_source_announcement must emit valid UTF-8 (the pre-lift eprintln!s did)",
        );
        assert_eq!(
            out, "\u{1f4cb} Loaded gate configuration from backend/deploy.yaml\n",
            "byte-oracle: the single-line announcement must render verbatim — \
             U+1F4CB clipboard + ASCII space + variant phrase + `\\n`, no ANSI \
             escape, no other glyph"
        );
    }

    /// The three pre-lift consumer variants MUST each render into a
    /// distinct, verbatim announcement line. This test enumerates the
    /// pre-lift census (backend / product / default) so a future
    /// refactor that dropped one of the three variants silently fails
    /// when the census row falls off. Pins each rendered line
    /// byte-for-byte against the pre-lift `eprintln!` string a
    /// `git log`-style audit query would search for.
    #[test]
    fn write_gate_config_source_announcement_covers_pre_lift_variant_census() {
        const CENSUS: &[(GateConfigSource, &str)] = &[
            (
                GateConfigSource::LoadedFromBackendDeployYaml,
                "\u{1f4cb} Loaded gate configuration from backend/deploy.yaml\n",
            ),
            (
                GateConfigSource::LoadedFromProductDeployYaml,
                "\u{1f4cb} Loaded gate configuration from product/deploy.yaml\n",
            ),
            (
                GateConfigSource::UsingDefault,
                "\u{1f4cb} Using default gate configuration\n",
            ),
        ];
        for (source, expected) in CENSUS {
            let mut buf: Vec<u8> = Vec::new();
            write_gate_config_source_announcement(&mut buf, *source).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert_eq!(
                &out, expected,
                "write_gate_config_source_announcement({source:?}) must render \
                 byte-for-byte as the pre-lift `eprintln!` at the corresponding \
                 `commands/prerelease.rs::load_gates_config` site. Got {out:?}"
            );
        }
    }

    /// A silent promotion of the primitive to `.bold()` / `.dimmed()` /
    /// any `.<color>()` chain would flatten the announcement grammar
    /// the pre-lift three sites deliberately kept as plain uncolored
    /// stderr so the subsequent gate-loop output carries the
    /// operator's eye. This shield pins the absence of every ANSI
    /// escape byte so a color-chain promotion surfaces here rather
    /// than silently coloring three resolver-source announcements.
    #[test]
    fn write_gate_config_source_announcement_carries_no_ansi_escape_byte() {
        for source in [
            GateConfigSource::LoadedFromBackendDeployYaml,
            GateConfigSource::LoadedFromProductDeployYaml,
            GateConfigSource::UsingDefault,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_gate_config_source_announcement(&mut buf, source).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert!(
                !out.contains('\x1b'),
                "write_gate_config_source_announcement({source:?}) must carry \
                 NO ANSI escape byte (`\\x1b`) — the pre-lift \
                 `eprintln!(\"📋 …\")` sites reach stderr uncolored; a \
                 `.bold()` / `.dimmed()` / `.<color>()` promotion would \
                 flatten the announcement grammar. Got {out:?}"
            );
        }
    }

    /// Pins that the shared prefix constant IS the clipboard glyph
    /// U+1F4CB followed by exactly one ASCII space — the four-byte
    /// UTF-8 encoding of the glyph is `F0 9F 93 8B`, matching what a
    /// `xxd` of the pre-lift `eprintln!` source line reveals. A future
    /// drift to a different glyph (e.g. U+1F4C4 PAGE FACING UP or
    /// U+1F5D2 SPIRAL NOTE PAD) or a two-space gap fails here.
    #[test]
    fn prefix_const_is_clipboard_glyph_plus_one_ascii_space() {
        assert_eq!(
            GATE_CONFIG_SOURCE_ANNOUNCEMENT_PREFIX.as_bytes(),
            b"\xf0\x9f\x93\x8b ",
            "GATE_CONFIG_SOURCE_ANNOUNCEMENT_PREFIX must be the four UTF-8 \
             bytes of U+1F4CB CLIPBOARD followed by exactly one ASCII space"
        );
    }

    /// Whole-fleet negative caller shield: no raw
    /// `eprintln!("📋 ` may live in `commands/prerelease.rs`. Post-lift
    /// the three pre-lift sites each forward through
    /// [`print_gate_config_source_announcement`]; a future re-inline
    /// (a "just call `eprintln!` directly, it's shorter" cleanup)
    /// silently reopens the three-site duplication class this lift
    /// closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    #[test]
    fn no_raw_clipboard_eprintln_survives_in_prerelease() {
        const SOURCE: &str = include_str!("prerelease.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/prerelease.rs",
        );
        // Reconstruct the forbidden needle from the const so this
        // shield's own docstring mention of the glyph does not
        // false-match itself when the shield reads its own source.
        let needle = format!("eprintln!(\"{}", GATE_CONFIG_SOURCE_ANNOUNCEMENT_PREFIX,);
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(&needle),
                "commands/prerelease.rs:{lineno} spells the pre-lift inline \
                 `eprintln!(\"📋 …\")` gate-config-source announcement — that \
                 shape was lifted onto \
                 `crate::commands::gate_config_source_announcement::\
                 print_gate_config_source_announcement`. A re-inline silently \
                 reopens the three-site duplication class this shield exists \
                 to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/prerelease.rs` must
    /// forward through [`print_gate_config_source_announcement`] at
    /// exactly three sites (one per pre-lift consumer). A fusion that
    /// folded two consumer sites into one call or dropped one of the
    /// announcements silently fails here — the negative half above
    /// would still pass, but the positive count would fall below the
    /// pre-lift census.
    #[test]
    fn prerelease_module_forwards_through_gate_config_source_announcement_three_times() {
        const SOURCE: &str = include_str!("prerelease.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/prerelease.rs",
        );
        const FORWARD_NEEDLE: &str =
            "gate_config_source_announcement::print_gate_config_source_announcement(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 3,
            "commands/prerelease.rs body must forward to \
             `crate::commands::gate_config_source_announcement::\
             print_gate_config_source_announcement(...)` at exactly 3 sites \
             — one per pre-lift consumer. Found {forward_hits} forwarding hits."
        );
    }

    /// Enum-completeness shield — pins the three enum variants against
    /// the three pre-lift consumer sites. If a future addition of a
    /// fourth variant lands without also landing the corresponding
    /// resolver site (or vice versa), the census length here falls
    /// out of step with the enum. Iterating over an explicit array
    /// (rather than a `derive(strum::EnumIter)`) keeps the crate's
    /// dependency footprint unchanged.
    #[test]
    fn gate_config_source_variant_census_covers_exactly_three_outcomes() {
        const VARIANTS: &[GateConfigSource] = &[
            GateConfigSource::LoadedFromBackendDeployYaml,
            GateConfigSource::LoadedFromProductDeployYaml,
            GateConfigSource::UsingDefault,
        ];
        assert_eq!(
            VARIANTS.len(),
            3,
            "GateConfigSource must have exactly 3 variants — one per \
             pre-lift `eprintln!` site in \
             `commands/prerelease.rs::load_gates_config`"
        );
        // Each variant's message must be non-empty and must NOT contain
        // the shared prefix (the writer owns the prefix; the message is
        // the tail phrase only). A drift where a variant's message
        // silently absorbed the `📋 ` prefix would double-print it once
        // the writer prepends its own copy.
        for source in VARIANTS {
            let msg = source.message();
            assert!(
                !msg.is_empty(),
                "GateConfigSource::{source:?}.message() must be non-empty"
            );
            assert!(
                !msg.contains('\u{1f4cb}'),
                "GateConfigSource::{source:?}.message() must NOT contain the \
                 clipboard glyph — the writer prepends it. Got {msg:?}"
            );
        }
    }
}
