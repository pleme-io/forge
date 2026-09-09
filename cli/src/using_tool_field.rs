//! Info-routed `🔧 Using <label>: <value>` tool-discovery-announcement
//! field grammar.
//!
//! Seven pre-lift sibling sites across
//! `{nix_hooks (×1: `NIX_HOOKS_PATH` env override branch inside
//! `NixHooks::discover` at :71), commands/bootstrap (×2: `cargo` +
//! `crate2nix` sigils inside `execute_regenerate` at :622–:623),
//! commands/pangea (×4: `cargo` + `crate2nix` sigils inside
//! `regenerate_cargo_nix` at :477–:478, `bundler` + `bundix` sigils
//! inside `regenerate_compiler` at :522–:523)}.rs` each restated the
//!
//! ```ignore
//! info!("🔧 Using <label>: {}", <value>);   // three wrench sites
//! info!("Using <label>: {}", <value>);      // four bare sites
//! ```
//!
//! stanza verbatim — every site announces a just-resolved binary or
//! env-var path being adopted for use in the imminently-spawned tool
//! run (`cargo update`, `crate2nix generate`, `bundle lock --update`,
//! `bundix -l`, or the `attic-push-hook` post-build hook). Post-lift the
//! seven sites reach for [`info_using_tool_field!`] and the glyph +
//! verb + separator + tracing verbosity are decided once here.
//!
//! # Canonicalized onto the wrench-glyph form
//!
//! Three pre-lift sites (`nix_hooks.rs:71` +
//! `commands/bootstrap.rs:622–:623`) already wore the `🔧` WRENCH
//! glyph (U+1F527, fully-qualified emoji, no variation selector); four
//! (`commands/pangea.rs:477–:478 + :522–:523`) did not. The
//! glyph-vs-no-glyph divergence was drift — both files discover build-
//! toolchain binaries with the same `<tool>_bin()` / `get_tool_path(…)`
//! sigils and announce them for the same imminent-spawn beat — so the
//! primitive canonicalizes onto the wrench-bearing form. Operator
//! visibility gains a single leading `🔧 ` prefix on the four
//! `commands/pangea.rs` lines; the announcement grammar aligns with
//! every sibling tool-discovery readout across the crate.
//!
//! # Distinct from `info!("Using pod: {}", pod)` at seed.rs
//!
//! Two sibling `info!("Using pod: {}", pod);` sites survive at
//! `commands/seed.rs:310 + :350` (inside `seed` / `unseed`), and they
//! are deliberately out of scope. `pod` there is a runtime Kubernetes
//! resource identifier returned by `find_primary_pod(...)` — a live
//! cluster-side resource being addressed for a `kubectl exec` — not a
//! discovered build-tool binary or env-var path being adopted for a
//! local process spawn. Collapsing the two grammars would fuse the
//! build-tool sigil family with the runtime-k8s-resource selection
//! family, erasing the local-vs-remote sink-target distinction the
//! operator uses to tell one line's meaning from the other. The caller
//! shield below matches only the `<label>: {}` shape when it also
//! carries an inline-literal label pinned by the pre-lift census, so
//! the `Using pod: {}` site is filtered out by the label-list allowlist.
//!
//! # Distinct from the sibling three-space-indented sub-item field primitives
//!
//! The crate carries a small family of `   <Label>: <value>` sub-item
//! field-readout primitives ([`crate::info_namespace_field!`],
//! [`crate::info_zone_id_field!`], [`crate::info_image_field!`],
//! [`crate::info_workload_field!`]) that all emit a THREE-space-indented
//! `<Label>: <value>` line under an emoji-anchored parent header. This
//! primitive is deliberately **not** one of them: the pre-lift stanzas
//! carry a zero-indent `🔧 Using <label>: <value>` phase-preamble
//! grammar with a leading WRENCH glyph anchor, not a bare
//! `   <Label>: <value>` sub-item readout under a separately-emitted
//! parent banner. A merge into any bare sub-item primitive would either
//! fabricate three spaces of indent the pre-lift sites do not carry, or
//! drop the leading `🔧 Using ` opener that anchors the tool-discovery
//! semantic.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::bootstrap=info` would stop matching once
//! the emission moved to `forge::using_tool_field`). The byte-oracle
//! writer sibling [`write_using_tool_field`] captures the exact
//! rendered body for the tests (the `🔧` glyph, the one-space gap, the
//! `Using ` verb, the interpolated label, the `: ` separator, the
//! interpolated value, the trailing newline) so the invariant is
//! pinned without racing an ambient tracing subscriber — the same
//! split [`crate::bookmark_git_sha_field::write_bookmark_git_sha_field`]
//! carries against [`crate::info_bookmark_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"🔧 Using <label>: <value>"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's label and value
/// with the pre-lift `🔧 ` + one-ASCII-space + `Using ` verb + `: `
/// separator that seven sibling sites spelled inline.
///
/// The [`crate::info_using_tool_field!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can pin
/// the exact emitted bytes (the `🔧` glyph, the one-space gap after
/// it, the `Using ` verb literal, the interpolated label, the `: `
/// separator literal, the interpolated value, the trailing newline)
/// without capturing a tracing subscriber and without racing an ambient
/// logger — the same split
/// [`crate::bookmark_git_sha_field::write_bookmark_git_sha_field`]
/// carries against [`crate::info_bookmark_git_sha_field!`].
///
/// The `label` and `value` parameters each accept any [`fmt::Display`]
/// rather than a concrete `&str` so a bare `&str` (six of the seven
/// pre-lift sites' shape today — every `<tool>_bin()` / `get_tool_path`
/// return is a `String` sourced from a `CARGO` / `CRATE2NIX` /
/// `BUNDLE_BIN` / `BUNDIX_BIN` env override with a PATH fallback), a
/// `std::path::Display` (the seventh site, `nix_hooks.rs:71`, forwards
/// `path_buf.display()`), an owned `String`, and a future
/// substrate::ToolBin newtype all flow through the same writer without
/// a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // Peer of the tracing-routed
                    // `info_using_tool_field!` macro; retained for the
                    // byte-oracle tests and for a future
                    // tool-discovery-summary consumer.
pub fn write_using_tool_field<W: io::Write>(
    w: &mut W,
    label: &dyn fmt::Display,
    value: &dyn fmt::Display,
) -> io::Result<()> {
    writeln!(w, "\u{1F527} Using {}: {}", label, value)
}

/// Emit a tool-discovery-announcement field readout via
/// [`tracing::info!`] on the fleet-standard
/// `"🔧 Using <label>: <value>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the seven pre-lift
/// site census, the canonicalization onto the wrench-glyph form, the
/// split against the runtime-k8s-pod `Using pod: {}` sibling, and the
/// split against the sibling three-space-indented sub-item field
/// primitives.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift (wrench form)
/// info!("🔧 Using NIX_HOOKS_PATH: {}", path_buf.display());
/// info!("🔧 Using cargo: {}", cargo);
///
/// // Pre-lift (bare form; canonicalized to wrench post-lift)
/// info!("Using bundler: {}", bundler);
///
/// // Post-lift
/// crate::info_using_tool_field!("NIX_HOOKS_PATH", path_buf.display());
/// crate::info_using_tool_field!("cargo", cargo);
/// crate::info_using_tool_field!("bundler", bundler);
/// ```
#[macro_export]
macro_rules! info_using_tool_field {
    ($label:expr, $value:expr) => {
        ::tracing::info!("\u{1F527} Using {}: {}", $label, $value)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: `🔧` (U+1F527, 4 bytes F0 9F 94 A7,
    // no variation selector), one ASCII space, the literal `Using `
    // (6 bytes), the interpolated label Display, the literal `: `
    // (2 bytes), the interpolated value Display, then `\n`. A future
    // refactor that swaps the glyph, drops the verb, changes the
    // separator, or drops the trailing newline flips this assertion
    // rather than silently diverging the seven consumer sites' surface.
    #[test]
    fn write_using_tool_field_emits_prefix_verb_label_separator_value_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/nix/store/…/bin/cargo").unwrap();
        assert_eq!(
            buf,
            b"\xf0\x9f\x94\xa7 Using cargo: /nix/store/\xe2\x80\xa6/bin/cargo\n"
        );
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_using_tool_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"NIX_HOOKS_PATH", &"/nix/store/abc-nix-hooks").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\u{1F527} Using NIX_HOOKS_PATH: /nix/store/abc-nix-hooks\n"
        );
    }

    // The seven pre-lift sites carry six distinct labels (`cargo`,
    // `crate2nix`, `bundler`, `bundix`, `NIX_HOOKS_PATH`) plus one
    // duplicate (`cargo`/`crate2nix` appear both in bootstrap.rs and
    // pangea.rs). Pin that every pre-lift label flows through the
    // writer verbatim — no case-fold, no underscore mangling, no
    // separator drift for the mixed-case (`NIX_HOOKS_PATH`) or
    // lowercase-only (`cargo` / `bundler`) labels.
    #[test]
    fn write_using_tool_field_forwards_all_prelift_labels_verbatim() {
        for label in ["cargo", "crate2nix", "bundler", "bundix", "NIX_HOOKS_PATH"] {
            let mut buf: Vec<u8> = Vec::new();
            write_using_tool_field(&mut buf, &label, &"/x/y").unwrap();
            let expected = format!("\u{1F527} Using {}: /x/y\n", label);
            assert_eq!(String::from_utf8(buf).unwrap(), expected);
        }
    }

    // Guard against WRENCH-vs-HAMMER-AND-WRENCH glyph confusion.
    // `🔧` WRENCH is U+1F527 (F0 9F 94 A7); `🛠` HAMMER AND WRENCH is
    // U+1F6E0 (F0 9F 9B A0). A future refactor that reached for the
    // more visually-elaborate HAMMER-AND-WRENCH would silently break
    // byte-oracle downstream comparators and break the sigil family
    // (`🔧` is the fleet-wide tool-discovery glyph).
    #[test]
    fn write_using_tool_field_emits_wrench_not_hammer_and_wrench() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/x/y").unwrap();
        // WRENCH is F0 9F 94 A7; HAMMER-AND-WRENCH is F0 9F 9B A0.
        // Bytes 2 and 3 differ (0x94 vs 0x9B, 0xA7 vs 0xA0).
        assert_eq!(
            &buf[0..4],
            &[0xf0, 0x9f, 0x94, 0xa7],
            "write_using_tool_field must emit U+1F527 WRENCH \
             (F0 9F 94 A7), NOT U+1F6E0 HAMMER AND WRENCH \
             (F0 9F 9B A0). Bytes: {buf:?}",
        );
    }

    // Guard against variation-selector drift: `🔧` (U+1F527) is
    // deliberately used as a bare 4-byte glyph. A future refactor that
    // appended U+FE0F would silently break byte-oracle downstream
    // comparators. Pin the exact 4-byte encoding: byte 4 must be an
    // ASCII space (0x20), not the first byte of U+FE0F (which is 0xEF).
    #[test]
    fn write_using_tool_field_does_not_append_variation_selector() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/x/y").unwrap();
        assert_eq!(
            buf[4], 0x20,
            "byte 4 must be an ASCII space (0x20); a U+FE0F variation \
             selector would place 0xEF there and break the byte-oracle. \
             Bytes: {buf:?}",
        );
    }

    // Guard against the two-space-after-glyph grammar drift: `⚠️  ` /
    // `⏭️  ` / `🏷️  ` siblings all use two ASCII spaces (their emoji
    // carry variation selectors and are visually narrower without the
    // extra space). `🔧` is already fully-qualified emoji, so a
    // two-space gap would visually widen the label off the neighboring
    // one-space `📦` / `🔖` / `🔧` shapes rather than align with them.
    // Pin the negative shape explicitly so a future reader who reaches
    // for the sibling two-space grammar hits this test.
    #[test]
    fn write_using_tool_field_does_not_use_two_space_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/x/y").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.starts_with("\u{1F527}  "),
            "write_using_tool_field must NOT emit two ASCII spaces \
             after the `🔧` glyph — the fleet-standard one-space grammar \
             for fully-qualified emoji is load-bearing. Actual: {s:?}",
        );
    }

    // Guard against a three-space-indent collapse onto the sibling
    // sub-item field primitives ([`crate::info_namespace_field!`],
    // [`crate::info_zone_id_field!`], [`crate::info_image_field!`],
    // [`crate::info_workload_field!`]) — all of which emit a
    // three-space-indented `<Label>: <value>` line under a
    // separately-emitted parent banner. This primitive is the ZERO-
    // indent tool-discovery-preamble shape and must NOT gain a leading
    // three-space indent.
    #[test]
    fn write_using_tool_field_uses_zero_indent_not_three_space() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/x/y").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with('\u{1F527}'),
            "must start with the wrench glyph (zero indent); got: {s:?}"
        );
        assert!(
            !s.starts_with("   "),
            "must NOT be three-space indent; got: {s:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B) — a future refactor that reached for
    // `colored` on the label or value side would break the ANSI-free
    // contract the tracing-routed sites depend on.
    #[test]
    fn write_using_tool_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_tool_field(&mut buf, &"cargo", &"/x/y").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_using_tool_field must emit no ANSI escape (0x1B) — \
             the tracing subscriber is configured `with_ansi(false)`. \
             Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's
    // location. The subscriber cannot be captured in-process without
    // racing whatever subscriber `main` installs. Instead, pin that
    // the macro accepts the supported arg shapes by expanding it at
    // compile time — a compile-fail here would fail the crate's
    // `cargo test` build gate.
    #[test]
    fn info_using_tool_field_macro_compiles_with_supported_arg_shapes() {
        // Both slots as bare `&str` — six of the seven pre-lift call
        // sites' shape (label a string literal, value a `String` local
        // sourced from `<tool>_bin()` / `get_tool_path`).
        let value_str: &str = "/nix/store/…/bin/cargo";
        crate::info_using_tool_field!("cargo", value_str);

        // Value as `std::path::Display` — the seventh site,
        // `nix_hooks.rs:71`, forwards `path_buf.display()` (an
        // `std::path::Display<'_>`) rather than a `&str`.
        let path = std::path::PathBuf::from("/nix/store/abc-nix-hooks");
        crate::info_using_tool_field!("NIX_HOOKS_PATH", path.display());

        // Both slots as owned `String` — supported for a future
        // dynamic-label caller (e.g. a `for (label, bin) in tools`
        // loop).
        let owned_label = String::from("bundler");
        let owned_value = String::from("/nix/store/xyz-bundle");
        crate::info_using_tool_field!(owned_label, owned_value);

        // A `Display`-wrapping newtype in each slot to prove the slots
        // take any `Display` (a future
        // `substrate::EnvVarName(String)` newtype or a
        // `substrate::ToolBin(PathBuf)` newtype would forward through
        // their own `Display` impl the same way).
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_using_tool_field!(Wrap("k"), Wrap("v"));
    }

    // Caller shield (negative half): no source line under `cli/src/`
    // may spell the pre-lift raw `info!("🔧 Using <label>: {}", …);`
    // or `info!("Using <label>: {}", …);` stanza inline any more —
    // for the six labels lifted by this primitive (`cargo`,
    // `crate2nix`, `bundler`, `bundix`, `NIX_HOOKS_PATH`).
    //
    // The scan walks the whole `src/` tree because two pre-lift sites
    // (`nix_hooks.rs`, outside `commands/`) live outside the
    // `commands/` subdir that most shields scan. Every future consumer
    // that wants the same grammar reaches for
    // `crate::info_using_tool_field!` on first grep, not by
    // copy-pasting the raw shape.
    //
    // The `Using pod: {}` sibling at `commands/seed.rs:{310,350}` is
    // deliberately out of scope (see module docs) and is filtered out
    // by the label allowlist: the shield matches only labels in the
    // pre-lift census, so `pod` does not appear.
    #[test]
    fn no_source_module_still_spells_raw_info_using_tool_field_stanza() {
        use std::path::{Path, PathBuf};
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("using_tool_field.rs");
        // The six lifted labels: five distinct plus `crate2nix` (which
        // appears in bootstrap.rs and pangea.rs both).
        let labels = ["cargo", "crate2nix", "bundler", "bundix", "NIX_HOOKS_PATH"];
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let mut stack = vec![src_dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                // Skip this primitive's own module — its doc-comment
                // and test-body prose reference the pre-lift shape.
                if p == this_file {
                    continue;
                }
                let source = std::fs::read_to_string(&p).unwrap();
                for (idx, line) in source.lines().enumerate() {
                    let trimmed = line.trim_start();
                    // Skip comment lines so unrelated docstrings that
                    // mention the shape do not self-hit.
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    for label in labels {
                        // Match both wrench-form
                        // `info!("🔧 Using <label>: {}", …)` and
                        // bare-form `info!("Using <label>: {}", …)`.
                        let wrench = format!("info!(\"\u{1F527} Using {label}: ");
                        let bare = format!("info!(\"Using {label}: ");
                        if line.contains(&wrench) || line.contains(&bare) {
                            offenders.push((p.clone(), idx + 1, line.to_string()));
                        }
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"[\u{1F527} ]Using <label>: {{}}\", <arg>);` \
             stanza(s) survive under `src/` for a lifted label — route \
             each through `crate::info_using_tool_field!(<label>, <value>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield (positive half): the three pre-lift modules MUST
    // each forward through `crate::info_using_tool_field!(` at least
    // as many times as the pre-lift census, so a migration that
    // dropped a call site outright leaves the negative "no raw inline
    // shape" scan trivially satisfied by absence but the positive
    // count still fails. Minimum-per-module counts: `nix_hooks.rs` (1),
    // `commands/bootstrap.rs` (2), `commands/pangea.rs` (4).
    #[test]
    fn every_prelift_module_forwards_through_info_using_tool_field_macro() {
        use std::path::PathBuf;
        let cli_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&str, usize)] = &[
            ("nix_hooks.rs", 1),
            ("commands/bootstrap.rs", 2),
            ("commands/pangea.rs", 4),
        ];
        for (rel_path, min_count) in expectations {
            let path = cli_root.join(rel_path);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {rel_path}: {e}"));
            let forwards = source.matches("crate::info_using_tool_field!(").count();
            assert!(
                forwards >= *min_count,
                "{rel_path} must forward at least {min_count} \
                 tool-discovery-announcement site(s) through \
                 `crate::info_using_tool_field!(`; found {forwards}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
