//! Canonical `.#<attr>` Nix-flake attribute reference constructor plus
//! the paired `Building .#<attr>...` pre-`nix build` info-line
//! announcement grammar.
//!
//! Two decisions co-located here because they answer the same question
//! at the same seam ("what does `.#<attr>` mean, and how do we narrate
//! that we are about to build it?"), consumed by three sibling flake-
//! build call sites:
//!
//! - `commands/local.rs::up` (`:56` announce + `:57`
//!   `build_flake_attr(&format!(".#{}", flake_attr))` reference).
//! - `commands/image_release.rs::build_nix_image` (`:203` announce +
//!   `:205` `build_flake_attr_in(&format!(".#{}", flake_attr), ...)`
//!   reference).
//! - `commands/build.rs::execute` (`:139`
//!   `let flake_ref = format!(".#{}", flake_attr);` reference only —
//!   the announcement stanza at `:128` is a distinct emoji-anchored
//!   `🔨 Building {} image for {}...` shape covering a two-axis
//!   `(flake_attr, arch)` readout that this primitive deliberately does
//!   not subsume).
//!
//! Pre-lift each site restated the bare
//!
//! ```ignore
//! info!("Building .#{}...", flake_attr);            // announce
//! let flake_ref = format!(".#{}", flake_attr);      // reference
//! ```
//!
//! grammar inline. Post-lift each site reaches for
//! [`info_building_flake_attr!`] (two announce sites) and
//! [`format_flake_attr_ref`] (three reference sites); the `.#` prefix,
//! the interpolation position, the trailing ellipsis, and the tracing
//! verbosity are decided once here.
//!
//! # The `.#` prefix is load-bearing — flake vs. path-input semantics
//!
//! The `.#` bytes are Nix flake-URL syntax: `.` is the "current flake"
//! shorthand, `#` opens the attribute suffix, `<attr>` is a
//! flake-output attribute inside `packages.<system>.<attr>` /
//! `nixosConfigurations.<attr>` / `apps.<system>.<attr>` (whichever
//! `nix build` resolves against the containing flake). A future drift
//! to `path:.#<attr>` (explicit path-input URL scheme, the sibling form
//! Nix accepts when the caller wants to opt out of a lock-file resolve)
//! or to `flake:.#<attr>` (explicit flake-input URL scheme) would flow
//! through this ONE constructor rather than three inline `format!`
//! bodies. Pinning the prefix at one site also keeps
//! [`crate::nix::build_flake_attr_in`]'s consumers uniform: that
//! primitive takes a pre-formed flake reference string and does NOT
//! reconstruct the `.#`, so a caller that hand-wrote `<attr>` bare
//! (without the `.#`) would silently produce `nix build <attr>`, which
//! resolves against the flake registry rather than the current working
//! tree — a wrong-tree build that the audit trail cannot recover from.
//!
//! # Distinct from `tool.rs`'s `.#<name>-<target>` 2-axis composition
//!
//! `commands/tool.rs::release` (at `:220`) composes a per-target
//! release-artifact reference as `format!(".#{}-{}", name, target)`,
//! iterating `targets = ["x86_64-linux", "aarch64-linux",
//! "x86_64-darwin", "aarch64-darwin"]` and calling `build_flake_attr_in`
//! against each. That construction is a distinct two-axis composition
//! (`<name>` × `<target>`) whose downstream binary is copied to a
//! `format!("{}-{}", name, target)` temp path, and its info
//! announcement at `:221` (`info!("Building {}...", flake_attr);`,
//! interpolating the ALREADY-PREFIXED string) has no `.#` in the format
//! literal. Merging it with this primitive would either force the
//! bare-`<attr>` sites to fabricate a `-<target>` suffix they do not
//! carry, or force `tool.rs` to route through a two-arg builder whose
//! call ergonomics are worse than the direct `format!` at three-plus
//! per-target invocations. Distinct primitive for a distinct grammar.
//!
//! # Distinct from `build.rs`'s emoji-anchored two-axis announcement
//!
//! `commands/build.rs::execute` (at `:128`) opens with
//! `info!("🔨 Building {} image for {}...", flake_attr, arch);` — a
//! zero-indent HAMMER-glyph-anchored announcement carrying both the
//! `<flake_attr>` and the `<arch>` (`x86_64-linux` / `aarch64-linux`)
//! it is building for. That is a distinct two-axis readout whose
//! `arch` slot has no analogue at the two `Building .#{}...` sites
//! (both of which build for the ambient system's default arch —
//! `commands/local.rs::up` runs the image under the local Docker
//! daemon, `commands/image_release.rs::build_nix_image` builds a
//! per-arch tarball whose arch is selected upstream via a separate
//! sub-flake resolve, not embedded in the announcement). Merging the
//! two grammars would either fabricate an `arch` slot the two sites
//! cannot semantically source, or drop the `arch` slot the
//! `build.rs::execute` site relies on for its `x86_64 vs. aarch64`
//! operator-visibility anchor. The `build.rs` reference at `:139`
//! (`let flake_ref = format!(".#{}", flake_attr);`) DOES route through
//! [`format_flake_attr_ref`] because the reference-form decision is
//! the same regardless of how the sibling announcement narrated the
//! build.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The [`info_building_flake_attr!`] macro expands to
//! `::tracing::info!(...)` at the caller's location, not to a function
//! wrapper, so tracing's automatic source-location capture (`file` +
//! `line` + `module_path`) matches the pre-lift behavior byte-for-
//! byte. A function-based wrapper would collapse every emission to the
//! wrapper's own site and break structured-log destinations that
//! filter by `module_path` (`RUST_LOG=forge::commands::local=info`
//! would stop matching once the emission moved to
//! `forge::flake_attr_ref`). The byte-oracle writer sibling
//! [`write_building_flake_attr`] captures the exact rendered body for
//! the tests (the zero indent, the `Building .#` prefix, the
//! interpolated attribute, the trailing `...` ellipsis, the trailing
//! newline) so the invariant is pinned without racing an ambient
//! tracing subscriber — the same split
//! [`crate::using_pod_field::write_using_pod_field`] carries against
//! [`crate::info_using_pod_field!`] and
//! [`crate::namespace_field::write_namespace_field`] carries against
//! [`crate::info_namespace_field!`].

use std::io;

/// Render the canonical `.#<attr>` Nix flake-attribute reference.
///
/// Three pre-lift sibling sites (`commands/local.rs::up`,
/// `commands/image_release.rs::build_nix_image`,
/// `commands/build.rs::execute`) each restated the
///
/// ```ignore
/// format!(".#{}", flake_attr)
/// ```
///
/// stanza verbatim. Post-lift they reach for this constructor and the
/// `.` (current-flake shorthand), the `#` (attribute-suffix separator),
/// the interpolation position, and the absence of any wrapping scheme
/// (`path:` / `flake:` / `git+file://`) are decided once here.
///
/// See the [module docs](self) for why the `.#` prefix is load-bearing
/// (flake-URL syntax vs. flake-registry lookup) and the split against
/// `tool.rs`'s two-axis `.#<name>-<target>` composition.
pub fn format_flake_attr_ref(flake_attr: &str) -> String {
    format!(".#{}", flake_attr)
}

/// Emits a single `"Building .#<attr>...\n"` line via [`writeln!`]
/// against the supplied writer, wrapping the caller's flake attribute
/// with the pre-lift zero-indent + `Building .#` prefix + `...`
/// ellipsis suffix that two sibling sites spelled inline.
///
/// The [`crate::info_building_flake_attr!`] macro is the
/// [`tracing::info!`] adapter that production code invokes; this
/// direct-writer variant exists so the fail-before-pass tests can pin
/// the exact emitted bytes (the zero indent, the `Building .#` prefix,
/// the interpolated attribute, the trailing `...` ellipsis, the
/// trailing newline) without capturing a tracing subscriber and
/// without racing an ambient logger — the same split
/// [`crate::using_pod_field::write_using_pod_field`] carries against
/// [`crate::info_using_pod_field!`] and
/// [`crate::namespace_field::write_namespace_field`] carries against
/// [`crate::info_namespace_field!`].
#[allow(dead_code)] // Peer of the tracing-routed `info_building_flake_attr!`
                    // macro, retained for the byte-oracle tests.
pub fn write_building_flake_attr<W: io::Write>(w: &mut W, flake_attr: &str) -> io::Result<()> {
    writeln!(w, "Building .#{}...", flake_attr)
}

/// Emit a pre-`nix build` announcement via [`tracing::info!`] on the
/// fleet-standard `"Building .#<attr>..."` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against `tool.rs`'s two-axis `.#<name>-<target>`
/// composition, the split against `build.rs`'s emoji-anchored
/// two-axis `🔨 Building {} image for {}...` announcement, and the
/// compounding rationale for keeping the announcement grammar owned by
/// one primitive.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("Building .#{}...", flake_attr);
///
/// // Post-lift
/// crate::info_building_flake_attr!(flake_attr);
/// ```
#[macro_export]
macro_rules! info_building_flake_attr {
    ($flake_attr:expr) => {
        ::tracing::info!("Building .#{}...", $flake_attr)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact rendered bytes for the reference constructor: the
    // ASCII period (0x2E), the ASCII hash (0x23), and the caller's
    // attribute verbatim — no trailing newline, no leading whitespace,
    // no wrapping scheme.
    #[test]
    fn format_flake_attr_ref_emits_period_hash_prefix_and_attr() {
        assert_eq!(format_flake_attr_ref("forge"), ".#forge");
    }

    // The reference is a bare `String`, not a line — it has no trailing
    // newline. A silent drift that appended `\n` would corrupt every
    // downstream `nix build <ref>` argv, since the argv slot is a
    // single token and the newline would be preserved by the caller's
    // process spawn.
    #[test]
    fn format_flake_attr_ref_has_no_trailing_newline() {
        let ref_ = format_flake_attr_ref("forge");
        assert!(
            !ref_.ends_with('\n'),
            "format_flake_attr_ref must NOT emit a trailing newline — \
             the return is an argv token, not a line. Got: {ref_:?}"
        );
    }

    // Pin the exact ASCII-period / ASCII-hash pair. A future refactor
    // that reached for `path:.#<attr>` or `flake:.#<attr>` (both valid
    // Nix flake-URL schemes, but distinct semantic layers) must be a
    // deliberate visible change of this primitive, not a drift of any
    // inline `format!` at the call sites.
    #[test]
    fn format_flake_attr_ref_uses_period_hash_prefix_bare() {
        let ref_ = format_flake_attr_ref("forge");
        assert!(
            ref_.starts_with(".#"),
            "reference must start with `.#` (ASCII period + ASCII \
             hash) — the current-flake shorthand + attribute-suffix \
             separator. Got: {ref_:?}"
        );
        // Explicit exclusions of the sibling URL-scheme forms.
        assert!(
            !ref_.starts_with("path:"),
            "reference must NOT carry the `path:` URL-scheme prefix \
             — that is a distinct opt-out-of-lock-file semantic layer. \
             Got: {ref_:?}"
        );
        assert!(
            !ref_.starts_with("flake:"),
            "reference must NOT carry the `flake:` URL-scheme prefix \
             — that is a distinct explicit-flake-input semantic layer. \
             Got: {ref_:?}"
        );
        assert!(
            !ref_.starts_with("git+file://"),
            "reference must NOT carry the `git+file://` URL-scheme \
             prefix — that would route through the git-URL-input \
             resolver rather than the current-working-tree flake. \
             Got: {ref_:?}"
        );
    }

    // Pin the exact rendered bytes for the announce writer: zero
    // indent, the literal `Building .#` (11 bytes) prefix, the
    // caller's attribute Display, the literal `...` (3 bytes) ellipsis
    // suffix, then `\n`. A future refactor that added an indent,
    // dropped the `.#` prefix, dropped the `...` ellipsis, or dropped
    // the trailing newline regresses this assertion.
    #[test]
    fn write_building_flake_attr_emits_zero_indent_prefix_attr_ellipsis_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        assert_eq!(buf, b"Building .#forge...\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_building_flake_attr_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "web-image").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "Building .#web-image...\n");
    }

    // Guard against a three-space-indent drift: the sibling sub-item
    // field-readout primitives ([`crate::info_namespace_field!`],
    // [`crate::info_image_field!`], [`crate::info_zone_id_field!`],
    // [`crate::info_workload_field!`]) all carry THREE spaces of indent
    // because they render as sub-items under an emoji-anchored parent
    // header emitted separately by the caller. This primitive is
    // deliberately the ZERO-indent shape because both pre-lift sites
    // emit as top-level narrative lines (no parent header — the
    // announcement IS the header the reference-resolve step follows).
    #[test]
    fn write_building_flake_attr_uses_zero_indent_not_three() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("Building"),
            "must start with the bare `Building` label (zero indent); \
             got: {s:?}"
        );
        assert!(
            !s.starts_with(" "),
            "must NOT lead with ANY whitespace; got: {s:?}"
        );
    }

    // Guard against a `🔨` HAMMER-glyph drift: `commands/build.rs::
    // execute` (at `:128`) carries a distinct
    // `info!("🔨 Building {} image for {}...", flake_attr, arch)`
    // shape. This primitive is deliberately glyphless — the two
    // pre-lift sites here do not carry an emoji anchor, and merging
    // grammars would either fabricate a `🔨` the sites do not source
    // or drop the `🔨` `build.rs::execute` relies on for its
    // operator-visibility anchor.
    #[test]
    fn write_building_flake_attr_emits_no_leading_emoji_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        // First byte must be the ASCII 'B' of "Building" (0x42); a
        // leading emoji would place a non-ASCII byte there.
        assert_eq!(
            buf[0], b'B',
            "byte 0 must be the ASCII 'B' of 'Building'; a leading \
             emoji would place a non-ASCII byte there. Bytes: {buf:?}"
        );
        // Explicit `🔨` HAMMER exclusion (U+1F528, F0 9F 94 A8).
        assert!(
            !buf.windows(4).any(|w| w == [0xF0, 0x9F, 0x94, 0xA8]),
            "must NOT emit the sibling `🔨` HAMMER anchor from \
             `build.rs::execute`; got: {buf:?}"
        );
    }

    // Pin the `.#` prefix on the announcement — a silent drop to a
    // bare `"Building {}..."` shape (matching `commands/tool.rs::
    // release`'s `:221` announcement, which prints the ALREADY-
    // PREFIXED string) would misinform the operator about whether the
    // build is against the current flake or against the flake
    // registry.
    #[test]
    fn write_building_flake_attr_carries_period_hash_before_interpolation() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains(".#forge"),
            "must interpolate the attribute as `.#<attr>` — the \
             flake-URL shorthand for the current flake. Got: {s:?}"
        );
        assert!(
            !s.contains(" forge..."),
            "must NOT drop the `.#` prefix — a bare `Building \
             <attr>...` would collide with `commands/tool.rs::release` \
             (`:221`) which prints an already-prefixed string. Got: \
             {s:?}"
        );
    }

    // Pin the trailing `...` ellipsis — a silent drop to bare
    // `"Building .#{}"` would break the fleet convention that a
    // "starting an operation" info line ends with `...` (see also
    // `crate::info_updated_field!`, `crate::info_using_tool_field!`,
    // and the many `📝 Updating <what>...` / `🔍 Verifying <what>...`
    // opening announcements throughout `commands/`).
    #[test]
    fn write_building_flake_attr_ends_with_ellipsis_before_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.ends_with("...\n"),
            "must end with `...\\n` — the fleet convention for a \
             'starting an operation' info line. Got: {s:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B).
    #[test]
    fn write_building_flake_attr_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_building_flake_attr(&mut buf, "forge").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_building_flake_attr must emit no ANSI escape \
             (0x1B). Bytes: {buf:?}",
        );
    }

    // The macro forwards to `::tracing::info!` at the caller's location.
    // The subscriber cannot be captured in-process without racing whatever
    // subscriber `main` installs. Instead, pin that the macro accepts the
    // supported arg shapes by expanding it at compile time — a compile-fail
    // here would fail the crate's `cargo test` build gate.
    #[test]
    fn info_building_flake_attr_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (both pre-lift call sites' shape today).
        let attr_str: &str = "forge";
        crate::info_building_flake_attr!(attr_str);

        // Owned `String` via the same slot.
        let owned = String::from("forge");
        crate::info_building_flake_attr!(owned);

        // A `&String` reference.
        let borrowed = &String::from("forge");
        crate::info_building_flake_attr!(borrowed);

        // A Display-wrapping newtype to prove the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> std::fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_building_flake_attr!(Wrap("forge"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("Building .#{}...", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_building_flake_attr!` on first grep, not by
    // copy-pasting the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_building_flake_attr_stanza() {
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
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains("info!(\"Building .#{}...\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"Building .#{{}}...\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_building_flake_attr!(<attr>)` instead:\n{:#?}",
            offenders
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `format!(".#{}", <arg>)` reference
    // construction inline any more. The three pre-lift sites migrated;
    // any future consumer that wants the same reference form reaches
    // for `crate::flake_attr_ref::format_flake_attr_ref` on first
    // grep. Distinct from the sibling `format!(".#{}-{}", name,
    // target)` at `commands/tool.rs::release` (`:220`), which is a
    // distinct two-axis composition and is NOT matched by the needle
    // below (the needle requires a `"` immediately after `{}` — the
    // two-axis site has `-` there).
    #[test]
    fn no_command_module_still_spells_raw_format_flake_attr_ref_stanza() {
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
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                // Anchored needle: `format!(".#{}"` (with the closing
                // `"` immediately after `{}`) matches the three
                // pre-lift sites and DOES NOT match `tool.rs`'s
                // `format!(".#{}-{}", ...)` (which has `-` after
                // `{}`, not `"`).
                if line.contains("format!(\".#{}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\".#{{}}\", <arg>)` stanza(s) survive under \
             `commands/` — route each through \
             `crate::flake_attr_ref::format_flake_attr_ref(<attr>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: each pre-lift module MUST forward
    // through the primitive at least once, so a migration that
    // dropped one call site outright leaves the negative "no raw
    // inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_building_flake_attr_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count).
        let expectations: &[(&str, usize)] = &[("local.rs", 1), ("image_release.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_building_flake_attr!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `Building .#<attr>...` site(s) through \
                 `crate::info_building_flake_attr!(`; found {forwards}. \
                 A dropped call would leave the negative raw-shape \
                 scan satisfied by absence.",
            );
        }
    }

    // Positive half of the reference-construction shield: each of
    // the three pre-lift modules MUST forward through
    // `format_flake_attr_ref` at least once. `tool.rs::release` is
    // deliberately NOT in this list — its `.#<name>-<target>` two-axis
    // composition is a distinct primitive scope.
    #[test]
    fn every_prelift_module_forwards_through_format_flake_attr_ref() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count).
        let expectations: &[(&str, usize)] =
            &[("local.rs", 1), ("image_release.rs", 1), ("build.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            // Match both the fully-qualified spelling and the sibling
            // `use crate::flake_attr_ref::format_flake_attr_ref;`
            // + bare `format_flake_attr_ref(` form so a future
            // ergonomic import at the call site does not break the
            // count floor.
            let forwards = source.matches("format_flake_attr_ref(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `.#<attr>` reference-construction site(s) through \
                 `format_flake_attr_ref(`; found {forwards}. A dropped \
                 call would leave the negative raw-shape scan satisfied \
                 by absence.",
            );
        }
    }
}
