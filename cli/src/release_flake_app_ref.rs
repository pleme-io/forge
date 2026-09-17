//! `.#release:<scope>` Nix flake-app reference constructor for the
//! Phase 1 forge release surface — the pre-lift
//! `format!(".#release:{}", service)` / `format!(".#release:{}:{}", product,
//! service)` composition four sibling sites restated verbatim.
//!
//! # Duplication being lifted
//!
//! Four pre-lift sites, two grammars:
//!
//! - Standalone-repo shape (`.#release:<service>`) — three sites:
//!   1. `commands/attestation.rs::compute_build_attestation`
//!      (`~L525`) — `nix path-info --derivation .#release:<service>`
//!      probe that resolves the release app's derivation path for
//!      the Phase 1.5 build-attestation `derivation` field.
//!   2. `commands/attestation.rs::compute_build_attestation`
//!      (`~L539`) — `nix path-info --recursive --json .#release:<service>`
//!      probe whose captured document folds through
//!      [`crate::store_path::canonical_closure_fingerprint`] into
//!      the `closure_hash` field.
//!   3. `commands/product_release.rs::run_nix_release_app`
//!      (`~L51`) — standalone branch of the `if standalone { … } else
//!      { … }` composition ahead of the `nix run <app>` spawn.
//!
//! - Monorepo shape (`.#release:<product>:<service>`) — one site:
//!   1. `commands/product_release.rs::run_nix_release_app`
//!      (`~L53`) — monorepo branch of the same composition.
//!
//! All four spellings share the `.#release:` prefix (11 bytes: ASCII
//! period + ASCII hash + ASCII `release` + ASCII colon) and the
//! trailing scope key; they differ only on whether the scope key is a
//! single `<service>` slot (standalone) or a two-slot
//! `<product>:<service>` composition (monorepo). Pre-lift a drift in
//! the prefix — an accidental `.#deploy:` from a copy-paste typo,
//! a silent `.#release-` dash separator, a dropped `.#` flake-URL
//! shorthand — had to hit all four sites in lockstep or diverge;
//! post-lift it hits ONE typed body and every consumer inherits the
//! shape from
//! [`crate::release_flake_app_ref::format_release_flake_app_ref`].
//!
//! # Distinct from the sibling `.#<attr>` bare-reference primitive
//!
//! [`crate::flake_attr_ref::format_flake_attr_ref`] owns the bare
//! `.#<attr>` shape (`format!(".#{}", flake_attr)`) three flake-build
//! sites reach for. That primitive's post-lift shield needle
//! (`format!(".#{}"`) requires the closing `"` to land immediately
//! after `{}` — the four sites lifted here spell `format!(".#release:{}"…`
//! (or `format!(".#release:{}:{}"…`), where the byte after `{}` is the
//! next literal character (`"` for the first, `:` for the last), and
//! the byte BEFORE `{}` is a literal `:` (never the `{` the bare-attr
//! shield needle looks for). The two primitives own distinct grammars
//! at distinct call sites; a merger would either force the bare-attr
//! sites to fabricate a `release:` scope prefix they do not carry, or
//! force this primitive to strip the `release:` scope prefix its four
//! sites universally require.
//!
//! # The `.#release:` prefix is load-bearing — flake-app URI syntax
//!
//! The `.#` bytes are Nix flake-URL syntax (`.` = current flake, `#` =
//! attribute suffix); the `release:` bytes name the top-level
//! `apps.<system>.release:<scope>` output the forge Phase 1 pipeline
//! defines. Both the standalone-repo shape and the monorepo shape
//! resolve against a `apps.<system>.release:<scope>` output whose
//! `<scope>` is either `<service>` (standalone) or
//! `<product>:<service>` (monorepo, using the ASCII `:` as the
//! product/service separator inside the flake-attribute name). A
//! silent drift to `.#release/<scope>` (path-style, invalid) or
//! `.#release-<scope>` (dash-style, would resolve to a distinct
//! attribute `release-<scope>` rather than the app-namespaced
//! `release:<scope>`) would flow through this ONE constructor rather
//! than four inline `format!` bodies.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `.#release:<scope>` shape lives
//! at ONE construction surface so a future refinement — the scheme
//! swap (`.#release:` → `.#release/`), a v2 flake schema that flips
//! the product/service separator (`:` → `.`), a future
//! per-target-arch suffix (`.#release:<scope>-<arch>`) — lands in one
//! place rather than in every consumer.
//!
//! §VI.1 three-is-a-law: three standalone-shape sites plus one
//! monorepo-shape site today; four total consumers clear the
//! duplication threshold well past the three-is-a-law floor.

use std::io;

/// Closed-enum scope key for the `.#release:<scope>` flake-app
/// reference. Two arms, one per pre-lift grammar:
///
/// - [`ReleaseAppScope::Standalone`] — `<service>` alone. Rendered as
///   `.#release:<service>` at the three standalone-shape sites.
/// - [`ReleaseAppScope::Monorepo`] — `<product>:<service>` two-slot
///   composition. Rendered as `.#release:<product>:<service>` at the
///   one monorepo-shape site.
///
/// The closed enum is deliberate: a bare `Option<&str>` product
/// parameter would leave the meaning of `product: Some("")` ambiguous
/// (empty-string product, or intended-standalone that forgot to pass
/// `None`?). The enum makes the two cases syntactically distinct at
/// every construction site and forecloses the empty-product
/// pseudo-standalone ambiguity structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAppScope<'a> {
    /// Standalone-repo shape: the product IS the repo root, so the
    /// scope key is a single `<service>` slot. Renders as
    /// `.#release:<service>`.
    Standalone { service: &'a str },
    /// Monorepo shape: the product lives under `pkgs/products/<product>`,
    /// so the scope key is a two-slot `<product>:<service>`
    /// composition. Renders as `.#release:<product>:<service>`.
    Monorepo { product: &'a str, service: &'a str },
}

/// Render the canonical `.#release:<scope>` Nix flake-app reference,
/// dispatching on the [`ReleaseAppScope`] arm.
///
/// # Element layout
///
/// - `.#` — Nix flake-URL shorthand: `.` is the current-flake, `#`
///   opens the attribute suffix.
/// - `release:` — the Phase 1 forge flake-app top-level scope name,
///   fixed literal.
/// - `<scope>` — either `<service>` (standalone) or `<product>:<service>`
///   (monorepo), driven by the [`ReleaseAppScope`] variant.
///
/// # Returned type
///
/// A fresh owned [`String`] every call. The reference is consumed by
/// argv-slice builders (a `nix run <ref>` spawn, a `nix path-info
/// <ref>` probe) that require a `&str` slot bound to a caller-owned
/// buffer; returning an owned [`String`] lets the caller choose its
/// lifetime rather than borrowing from a temporary the primitive would
/// drop at the return point.
pub fn format_release_flake_app_ref(scope: ReleaseAppScope<'_>) -> String {
    let mut buf: Vec<u8> = Vec::new();
    // Cannot fail: `Vec<u8>` never returns an `io::Error` on write.
    write_release_flake_app_ref(&mut buf, scope).expect("Vec<u8> write is infallible");
    // Cannot fail: all slot inputs are `&str` (already UTF-8) and the
    // literal bytes (`.`, `#`, `release`, `:`) are ASCII.
    String::from_utf8(buf).expect("composition of ASCII literals + &str slots is UTF-8")
}

/// Writer-taking sibling of [`format_release_flake_app_ref`]. Emits
/// the same bytes [`format_release_flake_app_ref`] returns, but
/// through an [`io::Write`] sink — the byte-oracle surface for tests
/// that pin the emitted composition against every drift class (a
/// prefix swap, a separator swap, an argv-order swap) without
/// allocating an intermediate [`String`].
///
/// # Byte contract
///
/// The written byte sequence is exactly the `.#release:` literal
/// (11 bytes), then either `<service>` (Standalone) or
/// `<product>:<service>` (Monorepo). No trailing newline, no framing
/// punctuation. A drift that added a framing prefix / suffix would
/// fail the byte-oracle tests below.
pub fn write_release_flake_app_ref<W: io::Write>(
    w: &mut W,
    scope: ReleaseAppScope<'_>,
) -> io::Result<()> {
    match scope {
        ReleaseAppScope::Standalone { service } => write!(w, ".#release:{}", service),
        ReleaseAppScope::Monorepo { product, service } => {
            write!(w, ".#release:{}:{}", product, service)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`format_release_flake_app_ref`] renders the
    /// pre-lift standalone `.#release:<service>` shape byte-for-byte.
    /// A drift that (a) swapped the prefix to `.#deploy:`,
    /// (b) dropped the `.#` flake-URL shorthand,
    /// (c) swapped the separator to `-` or `/`, or (d) upcased the
    /// scope name would fail this assertion.
    #[test]
    fn format_release_flake_app_ref_renders_standalone_byte_for_byte() {
        assert_eq!(
            format_release_flake_app_ref(ReleaseAppScope::Standalone { service: "forge" }),
            ".#release:forge",
        );
    }

    /// Byte-oracle: [`format_release_flake_app_ref`] renders the
    /// pre-lift monorepo `.#release:<product>:<service>` shape
    /// byte-for-byte, including the ASCII `:` product/service
    /// separator. A drift that swapped the separator to `-`, `/`, or
    /// `.` — silently retargeting to a distinct flake attribute — would
    /// fail this assertion.
    #[test]
    fn format_release_flake_app_ref_renders_monorepo_byte_for_byte() {
        assert_eq!(
            format_release_flake_app_ref(ReleaseAppScope::Monorepo {
                product: "pangea",
                service: "operator",
            }),
            ".#release:pangea:operator",
        );
    }

    /// Byte-oracle sibling: [`write_release_flake_app_ref`] emits the
    /// same bytes [`format_release_flake_app_ref`] returns, with no
    /// trailing newline and no framing punctuation. A refactor that
    /// promoted the writer to a `writeln!` (adding a `\n`) or that
    /// wrapped the reference in quotes / brackets would flip this
    /// assertion.
    #[test]
    fn write_release_flake_app_ref_emits_no_trailing_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_release_flake_app_ref(&mut buf, ReleaseAppScope::Standalone { service: "forge" })
            .unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, ".#release:forge");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             reference is consumed as a single positional arg, not as a \
             stand-alone log line; got {out:?}"
        );
    }

    /// Prefix pin: the reference starts with the exact `.#release:`
    /// 11-byte literal (`.` `#` `r` `e` `l` `e` `a` `s` `e` `:`). A
    /// drift that dropped the `.#` flake-URL shorthand — silently
    /// switching resolution from the current flake to the flake
    /// registry — would fail this pin.
    #[test]
    fn format_release_flake_app_ref_carries_dot_hash_release_colon_prefix() {
        for shape in [
            format_release_flake_app_ref(ReleaseAppScope::Standalone { service: "svc" }),
            format_release_flake_app_ref(ReleaseAppScope::Monorepo {
                product: "prod",
                service: "svc",
            }),
        ] {
            assert!(
                shape.starts_with(".#release:"),
                "reference must open with the `.#release:` literal — \
                 the fixed flake-URL shorthand + Phase 1 forge scope \
                 name; got {shape:?}"
            );
            // Explicit exclusions for common drifts.
            assert!(
                !shape.starts_with(".#deploy:"),
                "reference must NOT carry the `.#deploy:` scope — that \
                 would resolve to a distinct flake-app namespace; got \
                 {shape:?}"
            );
            assert!(
                !shape.starts_with(".#release-"),
                "reference must NOT carry the `.#release-` dash prefix \
                 — that would resolve to a distinct attribute \
                 `release-<scope>` rather than the app-namespaced \
                 `release:<scope>`; got {shape:?}"
            );
            assert!(
                !shape.starts_with("release:"),
                "reference must NOT drop the `.#` flake-URL shorthand \
                 — a bare `release:<scope>` would be parsed as a \
                 flake-registry alias, not a current-flake app ref; \
                 got {shape:?}"
            );
        }
    }

    /// Separator pin: inside the monorepo shape, the byte between the
    /// `<product>` slot and the `<service>` slot is the ASCII `:`
    /// (`0x3A`), NOT `-`, NOT `/`, NOT `.`. Nix parses the
    /// flake-attribute name on the literal ASCII colon; a silent swap
    /// to `-` would resolve to a distinct attribute
    /// (`.#release:<product>-<service>`) rather than the nested
    /// scope key `.#release:<product>:<service>`.
    #[test]
    fn format_release_flake_app_ref_monorepo_uses_ascii_colon_between_slots() {
        let shape = format_release_flake_app_ref(ReleaseAppScope::Monorepo {
            product: "abc",
            service: "xyz",
        });
        // Prefix ends at `.#release:` (10 bytes), then `abc` (3 bytes),
        // then the separator at index 13.
        assert_eq!(&shape[..10], ".#release:");
        assert_eq!(&shape[10..13], "abc");
        assert_eq!(
            shape.as_bytes()[13],
            b':',
            "byte at index 13 must be ASCII `:` (0x3A) — the \
             product/service separator inside the scope key"
        );
        assert_eq!(&shape[14..], "xyz");
    }

    /// Slot-order pin: inside the monorepo shape, the `<product>`
    /// slot lands FIRST (immediately after `.#release:`), and the
    /// `<service>` slot lands SECOND (after the interior `:`
    /// separator). A refactor that swapped the argv order — rendering
    /// `.#release:<service>:<product>` — would silently retarget every
    /// Phase 1 release-app spawn to a mis-scoped flake app, a
    /// destructive-in-production drift that a mere length check would
    /// not catch. Two distinct string arguments make the swap
    /// observable.
    #[test]
    fn format_release_flake_app_ref_monorepo_places_product_before_service() {
        let shape = format_release_flake_app_ref(ReleaseAppScope::Monorepo {
            product: "product-alpha",
            service: "service-beta",
        });
        // Strip the fixed `.#release:` prefix, split on the interior `:`.
        let tail = shape.strip_prefix(".#release:").unwrap();
        let (product_slot, service_slot) = tail.split_once(':').unwrap();
        assert_eq!(
            product_slot, "product-alpha",
            "product slot must land before the interior `:` separator"
        );
        assert_eq!(
            service_slot, "service-beta",
            "service slot must land after the interior `:` separator"
        );
    }

    /// Empty-slot discipline: the primitive owns COMPOSITION, not
    /// validation. Callers that hand an empty `service` or empty
    /// `product` receive a syntactically-empty half of the reference
    /// (e.g. `".#release:"` or `".#release::svc"`), NOT a bail nor a
    /// default. Nix's flake resolver will reject the empty half
    /// downstream; validation belongs at the boundary that owns the
    /// empty-check invariant, not at this shape-only composition
    /// primitive. Pins the contract so a future refactor cannot
    /// silently insert a default-product fallback or a
    /// `.unwrap_or(...)` guard here.
    #[test]
    fn format_release_flake_app_ref_composes_empty_slots_verbatim() {
        assert_eq!(
            format_release_flake_app_ref(ReleaseAppScope::Standalone { service: "" }),
            ".#release:",
        );
        assert_eq!(
            format_release_flake_app_ref(ReleaseAppScope::Monorepo {
                product: "",
                service: "svc",
            }),
            ".#release::svc",
        );
        assert_eq!(
            format_release_flake_app_ref(ReleaseAppScope::Monorepo {
                product: "prod",
                service: "",
            }),
            ".#release:prod:",
        );
    }

    /// No-ANSI guard: the reference is a bare argv token; a stray ANSI
    /// escape (0x1B) in the composed bytes would corrupt every
    /// downstream `nix run <ref>` / `nix path-info <ref>` spawn.
    #[test]
    fn format_release_flake_app_ref_emits_no_ansi_escape() {
        for shape in [
            format_release_flake_app_ref(ReleaseAppScope::Standalone { service: "forge" }),
            format_release_flake_app_ref(ReleaseAppScope::Monorepo {
                product: "pangea",
                service: "operator",
            }),
        ] {
            assert!(
                !shape.as_bytes().contains(&0x1b),
                "release-app reference must emit no ANSI escape (0x1B); \
                 got {shape:?}",
            );
        }
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift raw
    /// `format!(".#release:{}", …)` or
    /// `format!(".#release:{}:{}", …)` shapes inline. Every consumer
    /// reaches for [`format_release_flake_app_ref`] on first grep, not
    /// by copy-pasting the raw `format!` from an existing sibling.
    ///
    /// Anchored on the two exact `format!` shapes the four pre-lift
    /// sites carried — a rename to unrelated slot names or a distinct
    /// scope literal (e.g. `.#deploy:{}`) does not trip the shield,
    /// keeping the sibling `.#<attr>` primitive at its own home.
    #[test]
    fn no_command_module_still_spells_raw_release_flake_app_ref_format() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let release_shapes: &[&str] = &["format!(\".#release:{}\"", "format!(\".#release:{}:{}\""];
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
                for shape in release_shapes {
                    if line.contains(shape) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\".#release:{{}}\", …)` / \
             `format!(\".#release:{{}}:{{}}\", …)` literal(s) survive \
             under `commands/` — route each through \
             `crate::release_flake_app_ref::format_release_flake_app_ref\
             (ReleaseAppScope::…)` instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive half): the two pre-lift modules
    /// that housed the composition MUST each forward through
    /// [`format_release_flake_app_ref`] at least once, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_format_release_flake_app_ref() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count):
        // - attestation.rs — 2 standalone-shape probe sites
        //   (`compute_build_attestation`: `--derivation` +
        //   `--recursive --json`).
        // - product_release.rs — 1 fused site
        //   (`run_nix_release_app` folds the standalone / monorepo
        //   branching into a single `format_release_flake_app_ref(
        //   if standalone { Standalone { … } } else { Monorepo { … } })`
        //   call — one construction surface, two scope arms).
        let expectations: &[(&str, usize)] = &[("attestation.rs", 2), ("product_release.rs", 1)];
        let needle = "format_release_flake_app_ref(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `.#release:<scope>` reference-construction site(s) \
                 through `{needle}`; found {forwards}. A dropped call \
                 would leave the negative raw-shape scan satisfied by \
                 absence.",
            );
        }
    }
}
