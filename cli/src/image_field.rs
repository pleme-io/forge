//! Info-routed `   Image: <image>` three-space-indented image-name /
//! image-path field-readout grammar.
//!
//! Two pre-lift sibling sites across `commands/{cluster_overlay_release_preamble
//! (×1: `announce_release_start_and_compute_tag`, immediately below
//! `info!("🚀 Starting {} release", release_name)` and above
//! `info!("   Registry: {}", registry)`), deploy (×1:
//! `deploy_service_with_tag`, immediately below
//! `info!("📝 Updating kustomization.yaml...")` and above the sibling
//! `   Old tag:` / `   New tag:` field-readout pair)}.rs` each restated
//! the
//!
//! ```ignore
//! info!("   Image: {}", <image_path|image_name>);
//! ```
//!
//! stanza verbatim — three ASCII spaces of indent, the six-character
//! `Image:` label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted image string, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_image_field!`] and the indent width + label + separator +
//! tracing verbosity are decided once here.
//!
//! # Distinct from every sibling emoji-labeled tag-field primitive
//!
//! The crate carries a small family of `<emoji> <Label>: <value>` field
//! primitives ([`crate::info_git_sha_field!`],
//! [`crate::info_registry_field!`], [`crate::info_deploy_target_field!`],
//! [`crate::info_tags_field!`]) that all emit a zero-indent
//! glyph-anchored preamble line. This primitive is deliberately **not**
//! one of them: both pre-lift stanzas carry a three-ASCII-space indent
//! (each is a sub-item under a parent emoji-anchored header emitted
//! separately by the caller — `🚀 Starting <release> release` in
//! `cluster_overlay_release_preamble.rs`, `📝 Updating kustomization.yaml...`
//! in `deploy.rs`) and NO emoji glyph. A merge into any
//! `<emoji> Label:` primitive would either fabricate a glyph the two
//! pre-lift sites did not carry, or force the sibling emoji primitives
//! to drop their zero-indent anchor.
//!
//! # Sibling three-space-indented field primitives
//!
//! Three peers share the exact shape class this primitive occupies —
//! three ASCII spaces + `<Label>: ` + Display value + `\n` under an
//! emoji-anchored parent header — but carry different labels and
//! different value semantics:
//!
//! - [`crate::info_namespace_field!`] (`   Namespace: <ns>`) — the
//!   Kubernetes-namespace sub-item under `🔄 Performing rollback...` /
//!   `👀 Watching StatefulSet rollout...` parents.
//! - [`crate::info_zone_id_field!`] (`   Zone ID: <prefix>***`) — the
//!   masked Cloudflare-zone-id sub-item; distinct in that its value
//!   carries a fixed `***` masking suffix for tenant-identity hygiene.
//! - [`crate::info_workload_field!`] (`   Deployment: <name>` /
//!   `   StatefulSet: <name>`) — the workload-kind-tagged sub-item under
//!   rollout / rollback parents; distinct in that its label is
//!   enum-driven (Deployment vs. StatefulSet) rather than fixed.
//!
//! Each primitive is the sole home for its label and value shape. A
//! merge into any peer would either force this primitive's callers to
//! fabricate a masking suffix or a workload-kind enum they have no
//! source for, or force the peers to drop their load-bearing suffix or
//! enum discriminator.
//!
//! # The load-bearing three-space indent
//!
//! Both pre-lift sites spell the stanza with EXACTLY THREE ASCII spaces
//! of indent, matching the sibling three-space-indented field readouts
//! elsewhere in the same command modules:
//!
//! - `cluster_overlay_release_preamble.rs::announce_release_start_and_compute_tag`:
//!   the `Image` line at `:142` is immediately followed by
//!   `info!("   Registry: {}", registry);` at `:143`, then `println!();`
//!   at `:144` — a three-line pair-plus-break under the parent
//!   `🚀 Starting <release> release` header.
//! - `deploy.rs::deploy_service_with_tag`: the `Image` line at `:86` is
//!   immediately followed by `info!("   Old tag: {}", old_tag);` at `:87`
//!   and `info!("   New tag: {}", tag);` at `:88`, then `println!();` at
//!   `:89` — a four-line triple-plus-break shape under the parent
//!   `📝 Updating kustomization.yaml...` header.
//!
//! The three-space grammar aligns visually with the sibling `   URL:` /
//! `   Cache:` / `   Old tag:` / `   New tag:` / `   Total replicas:` /
//! `   Expected image tag:` / `   Namespace:` / `   Zone ID:` /
//! `   Deployment:` / `   StatefulSet:` field readouts scattered across
//! the same command modules. A future collapse to a two-space or
//! four-space grammar would misalign the whole family. Pin the
//! three-space width so a drift hits the byte-oracle test rather than
//! shipping a misaligned sub-item under the parent header.
//!
//! # The two pre-lift value shapes — path vs. name — both flow through
//!
//! The two pre-lift sites carry slightly different upstream value shapes
//! but rely on the same primitive:
//!
//! - `cluster_overlay_release_preamble.rs` passes `image_path: &str` —
//!   the full local filesystem path to a Nix-built OCI tarball
//!   (`/nix/store/…-image.tar.gz` or a `result` symlink resolution).
//! - `deploy.rs` passes `image_name: &str` — the last path component of
//!   the destination registry (`svc` from `ghcr.io/pleme-io/svc`), used
//!   to identify the image being retagged in the kustomization overlay.
//!
//! Both are pre-formatted `Display`-shaped strings by the caller; the
//! primitive forwards whichever form the caller supplies. A future
//! per-shape split (path-typed vs. name-typed) belongs in the caller's
//! newtype layer, not here.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's location,
//! not to a function wrapper, so tracing's automatic source-location
//! capture (`file` + `line` + `module_path`) matches the pre-lift
//! behavior byte-for-byte. A function-based wrapper would collapse every
//! emission to the wrapper's own site and break structured-log
//! destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::deploy=info` would stop matching once the
//! emission moved to `forge::image_field`). The byte-oracle writer
//! sibling [`write_image_field`] captures the exact rendered body for
//! the tests (the three-space indent, the `Image:` label, the
//! single-space gap before the image, the trailing newline) so the
//! invariant is pinned without racing an ambient tracing subscriber —
//! the same split
//! [`crate::namespace_field::write_namespace_field`] carries against
//! [`crate::info_namespace_field!`] and
//! [`crate::git_sha_field::write_git_sha_field`] carries against
//! [`crate::info_git_sha_field!`].

use std::fmt;
use std::io;

/// Emits a single `"   Image: <image>"` line via [`writeln!`] against
/// the supplied writer, wrapping the caller's image with the pre-lift
/// three-ASCII-space indent + `Image: ` label prefix that two sibling
/// sites spelled inline.
///
/// The [`crate::info_image_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the three-space indent, the `Image:` label literal, the
/// single-space gap before the image, the trailing newline) without
/// capturing a tracing subscriber and without racing an ambient logger
/// — the same split
/// [`crate::namespace_field::write_namespace_field`] carries against
/// [`crate::info_namespace_field!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
///
/// The `image` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (both pre-lift call sites' shape
/// today, sourced from a `&str` local), an owned `String`, `Cow<str>`,
/// and a future OCI-image newtype (`substrate::OciImageRef(String)` or a
/// `substrate::LocalImagePath(PathBuf)`) all flow through the same
/// writer without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // Peer of the tracing-routed `info_image_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_image_field<W: io::Write>(w: &mut W, image: &dyn fmt::Display) -> io::Result<()> {
    writeln!(w, "   Image: {}", image)
}

/// Emit a sub-item image field readout via [`tracing::info!`] on the
/// fleet-standard `"   Image: <image>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::info_namespace_field!`] /
/// [`crate::info_zone_id_field!`] / [`crate::info_workload_field!`]
/// (same three-space-indented shape class, different labels and value
/// semantics), and the compounding rationale for the load-bearing
/// three-space indent.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("   Image: {}", image_path);
///
/// // Post-lift
/// crate::info_image_field!(image_path);
/// ```
#[macro_export]
macro_rules! info_image_field {
    ($image:expr) => {
        ::tracing::info!("   Image: {}", $image)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: three ASCII spaces (0x20 0x20 0x20),
    // the literal `Image:` (6 bytes), one ASCII space, the interpolated
    // image Display, then `\n`. A future refactor that changes the
    // indent width, drops the colon, changes the label capitalization,
    // or drops the trailing newline regresses this assertion.
    #[test]
    fn write_image_field_emits_three_space_indent_label_image_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"ghcr.io/pleme-io/svc").unwrap();
        assert_eq!(buf, b"   Image: ghcr.io/pleme-io/svc\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_image_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"svc").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "   Image: svc\n");
    }

    // The `cluster_overlay_release_preamble.rs` pre-lift site passes an
    // `image_path: &str` — a local filesystem path to a Nix-built OCI
    // tarball, up to and including a `/nix/store/<hash>-<name>-<ver>/`
    // prefix. Pin that a long slash-bearing path flows through the
    // writer verbatim (no truncation, no basename extraction, no
    // path-separator mangling).
    #[test]
    fn write_image_field_forwards_nix_store_path_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let path = "/nix/store/abcdef1234567890abcdef1234567890-svc-0.1.1/image.tar.gz";
        write_image_field(&mut buf, &path).unwrap();
        let expected = format!("   Image: {}\n", path);
        assert_eq!(String::from_utf8(buf).unwrap(), expected);
    }

    // The `deploy.rs` pre-lift site passes an `image_name: &str` — the
    // last `/`-delimited component of the destination registry. Pin
    // that a bare short identifier flows through the writer without any
    // synthetic prefix, suffix, or path fabrication.
    #[test]
    fn write_image_field_forwards_bare_image_name_without_synthetic_prefix() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"svc").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s, "   Image: svc\n");
        // No accidental `/` or `:` insertion that would suggest the
        // writer is synthesizing a fully-qualified image reference from
        // the bare name.
        assert!(
            !s[10..].contains('/'),
            "must NOT synthesize a `/`-bearing path from a bare name; got: {s:?}"
        );
        assert!(
            !s[10..].contains(':'),
            "must NOT synthesize a `:<tag>` suffix from a bare name; got: {s:?}"
        );
    }

    // Guard against a two-space-indent drift: adjacent tracing lines in
    // the pre-lift release / deploy preambles carry a THREE-space
    // indent (a sub-item under the parent `🚀 Starting <release> release` /
    // `📝 Updating kustomization.yaml...` header). Pin the three-space
    // width so a future collapse to a two-space (`  `) or four-space
    // (`    `) grammar hits the byte-oracle test rather than shipping
    // a misaligned sub-item under the parent header.
    #[test]
    fn write_image_field_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"svc").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Image:"),
            "must start with three spaces + label; got: {s:?}"
        );
        assert!(
            !s.starts_with("  Image:"),
            "must NOT be two-space indent; got: {s:?}"
        );
        assert!(
            !s.starts_with("    Image:"),
            "must NOT be four-space indent; got: {s:?}"
        );
    }

    // Guard against a glyph drift: this primitive is deliberately the
    // sub-item shape — no emoji, no `📦` / `🎯` / `🏷️` anchor. A
    // future refactor that reached for the top-level emoji-labeled
    // family (e.g. `📦 Image:`) would break the parent-header + sub-item
    // grouping that the pre-lift preambles rely on.
    #[test]
    fn write_image_field_emits_no_leading_emoji_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"svc").unwrap();
        // First byte must be an ASCII space (0x20); a leading emoji
        // would place a non-ASCII byte there.
        assert_eq!(
            buf[0], 0x20,
            "byte 0 must be an ASCII space (0x20); a leading emoji \
             would place a non-ASCII byte there. Bytes: {buf:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B) — a future refactor that reached for
    // `colored` on the label side would break the ANSI-free contract
    // the tracing-routed sites depend on.
    #[test]
    fn write_image_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_image_field(&mut buf, &"svc").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_image_field must emit no ANSI escape (0x1B) — \
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
    fn info_image_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (both pre-lift call sites' shape today).
        let image_str: &str = "svc";
        crate::info_image_field!(image_str);

        // Owned `String` via the same slot.
        let owned = String::from("svc");
        crate::info_image_field!(owned);

        // A `&String` reference — a future caller may hold the image
        // as a `String` field and pass a shared reference.
        let borrowed = &String::from("svc");
        crate::info_image_field!(borrowed);

        // A future substrate::OciImageRef newtype would implement
        // Display — simulate with a Display-wrapping newtype to prove
        // the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_image_field!(Wrap("svc"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("   Image: {}", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_image_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_image_field_stanza() {
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
                if line.contains("info!(\"   Image: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"   Image: {{}}\", <arg>);` stanza(s) \
             survive under `commands/` — route each through \
             `crate::info_image_field!(<image>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the two pre-lift files MUST each
    // forward through `crate::info_image_field!(` at least once, so
    // a migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_image_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] =
            &[("cluster_overlay_release_preamble.rs", 1), ("deploy.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_image_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} image \
                 sub-item site(s) through `crate::info_image_field!(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
