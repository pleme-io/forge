//! Info-routed `Using pod: <pod>` zero-indent pod-selection field-readout
//! grammar.
//!
//! Two pre-lift sibling sites across `commands/seed.rs` — one at
//! `seed` (`:310`, immediately below
//! `info!("Finding primary postgres pod...")` and the sibling
//! `find_primary_pod(&env_cfg.namespace, &postgres_cluster)?` resolve),
//! one at `unseed` (`:350`, the same three-line preamble shape) — each
//! restated the
//!
//! ```ignore
//! info!("Using pod: {}", pod);
//! ```
//!
//! stanza verbatim — zero indent, the nine-character `Using pod:`
//! label, one ASCII space, the interpolated
//! [`std::fmt::Display`]-formatted pod name, and an `info!`-routed
//! emission via the tracing subscriber. Post-lift the sites reach for
//! [`info_using_pod_field!`] and the indent width + label + separator +
//! tracing verbosity are decided once here.
//!
//! # Distinct from the sibling `info!("🔧 Using <label>: {}", <value>)` primitive
//!
//! [`crate::info_using_tool_field!`] is the fleet's tool-discovery
//! announcement primitive: a zero-indent `🔧 Using <label>: <value>`
//! line, seven pre-lift sites migrated (`nix_hooks.rs:71` +
//! `commands/bootstrap.rs:622–:623` + `commands/pangea.rs:477–:478 +
//! :522–:523`), all announcing a just-resolved BUILD-TOOLCHAIN binary
//! or env-var path (`cargo`, `crate2nix`, `bundler`, `bundix`) being
//! adopted for an imminent local process spawn. Its own module docs
//! explicitly carve out this primitive's two `Using pod:` sites as
//! "deliberately out of scope" — the value being narrated is a
//! runtime Kubernetes resource identifier returned by
//! [`crate::commands::seed::find_primary_pod`], not a discovered
//! build-tool binary. Collapsing the two grammars would fuse the
//! build-tool sigil family with the runtime-k8s-resource selection
//! family, erasing the local-vs-remote sink-target distinction the
//! operator uses to tell one line's meaning from the other, and would
//! force one direction to either fabricate a `🔧` glyph the pod sites
//! do not carry, or drop the `🔧` glyph the tool sites rely on for
//! their operator-visibility anchor.
//!
//! # Distinct from the sibling three-space-indented sub-item field primitives
//!
//! The crate carries a small family of `   <Label>: <value>` sub-item
//! field-readout primitives ([`crate::info_namespace_field!`],
//! [`crate::info_zone_id_field!`], [`crate::info_image_field!`],
//! [`crate::info_workload_field!`]) that all emit a THREE-space-indented
//! `<Label>: <value>` line under an emoji-anchored parent header. This
//! primitive is deliberately **not** one of them: both pre-lift stanzas
//! carry ZERO indent (each is a top-level narrative line inside the
//! seed/unseed pod-discovery preamble, not a sub-item under a
//! separately-emitted emoji-anchored header). A merge into any bare
//! sub-item primitive would fabricate three spaces of indent the
//! pre-lift sites do not carry.
//!
//! # The two pre-lift sites are byte-identical
//!
//! Both `commands/seed.rs::seed` (at `:308–:310`) and
//! `commands/seed.rs::unseed` (at `:348–:350`) spell the same
//! three-line preamble:
//!
//! ```ignore
//! info!("Finding primary postgres pod...");
//! let pod = find_primary_pod(&env_cfg.namespace, &postgres_cluster)?;
//! info!("Using pod: {}", pod);
//! ```
//!
//! The two functions are mirror-image entry points — `seed` inserts
//! test profiles, `unseed` removes them — and both open with the same
//! pod-discovery step against the same `find_primary_pod` primitive.
//! The `Using pod:` narration is the third line of that preamble in
//! both flows. Lifting only that line (rather than the whole
//! three-line preamble as a fusion) keeps this primitive's scope tight
//! to the readout grammar and leaves the sibling announcement +
//! pod-resolve pair for a future fusion consolidation if the
//! find-and-narrate stanza recurs elsewhere.
//!
//! # Preserving `tracing::info!` at the call site
//!
//! The macro expands to `::tracing::info!(...)` at the caller's
//! location, not to a function wrapper, so tracing's automatic source-
//! location capture (`file` + `line` + `module_path`) matches the
//! pre-lift behavior byte-for-byte. A function-based wrapper would
//! collapse every emission to the wrapper's own site and break
//! structured-log destinations that filter by `module_path`
//! (`RUST_LOG=forge::commands::seed=info` would stop matching once the
//! emission moved to `forge::using_pod_field`). The byte-oracle writer
//! sibling [`write_using_pod_field`] captures the exact rendered body
//! for the tests (the zero indent, the `Using pod:` label, the
//! single-space gap before the pod name, the trailing newline) so the
//! invariant is pinned without racing an ambient tracing subscriber —
//! the same split
//! [`crate::namespace_field::write_namespace_field`] carries against
//! [`crate::info_namespace_field!`] and
//! [`crate::using_tool_field::write_using_tool_field`] carries against
//! [`crate::info_using_tool_field!`].

use std::fmt;
use std::io;

/// Emits a single `"Using pod: <pod>"` line via [`writeln!`] against
/// the supplied writer, wrapping the caller's pod name with the
/// pre-lift zero-indent + `Using pod: ` label prefix that two sibling
/// sites spelled inline.
///
/// The [`crate::info_using_pod_field!`] macro is the [`tracing::info!`]
/// adapter that production code invokes; this direct-writer variant
/// exists so the fail-before-pass tests can pin the exact emitted bytes
/// (the zero indent, the `Using pod:` label literal, the single-space
/// gap before the pod name, the trailing newline) without capturing a
/// tracing subscriber and without racing an ambient logger — the same
/// split [`crate::namespace_field::write_namespace_field`] carries
/// against [`crate::info_namespace_field!`] and
/// [`crate::using_tool_field::write_using_tool_field`] carries against
/// [`crate::info_using_tool_field!`].
///
/// The `pod` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (both pre-lift call sites' shape
/// today, sourced from a `String` returned by `find_primary_pod`), an
/// owned `String`, `Cow<str>`, and a future Kubernetes-pod newtype
/// (`substrate::KubePodName(String)`) all flow through the same writer
/// without a per-caller `.to_string()` intermediate.
#[allow(dead_code)] // Peer of the tracing-routed `info_using_pod_field!`
                    // macro, retained for the byte-oracle tests and for
                    // a future summary-report consumer.
pub fn write_using_pod_field<W: io::Write>(w: &mut W, pod: &dyn fmt::Display) -> io::Result<()> {
    writeln!(w, "Using pod: {}", pod)
}

/// Emit a pod-selection field readout via [`tracing::info!`] on the
/// fleet-standard `"Using pod: <pod>"` grammar.
///
/// The macro expands to a direct `::tracing::info!(...)` call at the
/// caller's location so tracing's automatic source-location capture is
/// preserved (a function wrapper would collapse every emission to the
/// wrapper's site — see the module docs for why that breaks per-module
/// filter routing). See the [module docs](self) for the sibling site
/// census, the split against [`crate::info_using_tool_field!`]
/// (build-tool discovery, `🔧` glyph, distinct semantic layer), the
/// split against the three-space-indented sub-item field primitives
/// (this primitive is zero-indent), and the compounding rationale for
/// keeping the pod-narration grammar owned by one primitive.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// info!("Using pod: {}", pod);
///
/// // Post-lift
/// crate::info_using_pod_field!(pod);
/// ```
#[macro_export]
macro_rules! info_using_pod_field {
    ($pod:expr) => {
        ::tracing::info!("Using pod: {}", $pod)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact prefix bytes: zero indent, the literal `Using pod:`
    // (10 bytes), one ASCII space, the interpolated pod Display, then
    // `\n`. A future refactor that added an indent, dropped the colon,
    // changed the label capitalization, or dropped the trailing newline
    // regresses this assertion.
    #[test]
    fn write_using_pod_field_emits_zero_indent_label_pod_and_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_pod_field(&mut buf, &"postgres-cluster-1-0").unwrap();
        assert_eq!(buf, b"Using pod: postgres-cluster-1-0\n");
    }

    // Human-readable pin of the exact grammar so a future reader can
    // eyeball the render without decoding bytes.
    #[test]
    fn write_using_pod_field_renders_expected_grammar() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_pod_field(&mut buf, &"postgres-cluster-1-0").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "Using pod: postgres-cluster-1-0\n"
        );
    }

    // A Kubernetes pod name is a DNS-1123 label — lowercase alphanumeric
    // + hyphens, 1..=253 chars (the RFC 1123 subdomain form CNPG uses
    // for its `<cluster>-<n>` primary-pod names). Pin that the writer
    // forwards a canonical CNPG-shaped name verbatim (no truncation,
    // no case-fold, no hyphen mangling). Guards against a future
    // helper that "sanitizes" the pod name at the primitive layer,
    // which the caller must have already done at input validation.
    #[test]
    fn write_using_pod_field_forwards_cnpg_shaped_name_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        let pod = "pleme-postgres-cluster-primary-0";
        write_using_pod_field(&mut buf, &pod).unwrap();
        let expected = format!("Using pod: {}\n", pod);
        assert_eq!(String::from_utf8(buf).unwrap(), expected);
    }

    // Guard against a three-space-indent drift: the sibling sub-item
    // field-readout primitives ([`crate::info_namespace_field!`],
    // [`crate::info_image_field!`], [`crate::info_zone_id_field!`],
    // [`crate::info_workload_field!`]) all carry THREE spaces of indent
    // because they render as sub-items under an emoji-anchored parent
    // header emitted separately by the caller. This primitive is
    // deliberately the ZERO-indent shape because both pre-lift sites
    // emit as top-level narrative lines inside the seed/unseed
    // pod-discovery preamble (no parent header). Pin the zero-indent
    // width so a future collapse onto the three-space family hits the
    // byte-oracle test rather than shipping a mis-indented pod line.
    #[test]
    fn write_using_pod_field_uses_zero_indent_not_three() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_pod_field(&mut buf, &"pod").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("Using pod:"),
            "must start with the bare label (zero indent); got: {s:?}"
        );
        assert!(
            !s.starts_with(" "),
            "must NOT lead with ANY whitespace; got: {s:?}"
        );
    }

    // Guard against the sibling `🔧 Using <label>:` shape drift: the
    // fleet's build-tool-discovery family
    // ([`crate::info_using_tool_field!`]) emits with a `🔧` WRENCH glyph
    // anchor (U+1F527). This primitive is deliberately glyphless — the
    // value narrated here is a runtime Kubernetes resource, not a
    // build-tool binary, and the operator uses the missing glyph to
    // tell one line's meaning from the other at a glance. Pin that
    // this primitive emits NO leading `🔧` (or any other emoji) — a
    // future collapse of the two grammars would either fabricate the
    // wrench the pod sites cannot semantically source, or drop the
    // wrench the tool sites rely on for their operator anchor.
    #[test]
    fn write_using_pod_field_emits_no_leading_emoji_glyph() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_pod_field(&mut buf, &"pod").unwrap();
        // First byte must be the ASCII 'U' of "Using pod:" (0x55); a
        // leading emoji would place a non-ASCII byte there.
        assert_eq!(
            buf[0], b'U',
            "byte 0 must be the ASCII 'U' of 'Using pod:'; a leading \
             emoji would place a non-ASCII byte there. Bytes: {buf:?}"
        );
        // Explicit `🔧` WRENCH exclusion (U+1F527, F0 9F 94 A7).
        assert!(
            !buf.windows(4).any(|w| w == [0xF0, 0x9F, 0x94, 0xA7]),
            "must NOT emit the sibling `🔧` WRENCH anchor; got: {buf:?}"
        );
    }

    // No-ANSI guard: the crate's `tracing_subscriber` initialization in
    // `main.rs` deliberately sets `with_ansi(false)` so CI log ingestion
    // sees clean records. Pin that this primitive's render carries no
    // ANSI escape byte (0x1B) — a future refactor that reached for
    // `colored` on the label side would break the ANSI-free contract
    // the tracing-routed sites depend on.
    #[test]
    fn write_using_pod_field_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        write_using_pod_field(&mut buf, &"pod").unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_using_pod_field must emit no ANSI escape (0x1B) — \
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
    fn info_using_pod_field_macro_compiles_with_supported_arg_shapes() {
        // Bare `&str` (a function local of the pre-lift call sites).
        let pod_str: &str = "pod";
        crate::info_using_pod_field!(pod_str);

        // Owned `String` via the same slot — `find_primary_pod` returns
        // `Result<String>` and both pre-lift sites bind the unwrapped
        // `String` to a `pod` local passed as `pod` (bare Display
        // forward, which the format machinery resolves through Deref
        // to `&str`).
        let owned = String::from("pod");
        crate::info_using_pod_field!(owned);

        // A `&String` reference — a future refactor may hold the pod
        // as a struct field and pass a shared reference.
        let borrowed = &String::from("pod");
        crate::info_using_pod_field!(borrowed);

        // A future substrate::KubePodName newtype would implement
        // Display — simulate with a Display-wrapping newtype to prove
        // the slot takes any Display.
        struct Wrap<'a>(&'a str);
        impl<'a> fmt::Display for Wrap<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        crate::info_using_pod_field!(Wrap("pod"));
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pre-lift raw `info!("Using pod: {}", <arg>);` stanza
    // inline any more. The two pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::info_using_pod_field!` on first grep, not by copy-pasting
    // the raw shape from an existing command module.
    #[test]
    fn no_command_module_still_spells_raw_info_using_pod_field_stanza() {
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
                if line.contains("info!(\"Using pod: {}\"") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `info!(\"Using pod: {{}}\", <arg>);` stanza(s) survive \
             under `commands/` — route each through \
             `crate::info_using_pod_field!(<pod>)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the pre-lift file `commands/seed.rs`
    // (which carries BOTH sibling sites — one in `seed`, one in
    // `unseed`) MUST forward through `crate::info_using_pod_field!(`
    // at least TWICE, so a migration that dropped one call site
    // outright leaves the negative "no raw inline shape" scan trivially
    // satisfied by absence but the positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_info_using_pod_field_macro() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // (module basename, minimum forward count from the pre-lift
        // census). Both pre-lift sites live in one file (seed.rs) —
        // one in `seed`, one in `unseed` — so the expectation floor is
        // 2 forwards in that single module.
        let expectations: &[(&str, usize)] = &[("seed.rs", 2)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("crate::info_using_pod_field!(").count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `Using pod:` site(s) through \
                 `crate::info_using_pod_field!(`; found {forwards}. A \
                 dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
