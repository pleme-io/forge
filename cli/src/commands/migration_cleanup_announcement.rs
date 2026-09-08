//! Migration cleanup-phase announcement — `🧹 Cleaning up <what>...`
//! single-line stanza primitive.
//!
//! Three sibling `println!("🧹 Cleaning up <what>...")` announcement
//! stanzas in `commands/migrations.rs` each spelled the same
//! broom-glyph + `Cleaning up` verb + trailing `...` ellipsis shape,
//! differing only in the `<what>` noun-phrase slot:
//!
//! ```ignore
//! println!("🧹 Cleaning up failed migration job...");     // post-fail branch
//! println!("🧹 Cleaning up existing migration jobs...");  // reset-status branch
//! println!("🧹 Cleaning up orphaned migration pods...");  // post-reset pods branch
//! ```
//!
//! Three occurrences of an identical shape past THEORY §VI.1's
//! three-is-a-law threshold; this module is the law-redeeming extraction.
//! Post-lift each site calls
//! [`print_migration_cleanup_announcement`] with a `&str` noun-phrase
//! naming the resource class being reaped, and inherits the canonical
//! `🧹 Cleaning up ` prefix + `...` ellipsis suffix through one site.
//!
//! # Byte-oracle
//!
//! [`write_migration_cleanup_announcement`] is the writer-taking
//! sibling — a `Vec<u8>` sink lets tests pin the exact rendered bytes
//! (the four-byte `🧹 ` glyph U+1F9F9 + trailing ASCII space + the
//! twelve-byte `Cleaning up ` verb + the caller's noun-phrase + the
//! three-byte `...` ellipsis + trailing `\n`, with NO ANSI escape) at
//! one site rather than as three lockstep literals across
//! `migrations.rs`.

use std::io;

/// The invariant prefix every pre-lift announcement spelled — the
/// broom glyph U+1F9F9, a trailing ASCII space, the `Cleaning up`
/// verb, and one more ASCII space before the caller-supplied
/// noun-phrase. Named as a `const` so a future re-branding of the
/// verb or the glyph (e.g. dropping the emoji for accessibility, or
/// promoting to `.dimmed()` inside a future `write_dimmed_cleanup_*`
/// sibling) reaches one site rather than three inline literals.
pub const CLEANUP_ANNOUNCEMENT_PREFIX: &str = "\u{1f9f9} Cleaning up ";

/// The invariant suffix every pre-lift announcement spelled — the
/// three-byte ASCII `...` ellipsis marking the ongoing-action tense
/// the operator sees before the actual `kubectl delete` output. Named
/// as a `const` so a future swap for the U+2026 HORIZONTAL ELLIPSIS
/// (`…`) reaches one site.
pub const CLEANUP_ANNOUNCEMENT_SUFFIX: &str = "...";

/// Emit the canonical `🧹 Cleaning up <what>...` migration
/// cleanup-phase announcement to stdout. Called immediately above
/// each `kubectl delete` fan-out in `commands/migrations.rs` to signal
/// to the operator which resource class the upcoming spawn is about
/// to reap.
///
/// Pre-lift each site spelled the announcement verbatim as
///
/// ```ignore
/// println!("🧹 Cleaning up <what>...");
/// ```
///
/// A future adjustment (a swap of the broom glyph for a stricter
/// hazard-symbol, a rebrand of the `Cleaning up` verb, a promotion to
/// `.dimmed()` so it recedes beneath the subsequent `kubectl` output,
/// wiring an OTLP `migration_cleanup_started` event alongside the
/// print) reaches ONE typed body rather than three lockstep sites.
///
/// Delegates to [`write_migration_cleanup_announcement`] against
/// [`std::io::stdout`]; the writer split exists so the fail-before-pass
/// byte-oracle test pins the exact rendered bytes without capturing
/// stdout.
pub fn print_migration_cleanup_announcement(what: &str) {
    let _ = write_migration_cleanup_announcement(&mut io::stdout().lock(), what);
}

/// Writer-taking sibling to [`print_migration_cleanup_announcement`].
/// Emits the single `🧹 Cleaning up <what>...\n` line via
/// [`writeln!`] against the supplied writer.
///
/// [`print_migration_cleanup_announcement`] is the stdout adapter;
/// this variant exists so tests can pin the exact prefix bytes (the
/// four-byte broom glyph U+1F9F9 + trailing ASCII space + the
/// twelve-byte `Cleaning up ` verb), the caller's noun-phrase, the
/// three-byte `...` ellipsis, and the absence of every ANSI palette
/// sequence without capturing stdout.
pub fn write_migration_cleanup_announcement<W: io::Write>(w: &mut W, what: &str) -> io::Result<()> {
    writeln!(
        w,
        "{}{}{}",
        CLEANUP_ANNOUNCEMENT_PREFIX, what, CLEANUP_ANNOUNCEMENT_SUFFIX
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-before-pass envelope for
    /// [`write_migration_cleanup_announcement`]. Pins the one-line
    /// body every pre-lift consumer spelled verbatim: the four-byte
    /// broom glyph U+1F9F9 + trailing ASCII space + the twelve-byte
    /// `Cleaning up ` verb + the caller's noun-phrase + the
    /// three-byte `...` ellipsis + trailing `\n`. A silent drift a
    /// future rewrite might introduce — swapping the broom glyph
    /// for a stricter hazard-symbol, dropping the trailing ellipsis,
    /// or dropping the space between glyph and verb — flips this
    /// assertion rather than compiling and silently diverging the
    /// three consumer sites' visual grammar.
    #[test]
    fn write_migration_cleanup_announcement_emits_broom_verb_noun_ellipsis_line_verbatim() {
        let mut buf: Vec<u8> = Vec::new();
        write_migration_cleanup_announcement(&mut buf, "failed migration job")
            .expect("write_migration_cleanup_announcement against a Vec<u8> writer must succeed");
        let out = String::from_utf8(buf).expect(
            "write_migration_cleanup_announcement must emit valid UTF-8 (the pre-lift println!s did)",
        );
        assert_eq!(
            out, "\u{1f9f9} Cleaning up failed migration job...\n",
            "byte-oracle: the single-line announcement must render verbatim — \
             U+1F9F9 broom + ASCII space + `Cleaning up ` + noun-phrase + `...` \
             + `\\n`, no ANSI escape, no other glyph"
        );
    }

    /// The three pre-lift consumer noun-phrases MUST each render into
    /// a distinct, verbatim announcement line. This test enumerates
    /// the pre-lift census (`failed migration job`, `existing migration
    /// jobs`, `orphaned migration pods`) so a future refactor that
    /// dropped one of the three flows silently fails when the census
    /// row falls off. Pins each rendered line byte-for-byte against
    /// the pre-lift string a `git log`-style audit query would search
    /// for.
    #[test]
    fn write_migration_cleanup_announcement_covers_pre_lift_noun_phrase_census() {
        const CENSUS: &[(&str, &str)] = &[
            (
                "failed migration job",
                "\u{1f9f9} Cleaning up failed migration job...\n",
            ),
            (
                "existing migration jobs",
                "\u{1f9f9} Cleaning up existing migration jobs...\n",
            ),
            (
                "orphaned migration pods",
                "\u{1f9f9} Cleaning up orphaned migration pods...\n",
            ),
        ];
        for (what, expected) in CENSUS {
            let mut buf: Vec<u8> = Vec::new();
            write_migration_cleanup_announcement(&mut buf, what).unwrap();
            let out = String::from_utf8(buf).unwrap();
            assert_eq!(
                &out, expected,
                "write_migration_cleanup_announcement({what:?}) must \
                 render byte-for-byte as the pre-lift `println!` at the \
                 corresponding `commands/migrations.rs` site. Got {out:?}"
            );
        }
    }

    /// A silent promotion of the primitive to `.bold()` / `.dimmed()` /
    /// any `.<color>()` chain would flatten the announcement grammar
    /// the pre-lift three sites deliberately kept as plain uncolored
    /// stdout so the subsequent `kubectl delete` output carries the
    /// operator's eye. This shield pins the absence of every ANSI
    /// escape byte so a color-chain promotion surfaces here rather
    /// than silently coloring three cleanup flows.
    #[test]
    fn write_migration_cleanup_announcement_carries_no_ansi_escape_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_migration_cleanup_announcement(&mut buf, "existing migration jobs").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains('\x1b'),
            "write_migration_cleanup_announcement must carry NO ANSI escape \
             byte (`\\x1b`) — the pre-lift `println!(\"🧹 Cleaning up ...\")` \
             sites reach stdout uncolored; a `.bold()` / `.dimmed()` / \
             `.<color>()` promotion would flatten the announcement grammar. \
             Got {out:?}"
        );
    }

    /// The primitive MUST NOT emit anything for the caller-supplied
    /// noun-phrase beyond the exact bytes handed in — no trimming,
    /// case-folding, punctuation injection, or newline suppression.
    /// A future normalisation at the primitive boundary would silently
    /// diverge from what the pre-lift inline `println!` did with the
    /// literal noun-phrase, and a caller passing an already-terminated
    /// phrase (`"foo..."`) would double-emit the ellipsis. Pin the
    /// verbatim-forwarding contract.
    #[test]
    fn write_migration_cleanup_announcement_forwards_noun_phrase_verbatim_no_normalisation() {
        let mut buf: Vec<u8> = Vec::new();
        // Deliberately gnarly noun-phrase — mixed case, embedded
        // punctuation, leading/trailing whitespace inside the string.
        write_migration_cleanup_announcement(&mut buf, "STAGE-2 orphan Job(s)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(
            out, "\u{1f9f9} Cleaning up STAGE-2 orphan Job(s)...\n",
            "write_migration_cleanup_announcement must forward the \
             noun-phrase verbatim — no trim, no case-fold, no punctuation \
             injection. Got {out:?}"
        );
    }

    /// Whole-fleet negative caller shield: no raw
    /// `println!("🧹 Cleaning up ...` may live in
    /// `commands/migrations.rs`. Post-lift the three pre-lift sites
    /// each forward through [`print_migration_cleanup_announcement`];
    /// a future re-inline (a "just call `println!` directly, it's
    /// shorter" cleanup) silently reopens the three-site duplication
    /// class this lift closed.
    ///
    /// Enforced against the module body BEFORE its first
    /// `#[cfg(test)]` region so a test-support mention of the raw
    /// shape does not defeat the shield.
    #[test]
    fn no_raw_broom_cleanup_println_survives_in_migrations() {
        const SOURCE: &str = include_str!("migrations.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/migrations.rs",
        );
        // Reconstruct the forbidden needle from the const so this
        // shield's own docstring mention of the glyph does not
        // false-match itself when the shield reads its own source.
        let needle = format!(
            "println!(\"{}Cleaning up ",
            "\u{1f9f9} " // reconstructed from const bytes rather than a raw literal
        );
        for (i, line) in body.lines().enumerate() {
            assert!(
                !line.contains(&needle),
                "commands/migrations.rs:{lineno} spells the pre-lift \
                 inline `println!(\"🧹 Cleaning up ...\")` cleanup-phase \
                 announcement — that shape was lifted onto \
                 `crate::commands::migration_cleanup_announcement::\
                 print_migration_cleanup_announcement`. A re-inline \
                 silently reopens the three-site duplication class this \
                 shield exists to close. Offending line: {line:?}",
                lineno = i + 1
            );
        }
    }

    /// Positive delegation shield — `commands/migrations.rs` must
    /// forward through [`print_migration_cleanup_announcement`] at
    /// exactly three sites (one per pre-lift consumer). A fusion that
    /// folded two consumer sites into one call or dropped one of the
    /// announcements silently fails here — the negative half above
    /// would still pass, but the positive count would fall below the
    /// pre-lift census.
    #[test]
    fn migrations_module_forwards_through_cleanup_announcement_primitive_three_times() {
        const SOURCE: &str = include_str!("migrations.rs");
        let body = crate::test_support::module_body_before_first_cfg_test(
            SOURCE,
            "commands/migrations.rs",
        );
        const FORWARD_NEEDLE: &str =
            "migration_cleanup_announcement::print_migration_cleanup_announcement(";
        let forward_hits = body.matches(FORWARD_NEEDLE).count();
        assert_eq!(
            forward_hits, 3,
            "commands/migrations.rs body must forward to \
             `crate::commands::migration_cleanup_announcement::\
             print_migration_cleanup_announcement(...)` at exactly 3 sites \
             — one per pre-lift consumer. Found {forward_hits} forwarding hits."
        );
    }
}
