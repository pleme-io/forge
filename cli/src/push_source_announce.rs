//! `>> <svc> (<source-phrase>)` Phase-1 push-source announce
//! primitive — the peer-class single-line stanza three sibling
//! `commands/product_release.rs::execute` Phase-1 push-source branches
//! each restated verbatim as
//! `println!("   {} {} (<phrase>)", ">>".dimmed(), svc.name.cyan())`.
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling sites each restated the same three-line
//! `println!("   {} {} (<phrase>)", ">>".dimmed(), svc.name.cyan())`
//! stanza verbatim, diverging only on the parenthesized source-phrase
//! literal (baked into the pre-lift format string, uncolored):
//!
//! 1. `commands/product_release.rs::execute` (~L475-479, `has_local
//!    && !skip_gates` push-prebuilt-from-E2E branch) — the
//!    `(push prebuilt from E2E)` phrase.
//! 2. `commands/product_release.rs::execute` (~L485-489, `skip_gates`
//!    fallback branch) — the `(build + push, gates were skipped)`
//!    phrase.
//! 3. `commands/product_release.rs::execute` (~L491-495, `!skip_gates`
//!    fallback branch, no prebuilt image) — the
//!    `(build + push, no prebuilt image)` phrase.
//!
//! Each of the three spellings renders the same byte shape: three
//! leading ASCII spaces, the dimmed `>>` prefix, one ASCII space, the
//! cyan service-name slot, one ASCII space, the plain-text
//! parenthesized source-phrase (baked into the pre-lift format string,
//! uncolored), and a trailing `\n`. A drift in the prefix (`>>` → `→`
//! under a symbol-rebrand), the leading-space count (`"   "` → `"  "`
//! under a spacing-tightening pass), the service-slot color (`.cyan()`
//! → `.cyan().bold()` under a stronger-visual-anchor mode), the
//! phrase's outer punctuation (`(<phrase>)` → `— <phrase>`), or the
//! delimiter between the service and the phrase at any one site
//! pre-lift diverged silently from the other two — the operator's eye
//! caught only the local branch, not the cross-branch grammar drift.
//!
//! # Distinct from the sibling `>>`-prefixed announce peers
//!
//! [`crate::product_workflow_intro_banner::print_product_workflow_intro_banner`]
//! owns the `>>`-BOLD-prefixed product-workflow intro banner
//! (`"{} {} <label> {}"` with a trailing `=`-rule underline pair). This
//! primitive owns the `>>`-DIMMED-prefixed per-service push-source
//! announce line whose parenthesized phrase encodes WHICH push-source
//! branch the Phase-1 loop took. The two primitives stay distinct
//! because the prefix palette encodes the message rank: bold `>>` on
//! the workflow-level intro banner, dimmed `>>` on the intra-loop
//! per-service source announce.
//!
//! [`crate::commands::subcommand_invocation`] owns the
//! `>>`-DIMMED-prefixed forge-subcommand-invocation announce
//! (`"   {} {} {}"` with a trailing joined-argv slot). This primitive
//! owns the two-slot `"   {} {} (<phrase>)"` shape with the
//! parenthesized phrase baked as a plain literal — no argv join, no
//! third dimmed slot.
//!
//! # THEORY grounding
//!
//! §V.1 knowable-platform construction guarantee: modelling the three
//! push-source variants as a closed enum makes an invalid Phase-1
//! push-source (a fourth branch someone added to the `if has_local &&
//! !skip_gates { … } else { if skip_gates { … } else { … } }` ladder
//! that the announce contract forgot to cover) structurally
//! impossible — the enum forces the announce site to name the new
//! variant, and every consumer inherits the new phrase from the
//! typed accessor rather than through a fourth inline `println!` a
//! future edit could omit.
//!
//! §VI.1 recurring-shape-to-helper past the three-times threshold:
//! three sites today all in `product_release.rs::execute` — clearing
//! the "three is a law" duplication threshold at exactly the point
//! THEORY calls a law. A future push-source variant (a fourth
//! `has_local && skip_gates` corner, a signed-artifact-only sibling
//! branch) adds ONE enum arm and ONE `phrase()` match arm and reaches
//! every announce site by construction rather than through a fourth
//! copy-pasted `println!` block.

use std::io;

use colored::Colorize;

/// The `>>` ASCII prefix opening every pre-lift push-source announce
/// line in the fixed `"   {} {} (<phrase>)"` template with
/// `">>".dimmed()` at the first slot. Named as a `const` so a future
/// swap (`>>` → `»` under a fleet-wide symbol rebrand, `>>` → `→`
/// under a directional-glyph pass) lands at ONE edit rather than
/// through three inline literal edits.
pub const PUSH_SOURCE_ANNOUNCE_PREFIX: &str = ">>";

/// Closed enum naming each pre-lift Phase-1 push-source branch that
/// spelled the `"   {} {} (<phrase>)"` announce stanza inline.
///
/// A future push-source variant (a fourth `has_local && skip_gates`
/// corner, a signed-artifact-only sibling branch) adds ONE arm here
/// and ONE arm in [`Self::phrase`], and every announce site inherits
/// the new phrase from the typed accessor rather than through a
/// fourth inline `println!` a future edit could omit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushSource {
    /// The `has_local && !skip_gates` branch that pushes the prebuilt
    /// Docker image built during Phase-0 E2E gates (avoiding a
    /// redundant Nix build).
    PushPrebuiltFromE2e,
    /// The `!has_local || skip_gates` fallback under `skip_gates` —
    /// the operator asked for `--skip-gates`, so no prebuilt image
    /// exists, and Phase-1 must build via Nix.
    BuildAndPushGatesSkipped,
    /// The `!has_local || skip_gates` fallback under `!skip_gates` —
    /// gates ran but the prebuilt image is absent (E2E didn't tag it,
    /// or a `docker image prune` cleared it), so Phase-1 must build
    /// via Nix.
    BuildAndPushNoPrebuiltImage,
}

impl PushSource {
    /// The parenthesized source-phrase (WITHOUT the outer parens; the
    /// parens are baked into the `write_push_source_announce`
    /// template) each pre-lift `println!` spelled as its plain-text
    /// literal.
    ///
    /// A drift here — a rewording, a case swap, a punctuation change
    /// — reaches every announce site by construction. Pre-lift, the
    /// same change would have required editing three separate
    /// `println!` format strings and any one omission would have
    /// silently diverged that branch's announce line.
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::PushPrebuiltFromE2e => "push prebuilt from E2E",
            Self::BuildAndPushGatesSkipped => "build + push, gates were skipped",
            Self::BuildAndPushNoPrebuiltImage => "build + push, no prebuilt image",
        }
    }
}

/// Prints the pre-lift per-service push-source announce line — the
/// dimmed `>>` prefix, the cyan service-name slot, and the
/// parenthesized push-source phrase — that all three
/// `commands/product_release.rs::execute` Phase-1 push-source branches
/// spelled inline pre-lift.
///
/// Delegates to [`write_push_source_announce`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass tests can pin the two-slot color ordering, the
/// leading-three-space indent, the dimmed prefix, the cyan
/// service-slot, and the parenthesized-plain-literal phrase by
/// inspecting emitted bytes rather than capturing stdout.
pub fn print_push_source_announce(svc_name: &str, source: PushSource) {
    let _ = write_push_source_announce(&mut io::stdout().lock(), svc_name, source);
}

/// Writer-taking sibling to [`print_push_source_announce`]. Emits the
/// same one-line body against a [`io::Write`] sink — the byte-oracle
/// surface for tests that pin the ANSI-wrapped prefix + service slot,
/// the uncolored parenthesized phrase, and the trailing `\n` without
/// capturing stdout.
///
/// # Byte contract
///
/// The written byte sequence is exactly:
///
/// ```text
///    \x1b[2m>>\x1b[0m \x1b[36m<svc_name>\x1b[0m (<source.phrase()>)\n
/// ```
///
/// (three leading ASCII spaces, dimmed `>>`, one space, cyan
/// `<svc_name>`, one space, `(`, uncolored `<source.phrase()>`, `)`,
/// trailing `\n`.)
pub fn write_push_source_announce<W: io::Write>(
    w: &mut W,
    svc_name: &str,
    source: PushSource,
) -> io::Result<()> {
    writeln!(
        w,
        "   {} {} ({})",
        PUSH_SOURCE_ANNOUNCE_PREFIX.dimmed(),
        svc_name.cyan(),
        source.phrase(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Mutex;

    /// Serialize the `.dimmed()` / `.cyan()` writer-level tests
    /// against the process-global [`colored::control::set_override`]
    /// toggle a peer test in `crate::ui` also acquires — a fair copy
    /// of the `AnsiOverrideForTest` guard shape in
    /// `cli/src/product_workflow_intro_banner.rs`. Cargo runs tests in
    /// parallel by default, so without a mutex two tests racing the
    /// override toggle would flap between the "ANSI on" and "ANSI
    /// off" arms.
    static ANSI_OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that force-enables [`colored`] ANSI emission for
    /// the duration of a writer-level byte-oracle test.
    struct AnsiOverrideForTest {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl AnsiOverrideForTest {
        fn acquire() -> Self {
            let lock = ANSI_OVERRIDE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            colored::control::set_override(true);
            Self { _lock: lock }
        }
    }

    impl Drop for AnsiOverrideForTest {
        fn drop(&mut self) {
            colored::control::unset_override();
        }
    }

    /// Byte-oracle: each of the three [`PushSource`] variants renders
    /// its pre-lift phrase verbatim — a rewording, a case flip, or a
    /// punctuation swap in [`PushSource::phrase`] fails here before
    /// any consumer re-routes.
    #[test]
    fn push_source_phrase_matches_pre_lift_parenthesized_literals() {
        assert_eq!(
            PushSource::PushPrebuiltFromE2e.phrase(),
            "push prebuilt from E2E",
            "PushPrebuiltFromE2e phrase must match the pre-lift \
             `(push prebuilt from E2E)` literal at product_release.rs:476"
        );
        assert_eq!(
            PushSource::BuildAndPushGatesSkipped.phrase(),
            "build + push, gates were skipped",
            "BuildAndPushGatesSkipped phrase must match the pre-lift \
             `(build + push, gates were skipped)` literal at \
             product_release.rs:486"
        );
        assert_eq!(
            PushSource::BuildAndPushNoPrebuiltImage.phrase(),
            "build + push, no prebuilt image",
            "BuildAndPushNoPrebuiltImage phrase must match the pre-lift \
             `(build + push, no prebuilt image)` literal at \
             product_release.rs:492"
        );
    }

    /// Byte-oracle: [`write_push_source_announce`] emits exactly one
    /// line — a trailing `\n`, no leading blank, no trailing framing
    /// blank pair. The pre-lift `println!` stanzas were one-line
    /// announces without a following `println!()`; a fusion that
    /// dropped or added a blank line here would drift the operator's
    /// scroll density.
    #[test]
    fn write_push_source_announce_emits_exactly_one_line() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_push_source_announce(&mut buf, "web", PushSource::PushPrebuiltFromE2e)
            .expect("write against Vec<u8> must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            1,
            "write_push_source_announce must emit exactly one line — \
             a trailing `\\n`, no leading blank, no trailing framing \
             blank pair; got {}:\n{:?}",
            lines.len(),
            out
        );
        assert!(
            out.ends_with('\n'),
            "line must end with `\\n`; got {:?}",
            out
        );
    }

    /// Byte-oracle: the emission begins with exactly three ASCII
    /// spaces then the dimmed `>>` prefix. A tightening pass that
    /// narrowed the leading indent to two spaces (or widened to four)
    /// would drift the pre-lift scroll density; this test pins the
    /// `"   "` indent verbatim.
    #[test]
    fn write_push_source_announce_starts_with_three_space_indent_then_prefix() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_push_source_announce(&mut buf, "svc", PushSource::PushPrebuiltFromE2e).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.starts_with("   "),
            "output must start with exactly three ASCII spaces — the \
             pre-lift `\"   {{}}\"` indent; got {:?}",
            out
        );
        // The 4th byte is the first byte of the dimmed-`>>` SGR wrap;
        // an ANSI-stripped view carries `>>` as the 4th–5th chars.
        assert!(
            out[3..].starts_with("\x1b["),
            "byte 3 must open an ANSI SGR sequence (the dimmed-`>>` \
             wrapper); got {:?}",
            &out[3..]
        );
    }

    /// Palette pin (prefix slot): the `dim` SGR parameter (`2`)
    /// reaches the buffer on the `>>` prefix. Every pre-lift consumer
    /// chained `.dimmed()` on `">>"` — a silent promotion to `.bold()`
    /// would drift the pre-lift byte contract and flip this.
    #[test]
    fn write_push_source_announce_carries_dim_on_prefix_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_push_source_announce(&mut buf, "svc", PushSource::PushPrebuiltFromE2e).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("\x1b[2m"),
            "output must carry the `dim` SGR parameter (`2`) on the \
             `>>` prefix slot — every pre-lift consumer chained \
             `.dimmed()`; got {:?}",
            out
        );
    }

    /// Palette pin (service slot): the `cyan` SGR parameter (`36`)
    /// reaches the buffer on the service-name slot. A promotion to
    /// `.cyan().bold()` (which would encode as `\x1b[1;36m` or
    /// `\x1b[36;1m`) or a swap to `.bright_cyan()` (`\x1b[96m`) would
    /// drift from the pre-lift `.cyan()` coloring.
    #[test]
    fn write_push_source_announce_carries_cyan_on_service_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_push_source_announce(&mut buf, "MY_SVC", PushSource::PushPrebuiltFromE2e).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("\x1b[36m"),
            "output must carry the `cyan` SGR parameter (`36`) on the \
             service slot; got {:?}",
            out
        );
        assert!(
            !out.contains("\x1b[96m"),
            "output must NOT carry `bright_cyan` (`96`) — the pre-lift \
             coloring was `.cyan()` alone; got {:?}",
            out
        );
        assert!(
            !out.contains("\x1b[1;36m") && !out.contains("\x1b[36;1m"),
            "output must NOT carry `.cyan().bold()` (`\\x1b[1;36m` / \
             `\\x1b[36;1m`) — the pre-lift coloring was `.cyan()` alone \
             on the service slot; got {:?}",
            out
        );
    }

    /// Byte-oracle: the phrase slot is UNCOLORED. Every pre-lift
    /// consumer baked the phrase as a plain-text literal directly
    /// into the format string (`"(push prebuilt from E2E)"`,
    /// `"(build + push, gates were skipped)"`, `"(build + push, no
    /// prebuilt image)"`), i.e. with no `.dimmed()` or other coloring.
    /// A silent promotion to `.dimmed()` on the phrase would drift the
    /// pre-lift byte contract.
    #[test]
    fn write_push_source_announce_phrase_slot_is_uncolored() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_push_source_announce(&mut buf, "svc", PushSource::BuildAndPushGatesSkipped).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let phrase = PushSource::BuildAndPushGatesSkipped.phrase();
        let idx = out
            .find(phrase)
            .unwrap_or_else(|| panic!("phrase {:?} present in {:?}", phrase, out));
        // The parenthesized phrase must be preceded by the opening
        // `(` byte (a plain ASCII byte, not an ANSI escape) — a silent
        // wrap in `.dimmed()` would put a `\x1b[2m` between the `(`
        // and the phrase bytes.
        assert!(
            idx > 0,
            "phrase must be preceded by at least one byte (the `(`)"
        );
        let preceding = &out.as_bytes()[idx - 1..idx];
        assert_eq!(
            preceding, b"(",
            "phrase must be preceded by the literal `(` byte — a silent \
             `.dimmed()` wrap would insert an ANSI escape between the `(` \
             and the phrase bytes; got preceding={:?}, out={:?}",
            preceding, out
        );
    }

    /// Byte-oracle: the phrase is wrapped in literal `(` and `)`
    /// bytes. The parens are baked into the primitive template, not
    /// into [`PushSource::phrase`], so a drift in either direction
    /// (paren migration into `phrase()`, or dropping the parens from
    /// the template) fails here.
    #[test]
    fn write_push_source_announce_wraps_phrase_in_literal_parens() {
        let _override_guard = AnsiOverrideForTest::acquire();
        for source in [
            PushSource::PushPrebuiltFromE2e,
            PushSource::BuildAndPushGatesSkipped,
            PushSource::BuildAndPushNoPrebuiltImage,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            write_push_source_announce(&mut buf, "svc", source).unwrap();
            let out = String::from_utf8(buf).unwrap();
            let expected_fragment = format!("({})", source.phrase());
            assert!(
                out.contains(&expected_fragment),
                "output for {:?} must contain the parenthesized fragment \
                 `{}` verbatim; got {:?}",
                source,
                expected_fragment,
                out
            );
        }
    }

    /// Equivalence oracle: passing each of the three pre-lift phrases
    /// yields bytes byte-for-byte identical to the pre-lift stanza
    /// spelled inline. Pins the migration end-to-end — a drift in the
    /// primitive body against the pre-lift idiom fails HERE, not
    /// after a consumer has already been re-wired.
    #[test]
    fn write_push_source_announce_matches_pre_lift_stanza_bytes() {
        let _override_guard = AnsiOverrideForTest::acquire();
        for (source, phrase) in [
            (PushSource::PushPrebuiltFromE2e, "push prebuilt from E2E"),
            (
                PushSource::BuildAndPushGatesSkipped,
                "build + push, gates were skipped",
            ),
            (
                PushSource::BuildAndPushNoPrebuiltImage,
                "build + push, no prebuilt image",
            ),
        ] {
            let svc_name = "svc-alpha";
            let mut via_primitive: Vec<u8> = Vec::new();
            write_push_source_announce(&mut via_primitive, svc_name, source).unwrap();
            let mut via_pre_lift: Vec<u8> = Vec::new();
            writeln!(
                &mut via_pre_lift,
                "   {} {} ({})",
                ">>".dimmed(),
                svc_name.cyan(),
                phrase,
            )
            .unwrap();
            assert_eq!(
                via_primitive, via_pre_lift,
                "primitive output must match the pre-lift inline stanza \
                 byte-for-byte for source={source:?}, phrase={phrase:?}"
            );
        }
    }

    /// Post-lift shield (positive half): `commands/product_release.rs`
    /// MUST forward through [`print_push_source_announce`] at least
    /// three times — one call per pre-lift push-source branch. A
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails here.
    #[test]
    fn product_release_forwards_three_push_source_announce_calls() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("product_release.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
        let needle = "print_push_source_announce(";
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 3,
            "{} must forward at least three push-source announce \
             composition(s) through `{needle}`; found {forwards}. A \
             dropped call would leave the negative raw-shape scan \
             satisfied by absence.",
            path.display(),
        );
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift push-source
    /// announce shape inline — the three-line
    /// `println!("   {} {} (<phrase>)", ">>".dimmed(),
    /// <svc>.cyan())` composition. Every push-source branch reaches
    /// for [`print_push_source_announce`] on first grep, not by
    /// copy-pasting the raw `println!` from an existing sibling.
    ///
    /// The shield's needle is the joint co-occurrence of the leading
    /// `">>".dimmed()` prefix, the `.cyan()` service slot, and a
    /// parenthesized-phrase-shaped suffix on the same `println!`
    /// block — the exact three-slot shape only these push-source
    /// branches spelled pre-lift. Other `">>".dimmed()` sites under
    /// `commands/` use different templates (three-slot
    /// `"   {} {} {}"` with a trailing dimmed slot at
    /// `commands/subcommand_invocation.rs`, or `"   {} <verb> {} in
    /// {}..."` at `commands/product_release.rs::run_health_check`
    /// which carries neither `.cyan()` nor a parenthesized phrase in
    /// the same block) and remain unaffected.
    #[test]
    fn no_commands_module_still_spells_raw_push_source_announce_println() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        let mut files: Vec<PathBuf> = Vec::new();
        walk(&src_dir, &mut files);

        // The three pre-lift phrases as literal fragments — the
        // parenthesized suffix each pre-lift `println!` format string
        // carried verbatim. A surviving raw `println!` block that
        // spelled any one of these three fragments alongside a
        // `">>".dimmed()` prefix would be a re-introduced pre-lift
        // stanza.
        let phrase_fragments: &[&str] = &[
            "(push prebuilt from E2E)",
            "(build + push, gates were skipped)",
            "(build + push, no prebuilt image)",
        ];
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for path in files {
            let src = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in src.lines().enumerate() {
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
                for fragment in phrase_fragments {
                    if line.contains(fragment) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw pre-lift `(<push-source phrase>)` fragment(s) survive \
             on a consumer site — route each through \
             `crate::push_source_announce::print_push_source_announce(\
             svc_name, source)` with the matching `PushSource` variant \
             instead:\n{offenders:#?}"
        );
    }
}
