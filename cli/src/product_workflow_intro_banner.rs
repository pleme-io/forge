//! `>> <product> <label> <detail>` product-workflow intro banner
//! fusion primitive — the peer-class two-line stanza distinct from
//! [`crate::release_workflow_intro_banner::write_release_workflow_intro_banner`]
//! (its `🚀` sibling for single-service release entry points) and from
//! [`crate::ui::write_command_intro_banner`] (the four-part
//! `<emoji> <verb.bold()> <subject.cyan()> <detail.dimmed()>`
//! command intro at width 50).
//!
//! # Duplication being lifted
//!
//! Two pre-lift sibling sites each restated the same two-line
//! `println!("{} {} <label> {}", ">>".bold(), product.cyan().bold(),
//! <detail>.dimmed()); crate::ui::print_ascii_title_underline(60);`
//! stanza verbatim, diverging only on the caller-owned label
//! (baked as a plain-text literal into the format string) and on the
//! detail slot:
//!
//! 1. `commands/rollback.rs::execute` (~L119-125) — the `Rollback`
//!    intro at the product-rollback entry point; detail is
//!    `format!("(env: {})", target_env)`. Underline width 60.
//! 2. `commands/product_release.rs::execute` (~L359-365) — the
//!    `Product Release` intro at the product-release entry point;
//!    detail is `format!("(env: {}, sha: {})", target_env, git_sha)`.
//!    Underline width 60.
//!
//! Each of the two spellings renders the same byte shape: the bold
//! `>>` prefix, one ASCII space, the cyan+bold product slot, one
//! ASCII space, the plain-text label (baked into the pre-lift format
//! string, uncolored), one ASCII space, the dimmed parenthesized
//! detail slot, a trailing `\n`, then the
//! [`crate::ui::write_ascii_title_underline`]-delegated `=`-rule +
//! blank pair at width 60. A drift in the prefix (`>>` → `→` under
//! a symbol-rebrand), the slot ordering (a promotion of the label
//! ahead of the product), the color palette (a promotion of the
//! label to `.bold()` under a stronger-visual-anchor mode), or the
//! trailing underline width at either site pre-lift diverged
//! silently from the other — the operator's eye caught only the
//! local intro line, not the cross-command banner grammar drift.
//!
//! # Distinct from the sibling `release_workflow_intro_banner`
//!
//! The `🚀`-prefixed peer at
//! [`crate::release_workflow_intro_banner`] anchors on
//! `<service.cyan().bold()> <label.bold()> <detail.dimmed()>` —
//! same three-slot color contract but with the label BOLDED and a
//! ROCKET glyph prefix, at four sites where the workflow entry
//! point is a single-service release. This primitive owns the
//! product-scope siblings whose prefix is a plain ASCII `>>` and
//! whose label rides as plain text inside the format string. The
//! two primitives stay distinct because their prefix encodes the
//! scope-of-work contract: `🚀` on a service release, `>>` on a
//! product-level orchestration (release or rollback across N
//! services and environments).
//!
//! # Delegation, not re-implementation
//!
//! The `=`-rule + blank pair beneath the title is delegated to
//! [`crate::ui::write_ascii_title_underline`] — the same primitive
//! both [`crate::ui::write_command_intro_banner`] and
//! [`crate::release_workflow_intro_banner::write_release_workflow_intro_banner`]
//! delegate to. A future swap of the rule glyph (`=` → `━`) or a
//! standardization of the rule width across all banner classes lands
//! in ONE place and every banner primitive inherits by composition.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `>> <product> <label>
//! <detail>` product-workflow intro shape lives at ONE construction
//! surface — a future refinement (a `>>` → `»` prefix swap under a
//! fleet-wide symbol rebrand, an added OTLP
//! `product_workflow_started` observability span alongside the
//! print, a hoist of the width into a typed `WorkflowScope::Product`
//! projection) lands in one place rather than in every consumer.

use std::io;

use colored::Colorize;

/// The `>>` ASCII prefix opening the product-workflow intro banner
/// every pre-lift consumer spelled inline in the fixed
/// `"{} {} <label> {}"` template with `">>".bold()` at the first
/// slot. Named as a `const` so a future swap (`>>` → `»` under a
/// fleet-wide symbol rebrand) lands at ONE edit rather than through
/// two inline literal edits.
pub const PRODUCT_WORKFLOW_INTRO_BANNER_PREFIX: &str = ">>";

/// Underline width every pre-lift consumer paired with the
/// `>>`-prefixed banner via
/// `crate::ui::print_ascii_title_underline(60)`. Pinned as a named
/// constant so a future standardization (a narrowing to 50 to match
/// the sibling `COMMAND_INTRO_BANNER_UNDERLINE_WIDTH`, a widening
/// beyond 60) happens at ONE typed boundary rather than through two
/// literal-argument sites.
pub const PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH: usize = 60;

/// Prints the two-line product-workflow intro banner — the
/// `>>.bold() <product.cyan().bold()> <label> <detail.dimmed()>`
/// title line followed by an `=`-rule + blank pair at
/// [`PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH`], delegated
/// through [`crate::ui::print_ascii_title_underline`].
///
/// Delegates to [`write_product_workflow_intro_banner`] against
/// [`std::io::stdout()`]; the writer split exists so the
/// fail-before-pass tests can pin the four-slot color ordering, the
/// ANSI escape palette on each argument, and the delegated
/// underline width by inspecting emitted bytes rather than
/// capturing stdout.
///
/// # Parameters
///
/// - `product` — the product name (e.g. `"web"`, `"pangea"`);
///   rendered `.cyan().bold()` so the eye locks onto WHICH product
///   is running the workflow.
/// - `label` — the workflow name baked into the pre-lift format
///   string as a plain literal (e.g. `"Rollback"`, `"Product
///   Release"`); rendered UNCOLORED so the byte shape matches the
///   pre-lift stanza.
/// - `detail` — the parenthesized detail (e.g. `"(env: staging)"`,
///   `"(env: staging, sha: abc123)"`); rendered `.dimmed()`.
pub fn print_product_workflow_intro_banner(product: &str, label: &str, detail: &str) {
    let _ =
        write_product_workflow_intro_banner(&mut std::io::stdout().lock(), product, label, detail);
}

/// Writer-taking sibling to [`print_product_workflow_intro_banner`].
/// Emits the same two-line body [`print_product_workflow_intro_banner`]
/// writes to stdout, but through a [`io::Write`] sink — the
/// byte-oracle surface for tests that pin the ANSI-wrapped title
/// line, the delegated underline width, and the trailing framing
/// blank without capturing stdout.
///
/// # Byte contract
///
/// The written byte sequence is exactly:
///
/// ```text
/// \x1b[1m>>\x1b[0m <\x1b[1;36m|\x1b[36;1m|\x1b[1m\x1b[36m><product>\x1b[0m
///    <label>
///    \x1b[2m<detail>\x1b[0m\n
/// <=×PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH>\n
/// \n
/// ```
///
/// (line-broken here for readability; actually emitted as three
/// lines: title + rule + blank). The rule + blank pair is
/// delegated to [`crate::ui::write_ascii_title_underline`] so the
/// underline grammar reaches this primitive through the peer's
/// typed body rather than a second literal `"=".repeat(width)`.
pub fn write_product_workflow_intro_banner<W: io::Write>(
    w: &mut W,
    product: &str,
    label: &str,
    detail: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{} {} {} {}",
        PRODUCT_WORKFLOW_INTRO_BANNER_PREFIX.bold(),
        product.cyan().bold(),
        label,
        detail.dimmed(),
    )?;
    crate::ui::write_ascii_title_underline(w, PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Mutex;

    /// Serialize the `.cyan().bold()` / `.bold()` / `.dimmed()`
    /// writer-level tests against the process-global
    /// [`colored::control::set_override`] toggle a peer test in
    /// `crate::ui` also acquires — a fair copy of the
    /// `AnsiOverrideForTest` guard in `cli/src/ui.rs`. Cargo runs
    /// tests in parallel by default, so without a mutex two tests
    /// racing the override toggle would flap between the "ANSI on"
    /// and "ANSI off" arms.
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

    /// Byte-oracle: [`write_product_workflow_intro_banner`] emits
    /// exactly three lines — the fused `>> <p> <l> <d>` title, the
    /// `=`-rule at [`PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH`],
    /// then a framing blank.
    #[test]
    fn write_product_workflow_intro_banner_emits_three_lines() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "web", "Rollback", "(env: staging)")
            .expect("write against Vec<u8> must succeed");
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            3,
            "write_product_workflow_intro_banner must emit exactly three \
             lines — the fused `>>` title, the `=`-rule at width 60, then \
             a framing blank; got {}:\n{:?}",
            lines.len(),
            out
        );
    }

    /// Byte-oracle: the rule line is exactly
    /// [`PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH`] `=` bytes
    /// followed by `\n`. A silent narrowing (60 → 50 under a
    /// standardization to match the command-intro banner width)
    /// flips this.
    #[test]
    fn write_product_workflow_intro_banner_rule_line_matches_pinned_width() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "p", "L", "(d)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        let expected = format!(
            "{}\n",
            "=".repeat(PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH)
        );
        assert_eq!(
            lines[1], expected,
            "line 1 must be exactly {} `=` bytes + `\\n` — the rule width \
             is delegated to `write_ascii_title_underline` with the pinned \
             constant; got {:?}",
            PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH, lines[1]
        );
    }

    /// Byte-oracle: line 2 is exactly `\n`. The trailing framing
    /// blank comes from [`crate::ui::write_ascii_title_underline`]'s
    /// own second `writeln!(w)`; a fusion that dropped it fails here.
    #[test]
    fn write_product_workflow_intro_banner_trailing_line_is_framing_blank() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "p", "L", "(d)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        assert_eq!(
            lines[2], "\n",
            "line 2 must be exactly `\\n` — the trailing framing blank \
             comes from `write_ascii_title_underline`; got {:?}",
            lines[2]
        );
    }

    /// Palette pin (prefix slot): the `bold` SGR parameter (`1`)
    /// reaches the buffer on the `>>` prefix. Every pre-lift
    /// consumer chained `.bold()` on `">>"` — a silent drop flips
    /// this.
    #[test]
    fn write_product_workflow_intro_banner_carries_bold_on_prefix_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "p", "L", "(d)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("\x1b[1m") || out.contains("\x1b[1;36m") || out.contains("\x1b[36;1m"),
            "output must carry the `bold` SGR parameter (`1`) — every \
             pre-lift consumer chained `.bold()` on the `>>` prefix; \
             got {:?}",
            out
        );
    }

    /// Palette pin (product slot): the `cyan` SGR parameter (`36`)
    /// AND the `bold` SGR parameter (`1`) both reach the buffer.
    /// `colored` folds `.cyan().bold()` into a single compound
    /// `\x1b[1;36m` SGR sequence on 2.x; accept any encoding so the
    /// contract is BOTH SGR parameters reach the wire. A promotion
    /// to `.bright_cyan()` (`\x1b[96m`) would drift from the pre-lift
    /// coloring on the product slot.
    #[test]
    fn write_product_workflow_intro_banner_carries_cyan_bold_on_product_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "product-alpha", "L", "(d)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        let carries_cyan =
            out.contains("\x1b[36m") || out.contains("\x1b[1;36m") || out.contains("\x1b[36;1m");
        assert!(
            carries_cyan,
            "output must carry the `cyan` SGR parameter (`36`) on the \
             product slot; got {:?}",
            out
        );
        assert!(
            !out.contains("\x1b[96m"),
            "output must NOT carry `bright_cyan` (`96`) — the pre-lift \
             coloring was `.cyan().bold()` alone; got {:?}",
            out
        );
    }

    /// Palette pin (detail slot): the `dim` SGR parameter (`2`)
    /// reaches the buffer — every pre-lift consumer chained
    /// `.dimmed()` on the parenthesized detail slot so the eye
    /// followed the prefix + product + label above rather than the
    /// contextual aside.
    #[test]
    fn write_product_workflow_intro_banner_carries_dim_on_detail_slot() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "p", "L", "(detail-body)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("\x1b[2m"),
            "output must carry the `dim` SGR parameter (`2`) on the \
             detail slot — a silent drop of `.dimmed()` flips this; \
             got {:?}",
            out
        );
    }

    /// Slot-order pin: the plain-text projection of line 0 (with
    /// ANSI stripped) places `product`, then `label`, then `detail`
    /// in that exact order between the leading `>> ` and the
    /// trailing `\n`. A refactor that swapped the argv order would
    /// silently retarget every intro banner and a mere length check
    /// would not catch it.
    #[test]
    fn write_product_workflow_intro_banner_places_product_label_detail_in_order() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "PROD_SLOT", "LABEL_SLOT", "DETAIL_SLOT")
            .unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.split_inclusive('\n').collect();
        let product_pos = lines[0].find("PROD_SLOT").expect("product present");
        let label_pos = lines[0].find("LABEL_SLOT").expect("label present");
        let detail_pos = lines[0].find("DETAIL_SLOT").expect("detail present");
        assert!(
            product_pos < label_pos,
            "product must land before label; got product={product_pos} label={label_pos}"
        );
        assert!(
            label_pos < detail_pos,
            "label must land before detail; got label={label_pos} detail={detail_pos}"
        );
    }

    /// Byte-oracle: the label slot is UNCOLORED. Every pre-lift
    /// consumer baked the label as a plain-text literal directly
    /// into the format string (`"{} {} Rollback {}"`,
    /// `"{} {} Product Release {}"`), i.e. with no `.bold()` or
    /// other coloring. A silent promotion to `.bold()` on the label
    /// would drift the pre-lift byte contract; this test pins the
    /// contract by asserting the label bytes appear in the output
    /// with no preceding SGR wrap immediately before them.
    #[test]
    fn write_product_workflow_intro_banner_label_slot_is_uncolored() {
        let _override_guard = AnsiOverrideForTest::acquire();
        let mut buf: Vec<u8> = Vec::new();
        write_product_workflow_intro_banner(&mut buf, "p", "MYLABEL", "(d)").unwrap();
        let out = String::from_utf8(buf).unwrap();
        // The label bytes appear literally; and they are NOT
        // preceded by the `\x1b[1mMYLABEL` bold wrapper. The
        // preceding byte in the emitted stream is a plain ASCII
        // space (the separator between the product's reset `\x1b[0m`
        // and the label).
        let idx = out.find("MYLABEL").expect("label present");
        assert!(
            idx > 0,
            "label must be preceded by at least one byte (the separator space)"
        );
        // Slice back a small window and check no ANSI escape sits
        // immediately before the label bytes.
        let start = idx.saturating_sub(6);
        let window = &out[start..idx];
        assert!(
            !window.ends_with("\x1b[1m"),
            "label must NOT be wrapped in a bold SGR — the pre-lift \
             format string baked it as a plain literal. Got window={:?} \
             before label at idx={}",
            window,
            idx
        );
    }

    /// Equivalence oracle: passing the two sites' actual arguments
    /// yields bytes byte-for-byte identical to the pre-lift stanza
    /// spelled inline. Pins the migration end-to-end: a drift in
    /// the primitive body against the pre-lift idiom fails HERE,
    /// not after a consumer has already been re-wired.
    #[test]
    fn write_product_workflow_intro_banner_matches_pre_lift_stanza_bytes() {
        let _override_guard = AnsiOverrideForTest::acquire();
        for (product, label, detail) in [
            ("web", "Rollback", "(env: staging)"),
            ("pangea", "Product Release", "(env: staging, sha: abc123ef)"),
        ] {
            let mut via_primitive: Vec<u8> = Vec::new();
            write_product_workflow_intro_banner(&mut via_primitive, product, label, detail)
                .unwrap();
            let mut via_pre_lift: Vec<u8> = Vec::new();
            // Reference stanza: the pre-lift shape the two consumer
            // sites each spelled inline, reconstructed here via the
            // same `writeln!` idiom against a `Vec<u8>` writer.
            // Note: the label is a plain-text literal (uncolored)
            // just as it appears in the pre-lift `"{} {} <label> {}"`
            // format string.
            writeln!(
                &mut via_pre_lift,
                "{} {} {} {}",
                ">>".bold(),
                product.cyan().bold(),
                label,
                detail.dimmed(),
            )
            .unwrap();
            crate::ui::write_ascii_title_underline(
                &mut via_pre_lift,
                PRODUCT_WORKFLOW_INTRO_BANNER_UNDERLINE_WIDTH,
            )
            .unwrap();
            assert_eq!(
                via_primitive, via_pre_lift,
                "primitive output must match the pre-lift inline stanza \
                 byte-for-byte for (product={product:?}, label={label:?}, \
                 detail={detail:?})"
            );
        }
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` may still spell the pre-lift
    /// `println!("{} {} <label> {}", ">>".bold(), ...` two-line
    /// stanza inline. Every consumer reaches for
    /// [`print_product_workflow_intro_banner`] on first grep, not
    /// by copy-pasting the raw `println!` from an existing sibling.
    #[test]
    fn no_commands_module_still_spells_raw_bold_greater_greater_intro_println() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = "\">>\".bold()";
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
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for path in files {
            let source = std::fs::read_to_string(&path).unwrap();
            let mut in_block_comment = false;
            for (idx, line) in source.lines().enumerate() {
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
                if line.contains(needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `\">>\".bold()` product-workflow intro-banner literal(s) \
             survive on a consumer site — route each through \
             `crate::product_workflow_intro_banner::\
             print_product_workflow_intro_banner(product, label, detail)` \
             instead:\n{offenders:#?}"
        );
    }

    /// Post-lift shield (positive half): each of the two pre-lift
    /// modules that housed the composition MUST forward through
    /// [`print_product_workflow_intro_banner`] at least once. A
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails here.
    #[test]
    fn every_prelift_module_forwards_through_product_workflow_intro_banner() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "rollback.rs"], 1),
            (&["commands", "product_release.rs"], 1),
        ];
        let needle = "print_product_workflow_intro_banner(";
        for (segments, min_count) in expectations {
            let mut path = src_dir.clone();
            for s in *segments {
                path.push(s);
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {min_count} product-workflow \
                 intro-banner composition(s) through `{needle}`; found \
                 {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
