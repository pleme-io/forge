//! `[Y/n]` / `[y/N]` yes-or-no confirmation prompt — the paired
//! `print!("{question} [<hint>] ") + stdout().flush() + read_line() +
//! trim().to_lowercase() + y|yes membership test + default-aware
//! empty-input decision` stanza the two interactive `commands/*.rs`
//! sites spelled inline pre-lift.
//!
//! # Pre-lift census — two sibling stanzas, one prompt-and-decide shape
//!
//! Two consumer sites each restated the same six-step stanza — a
//! `print!` of the question and hint, a `stdout().flush()`, a
//! `read_line` into a mutable `String`, a `trim().to_lowercase()`
//! fold, a `y|yes` membership test, and a default-aware empty-input
//! branch — diverging only on the default side of the prompt and the
//! caller's cancel-outcome policy.
//!
//! Site 1 is `commands/rollback.rs::execute` — the pre-`--force` gate
//! that asks `"Proceed with rollback? [Y/n] "` before redeploying the
//! previous tag. Default is Yes (empty input proceeds), and the
//! cancel outcome is a soft `println!` of a yellow
//! `"Rollback cancelled."` line and a bare `return Ok(())` rather
//! than a `bail!` — a user who typed `n`/`no` is doing exactly what
//! the command promised was reversible, and the flow returns cleanly.
//!
//! Site 2 is `commands/pangea_infra.rs::confirm` — the module-local
//! helper that every `plan` / `apply` / `destroy` phase gates on,
//! spelling `"{message} [y/N] "`. Default is No (empty input
//! cancels), and the cancel outcome is
//! `bail!("Operation cancelled by user")` — a terraform SDLC phase
//! the operator declined must NOT fall through to the next step in
//! the pipeline.
//!
//! Both stanzas past THEORY §VI.1's duplication trigger (PRIME
//! DIRECTIVE: duplication budget is zero). A prompt-and-decide drift
//! at either site — a swap of `y|yes` for a stricter `y`-only test, a
//! drop of the `to_lowercase()` fold that would silently reject a
//! `Y`/`YES` reply, an inversion of the default branch, or a change
//! to the hint capitalization that misled the operator about which
//! side of the prompt Enter takes — pre-lift had to hit two sites in
//! lockstep or diverge; post-lift it hits ONE typed body and every
//! consumer inherits the change from
//! `prompt_confirm(question, PromptDefault::<Yes|No>)`.
//!
//! # Straggler outside this lift — the strict-`y` sessions.rs site
//!
//! `commands/sessions.rs::execute` carries a third interactive-prompt
//! stanza (`"⚠️  This will log out {} user(s). Continue? (y/N) "`,
//! then `!input.trim().eq_ignore_ascii_case("y")` → cancel) whose
//! post-read classification is strictly `y` (case-insensitive) — NOT
//! `y|yes`. A user who typed `yes` at that prompt would silently
//! cancel where every other prompt in the fleet proceeds. That is a
//! genuine pre-lift divergence, not a shape difference, and folding it
//! through this primitive would silently WIDEN the accepted-yes set
//! from `{y, Y}` to `{y, Y, yes, YES, Yes, ...}` at the one site whose
//! operator has been trained on the stricter shape. The site stays as
//! a deliberate straggler; a future lift may either normalize its
//! semantics through a second `AcceptedYes` axis on this primitive or
//! confirm that its stricter policy was intentional and leave it in
//! place.
//!
//! # Two axes, one closed enum
//!
//! [`PromptDefault`] is a two-variant closed enum whose two projections
//! —
//! [`PromptDefault::hint`] (the bracketed suffix appended to the
//! question) and [`PromptDefault::empty_input_decision`] (the boolean
//! that fires when the user pressed Enter with no input) — must move
//! together. The hint's capitalization signals which side Enter takes,
//! and the empty-input decision IS that side; a refactor that drifts
//! either projection independently is a UX bug (a `[Y/n]` prompt that
//! secretly defaults to No, or a `[y/N]` prompt that secretly defaults
//! to Yes, silently gets the OPPOSITE answer from the one the operator
//! reads). The two projections live on the same enum variant, so a
//! consumer that reaches for one automatically inherits the other,
//! and byte-oracle tests below pin the correlation.
//!
//! # Composition
//!
//! [`prompt_confirm`] wires the primitive against
//! [`std::io::stdin`]/[`std::io::stdout`] and returns
//! `anyhow::Result<bool>` (Ok(true) = proceed, Ok(false) = cancel);
//! [`decide_prompt_confirm`] is the reader/writer-taking sibling that
//! pins the exact emitted prompt bytes and reads a caller-supplied
//! response line, for byte-oracle tests that must not touch the real
//! stdio streams.
//!
//! The callers apply their cancel-outcome policy at the `bool` return:
//! `rollback.rs` matches on `false` to soft-return with a yellow
//! `Rollback cancelled.` line; `pangea_infra.rs::confirm` matches on
//! `false` to `bail!("Operation cancelled by user")`. Both policies
//! live at the caller (where they belong — the caller knows whether
//! its cancel is a graceful no-op or a hard stop), and the primitive
//! owns only the prompt-and-decide layer they agree on.

use std::io::{BufRead, Write};

use anyhow::Result;

/// Which side of a `y|n` prompt is the default — the answer that fires
/// when the user presses Enter without typing anything.
///
/// The two variants project into two byte-level shapes that MUST move
/// together: the trailing bracketed hint appended to the question
/// ([`hint`](Self::hint)) and the boolean returned when the read line
/// is empty ([`empty_input_decision`](Self::empty_input_decision)).
/// The hint's capitalization is the ONLY signal the operator has about
/// which side Enter takes; a drift where the two projections disagreed
/// would silently invert the meaning of Enter at the two consumer
/// sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptDefault {
    /// Enter with no input means yes (proceed). Hint renders as `[Y/n]`.
    Yes,
    /// Enter with no input means no (cancel). Hint renders as `[y/N]`.
    No,
}

impl PromptDefault {
    /// The trailing bracketed hint the prompt appends after the
    /// question — `"[Y/n]"` when Yes is the default,
    /// `"[y/N]"` when No is. The capitalized letter marks the default
    /// side per long-standing Unix CLI convention (`git rebase -i`,
    /// `apt`, `dnf`, `dpkg`, `rm -i`, …). Pinned by byte-oracle test
    /// below so the hint capitalization keeps tracking the default.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Yes => "[Y/n]",
            Self::No => "[y/N]",
        }
    }

    /// The boolean the prompt returns when the user pressed Enter with
    /// no typed characters. Correlated with [`hint`](Self::hint) — a
    /// `[Y/n]` prompt returns `true` on empty input, a `[y/N]` prompt
    /// returns `false`. Byte-oracle test below pins the correlation.
    pub fn empty_input_decision(self) -> bool {
        match self {
            Self::Yes => true,
            Self::No => false,
        }
    }
}

/// Render the `"<question> <hint> "` prompt line to stdout, flush,
/// read one line from stdin, and classify the trimmed lowercase reply
/// as proceed (`true`) or cancel (`false`).
///
/// Empty input takes the default (`PromptDefault::Yes` → `true`,
/// `PromptDefault::No` → `false`); `"y"` and `"yes"` (case-insensitive
/// via `to_lowercase`) proceed; every other reply cancels.
///
/// Delegates to [`decide_prompt_confirm`] against a locked stdin/stdout
/// pair; the reader/writer split exists so the fail-before-pass tests
/// can pin the emitted prompt bytes and drive the decision under a
/// synthetic reply without touching the real stdio streams.
pub fn prompt_confirm(question: &str, default: PromptDefault) -> Result<bool> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    Ok(decide_prompt_confirm(
        &mut stdin.lock(),
        &mut stdout,
        question,
        default,
    )?)
}

/// Reader/writer-taking sibling of [`prompt_confirm`].
///
/// # Byte contract
///
/// Writes the prompt bytes `"<question> <hint> "` (a single ASCII
/// space between question and hint, one trailing ASCII space after
/// the hint so the operator's typed reply visually detaches from the
/// prompt) to `writer` and flushes it before reading. Then reads a
/// single line from `reader` via [`BufRead::read_line`], folds it via
/// `.trim().to_lowercase()`, and classifies:
///
/// - empty (`""`) → `default.empty_input_decision()`.
/// - `"y"` or `"yes"` → `true` (proceed).
/// - anything else → `false` (cancel).
///
/// Two pre-lift call sites (`commands/rollback.rs::execute`,
/// `commands/pangea_infra.rs::confirm`) each spelled the six-step
/// stanza inline; this function emits the byte-identical prompt bytes
/// and returns the byte-identical decision the pre-lift stanzas would
/// have produced.
pub fn decide_prompt_confirm<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    default: PromptDefault,
) -> std::io::Result<bool> {
    write!(writer, "{} {} ", question, default.hint())?;
    writer.flush()?;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let answer = line.trim().to_lowercase();

    Ok(if answer.is_empty() {
        default.empty_input_decision()
    } else {
        answer == "y" || answer == "yes"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`PromptDefault::Yes`] renders as `"[Y/n]"` and
    /// [`PromptDefault::No`] renders as `"[y/N]"` — the two pre-lift
    /// hint strings the two consumer sites spelled inline. A silent
    /// flip of the capitalized side (either variant) misleads the
    /// operator into pressing Enter for the OPPOSITE decision from
    /// the one the primitive returns — the class of UX bug this pin
    /// exists to catch.
    #[test]
    fn hint_matches_pre_lift_bytes() {
        assert_eq!(PromptDefault::Yes.hint(), "[Y/n]");
        assert_eq!(PromptDefault::No.hint(), "[y/N]");
    }

    /// Byte-oracle: the empty-input decision is correlated with the
    /// hint's capitalized side. `PromptDefault::Yes` → `true`;
    /// `PromptDefault::No` → `false`. A refactor that drifted one
    /// projection independently of the other (a `[Y/n]` hint whose
    /// empty-input decision was `false`, or a `[y/N]` hint whose
    /// empty-input decision was `true`) inverts the meaning of Enter
    /// against every reader's expectation.
    #[test]
    fn empty_input_decision_matches_hint_default_side() {
        assert!(PromptDefault::Yes.empty_input_decision());
        assert!(!PromptDefault::No.empty_input_decision());
    }

    /// Prompt-emission byte-oracle: the writer emits exactly
    /// `"<question> <hint> "` — one ASCII space between the question
    /// and the hint, one trailing ASCII space after the hint. A
    /// refactor that dropped either space would run the operator's
    /// typed reply straight into the hint (`"Proceed? [Y/n]y"`) or
    /// stack the question and hint (`"Proceed?[Y/n] "`).
    #[test]
    fn decide_prompt_confirm_emits_question_space_hint_space_prompt_bytes() {
        let mut reader = &b"y\n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let _ = decide_prompt_confirm(
            &mut reader,
            &mut writer,
            "Proceed with rollback?",
            PromptDefault::Yes,
        )
        .unwrap();
        assert_eq!(writer, b"Proceed with rollback? [Y/n] ");
    }

    /// Prompt-emission byte-oracle for the No-default variant — the
    /// pre-lift `pangea_infra.rs::confirm` shape. Fixed message
    /// (`Apply these terraform changes?`) and `[y/N]` hint. A refactor
    /// that swapped the hint for the Yes-default variant on this
    /// caller shape would silently make Enter approve a
    /// `terraform apply` — the exact UX bug the closed-enum
    /// correlation exists to prevent.
    #[test]
    fn decide_prompt_confirm_emits_no_default_hint_variant() {
        let mut reader = &b"y\n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let _ = decide_prompt_confirm(
            &mut reader,
            &mut writer,
            "Apply these terraform changes?",
            PromptDefault::No,
        )
        .unwrap();
        assert_eq!(writer, b"Apply these terraform changes? [y/N] ");
    }

    /// Empty input under [`PromptDefault::Yes`] returns `true`
    /// (proceed) — the pre-lift `rollback.rs` semantic. An operator
    /// who reads `[Y/n]` and presses Enter expects the reversible
    /// rollback to proceed.
    #[test]
    fn decide_prompt_confirm_empty_input_yes_default_proceeds() {
        let mut reader = &b"\n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let decision =
            decide_prompt_confirm(&mut reader, &mut writer, "Q?", PromptDefault::Yes).unwrap();
        assert!(decision);
    }

    /// Empty input under [`PromptDefault::No`] returns `false`
    /// (cancel) — the pre-lift `pangea_infra.rs::confirm` semantic.
    /// An operator who reads `[y/N]` and presses Enter expects the
    /// irreversible terraform SDLC phase to cancel.
    #[test]
    fn decide_prompt_confirm_empty_input_no_default_cancels() {
        let mut reader = &b"\n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let decision =
            decide_prompt_confirm(&mut reader, &mut writer, "Q?", PromptDefault::No).unwrap();
        assert!(!decision);
    }

    /// `"y"` and `"yes"` (case-insensitive) return `true` under EITHER
    /// default — the pre-lift `y|yes` membership shape both sites
    /// spelled. Loop across the two defaults and the two accepted
    /// spellings in six case orderings each.
    #[test]
    fn decide_prompt_confirm_y_and_yes_case_insensitive_proceed_under_either_default() {
        for default in [PromptDefault::Yes, PromptDefault::No] {
            for reply in &[
                &b"y\n"[..],
                &b"Y\n"[..],
                &b"yes\n"[..],
                &b"YES\n"[..],
                &b"Yes\n"[..],
                &b"yEs\n"[..],
            ] {
                let mut reader = *reply;
                let mut writer: Vec<u8> = Vec::new();
                let decision =
                    decide_prompt_confirm(&mut reader, &mut writer, "Q?", default).unwrap();
                assert!(
                    decision,
                    "reply {:?} under default {:?} must proceed",
                    reply, default,
                );
            }
        }
    }

    /// `"n"`, `"no"`, and every non-`y|yes` non-empty reply return
    /// `false` (cancel) under EITHER default. Byte-oracle over the
    /// six pre-lift-observed cancel replies. A regression that
    /// widened acceptance to include e.g. `"ok"` or `"proceed"` would
    /// flip at least one of these.
    #[test]
    fn decide_prompt_confirm_non_yes_replies_cancel_under_either_default() {
        for default in [PromptDefault::Yes, PromptDefault::No] {
            for reply in &[
                &b"n\n"[..],
                &b"no\n"[..],
                &b"NO\n"[..],
                &b"banana\n"[..],
                &b"ok\n"[..],
                &b" y \n"[..], // leading/trailing whitespace only survives if `trim` runs; keep this to pin the trim
            ] {
                let mut reader = *reply;
                let mut writer: Vec<u8> = Vec::new();
                let decision =
                    decide_prompt_confirm(&mut reader, &mut writer, "Q?", default).unwrap();
                // The one exception: `" y "` after `trim` becomes `y`, which proceeds.
                let expected = *reply == b" y \n";
                assert_eq!(
                    decision, expected,
                    "reply {:?} under default {:?} produced unexpected decision",
                    reply, default,
                );
            }
        }
    }

    /// Whitespace-only replies are folded by [`str::trim`] to the
    /// empty string and take the default. Pins the trim step against
    /// a future refactor that dropped it — a `" \n"` reply from an
    /// impatient operator hitting space then Enter would then be
    /// classified as a non-yes cancel under Yes-default, silently
    /// blocking a rollback.
    #[test]
    fn decide_prompt_confirm_whitespace_only_reply_folds_to_default() {
        let mut reader = &b"   \n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let decision =
            decide_prompt_confirm(&mut reader, &mut writer, "Q?", PromptDefault::Yes).unwrap();
        assert!(decision);

        let mut reader = &b"   \n"[..];
        let mut writer: Vec<u8> = Vec::new();
        let decision =
            decide_prompt_confirm(&mut reader, &mut writer, "Q?", PromptDefault::No).unwrap();
        assert!(!decision);
    }

    /// Caller shield (positive half): both pre-lift consumer modules
    /// forward through [`prompt_confirm`] at least once — a dropped
    /// call site would leave the negative "no raw prompt shape" scan
    /// (below) satisfied by absence but the positive count still
    /// fails.
    #[test]
    fn every_prelift_module_forwards_through_prompt_confirm() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("rollback.rs"), 1),
            (crate_src.join("commands").join("pangea_infra.rs"), 1),
        ];
        let needle = "prompt_confirm(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} interactive-prompt site(s) \
                 through `{}`; found {}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw `"[Y/n] "` /
    /// `"[y/N] "` hint literals inline any more, except in the
    /// `sessions.rs` deliberate straggler (whose strict-`y`
    /// classification is documented at the module header and lies
    /// outside this primitive's contract). Anchored on the exact
    /// pre-lift hint bytes.
    #[test]
    fn no_command_module_still_spells_raw_prompt_hint_literal() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dir = crate_src.join("commands");

        let hint_needles = ["\"[Y/n] \"", "\"[y/N] \""];
        let format_hint_needles = ["[Y/n] ", "[y/N] "];
        // File that carries the documented straggler; the module doc-comment on
        // `prompt_confirm.rs` names the site so the scan can safely skip it.
        let straggler = crate_src.join("commands").join("sessions.rs");

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&scan_dir).unwrap().flatten() {
            let path = entry.path();
            if path == straggler {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
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
                let hits_hint = hint_needles.iter().any(|n| line.contains(n));
                let hits_format = format_hint_needles.iter().any(|n| line.contains(n));
                if hits_hint || hits_format {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[Y/n] ` / `[y/N] ` prompt-hint literal(s) survive under \
             `commands/` (outside the documented `sessions.rs` \
             straggler) — route each through \
             `crate::prompt_confirm::prompt_confirm()` instead:\n{:#?}",
            offenders
        );
    }
}
