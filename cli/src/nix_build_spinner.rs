//! Green-palette `Building with Nix...` spinner primitive.
//!
//! Two pre-lift sibling sites across `commands/{build (×1:
//! `execute`'s primary `nix build .#<flake_attr>` invocation,
//! post-`🔨 Building <attr> image for <arch>...` preamble +
//! trailing blank line), github_runner_ci (×1: `execute`'s
//! `.#dockerImage` runner-image build inside the build-step arm,
//! post-`   Working directory: <dir>` + `   Architecture: x86_64-linux`
//! readouts + trailing blank line)}.rs` each restated the
//!
//! ```ignore
//! let <name> = styled_spinner(SpinnerStyle::Green, "Building with Nix...");
//! ```
//!
//! stanza verbatim before spawning the `nix build` command and
//! finishing the spinner with `.finish_and_clear()` on every
//! outcome path. Two occurrences past THEORY §VI.1's "two
//! occurrences is a coincidence" threshold, but the shape is a
//! distinctive palette-and-message fusion — a
//! [`crate::ui::SpinnerStyle::Green`] palette choice + the
//! `Building with Nix...` message literal + the underlying
//! [`crate::ui::styled_spinner`] constructor — and the message
//! is the operator's only visible narration of the phase because
//! Nix's own `--print-build-logs` stream is inherited to stderr
//! rather than surfaced through the spinner. A palette drift at
//! one site alone (Green → Cyan) or a verb drift (Building →
//! Compiling / Realizing) forks the two nix-build phase readouts
//! against each other with no compile-time signal.
//!
//! Post-lift each flow calls [`nix_build_spinner()`] and inherits
//! the canonical palette + message through one site. Sibling of
//! [`crate::commands::manifest_push::commit_and_push_manifest_with_progress`]
//! and the const-pinned message constants in
//! `commands/manifest_push.rs` — same
//! constant-pinned-message-plus-fused-constructor discipline, applied
//! to the two nix-build phase-open sites.
//!
//! # The `Green` palette, not `Cyan` or `Yellow`
//!
//! Both pre-lift sites spell [`crate::ui::SpinnerStyle::Green`]
//! verbatim. Green is the fleet's mental anchor for a
//! forward-progress build/compile phase (mirrors
//! `PUSHING_TO_MAIN_SPINNER_MESSAGE`'s Green palette in
//! `commands/manifest_push.rs` and the `nix build` invocation in
//! `commands/comprehensive_release.rs`'s cargo-test spinner);
//! [`crate::ui::SpinnerStyle::Cyan`] is reserved for the
//! per-suite integration-test spinner grammar in
//! `commands/integration_tests.rs`. A future palette drift on
//! this primitive would silently re-color both nix-build phases
//! against the fleet's build-phase-is-green convention rather
//! than at the compile boundary.
//!
//! # The `Building with Nix...` message, not `Compiling` or `Realizing`
//!
//! Both pre-lift sites spell the exact 20-byte ASCII message
//! `Building with Nix...` — capitalized `B`, lower-case `w` in
//! `with`, capitalized `N` in `Nix`, three ASCII dots at the tail
//! (not a `\u{2026}` HORIZONTAL ELLIPSIS). The message
//! deliberately says `Building` (matches the fleet's
//! `🔨 Building <flake_attr> image ...` preamble immediately
//! above at both sites) rather than `Compiling` (Rust-specific
//! verb reserved for cargo phases) or `Realizing` (a Nix-internal
//! verb the operator does not need to see). The byte-oracle
//! sibling [`write_nix_build_spinner_message`] pins the exact 20
//! bytes so any of these drifts flips the assertion rather than
//! shipping.
//!
//! # Direct-writer sibling despite the spinner routing
//!
//! [`nix_build_spinner`] emits its message through
//! [`indicatif::ProgressBar`]'s own draw loop rather than
//! through a plain `writeln!` on stdout, so the visible message
//! is not byte-oracle-testable from a hermetic `#[cfg(test)]`
//! block without racing the draw loop. The
//! [`write_nix_build_spinner_message`] direct-writer sibling
//! emits the same message bytes into an in-memory writer so the
//! byte-level assertion can pin the exact 20-byte spelling —
//! the same writer/print split
//! [`crate::commands::manifest_push::write_commit_and_push_manifest_narrative`],
//! [`crate::nonfatal_warning::write_nonfatal_warn`],
//! [`crate::attic_configure_step::write_attic_configure_step`],
//! and [`crate::registry_field::write_registry_field`] each
//! carry against their tracing/indicatif-routed production
//! counterparts.

use indicatif::ProgressBar;
use std::io;

use crate::ui::{styled_spinner, SpinnerStyle};

/// The canonical op-label the two nix-build phase-open sites in
/// `commands/{build,github_runner_ci}.rs` each passed to
/// [`crate::retry::run_inherited_status`] as its second argument.
/// Pinned as a `const` so the operator-facing failure envelope
/// [`crate::retry::run_inherited_status`] emits by construction —
/// `"Failed to run nix build"` on spawn failure, `"nix build failed
/// (exit {code})"` on non-zero exit, `"nix build failed (killed by
/// signal)"` on signal termination — carries the same 9-byte
/// `nix build` label at both flows. A drift here (e.g. one site to
/// `"nix-build"`, one to `"nix build image"`) would silently fork
/// the two phase-open flows' failure envelopes.
pub const NIX_BUILD_OP_LABEL: &str = "nix build";

/// The canonical `Building with Nix...` spinner message the two
/// nix-build phase-open sites in `commands/{build,github_runner_ci}.rs`
/// each passed to [`crate::ui::styled_spinner`] with
/// [`SpinnerStyle::Green`]. Pinned as a `const` so a future
/// re-branding (a verb swap to `Compiling`, a target-clarifying
/// tail like `Building with Nix (this may take a while)...`) flows
/// to both flows from one edit rather than through two inline
/// literal edits.
pub const BUILDING_WITH_NIX_SPINNER_MESSAGE: &str = "Building with Nix...";

/// Emit the canonical `Building with Nix...` message to `w` as one
/// line WITHOUT a trailing newline — the message body every
/// pre-lift consumer passed to [`indicatif::ProgressBar::set_message`],
/// which itself does not append a newline (the spinner draw loop
/// re-renders the message in place).
///
/// The writer split exists because the production constructor
/// [`nix_build_spinner`] emits its message through
/// [`indicatif::ProgressBar`]'s draw loop, which is not
/// byte-oracle-testable in a hermetic `#[cfg(test)]` block without
/// racing the draw loop. The direct writer emits the same 20 message
/// bytes into a `Vec<u8>` so the fail-before-pass test can pin the
/// exact spelling via `String::from_utf8` — a rename of the const
/// (a `Building` → `Compiling` verb swap, a drift of the three
/// ASCII dots to a U+2026 ellipsis) flips the assertion at ONE site
/// rather than silently forking the phase-open grammar across two
/// nix-build flows.
///
/// Same writer/print split every prior sibling-writer refactor
/// honors (see `nonfatal_warning.rs`, `success_step.rs`,
/// `attic_configure_step.rs`, `registry_field.rs`,
/// `manifest_push.rs` for the canonical split rationale).
#[allow(dead_code)] // See doc comment: the writer is a test/byte-oracle
                    // peer of the indicatif-routed
                    // `nix_build_spinner` constructor, and a
                    // future `collect_nix_build_phase_events`
                    // summary sibling will consume it directly.
pub fn write_nix_build_spinner_message<W: io::Write>(w: &mut W) -> io::Result<()> {
    write!(w, "{}", BUILDING_WITH_NIX_SPINNER_MESSAGE)
}

/// Construct the canonical [`SpinnerStyle::Green`]-tinted spinner
/// carrying the [`BUILDING_WITH_NIX_SPINNER_MESSAGE`] message body
/// — the pre-lift `styled_spinner(SpinnerStyle::Green, "Building
/// with Nix...")` two-argument shape that the two nix-build
/// phase-open sites in `commands/{build,github_runner_ci}.rs` each
/// spelled inline verbatim.
///
/// Post-lift each site calls [`nix_build_spinner`] and inherits the
/// canonical palette + message through one body — a palette drift
/// (Green → Cyan / Yellow) or a message drift (`Building` →
/// `Compiling` / `Realizing`, or the addition/removal of the
/// trailing dots) flips the test envelopes rather than silently
/// forking the two flows' operator-facing readout.
///
/// # Lifecycle
///
/// The caller retains ownership of the returned [`ProgressBar`] and
/// is responsible for calling [`ProgressBar::finish_and_clear`] (or
/// [`ProgressBar::finish_with_message`]) once the underlying
/// `nix build` spawn returns. Both pre-lift consumer sites chose
/// [`finish_and_clear`] because the subsequent `crate::info_success!`
/// / `println!` narration renders the completion status; a fused
/// finish-message primitive would collide with that narration.
pub fn nix_build_spinner() -> ProgressBar {
    styled_spinner(SpinnerStyle::Green, BUILDING_WITH_NIX_SPINNER_MESSAGE)
}

/// Spawn `cmd` under `spinner`, clear the spinner on every path,
/// and propagate the typed [`crate::retry::run_inherited_status`]
/// outcome. The load-bearing invariant this primitive encodes: the
/// spinner MUST clear BEFORE the `?` propagation, so a spawn error
/// (nix not on PATH, permission denied, fork failed) does not leak
/// a live spinner beneath the printed error line.
///
/// Pre-lift the two nix-build phase-open sites in
/// `commands/{build,github_runner_ci}.rs` each spelled the
///
/// ```ignore
/// let outcome = crate::retry::run_inherited_status(cmd, "nix build").await;
/// spinner.finish_and_clear();
/// outcome?;
/// ```
///
/// three-line stanza inline. The bind-before-`?` order is the load-
/// bearing detail: an earlier revision at both sites propagated with
/// `?` on `.context("Failed to run nix build")` BEFORE the spinner
/// finished, leaving the terminal with a live spinner animating
/// beneath the printed error on the spawn-failure path (see the
/// pre-lift comment blocks at commands/build.rs:185-199 and
/// commands/github_runner_ci.rs:341-358 for the historical rationale).
/// A third phase-open site restating the stanza inline could easily
/// re-invert the order; routing every consumer through this one body
/// makes the invariant structural rather than by-convention.
///
/// The op-label passed to [`crate::retry::run_inherited_status`] is
/// pinned to the module-level [`NIX_BUILD_OP_LABEL`] const, so the
/// operator-facing failure envelope is byte-identical across both
/// flows by construction — a caller cannot pass a drifted label
/// because it does not appear on the primitive's surface.
pub async fn run_nix_build_under_spinner(
    cmd: tokio::process::Command,
    spinner: ProgressBar,
) -> anyhow::Result<()> {
    let outcome = crate::retry::run_inherited_status(cmd, NIX_BUILD_OP_LABEL).await;
    spinner.finish_and_clear();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact 20-byte ASCII spelling of the canonical
    /// spinner message: capitalized `B` in `Building`, one ASCII
    /// space, lower-case `with`, one ASCII space, capitalized
    /// `Nix`, three ASCII dots (not a U+2026 ellipsis). Any drift
    /// — a verb swap (`Compiling`), a target-clarifying suffix
    /// (`Building with Nix (this may take a while)...`), an
    /// ellipsis substitution — regresses this assertion.
    #[test]
    fn building_with_nix_spinner_message_pins_the_pre_lift_bytes_verbatim() {
        assert_eq!(BUILDING_WITH_NIX_SPINNER_MESSAGE, "Building with Nix...");
        // 20 ASCII bytes: B-u-i-l-d-i-n-g- -w-i-t-h- -N-i-x-.-.-.
        assert_eq!(BUILDING_WITH_NIX_SPINNER_MESSAGE.len(), 20);
        assert!(
            BUILDING_WITH_NIX_SPINNER_MESSAGE.is_ascii(),
            "the canonical message must remain pure ASCII — a drift to \
             a U+2026 HORIZONTAL ELLIPSIS or a fancy `Nix` glyph would \
             fork the two operator-facing readouts against each other"
        );
    }

    /// Fail-before-pass envelope for the direct-writer sibling: the
    /// 20-byte body emitted verbatim, no trailing newline (matches
    /// [`indicatif::ProgressBar::set_message`], which the production
    /// constructor routes to).
    #[test]
    fn write_nix_build_spinner_message_emits_the_canonical_20_ascii_bytes_no_newline() {
        let mut buf: Vec<u8> = Vec::new();
        write_nix_build_spinner_message(&mut buf).unwrap();
        assert_eq!(buf, b"Building with Nix...");
        assert_eq!(String::from_utf8(buf).unwrap(), "Building with Nix...");
    }

    /// [`nix_build_spinner`] must return a spinner-flavored
    /// [`ProgressBar`] — `bar.length()` is `None`, mirroring
    /// [`crate::ui::styled_spinner`]'s spinner-vs-determinate
    /// contract. A future fusion that accidentally routed to
    /// [`indicatif::ProgressBar::new`] would render a determinate
    /// track with an empty `{pos}/{len}` slot beneath the nix
    /// build's inherited stderr — silently degrading both flows'
    /// readout without touching the message.
    #[test]
    fn nix_build_spinner_returns_a_spinner_flavored_bar_not_a_determinate_bar() {
        let bar = nix_build_spinner();
        assert_eq!(
            bar.length(),
            None,
            "nix_build_spinner must return a spinner-flavored bar (no length), \
             not a determinate one — the underlying `nix build` phase has no \
             pre-known step count to advance a `{{pos}}/{{len}}` slot against"
        );
        bar.finish_and_clear();
    }

    /// [`nix_build_spinner`] must render the canonical message.
    /// Wrapped in a direct getter on the returned bar's own
    /// `message()` — the same field [`indicatif::ProgressBar::set_message`]
    /// writes to. A future primitive that renamed the const
    /// without also updating the constructor's `set_message` call
    /// (or vice versa) would flip this envelope rather than
    /// silently divorcing the const from the actual bar the two
    /// consumer sites see.
    #[test]
    fn nix_build_spinner_message_matches_the_canonical_pinned_constant() {
        let bar = nix_build_spinner();
        assert_eq!(bar.message(), BUILDING_WITH_NIX_SPINNER_MESSAGE);
        bar.finish_and_clear();
    }

    /// Caller-shield: `commands/build.rs` MUST route its
    /// nix-build phase-open spinner through
    /// [`nix_build_spinner`] and MUST NOT re-inline the raw
    /// `styled_spinner(SpinnerStyle::Green, "Building with Nix...")`
    /// two-argument stanza on any code line. A future "just call
    /// `styled_spinner` directly, it's shorter" cleanup would
    /// re-open the duplication class this lift closes; the
    /// shield fires such a re-inline at compile-time-of-tests
    /// rather than in the terminal.
    #[test]
    fn commands_build_delegates_nix_build_spinner_to_the_primitive() {
        const SOURCE: &str = include_str!("commands/build.rs");
        assert!(
            SOURCE.contains("crate::nix_build_spinner::nix_build_spinner("),
            "commands/build.rs must delegate its nix-build phase-open spinner \
             through `crate::nix_build_spinner::nix_build_spinner()` — the \
             canonical Green-palette + `Building with Nix...`-message fusion."
        );
        let hits = crate::test_support::code_line_hits(
            SOURCE,
            "styled_spinner(SpinnerStyle::Green, \"Building with Nix...\"",
        );
        assert!(
            hits.is_empty(),
            "commands/build.rs must NOT re-inline the \
             `styled_spinner(SpinnerStyle::Green, \"Building with Nix...\")` \
             stanza — every nix-build phase-open spinner must route through \
             `crate::nix_build_spinner::nix_build_spinner()`. Offending lines: {hits:?}"
        );
    }

    /// Caller-shield: `commands/github_runner_ci.rs` MUST route
    /// its nix-build phase-open spinner through
    /// [`nix_build_spinner`] and MUST NOT re-inline the raw
    /// `styled_spinner(SpinnerStyle::Green, "Building with Nix...")`
    /// two-argument stanza on any code line. Same discipline as
    /// the sibling shield on `commands/build.rs`.
    #[test]
    fn commands_github_runner_ci_delegates_nix_build_spinner_to_the_primitive() {
        const SOURCE: &str = include_str!("commands/github_runner_ci.rs");
        assert!(
            SOURCE.contains("crate::nix_build_spinner::nix_build_spinner("),
            "commands/github_runner_ci.rs must delegate its nix-build phase-open \
             spinner through `crate::nix_build_spinner::nix_build_spinner()` — \
             the canonical Green-palette + `Building with Nix...`-message fusion."
        );
        let hits = crate::test_support::code_line_hits(
            SOURCE,
            "styled_spinner(SpinnerStyle::Green, \"Building with Nix...\"",
        );
        assert!(
            hits.is_empty(),
            "commands/github_runner_ci.rs must NOT re-inline the \
             `styled_spinner(SpinnerStyle::Green, \"Building with Nix...\")` \
             stanza — every nix-build phase-open spinner must route through \
             `crate::nix_build_spinner::nix_build_spinner()`. Offending lines: {hits:?}"
        );
    }

    /// Byte-oracle: [`NIX_BUILD_OP_LABEL`] carries the 9-byte ASCII
    /// spelling `nix build` — one lower-case word, one ASCII space,
    /// one lower-case word. Any drift (`"nix-build"`, `"nix build
    /// image"`, `"Nix build"`) would fork both flows' operator-facing
    /// failure envelope: `"Failed to run <op>"` on spawn failure,
    /// `"<op> failed (exit {code})"` on non-zero exit.
    #[test]
    fn nix_build_op_label_pins_the_pre_lift_bytes_verbatim() {
        assert_eq!(NIX_BUILD_OP_LABEL, "nix build");
        // 9 ASCII bytes: n-i-x- -b-u-i-l-d
        assert_eq!(NIX_BUILD_OP_LABEL.len(), 9);
        assert!(
            NIX_BUILD_OP_LABEL.is_ascii(),
            "the canonical op-label must remain pure ASCII"
        );
    }

    /// Success path: a shim that exits 0 makes
    /// [`run_nix_build_under_spinner`] return `Ok(())`, AND the
    /// spinner is finished on that path (so no live spinner leaks
    /// beneath any subsequent `crate::info_success!` narration).
    #[tokio::test]
    async fn run_nix_build_under_spinner_zero_exit_returns_ok_and_finishes_spinner() {
        let (_dir, shim) = crate::test_support::make_executable_shim("nix", "#!/bin/sh\nexit 0\n");
        let cmd = tokio::process::Command::new(&shim);
        let spinner = nix_build_spinner();
        let handle = spinner.clone();
        let result = run_nix_build_under_spinner(cmd, spinner).await;
        assert!(
            result.is_ok(),
            "zero-exit must surface as Ok(()), got: {result:?}"
        );
        assert!(
            handle.is_finished(),
            "spinner must be finished on the success path — a leaked live \
             spinner would race the subsequent `info_success!` narration \
             at both consumer sites"
        );
    }

    /// Non-zero exit path: a shim that exits 7 makes
    /// [`run_nix_build_under_spinner`] return an `anyhow::Error` whose
    /// `Display` form carries BOTH the pinned `nix build` op-label
    /// AND the captured exit code. The spinner MUST also be finished
    /// on this path — the load-bearing invariant a naive `outcome?`
    /// -before-`finish_and_clear()` ordering would break.
    #[tokio::test]
    async fn run_nix_build_under_spinner_nonzero_exit_carries_op_and_code_and_finishes_spinner() {
        let (_dir, shim) = crate::test_support::make_executable_shim("nix", "#!/bin/sh\nexit 7\n");
        let cmd = tokio::process::Command::new(&shim);
        let spinner = nix_build_spinner();
        let handle = spinner.clone();
        let err = run_nix_build_under_spinner(cmd, spinner)
            .await
            .expect_err("nonzero exit must fail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("nix build"),
            "op label `nix build` must appear in failure message, got: {msg}"
        );
        assert!(
            msg.contains("exit 7"),
            "exit code `exit 7` must appear in failure message, got: {msg}"
        );
        assert!(
            handle.is_finished(),
            "spinner must be finished on the non-zero-exit path — the load-\
             bearing invariant a `outcome?`-before-`finish_and_clear()` \
             re-inversion would break"
        );
    }

    /// Spawn-failure path: a missing binary makes
    /// [`run_nix_build_under_spinner`] return an `anyhow::Error`
    /// carrying the `nix build` op-label. The spinner MUST be
    /// finished on this path too — this is the exact case the pre-
    /// lift comment blocks at commands/{build,github_runner_ci}.rs
    /// call out as historically broken (a `?` on `.context("Failed
    /// to run nix build")` running BEFORE `spinner.finish_and_clear()`
    /// left a live spinner animating beneath the printed error).
    /// Post-lift this test locks that invariant in place.
    #[tokio::test]
    async fn run_nix_build_under_spinner_spawn_failure_finishes_spinner_before_propagation() {
        let cmd = tokio::process::Command::new(
            "/nonexistent/path/to/nix-build-binary-that-does-not-exist",
        );
        let spinner = nix_build_spinner();
        let handle = spinner.clone();
        let err = run_nix_build_under_spinner(cmd, spinner)
            .await
            .expect_err("missing binary must fail");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("nix build"),
            "op label `nix build` must appear in spawn-failure message, got: {msg}"
        );
        assert!(
            handle.is_finished(),
            "spinner must be finished on the spawn-failure path — this is the \
             exact regression class the primitive was extracted to make \
             structurally impossible at both consumer sites"
        );
    }

    /// Caller-shield: `commands/build.rs` MUST route its nix-build
    /// spawn-plus-spinner-cleanup through
    /// [`run_nix_build_under_spinner`] and MUST NOT re-inline the
    /// raw `run_inherited_status(cmd, "nix build")` +
    /// `spinner.finish_and_clear()` two-line stanza on any code line.
    /// A future revert that split the primitive back into an inline
    /// `outcome?` right after the retry call would re-open the
    /// spawn-failure spinner-leak class the primitive closes; the
    /// shield fires that re-inline at compile-time-of-tests rather
    /// than in the terminal.
    #[test]
    fn commands_build_delegates_run_nix_build_under_spinner_to_the_primitive() {
        const SOURCE: &str = include_str!("commands/build.rs");
        assert!(
            SOURCE.contains("crate::nix_build_spinner::run_nix_build_under_spinner("),
            "commands/build.rs must delegate its nix-build spawn-plus-spinner-cleanup \
             through `crate::nix_build_spinner::run_nix_build_under_spinner()` — the \
             canonical bind-before-`?`-ordered spinner-safe primitive."
        );
        let hits = crate::test_support::code_line_hits(
            SOURCE,
            "crate::retry::run_inherited_status(cmd, \"nix build\")",
        );
        assert!(
            hits.is_empty(),
            "commands/build.rs must NOT re-inline the \
             `crate::retry::run_inherited_status(cmd, \"nix build\")` \
             stanza — every nix-build spawn under the phase-open spinner \
             must route through `crate::nix_build_spinner::run_nix_build_under_spinner()`. \
             Offending lines: {hits:?}"
        );
    }

    /// Caller-shield: `commands/github_runner_ci.rs` MUST route
    /// its nix-build spawn-plus-spinner-cleanup through
    /// [`run_nix_build_under_spinner`] and MUST NOT re-inline the
    /// raw `run_inherited_status(build_cmd, "nix build")` +
    /// `spinner.finish_and_clear()` two-line stanza on any code line.
    /// Same discipline as the sibling shield on `commands/build.rs`.
    #[test]
    fn commands_github_runner_ci_delegates_run_nix_build_under_spinner_to_the_primitive() {
        const SOURCE: &str = include_str!("commands/github_runner_ci.rs");
        assert!(
            SOURCE.contains("crate::nix_build_spinner::run_nix_build_under_spinner("),
            "commands/github_runner_ci.rs must delegate its nix-build spawn-plus-\
             spinner-cleanup through \
             `crate::nix_build_spinner::run_nix_build_under_spinner()` — the \
             canonical bind-before-`?`-ordered spinner-safe primitive."
        );
        let hits = crate::test_support::code_line_hits(
            SOURCE,
            "crate::retry::run_inherited_status(build_cmd, \"nix build\")",
        );
        assert!(
            hits.is_empty(),
            "commands/github_runner_ci.rs must NOT re-inline the \
             `crate::retry::run_inherited_status(build_cmd, \"nix build\")` \
             stanza — every nix-build spawn under the phase-open spinner \
             must route through `crate::nix_build_spinner::run_nix_build_under_spinner()`. \
             Offending lines: {hits:?}"
        );
    }
}
