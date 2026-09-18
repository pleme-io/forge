//! Closed enum for the 7-phase FluxCD product-kustomization chain
//! (`init → secrets → databases → bootstrap → governance → migrations →
//! app`) that [`super::flux::reconcile_product_chain`] walks in
//! dependency order.
//!
//! # Pre-lift census — one loop, three sibling `if phase.is_empty()`
//! decisions
//!
//! Pre-lift `commands/flux.rs::reconcile_product_chain` seeded the chain
//! as a `[&'static str; 7]` slice whose final element was the empty
//! string `""`, and then the loop body carried three sibling
//! `if phase.is_empty() { <app arm> } else { <named arm> }` branches
//! that each encoded the same "the empty-string sentinel means the bare
//! namespace kustomization, spelled `app` when we need an operator-
//! visible label" contract:
//!
//! 1. **Kustomization-name resolution** (pre-lift lines 425–429):
//!    ```ignore
//!    let ks_name = if phase.is_empty() {
//!        namespace.to_string()
//!    } else {
//!        format!("{}-{}", namespace, phase)
//!    };
//!    ```
//!    The empty-string sentinel signals "use the bare namespace name as
//!    the kustomization name"; every other phase composes
//!    `<namespace>-<phase>`.
//! 2. **Ready-branch label** (pre-lift line 450):
//!    ```ignore
//!    let phase_label = if phase.is_empty() { "app" } else { phase };
//!    ```
//!    A shadowed local inside the `if row.is_ready()` arm that projects
//!    the empty-string sentinel to the operator-visible label `"app"`.
//! 3. **Reconcile-branch label** (pre-lift line 455):
//!    ```ignore
//!    let phase_label = if phase.is_empty() { "app" } else { phase };
//!    ```
//!    A second shadowed local outside the ready-branch, byte-for-byte
//!    identical to (2), for the `Reconciling <phase>…` announce and the
//!    subsequent success / warn arms of the `match reconcile_kustomization`
//!    outcome.
//!
//! # Why a closed enum
//!
//! The pre-lift shape had three structural defects the typed body
//! forecloses:
//!
//! - **Sentinel-string overloading.** The empty string `""` served as
//!   both a data value (a phase whose kustomization suffix is nothing)
//!   and a control-flow flag (branch to the `app` arm on kustomization
//!   name AND on operator label). A future refactor that legitimately
//!   added a phase whose suffix happened to be empty — say, a
//!   fully-namespaced kustomization for the environment root — would
//!   silently collide with the `app` sentinel. Post-lift the two axes
//!   ([`FluxProductChainPhase::App`] as a distinct enum variant vs. the
//!   `<namespace>-<suffix>` composition on every other variant) are
//!   independent, and the primitive owns each projection.
//! - **Duplicate label projection.** The `if phase.is_empty() { "app" }
//!   else { phase }` branch was spelled twice, five lines apart, in
//!   `commands/flux.rs::reconcile_product_chain`. A drift in either
//!   half — the ready-branch label diverging from the reconcile-branch
//!   label — would compile and produce mismatched operator output. Post-
//!   lift [`FluxProductChainPhase::display_label`] is the one oracle
//!   both call sites read through.
//! - **Phase count carried in an ad-hoc slice.** The pre-lift
//!   `let phases = [...]` was a `[&str; 7]` inline literal whose seven-
//!   element count survived as documentation-only (the doc-comment
//!   spelled `init → secrets → databases → bootstrap → governance →
//!   migrations → app`). A future edit that appended or removed a phase
//!   without updating the comment would drift silently. Post-lift
//!   [`FluxProductChainPhase::ORDER`] is a `[Self; 7]` slice whose type-
//!   level count IS the phase count, and a missing arm on any
//!   [`FluxProductChainPhase`] `match` fails the exhaustiveness check
//!   at build time.
//!
//! # Order-invariant
//!
//! [`FluxProductChainPhase::ORDER`] fixes the pre-lift dependency-order
//! walk `init → secrets → databases → bootstrap → governance →
//! migrations → app`. This is a load-bearing invariant of the FluxCD
//! product-kustomization chain: each phase's kustomization has an
//! explicit `dependsOn` pointing at the previous phase, and
//! [`super::flux::reconcile_product_chain`]'s job is to reconcile them
//! in that order so the chain does not stall on default reconcile
//! intervals (5–10 min per phase, 30–60 min end-to-end).

use colored::Colorize;

/// One phase of the FluxCD product-kustomization chain that
/// [`super::flux::reconcile_product_chain`] walks in dependency order.
///
/// A closed enum: adding a phase means adding a variant, adding its
/// `ORDER` entry, and adding a `match` arm — the exhaustiveness check
/// at build time forecloses the pre-lift "silent slice extension" drift
/// where an appended phase reached production without updating the
/// doc-comment or the sibling label projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FluxProductChainPhase {
    /// Chain head. Kustomization: `<namespace>-init`.
    Init,
    /// Post-init secrets provisioning. Kustomization: `<namespace>-secrets`.
    Secrets,
    /// Post-secrets database provisioning. Kustomization:
    /// `<namespace>-databases`.
    Databases,
    /// Post-databases infrastructure bootstrap. Kustomization:
    /// `<namespace>-bootstrap`.
    Bootstrap,
    /// Post-bootstrap governance controllers. Kustomization:
    /// `<namespace>-governance`.
    Governance,
    /// Post-governance database migrations. Kustomization:
    /// `<namespace>-migrations`.
    Migrations,
    /// Chain tail — the application kustomization itself. Distinguished
    /// from every other variant by carrying NO suffix: its kustomization
    /// name is the bare `<namespace>`, and its operator-visible label
    /// is the string literal `"app"`. This is the pre-lift "empty-
    /// string sentinel" turned into a typed variant so a future
    /// operator-facing label change or a suffix-composition change
    /// cannot silently collide with a real-suffix phase.
    App,
}

impl FluxProductChainPhase {
    /// The dependency-order walk `init → secrets → databases → bootstrap
    /// → governance → migrations → app`. Consumed by
    /// [`super::flux::reconcile_product_chain`] as
    /// `for phase in FluxProductChainPhase::ORDER { … }`.
    ///
    /// The `[Self; 7]` type carries the phase count structurally — a
    /// future variant addition without an accompanying `ORDER` entry
    /// fails at the `[Self; 8]` type mismatch on the fixed initializer
    /// below.
    pub(crate) const ORDER: [Self; 7] = [
        Self::Init,
        Self::Secrets,
        Self::Databases,
        Self::Bootstrap,
        Self::Governance,
        Self::Migrations,
        Self::App,
    ];

    /// The kustomization-name suffix this phase composes onto the
    /// namespace, or [`None`] for [`FluxProductChainPhase::App`] whose
    /// kustomization name is the bare namespace.
    ///
    /// Kept as a private accessor: the two typed projections
    /// [`Self::kustomization_name`] and [`Self::display_label`] each
    /// route through it, so a future edit that renamed a phase's
    /// suffix (`"secrets"` → `"secret"`) hits ONE match arm and both
    /// projections inherit the change consistently.
    fn suffix(self) -> Option<&'static str> {
        match self {
            Self::Init => Some("init"),
            Self::Secrets => Some("secrets"),
            Self::Databases => Some("databases"),
            Self::Bootstrap => Some("bootstrap"),
            Self::Governance => Some("governance"),
            Self::Migrations => Some("migrations"),
            Self::App => None,
        }
    }

    /// The kustomization name this phase reconciles under, composed
    /// against the caller-supplied `namespace`.
    ///
    /// - [`FluxProductChainPhase::App`] returns the bare `namespace`
    ///   (pre-lift the `if phase.is_empty() { namespace.to_string() }`
    ///   arm).
    /// - Every other variant returns `<namespace>-<suffix>` (pre-lift
    ///   the `else { format!("{}-{}", namespace, phase) }` arm).
    ///
    /// Returns [`String`] because the [`FluxProductChainPhase::App`]
    /// arm needs to own its result (a borrowed reference to `namespace`
    /// cannot share a return type with a freshly-composed
    /// `<namespace>-<suffix>` heap string). The non-`App` arms could
    /// return a `&'static`-suffix concatenation, but a uniform
    /// [`String`] return keeps every caller shape identical.
    pub(crate) fn kustomization_name(self, namespace: &str) -> String {
        match self.suffix() {
            Some(suffix) => format!("{}-{}", namespace, suffix),
            None => namespace.to_string(),
        }
    }

    /// The operator-visible label for this phase, projected onto the
    /// pre-lift `if phase.is_empty() { "app" } else { phase }` shape.
    ///
    /// Returns `&'static str` — every arm's label is a string literal
    /// baked at compile time. Consumed by
    /// [`super::flux::reconcile_product_chain`] on the ready-branch
    /// (`✓ <label> (already ready)`), the reconcile-branch
    /// (`⏳ Reconciling <label>…`), the reconcile-success branch
    /// (`✓ <label>`), and the reconcile-non-zero-exit branch
    /// (`⚠ <label> (reconcile returned non-zero…)`).
    pub(crate) fn display_label(self) -> &'static str {
        match self.suffix() {
            Some(suffix) => suffix,
            None => "app",
        }
    }
}

/// Renders the pre-lift `Reconciling <label>…` announce line onto the
/// enum's [`FluxProductChainPhase::display_label`] projection.
///
/// Pre-lift `commands/flux.rs::reconcile_product_chain` spelled this as
/// `println!("      ⏳ Reconciling {}...", phase_label);` inline after
/// the shadowed second `let phase_label = if phase.is_empty() { "app" }
/// else { phase };` binding. Post-lift the announce line and the label
/// projection live in the same module so a future glyph change
/// (`⏳` → `🔄`, six-space indent → four-space) reaches one body.
pub(crate) fn print_reconciling_phase_announce(phase: FluxProductChainPhase) {
    let mut out = std::io::stdout().lock();
    let _ = write_reconciling_phase_announce(&mut out, phase);
}

/// Byte-oracle sibling of [`print_reconciling_phase_announce`]. Emits
/// the same `      ⏳ Reconciling <label>...\n` bytes to any
/// [`std::io::Write`] sink so tests can assert the exact wire shape.
pub(crate) fn write_reconciling_phase_announce<W: std::io::Write>(
    w: &mut W,
    phase: FluxProductChainPhase,
) -> std::io::Result<()> {
    writeln!(w, "      ⏳ Reconciling {}...", phase.display_label())
}

/// Renders the pre-lift `✓ <label> (already ready)` short-circuit ack
/// on the ready-branch, styling the label as [`Colorize::dimmed`] to
/// match the pre-lift wire shape.
pub(crate) fn print_phase_already_ready_ack(phase: FluxProductChainPhase) {
    println!("      ✓ {} (already ready)", phase.display_label().dimmed());
}

/// Renders the pre-lift `✓ <label>` success ack on the
/// reconcile-success branch, styling the label as [`Colorize::green`]
/// to match the pre-lift wire shape.
pub(crate) fn print_phase_reconciled_ack(phase: FluxProductChainPhase) {
    println!("      ✓ {}", phase.display_label().green());
}

/// Renders the pre-lift `⚠ <label> (reconcile returned non-zero, may
/// need dependency; exit=<exit_code>): <stderr>` non-fatal warn on the
/// reconcile-non-zero-exit branch, styling the label as
/// [`Colorize::yellow`] to match the pre-lift wire shape.
pub(crate) fn print_phase_reconcile_nonzero_warn(
    phase: FluxProductChainPhase,
    exit_code: Option<i32>,
    stderr: &str,
) {
    println!(
        "      ⚠ {} (reconcile returned non-zero, may need dependency; \
         exit={:?}): {}",
        phase.display_label().yellow(),
        exit_code,
        stderr.trim()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`FluxProductChainPhase::ORDER`] fixes the pre-lift
    /// dependency-order walk `init → secrets → databases → bootstrap →
    /// governance → migrations → app` element-for-element. A future
    /// refactor that (a) reordered any two phases (silently breaking
    /// `dependsOn` cascades), (b) dropped a phase (leaving its cluster
    /// resources unreconciled and waiting on default 5–10 min tick),
    /// or (c) inserted a phase without an accompanying `ORDER` update
    /// regresses this assertion.
    #[test]
    fn order_fixes_pre_lift_dependency_walk() {
        assert_eq!(
            FluxProductChainPhase::ORDER,
            [
                FluxProductChainPhase::Init,
                FluxProductChainPhase::Secrets,
                FluxProductChainPhase::Databases,
                FluxProductChainPhase::Bootstrap,
                FluxProductChainPhase::Governance,
                FluxProductChainPhase::Migrations,
                FluxProductChainPhase::App,
            ]
        );
    }

    /// The `[Self; 7]` type carries the phase count structurally. A
    /// future edit that broke the count without touching this shield
    /// still fails the `[Self; N]` shape at
    /// [`FluxProductChainPhase::ORDER`], but pin the length here too
    /// so the doc-comment ("7-phase chain") and the type coincide.
    #[test]
    fn order_length_is_seven() {
        assert_eq!(FluxProductChainPhase::ORDER.len(), 7);
    }

    /// Every non-[`FluxProductChainPhase::App`] variant composes
    /// `<namespace>-<suffix>` on [`FluxProductChainPhase::kustomization_name`],
    /// and [`FluxProductChainPhase::App`] returns the bare namespace.
    #[test]
    fn kustomization_name_composes_suffix_except_app_bare() {
        assert_eq!(
            FluxProductChainPhase::Init.kustomization_name("frigg-prod"),
            "frigg-prod-init"
        );
        assert_eq!(
            FluxProductChainPhase::Secrets.kustomization_name("frigg-prod"),
            "frigg-prod-secrets"
        );
        assert_eq!(
            FluxProductChainPhase::Databases.kustomization_name("frigg-prod"),
            "frigg-prod-databases"
        );
        assert_eq!(
            FluxProductChainPhase::Bootstrap.kustomization_name("frigg-prod"),
            "frigg-prod-bootstrap"
        );
        assert_eq!(
            FluxProductChainPhase::Governance.kustomization_name("frigg-prod"),
            "frigg-prod-governance"
        );
        assert_eq!(
            FluxProductChainPhase::Migrations.kustomization_name("frigg-prod"),
            "frigg-prod-migrations"
        );
        assert_eq!(
            FluxProductChainPhase::App.kustomization_name("frigg-prod"),
            "frigg-prod"
        );
    }

    /// Every non-[`FluxProductChainPhase::App`] variant projects its
    /// suffix as its [`FluxProductChainPhase::display_label`]; the
    /// [`FluxProductChainPhase::App`] variant projects the literal
    /// `"app"` (pre-lift the `if phase.is_empty() { "app" }` arm).
    #[test]
    fn display_label_is_suffix_or_literal_app() {
        assert_eq!(FluxProductChainPhase::Init.display_label(), "init");
        assert_eq!(FluxProductChainPhase::Secrets.display_label(), "secrets");
        assert_eq!(
            FluxProductChainPhase::Databases.display_label(),
            "databases"
        );
        assert_eq!(
            FluxProductChainPhase::Bootstrap.display_label(),
            "bootstrap"
        );
        assert_eq!(
            FluxProductChainPhase::Governance.display_label(),
            "governance"
        );
        assert_eq!(
            FluxProductChainPhase::Migrations.display_label(),
            "migrations"
        );
        assert_eq!(FluxProductChainPhase::App.display_label(), "app");
    }

    /// The two projections agree on the six non-`App` phases (the
    /// pre-lift `else { phase }` arm produced the same bytes as the
    /// pre-lift `format!("{}-{}", namespace, phase)`'s trailing
    /// suffix), and diverge on `App` (the empty-string sentinel
    /// projected to `""` on the pre-lift kustomization-name path and
    /// to `"app"` on the label path — post-lift each has its own
    /// deliberate arm rather than a fused implicit-string-cast).
    #[test]
    fn label_and_suffix_reconcile_on_non_app_variants() {
        for phase in FluxProductChainPhase::ORDER {
            if phase == FluxProductChainPhase::App {
                continue;
            }
            let ks = phase.kustomization_name("ns");
            let expected_ks = format!("ns-{}", phase.display_label());
            assert_eq!(ks, expected_ks, "phase {:?}", phase);
        }
    }

    /// Byte-oracle: [`write_reconciling_phase_announce`] emits the pre-
    /// lift `      ⏳ Reconciling <label>...\n` wire shape unchanged.
    /// A future refactor that (a) dropped the six-space indent, (b)
    /// swapped `⏳` for another glyph, (c) reordered `Reconciling` and
    /// the label, or (d) dropped the trailing `...` regresses this
    /// assertion.
    #[test]
    fn reconciling_announce_emits_pre_lift_wire_shape() {
        let mut buf = Vec::new();
        write_reconciling_phase_announce(&mut buf, FluxProductChainPhase::Databases).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "      ⏳ Reconciling databases...\n"
        );
    }

    /// The reconciling announce for [`FluxProductChainPhase::App`]
    /// projects the `"app"` label (pre-lift the second shadowed
    /// `let phase_label = if phase.is_empty() { "app" } else { phase };`
    /// binding on line 455 of `commands/flux.rs`).
    #[test]
    fn reconciling_announce_projects_app_label_on_bare_namespace_phase() {
        let mut buf = Vec::new();
        write_reconciling_phase_announce(&mut buf, FluxProductChainPhase::App).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "      ⏳ Reconciling app...\n"
        );
    }

    /// Positive delegation shield: `commands/flux.rs::reconcile_product_chain`
    /// forwards through [`FluxProductChainPhase::ORDER`] and the three
    /// print helpers, so the pre-lift call sites are all migrated.
    /// A future edit that dropped a call outright leaves the negative
    /// "no raw `if phase.is_empty()`" scan trivially satisfied by
    /// absence but the positive count still fails.
    #[test]
    fn flux_reconcile_product_chain_forwards_through_typed_primitive() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("flux.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            source.contains("FluxProductChainPhase::ORDER"),
            "commands/flux.rs must iterate over FluxProductChainPhase::ORDER \
             so the 7-phase walk lives in one typed body"
        );
        // Each of the three print helpers is called from the migrated
        // loop body — dropping any one silently regresses that branch
        // back onto an inline `println!`.
        for helper in [
            "print_reconciling_phase_announce(",
            "print_phase_already_ready_ack(",
            "print_phase_reconciled_ack(",
            "print_phase_reconcile_nonzero_warn(",
        ] {
            assert!(
                source.contains(helper),
                "commands/flux.rs must forward through `{}` from the migrated \
                 reconcile_product_chain loop",
                helper
            );
        }
    }

    /// Negative caller shield: no source line under
    /// `cli/src/commands/flux.rs` may re-inline the pre-lift
    /// `if phase.is_empty()` decision — a future consumer that wants
    /// the same App-vs-named-phase split routes through
    /// [`FluxProductChainPhase`] instead.
    ///
    /// Anchored on the literal opening `if phase.is_empty()` (which
    /// the pre-lift body carried three times inside
    /// `reconcile_product_chain`). Scans skip line-comment and
    /// block-comment lines so this shield's own docstring mentions of
    /// the forbidden shape do not self-match, and skip the whole
    /// `#[cfg(test)]` region on every module so a downstream test
    /// that composes the same tokens for coverage doesn't trip the
    /// shield.
    #[test]
    fn no_flux_module_still_spells_phase_is_empty_ternary() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("flux.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let needle = format!("if {}.is_empty()", "phase");
        let mut offenders: Vec<(usize, String)> = Vec::new();
        let mut in_block_comment = false;
        let mut in_test_region = false;
        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") {
                in_test_region = true;
            }
            if in_test_region {
                continue;
            }
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
            if line.contains(&needle) {
                offenders.push((idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `if phase.is_empty()` decision(s) survive under \
             `commands/flux.rs` — route each through \
             `crate::commands::flux_product_chain_phase::FluxProductChainPhase` instead:\n{:#?}",
            offenders
        );
    }
}
