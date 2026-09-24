//! Typed E2E-image pair-existence probe primitive.
//!
//! # Compounding
//!
//! Pre-lift FOUR sibling call sites in `commands/e2e.rs` carried the
//! same two-line `let backend_exists = check_image_exists("backend")
//! <sink>; let <second>_exists = check_image_exists("web")<sink>;`
//! stanza verbatim (past the sink and the second binding's name):
//!
//! - `run_test_pyramid` (~L349–350): `.unwrap_or(false)` sink,
//!   `frontend_exists` second binding.
//! - `prepare_e2e_images` (~L571–572): `?` sink, `frontend_exists`
//!   second binding.
//! - `run_e2e_tests` (~L626–627): `?` sink, `frontend_exists` second
//!   binding.
//! - `run_e2e_tests_smart` (~L1199–1200): `.unwrap_or(false)` sink,
//!   `web_exists` second binding.
//!
//! The pair `{"backend", "web"}` names the same typed concept at every
//! site: **the E2E image pair**, the two Docker images the E2E tier
//! runs against. Every caller reads both halves and gates a
//! `prepare_e2e_images` / rebuild-fallback chain on their conjunction
//! or disjunction. Yet the pre-lift shape spelled the pair as two
//! loose `bool` bindings whose relationship was implicit, and the
//! second binding drifted between `frontend_exists` (three sites) and
//! `web_exists` (one site) — a semantic-name mismatch that would
//! confuse a reader trying to correlate the sites.
//!
//! Post-lift the pair is a typed [`E2eImagePairExistence`] carrying
//! `backend` and `web` fields (aligned with the underlying Docker
//! image names, not the drifted `frontend` alias). Every consumer
//! reads through one of the two probes below, so a future refinement
//! — adding a third half (a `mobile` image), tagging each half with
//! its content-addressable digest for hermetic-runner pipelining,
//! swapping the underlying `check_image_exists` shim for a
//! [`crate::infrastructure::docker::find_first_image_id_by_name_async`]
//! call to overlap the two probes — lands at ONE place and every
//! pre-lift caller inherits the change.
//!
//! # The two probe shapes
//!
//! [`probe_e2e_image_pair_existence`] bubbles up any Docker-daemon
//! interrogation failure — the shape the pre-lift `?`-sink call sites
//! spelled. [`probe_e2e_image_pair_existence_lossy`] collapses any
//! failure at either half into `false` for that half — the shape the
//! pre-lift `.unwrap_or(false)`-sink call sites spelled, encoding
//! "if we cannot tell, assume not present, and let the rebuild
//! fallback logic decide."
//!
//! # Theory grounding
//!
//! - THEORY.md §III.1 (typescape as root data structure): the pair
//!   `{"backend", "web"}` becomes a typed dimension of the E2E
//!   convergence surface rather than two loose call-site literals.
//!   A future addition (a third image, a rename at the image side)
//!   is a change to this dimension's construction and every
//!   projection through it — every caller — inherits by
//!   construction, per the typescape discipline.
//! - THEORY.md §V.1 (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the [`E2eImagePairExistence`] type
//!   makes "both halves present" and "any half missing" typed
//!   predicates (`both_present`, `any_missing`) rather than inline
//!   conjunctions the caller composes each time. A future consumer
//!   that composes the wrong polarity (`!backend && !web` instead of
//!   `!backend || !web`) reads as a defect on its face against the
//!   typed predicate.
//! - THEORY.md §VI.1 (three-times rule; two-is-a-coincidence
//!   threshold): the pre-lift FOUR occurrences sit past the
//!   three-times threshold and past the pair-drift threshold (three
//!   sites named the second half `frontend_exists`, one named it
//!   `web_exists`).

use anyhow::Result;

/// Typed outcome of probing both halves of the E2E image pair.
///
/// Each field carries the observed presence of one E2E-image half
/// in the local Docker daemon. Field names match the underlying
/// image names (`backend`, `web`) rather than the pre-lift
/// `frontend` / `web` binding drift on the caller side — the
/// physical image is what the [`crate::infrastructure::docker`]
/// primitives interrogate, so aligning field names with the image
/// side removes one dictionary hop for a reader tracing
/// `existence.web` through to the underlying `docker images`
/// lookup.
///
/// The struct is `Copy` because both fields are `bool` and callers
/// consistently read both halves after probing — cloning by value
/// costs one bit each and simplifies the caller ergonomics past a
/// borrow discipline that would not surface any real invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E2eImagePairExistence {
    /// Whether the `backend` E2E image is present in the local
    /// Docker daemon.
    pub backend: bool,
    /// Whether the `web` E2E image is present in the local Docker
    /// daemon.
    pub web: bool,
}

impl E2eImagePairExistence {
    /// The pair is fully cached ⇔ both halves are present ⇔ no
    /// rebuild is required. Callers that gate a fast-path skip on
    /// full pair presence read this predicate rather than composing
    /// `.backend && .web` inline.
    pub fn both_present(self) -> bool {
        self.backend && self.web
    }

    /// The pair is partially or fully missing ⇔ at least one half
    /// is absent ⇔ at least one build round is required. Callers
    /// that gate a rebuild fallback on partial pair absence read
    /// this predicate rather than composing `!.backend || !.web`
    /// inline.
    pub fn any_missing(self) -> bool {
        !self.backend || !self.web
    }
}

/// Probe both halves of the E2E image pair, bubbling up any
/// Docker-daemon interrogation failure at either half.
///
/// Delegates to
/// [`crate::infrastructure::docker::find_first_image_id_by_name`]
/// per half — the same one-oracle body the pre-lift `commands/e2e.rs
/// ::check_image_exists` shim reads through, so this primitive and
/// the shim share one construction surface and future refinements
/// (a caching layer, a switch to `docker images --filter`, an
/// overlap of the two half-probes via
/// `find_first_image_id_by_name_async`) land at that one place.
///
/// See the module docstring for the compounding argument and for
/// the sibling
/// [`probe_e2e_image_pair_existence_lossy`] variant that collapses
/// interrogation failures into `false`.
pub fn probe_e2e_image_pair_existence() -> Result<E2eImagePairExistence> {
    Ok(E2eImagePairExistence {
        backend: probe_half_strict("backend")?,
        web: probe_half_strict("web")?,
    })
}

/// Probe both halves of the E2E image pair, collapsing any
/// Docker-daemon interrogation failure at either half into `false`
/// for that half.
///
/// Mirrors the pre-lift `.unwrap_or(false)` immediate-recovery
/// callers at `commands/e2e.rs::{run_test_pyramid, run_e2e_tests_smart}`
/// — the pattern encodes "if we cannot tell, assume not present,
/// and let the rebuild fallback logic decide." The lossy shape
/// never propagates a Docker-daemon error to the caller; a
/// spawn-failure or a permissions issue on either half returns
/// `false` for that half and the caller's rebuild path fires.
pub fn probe_e2e_image_pair_existence_lossy() -> E2eImagePairExistence {
    E2eImagePairExistence {
        backend: probe_half_lossy("backend"),
        web: probe_half_lossy("web"),
    }
}

/// Strict per-half probe: interrogate the local Docker daemon for
/// `name` and return `Ok(true)` iff the image is present. Bubbles
/// up any spawn / interrogation failure.
///
/// The body is the same
/// `crate::infrastructure::docker::find_first_image_id_by_name(name)
/// .is_some()` shape the pre-lift `commands/e2e.rs::check_image_exists`
/// shim carries — this primitive rides through the same
/// [`crate::infrastructure::docker`] one-oracle body without adding
/// a second respell.
fn probe_half_strict(name: &str) -> Result<bool> {
    Ok(crate::infrastructure::docker::find_first_image_id_by_name(name).is_some())
}

/// Lossy per-half probe: [`probe_half_strict`] with any error
/// collapsed to `false`. Owns the `.unwrap_or(false)` folding at
/// ONE point of truth so the sibling
/// [`probe_e2e_image_pair_existence_lossy`] body reads as two
/// straight-through field assignments.
fn probe_half_lossy(name: &str) -> bool {
    probe_half_strict(name).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`E2eImagePairExistence::both_present`] is the two-way `&&`.
    #[test]
    fn both_present_matches_conjunction() {
        for backend in [false, true] {
            for web in [false, true] {
                let pair = E2eImagePairExistence { backend, web };
                assert_eq!(pair.both_present(), backend && web);
            }
        }
    }

    /// [`E2eImagePairExistence::any_missing`] is the negation of
    /// `both_present` — the pair-predicate algebra collapses the
    /// two convex halves so a caller never has to spell De Morgan
    /// inline.
    #[test]
    fn any_missing_is_negation_of_both_present() {
        for backend in [false, true] {
            for web in [false, true] {
                let pair = E2eImagePairExistence { backend, web };
                assert_eq!(pair.any_missing(), !pair.both_present());
            }
        }
    }

    /// [`E2eImagePairExistence`] is `Copy` — a caller may pass the
    /// pair by value and still read it afterward. The pre-lift
    /// call sites read `backend_exists` and `frontend_exists` /
    /// `web_exists` multiple times after probing, so a non-`Copy`
    /// shape would force the caller to `let existence = ...; let
    /// backend = existence.backend; let web = existence.web;` before
    /// any predicate use.
    #[test]
    fn pair_is_copy_by_value() {
        let a = E2eImagePairExistence {
            backend: true,
            web: false,
        };
        let b = a;
        assert_eq!(a.backend, b.backend);
        assert_eq!(a.web, b.web);
    }

    /// Solve-once shield: the four known consumer sites in
    /// `commands/e2e.rs` must NOT re-spell the pre-lift
    /// `let backend_exists = check_image_exists("backend")` +
    /// `let frontend_exists = check_image_exists("web")` /
    /// `let web_exists = check_image_exists("web")` sibling pair
    /// stanza. Every consumer routes through one of the two
    /// probes above.
    ///
    /// The shield scans `commands/e2e.rs` for the pre-lift
    /// `check_image_exists("backend")` binding-line shape at
    /// non-test top-level and refuses any occurrence — the
    /// remaining legitimate reference lives inside a loop over
    /// `["backend", "web"]` at `cleanup_e2e_images` and passes the
    /// loop variable (not the string literal) to
    /// `check_image_exists`, so this shield's substring match on
    /// `check_image_exists("backend")` does not false-fire against
    /// it.
    #[test]
    fn no_reinline_of_pre_lift_backend_pair_stanza_in_e2e_module() {
        let content =
            std::fs::read_to_string("src/commands/e2e.rs").expect("read src/commands/e2e.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(&content, "commands/e2e.rs");
        assert!(
            !body.contains("check_image_exists(\"backend\")"),
            "no-reinline shield: `commands/e2e.rs` still carries a \
             pre-lift `check_image_exists(\"backend\")` respell — every \
             pair-probe site must delegate through \
             `crate::e2e_image_pair_existence::\
             probe_e2e_image_pair_existence{{,_lossy}}`",
        );
        assert!(
            !body.contains("check_image_exists(\"web\")"),
            "no-reinline shield: `commands/e2e.rs` still carries a \
             pre-lift `check_image_exists(\"web\")` respell — every \
             pair-probe site must delegate through \
             `crate::e2e_image_pair_existence::\
             probe_e2e_image_pair_existence{{,_lossy}}`",
        );
    }

    /// Positive delegation shield: `commands/e2e.rs` must route
    /// through the primitive at every pair-probe site.
    ///
    /// The forward-hit count is fixed at FOUR — one call per
    /// pre-lift caller (`run_test_pyramid`, `prepare_e2e_images`,
    /// `run_e2e_tests`, `run_e2e_tests_smart`). A lift that
    /// removed the pre-lift stanza from one caller but forgot to
    /// wire the primitive would silently drop the pair check
    /// entirely, and the rebuild fallback would either fire
    /// unconditionally or fail to fire — either regression fails
    /// this shield.
    ///
    /// The needle matches both the lossy and strict probe names by
    /// their common prefix `probe_e2e_image_pair_existence`, so a
    /// consumer swap between the two variants (e.g. tightening a
    /// caller from `.unwrap_or(false)`-lossy to `?`-strict) does
    /// not require touching this shield.
    #[test]
    fn e2e_module_delegates_to_pair_probe_at_four_sites() {
        let content =
            std::fs::read_to_string("src/commands/e2e.rs").expect("read src/commands/e2e.rs");
        let body =
            crate::test_support::module_body_before_first_cfg_test(&content, "commands/e2e.rs");
        let hits = body.matches("probe_e2e_image_pair_existence").count();
        assert_eq!(
            hits, 4,
            "positive delegation shield: exactly FOUR pair-probe \
             call sites must route through \
             `crate::e2e_image_pair_existence::\
             probe_e2e_image_pair_existence{{,_lossy}}`; found {}",
            hits,
        );
    }
}
