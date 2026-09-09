//! Canonical `app=<name>` Kubernetes label-selector grammar.
//!
//! Thirteen pre-lift sibling sites across
//! `commands/{github_runner_ci (×1: watch-branch pod-list-JSON probe at
//! :544, inside a `kubectl get pods -n <ns> -l app=<name> -o json`
//! argv slice), product_release (×1: `verify_deployment_status` at
//! :103, bound as `let app_selector = ...` and threaded into a
//! `kubectl get pods -n <ns> -l <sel> -o jsonpath=…` shape), rollout
//! (×1: `execute` at :104, bound as `let label_selector = ...` for
//! the pod-history probe loop), flux (×4: `gather_deployment_diagnostics`
//! at :699 pod-list JSON, :831 wide-format pod dump, :848 per-container
//! state jsonpath, and :862 waiting/terminated-reason jsonpath), migrations
//! (×1: `find_migration_jobs_for_service` at :904, name-list jsonpath),
//! rust_service (×2 pre-lift, ×1 post-lift: `verify_deployment_status`
//! pod-phase probe + pod-image-tag probe now share one
//! `let app_selector = ...` bind that both
//! `crate::first_pod_field_argv::first_pod_field_get_pods_argv(namespace,
//! &app_selector, FirstPodField::<variant>)` calls borrow), status (×3: `probe_pods` at
//! :440 pod-list JSON, `probe_services` at :1065 service-list JSON,
//! `probe_jobs` at :1118 sorted job-list JSON)}.rs` each spelled the
//!
//! ```ignore
//! format!("app={}", <name>)
//! ```
//!
//! stanza verbatim to build the value that a downstream `kubectl -l
//! <selector>` flag reads. Post-lift the sites reach for
//! [`format_app_label_selector`] and the `app=` label key + the
//! interpolated Display value + the exact byte shape of the emitted
//! selector are decided once here.
//!
//! # The load-bearing `app=` label key
//!
//! `app` is the canonical Kubernetes recommended-label key
//! (`app.kubernetes.io/name` is the fully-qualified sibling; the bare
//! `app` short form is what every pre-lift consumer emits and what every
//! matching pleme-io Helm chart / kustomization template stamps on its
//! Pod / Deployment / StatefulSet / Job / Service specs). A drift to
//! a different key (`component=<name>`, `service=<name>`,
//! `app.kubernetes.io/name=<name>`) would misalign every kubectl probe
//! from its matching workload label, so the label key is pinned here
//! rather than threaded through the call.
//!
//! # Distinct from the sibling multi-key selector shape
//!
//! `commands/migrations.rs::execute` at `:947` carries the sibling
//! `format!("app={},component=migration", service)` stanza — same
//! `app=<name>` head, but with a comma-delimited `,component=migration`
//! tail. That shape is deliberately outside this primitive's contract:
//! the tail is a fixed literal keyed to migration-job selection, not a
//! caller-supplied second label, and lifting it here would either force
//! this primitive to grow a variadic-selector API (which none of the
//! thirteen pre-lift sites need), or split the migration-job selector
//! into two primitives that would then be forever recomposed at the
//! call site. The negative caller shield below is scoped to the pure
//! `format!("app={}"` shape (closing quote before the comma), so the
//! sibling multi-key `app={},component=…` string escapes the shield
//! by construction — its closing quote comes after the `component=`
//! tail.
//!
//! # Compounding
//!
//! Every future kubectl-probe added to a command module reaches for
//! this primitive on first grep rather than fabricating a fresh
//! `format!("app={}", …)` copy. A future migration to the fully
//! qualified `app.kubernetes.io/name=<name>` recommended label — or to
//! an entirely different fleet-standard selector — flows to all
//! thirteen call sites from one edit; the alternative is a
//! grep-and-edit sweep across eight command modules on every drift.
//!
//! Grounded in THEORY.md §V.1 (construction guarantees — the knowable
//! platform): the label key that binds a kubectl probe to its target
//! workload is a construction detail of the fleet's Kubernetes surface,
//! and its rendering belongs in one typed primitive rather than in
//! thirteen inline `format!` stanzas whose drift is a grep away.

use std::fmt;

/// Render the canonical `app=<name>` Kubernetes label selector.
///
/// Pure function — no I/O, no allocation beyond the returned `String`.
/// Pinning the format at one site means a future drift to a new
/// selector convention (a `app.kubernetes.io/name=<name>` fully
/// qualified key, an escaping pass for values that carry a comma or
/// equals sign, a per-cluster label-prefix override) flows to all
/// thirteen kubectl-probe call sites from one edit.
///
/// The `name` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (every pre-lift call site's shape
/// today, sourced from a `String` function parameter or a `&str` local),
/// an owned `String`, `Cow<str>`, and a future substrate deployment
/// newtype (`substrate::DeploymentName(String)`) all flow through the
/// same builder without a per-caller `.to_string()` intermediate.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// let label_selector = format!("app={}", name);
///
/// // Post-lift
/// let label_selector = crate::k8s_label_selector::format_app_label_selector(&name);
/// ```
pub fn format_app_label_selector(name: &dyn fmt::Display) -> String {
    format!("app={}", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact rendered bytes: the four-character `app=` label key
    // prefix (0x61 0x70 0x70 0x3D), followed by the interpolated name
    // Display, with no trailing newline. A future refactor that
    // changes the label key, drops the equals separator, adds a
    // trailing newline, or quotes the value regresses this assertion.
    #[test]
    fn format_app_label_selector_emits_app_equals_name() {
        let s = format_app_label_selector(&"pleme-bff");
        assert_eq!(s, "app=pleme-bff");
        assert_eq!(s.as_bytes(), b"app=pleme-bff");
    }

    // A Kubernetes label VALUE is a 63-char max DNS-1123 label:
    // lowercase alphanumeric + hyphens, no dots, no equals, no comma.
    // Pin that the builder forwards a canonical 63-char value verbatim
    // (no truncation, no case-fold, no hyphen mangling). Guards against
    // a future helper that "sanitizes" the value at the primitive
    // layer, which the caller must have already done at input
    // validation (the fleet's deployment names all satisfy DNS-1123 by
    // convention).
    #[test]
    fn format_app_label_selector_forwards_max_length_dns1123_label_verbatim() {
        let name = "a".repeat(63);
        let s = format_app_label_selector(&name);
        let expected = format!("app={}", name);
        assert_eq!(s, expected);
        assert_eq!(s.len(), 4 + 63);
    }

    // Guard against a trailing-newline drift: the builder returns a
    // pure selector value that is threaded directly into a
    // `kubectl -l <sel>` flag; a stray `\n` would break the kubectl
    // argv (the flag value would be interpreted as containing a
    // newline character, which would then be rejected as an invalid
    // label selector).
    #[test]
    fn format_app_label_selector_emits_no_trailing_newline() {
        let s = format_app_label_selector(&"pleme-bff");
        assert!(
            !s.ends_with('\n'),
            "must NOT end with a newline; got: {s:?}"
        );
        assert!(
            !s.contains('\n'),
            "must NOT contain any newline; got: {s:?}"
        );
    }

    // Guard against a leading-whitespace drift: kubectl label
    // selectors are strict about whitespace; a `" app=…"` value would
    // be rejected. Pin that the builder's output starts with the `a`
    // of `app=` immediately.
    #[test]
    fn format_app_label_selector_emits_no_leading_whitespace() {
        let s = format_app_label_selector(&"pleme-bff");
        assert!(s.starts_with("app="), "must start with `app=`; got: {s:?}");
        assert!(
            !s.starts_with(' '),
            "must NOT start with whitespace; got: {s:?}"
        );
    }

    // A `&String` reference — every pre-lift call site's actual shape
    // today (a `namespace: String` / `service: String` / `name: String`
    // function parameter passed to the primitive by borrow). Prove the
    // slot takes both a `&str` and a `&String` via the
    // `&dyn Display` acceptance.
    #[test]
    fn format_app_label_selector_accepts_string_reference_and_str() {
        let owned = String::from("pleme-bff");
        let borrowed: &String = &owned;
        let s1 = format_app_label_selector(borrowed);
        let s2 = format_app_label_selector(&"pleme-bff");
        assert_eq!(s1, s2);
        assert_eq!(s1, "app=pleme-bff");
    }

    // A future substrate::DeploymentName newtype would implement
    // Display — simulate with a Display-wrapping newtype to prove the
    // slot takes any Display, not merely `&str` / `&String`.
    #[test]
    fn format_app_label_selector_accepts_arbitrary_display_newtype() {
        struct Wrap<'a>(&'a str);
        impl fmt::Display for Wrap<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        let s = format_app_label_selector(&Wrap("pleme-bff"));
        assert_eq!(s, "app=pleme-bff");
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // spell the pure `format!("app={}"` (closing quote before the
    // comma) selector construction inline any more. The thirteen
    // pre-lift sites migrated; any future consumer that wants the same
    // grammar reaches for
    // `crate::k8s_label_selector::format_app_label_selector` on first
    // grep, not by copy-pasting the raw shape from an existing command
    // module.
    //
    // Deliberately scoped to the pure `app={}` shape (closing quote
    // BEFORE the comma) so the sibling multi-key
    // `format!("app={},component=migration", service)` in
    // `migrations.rs` — whose closing quote comes AFTER a
    // comma-delimited tail — escapes this shield by construction. See
    // the module docs for why the multi-key variant stays outside the
    // primitive's contract.
    #[test]
    fn no_command_module_still_spells_raw_pure_app_label_selector() {
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
                // Pure form: `format!("app={}"` followed by a comma
                // (closing quote before the comma). The `,component=`
                // sibling has `format!("app={},component=` — no
                // closing quote before its comma — so it does NOT
                // match.
                if line.contains("format!(\"app={}\",") {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"app={{}}\", <name>)` stanza(s) survive \
             under `commands/` — route each through \
             `crate::k8s_label_selector::format_app_label_selector(&<name>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the eight pre-lift files MUST each
    // forward through
    // `crate::k8s_label_selector::format_app_label_selector(` at least
    // once (some multiple times per the pre-lift census), so a
    // migration that dropped a call site outright leaves the negative
    // "no raw inline shape" scan trivially satisfied by absence but
    // the positive count still fails.
    //
    // Per-file minima from the pre-lift census:
    //   github_runner_ci.rs: 1  (watch-branch pod-list JSON)
    //   product_release.rs:  1  (verify_deployment_status)
    //   rollout.rs:          1  (execute pod-history probe)
    //   flux.rs:             4  (gather_deployment_diagnostics ×4)
    //   migrations.rs:       1  (find_migration_jobs_for_service)
    //   rust_service.rs:     1  (pod-phase probe + pod-image-tag probe
    //                           share one `let app_selector = ...` bind
    //                           post-lift onto
    //                           `crate::first_pod_field_argv::first_pod_field_get_pods_argv`,
    //                           which takes the selector by `&str`; the
    //                           two probes now spawn against the same
    //                           borrowed selector rather than
    //                           re-formatting `app=<name>` twice at
    //                           adjacent call sites)
    //   status.rs:           3  (probe_pods + probe_services + probe_jobs)
    #[test]
    fn every_prelift_module_forwards_through_format_app_label_selector() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[
            ("github_runner_ci.rs", 1),
            ("product_release.rs", 1),
            ("rollout.rs", 1),
            ("flux.rs", 4),
            ("migrations.rs", 1),
            ("rust_service.rs", 1),
            ("status.rs", 3),
        ];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::k8s_label_selector::format_app_label_selector(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} `app=<name>` \
                 selector site(s) through \
                 `crate::k8s_label_selector::format_app_label_selector(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
