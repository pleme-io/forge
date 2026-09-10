//! Canonical `involvedObject.name=<name>` Kubernetes field-selector grammar.
//!
//! Three pre-lift sibling sites across `commands/status.rs::fetch_events`
//! (:1175, inside a nine-arg `kubectl get events -n <ns> --field-selector
//! involvedObject.name=<deployment> -o json --sort-by=.lastTimestamp` argv
//! slice threaded into [`crate::infrastructure::kubectl::kubectl_list_items`]),
//! `commands/flux.rs::gather_deployment_diagnostics` (:885, inside a
//! ten-arg `kubectl get events -n <ns> --sort-by=.lastTimestamp
//! --field-selector involvedObject.name=<deployment> -o custom-columns=…
//! --no-headers` argv slice threaded into
//! [`crate::infrastructure::kubectl::kubectl_probe_stdout_capture`]), and
//! `k8s.rs::get_pod_events` (:295, threaded into a `kube::api::ListParams::
//! default().fields(...)` builder on the typed `kube` client) each spelled
//! the
//!
//! ```ignore
//! format!("involvedObject.name={}", <name>)
//! ```
//!
//! stanza verbatim to build the value that a downstream `--field-selector`
//! flag (or `ListParams::fields` builder) reads. Post-lift the sites reach
//! for [`format_involved_object_name_field_selector`] and the
//! `involvedObject.name=` field-key + the interpolated Display value + the
//! exact byte shape of the emitted selector are decided once here.
//!
//! Grounded in THEORY.md §VI.1's three-times rule: two sibling call sites
//! is a coincidence, three is a law and the shape belongs in a typed
//! primitive rather than in three inline `format!` stanzas whose drift is
//! a grep away.
//!
//! # The load-bearing `involvedObject.name` field path
//!
//! `involvedObject.name` is the exact Kubernetes Event fieldset path a
//! kubectl `--field-selector` (or `kube::api::ListParams::fields`) reads
//! to narrow an `Event`-collection listing to events whose
//! `involvedObject` reference targets a specific named workload — the
//! only field kubectl's Event field-selector allowlist accepts on the
//! `name` axis. A drift to `involvedObject.kind`, `metadata.name`, or a
//! misspelled `involvedObject.Name` (case-sensitive) would either match
//! nothing or match a different-axis field, so the field path is pinned
//! here rather than threaded through the call.
//!
//! # Distinct from the sibling `app=<name>` label-selector shape
//!
//! [`crate::k8s_label_selector::format_app_label_selector`] carries the
//! sibling `app=<name>` grammar consumed by `kubectl -l <selector>` (a
//! label selector). Two grammars, one shape (`<key>=<value>`), routed
//! through disjoint kubectl flags (`--field-selector` vs `-l`) that
//! kubectl's server parses through separate filter chains: label
//! selectors match `metadata.labels`; field selectors match a fixed
//! server-side allowlist of scalar fields (`metadata.name`,
//! `metadata.namespace`, `involvedObject.name`, `status.phase`, etc.).
//! Folding both grammars behind one primitive would either force every
//! caller to spell the axis at the call site (defeating the compression),
//! or make the grammar drift invisible at the call site the way the
//! `app=` and `involvedObject.name=` grammars are each greppable today.
//!
//! # Compounding
//!
//! Every future kubectl event-probe added to a command module (or a
//! typed `kube` client caller) reaches for this primitive on first grep
//! rather than fabricating a fresh `format!("involvedObject.name={}",
//! …)` copy. A future migration to a fully qualified `involvedObject.
//! apiVersion=` narrowing, or to a per-cluster field-selector prefix
//! override, flows to all three call sites from one edit; the alternative
//! is a grep-and-edit sweep across three modules on every drift.
//!
//! Grounded in THEORY.md §V.1 (construction guarantees — the knowable
//! platform): the field-selector value that binds a kubectl event probe
//! to its target workload is a construction detail of the fleet's
//! Kubernetes surface, and its rendering belongs in one typed primitive
//! rather than in three inline `format!` stanzas whose drift is a grep
//! away.

use std::fmt;

/// Render the canonical `involvedObject.name=<name>` Kubernetes
/// field-selector value.
///
/// Pure function — no I/O, no allocation beyond the returned `String`.
/// Pinning the format at one site means a future drift to a new
/// field-selector convention (a fully qualified `involvedObject.
/// apiVersion=` narrowing, an escaping pass for values that carry a
/// comma or equals sign, a per-cluster field-prefix override) flows to
/// all three kubectl-event / `kube`-Event call sites from one edit.
///
/// The `name` parameter accepts any [`fmt::Display`] rather than a
/// concrete `&str` so a bare `&str` (every pre-lift call site's shape
/// today, sourced from a `String` function parameter or a `&str` local),
/// an owned `String`, `Cow<str>`, and a future substrate deployment or
/// pod newtype (`substrate::DeploymentName(String)`,
/// `substrate::PodName(String)`) all flow through the same builder
/// without a per-caller `.to_string()` intermediate.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift
/// let selector = format!("involvedObject.name={}", deployment_name);
///
/// // Post-lift
/// let selector = crate::k8s_field_selector::format_involved_object_name_field_selector(
///     &deployment_name,
/// );
/// ```
pub fn format_involved_object_name_field_selector(name: &dyn fmt::Display) -> String {
    format!("involvedObject.name={}", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the exact rendered bytes: the twenty-character
    // `involvedObject.name=` field-key prefix, followed by the
    // interpolated name Display, with no trailing newline. A future
    // refactor that changes the field key, drops the equals separator,
    // adds a trailing newline, or quotes the value regresses this
    // assertion.
    #[test]
    fn format_involved_object_name_field_selector_emits_involved_object_name_equals_name() {
        let s = format_involved_object_name_field_selector(&"pleme-bff");
        assert_eq!(s, "involvedObject.name=pleme-bff");
        assert_eq!(s.as_bytes(), b"involvedObject.name=pleme-bff");
    }

    // A Kubernetes workload NAME is a 253-char max DNS-1123 subdomain
    // (Deployment/StatefulSet/Pod names), lowercase alphanumeric +
    // hyphens + dots. Pin that the builder forwards a canonical
    // representative value verbatim (no truncation, no case-fold, no
    // hyphen mangling). Guards against a future helper that "sanitizes"
    // the value at the primitive layer, which the caller must have
    // already done at input validation.
    #[test]
    fn format_involved_object_name_field_selector_forwards_dns1123_subdomain_verbatim() {
        let name = "a".repeat(63);
        let s = format_involved_object_name_field_selector(&name);
        let expected = format!("involvedObject.name={}", name);
        assert_eq!(s, expected);
        assert_eq!(s.len(), 20 + 63);
    }

    // Guard against a trailing-newline drift: the builder returns a
    // pure selector value that is threaded directly into a kubectl
    // `--field-selector <sel>` flag (or `ListParams::fields`); a stray
    // `\n` would break the kubectl argv (the flag value would be
    // interpreted as containing a newline character, which the kube
    // apiserver would reject as an invalid field-selector).
    #[test]
    fn format_involved_object_name_field_selector_emits_no_trailing_newline() {
        let s = format_involved_object_name_field_selector(&"pleme-bff");
        assert!(
            !s.ends_with('\n'),
            "must NOT end with a newline; got: {s:?}"
        );
        assert!(
            !s.contains('\n'),
            "must NOT contain any newline; got: {s:?}"
        );
    }

    // Guard against a leading-whitespace drift: kubectl field
    // selectors are strict about whitespace; a `" involvedObject.
    // name=…"` value would be rejected. Pin that the builder's output
    // starts with the `i` of `involvedObject.name=` immediately.
    #[test]
    fn format_involved_object_name_field_selector_emits_no_leading_whitespace() {
        let s = format_involved_object_name_field_selector(&"pleme-bff");
        assert!(
            s.starts_with("involvedObject.name="),
            "must start with `involvedObject.name=`; got: {s:?}"
        );
        assert!(
            !s.starts_with(' '),
            "must NOT start with whitespace; got: {s:?}"
        );
    }

    // A `&String` reference — every pre-lift call site's actual shape
    // today (a `deployment_name: &str` / `pod_name: &str` function
    // parameter passed to the primitive by borrow). Prove the slot
    // takes both a `&str` and a `&String` via the `&dyn Display`
    // acceptance.
    #[test]
    fn format_involved_object_name_field_selector_accepts_string_reference_and_str() {
        let owned = String::from("pleme-bff");
        let borrowed: &String = &owned;
        let s1 = format_involved_object_name_field_selector(borrowed);
        let s2 = format_involved_object_name_field_selector(&"pleme-bff");
        assert_eq!(s1, s2);
        assert_eq!(s1, "involvedObject.name=pleme-bff");
    }

    // A future substrate::DeploymentName / PodName newtype would
    // implement Display — simulate with a Display-wrapping newtype to
    // prove the slot takes any Display, not merely `&str` / `&String`.
    #[test]
    fn format_involved_object_name_field_selector_accepts_arbitrary_display_newtype() {
        struct Wrap<'a>(&'a str);
        impl fmt::Display for Wrap<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        let s = format_involved_object_name_field_selector(&Wrap("pleme-bff"));
        assert_eq!(s, "involvedObject.name=pleme-bff");
    }

    // Caller shield: no source line under `cli/src/` may spell the raw
    // `format!("involvedObject.name={}"` field-selector construction
    // inline any more. The three pre-lift sites migrated; any future
    // consumer that wants the same grammar reaches for
    // `crate::k8s_field_selector::format_involved_object_name_field_selector`
    // on first grep, not by copy-pasting the raw shape from an
    // existing module.
    //
    // Scoped to the WHOLE `cli/src/` tree (not just `commands/`)
    // because the third pre-lift site lives at `cli/src/k8s.rs:295` —
    // a typed `kube` client caller under `src/` proper — so a
    // `commands/`-only shield would miss the drift-critical
    // `ListParams::fields` builder. This module's own source is
    // skipped so its doc-comment and test-body prose that reference
    // the pre-lift shape do not self-hit.
    #[test]
    fn no_source_module_still_spells_raw_involved_object_name_field_selector() {
        use std::path::{Path, PathBuf};
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("k8s_field_selector.rs");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let mut stack = vec![src_dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                if p == this_file {
                    continue;
                }
                let source = std::fs::read_to_string(&p).unwrap();
                for (idx, line) in source.lines().enumerate() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    if line.contains("format!(\"involvedObject.name={}\"") {
                        offenders.push((p.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"involvedObject.name={{}}\", <name>)` \
             stanza(s) survive under `cli/src/` — route each through \
             `crate::k8s_field_selector::format_involved_object_name_field_selector(&<name>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: the three pre-lift files MUST each
    // forward through
    // `crate::k8s_field_selector::format_involved_object_name_field_selector(`
    // at least once, so a migration that dropped a call site outright
    // leaves the negative "no raw inline shape" scan trivially
    // satisfied by absence but the positive count still fails.
    //
    // Per-file minima from the pre-lift census:
    //   commands/status.rs:  1  (fetch_events)
    //   commands/flux.rs:    1  (gather_deployment_diagnostics)
    //   k8s.rs:              1  (get_pod_events)
    #[test]
    fn every_prelift_module_forwards_through_format_involved_object_name_field_selector() {
        use std::path::PathBuf;
        let cli_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&str, usize)] = &[
            ("commands/status.rs", 1),
            ("commands/flux.rs", 1),
            ("k8s.rs", 1),
        ];
        for (rel_path, min_count) in expectations {
            let path = cli_root.join(rel_path);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::k8s_field_selector::format_involved_object_name_field_selector(")
                .count();
            assert!(
                forwards >= *min_count,
                "{rel_path} must forward at least {min_count} \
                 `involvedObject.name=<name>` field-selector site(s) through \
                 `crate::k8s_field_selector::format_involved_object_name_field_selector(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
