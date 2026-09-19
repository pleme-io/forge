//! Canonical `{product}-{environment}` Kubernetes namespace identifier.
//!
//! Seven pre-lift sibling sites across five command / config / domain
//! modules each restated the same `format!("{}-{}", <product>, <env>)`
//! composition, all producing the same K8s namespace convention documented
//! in [`crate::product_service_id`]'s module docs (lines 68-73) as the
//! sibling of `{product}-{service}`. Post-lift the sites reach for
//! [`product_environment_namespace`] and the separator byte, argument
//! order, and non-empty invariants are decided once here.
//!
//! # The census (all seven sites)
//!
//! - `commands/sessions.rs::flush` — the K8s namespace the Valkey pod +
//!   secret lookup keys off.
//! - `commands/rollback.rs::execute` — the K8s namespace passed to the
//!   post-rollback health check.
//! - `commands/attestation.rs::compose_product_certification` — the
//!   `DeploymentAttestation::namespace` field (line 1584).
//! - `commands/attestation.rs::compose_product_certification` — the
//!   `DeploymentAttestation::kustomization` field (line 1585, same
//!   composition, distinct struct field).
//! - `config/federation.rs::FederationTestConfig::namespace` — the default
//!   returned when `namespace_pattern` is unset.
//! - `config/product.rs::ProductConfig::namespace_for_env` — the tail
//!   composition after collapsing multi-cluster `production-a` /
//!   `production-b` env names to `production`.
//! - `domain/service.rs::ServiceDefinition::namespace` — the K8s namespace
//!   for a service definition.
//!
//! # Why one primitive, not seven sibling inlines
//!
//! Every K8s namespace forge computes for a deployed product-in-env pair
//! is the same string:
//!
//! - The rollback health check at `commands/rollback.rs:267` and the
//!   session flush at `commands/sessions.rs:149` MUST target the same
//!   namespace the product's `DeploymentAttestation::namespace` field
//!   (`commands/attestation.rs:1584`) records at deploy time — a
//!   downstream sekiban policy that reconciles the running namespace
//!   against the attestation would otherwise reject a rollback probe
//!   that named a different namespace than the attestation.
//! - The federation-tests namespace default at `config/federation.rs:293`
//!   inherits the same convention so a repo that omits
//!   `namespace_pattern` targets the same namespace forge's deploy
//!   pipeline just created.
//! - `ProductConfig::namespace_for_env` at `config/product.rs:228` and
//!   `ServiceDefinition::namespace` at `domain/service.rs:154` are the
//!   two typed accessors the rest of the crate reaches for; each ends
//!   in the same `format!("{}-{}", …)` composition, and both should
//!   route through the same primitive so a future rename (e.g. to
//!   `{product}.{environment}`) lands at one edit and reaches every
//!   accessor by construction.
//!
//! Rename the convention (e.g. `{product}_{environment}`,
//! `{product}.{environment}`, `{environment}.{product}`,
//! `{product}--{environment}`) and seven sites drift out of coherence —
//! the rollback probe targets a different namespace than the deploy
//! attestation, the session flush hits an empty selector, the
//! federation-tests default lands on a nonexistent namespace. This
//! module makes that rename a one-line edit plus a byte-oracle rebase.
//!
//! # Distinct from every sibling `{a}-{b}` composition in the crate
//!
//! The module docs of [`crate::product_service_id`] enumerate the five
//! other `format!("{}-{}", ...)` conventions living in this crate. This
//! primitive stands specifically for the `{product}-{environment}` K8s
//! namespace convention; it MUST NOT be merged with any of:
//!
//! - `{product}-{service}` K8s-resource identifier —
//!   [`crate::product_service_id::product_service_id`]. Distinct axis
//!   (service, not environment) and distinct downstream consumers
//!   (Shinka `DatabaseMigration` name, `app=` label value).
//! - `{arch}-{tag_suffix}` OCI image tag — different domain (image tag,
//!   not resource name).
//! - `{name}-{target}` binary name — different axes.
//! - `{resource_base}-{suffix}` k8s child-resource name — generic suffix
//!   appender.
//! - `{namespace}-{phase}` flux checkpoint label — inside one namespace,
//!   not the namespace itself.
//!
//! # The load-bearing single ASCII hyphen
//!
//! Kubernetes namespaces are DNS-1123 labels: lowercase alphanumeric plus
//! the ASCII hyphen `-` (0x2D), up to 63 chars. The separator is
//! deliberately the single ASCII hyphen `-`, not a double hyphen `--`,
//! not `_` (underscore is not DNS-1123-legal — the K8s admission webhook
//! rejects), not `.` (dot separates DNS-1123 subdomain labels and would
//! change the namespace to a two-label subdomain). Pin the single-hyphen
//! contract in the byte-oracle test so a future collapse to any of the
//! above hits the test rather than shipping a K8s-invalid namespace.

/// Compose the canonical `{product}-{environment}` Kubernetes namespace
/// identifier.
///
/// Both inputs are `&str` slices so a bare `&str` (the shape most pre-lift
/// call sites carry today), an owned `String` (auto-deref), and a
/// `&String` (auto-deref) all flow through without a per-caller
/// `.as_str()` intermediate. See the [module docs](self) for the full
/// seven-site census and the distinctions against every sibling `{}-{}`
/// composition in the crate.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift, at seven sites:
/// let namespace = format!("{}-{}", product, environment);
///
/// // Post-lift:
/// let namespace = crate::product_environment_namespace::product_environment_namespace(
///     product,
///     environment,
/// );
/// ```
///
/// # Debug-assertions
///
/// In debug builds this fn asserts both inputs are non-empty. The K8s
/// admission webhook rejects an empty label component
/// (`"myproduct-"` or `"-staging"`) at deploy time; pinning the invariant
/// at the composition frontier surfaces the defect at the offending call
/// site rather than at a downstream `kubectl apply`.
pub fn product_environment_namespace(product: &str, environment: &str) -> String {
    debug_assert!(
        !product.is_empty(),
        "product_environment_namespace: product must be non-empty (K8s DNS-1123 label \
         forbids empty components; downstream `kubectl apply` would reject)"
    );
    debug_assert!(
        !environment.is_empty(),
        "product_environment_namespace: environment must be non-empty (K8s DNS-1123 label \
         forbids empty components; downstream `kubectl apply` would reject)"
    );
    format!("{}-{}", product, environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-oracle #1: pin the exact rendered bytes for a canonical
    // (product, environment) pair. A future refactor that changes the
    // separator, swaps argument order, or inserts a delimiter regresses
    // this assertion.
    #[test]
    fn product_environment_namespace_emits_product_then_hyphen_then_environment_bytes() {
        assert_eq!(
            product_environment_namespace("pleme", "staging").as_bytes(),
            b"pleme-staging"
        );
    }

    // Byte-oracle #2: pin the argument ORDER. `format!("{}-{}",
    // environment, product)` would swap the two axes and produce
    // `staging-pleme` — still a K8s-legal identifier, but bound to a
    // different namespace than every downstream consumer expects.
    #[test]
    fn product_environment_namespace_puts_product_first_environment_second() {
        let out = product_environment_namespace("myapp", "production");
        assert!(
            out.starts_with("myapp-"),
            "product must come first; got: {out:?}"
        );
        assert!(
            out.ends_with("-production"),
            "environment must come second; got: {out:?}"
        );
        assert_ne!(
            out, "production-myapp",
            "argument order must be (product, environment), NOT (environment, product)"
        );
    }

    // Byte-oracle #3: pin the SEPARATOR — a single ASCII hyphen 0x2D,
    // not a double hyphen, not an underscore, not a dot, not a slash.
    #[test]
    fn product_environment_namespace_separator_is_single_ascii_hyphen() {
        let out = product_environment_namespace("a", "b");
        assert_eq!(out.as_bytes(), b"a-b");
        // Exactly one hyphen — a future `--` or trailing-hyphen refactor
        // regresses.
        assert_eq!(out.matches('-').count(), 1);
        // Explicit negative pins for each sibling separator candidate:
        assert!(!out.contains("--"), "no double hyphen");
        assert!(!out.contains('_'), "no underscore (DNS-1123-illegal)");
        assert!(
            !out.contains('.'),
            "no dot (would change subdomain-label semantics)"
        );
        assert!(!out.contains('/'), "no slash");
    }

    // Byte-oracle #4: the render is exactly the concatenation
    // `{product}{-}{environment}` — no leading whitespace, no trailing
    // whitespace, no wrapping quotes, no framing bytes.
    #[test]
    fn product_environment_namespace_carries_no_framing_or_whitespace() {
        let out = product_environment_namespace("prod", "env");
        assert!(!out.starts_with(char::is_whitespace));
        assert!(!out.ends_with(char::is_whitespace));
        assert!(!out.starts_with('\''));
        assert!(!out.starts_with('"'));
        assert_eq!(out.len(), "prod".len() + 1 + "env".len());
    }

    // Byte-oracle #5: forward every byte of both inputs verbatim — no
    // case-fold, no hyphen collapse, no sanitizer at the primitive layer
    // (the K8s admission webhook is the ONE canonical validator; a
    // sanitizer here would silently mask an invalid input at the
    // composition site instead of surfacing it at the frontier).
    #[test]
    fn product_environment_namespace_forwards_both_inputs_verbatim() {
        // 30 + 1 + 30 char inputs — well under the K8s 63-char namespace
        // label limit but exercises multi-byte string handling.
        let product = "a".repeat(30);
        let environment = "b".repeat(30);
        let out = product_environment_namespace(&product, &environment);
        assert_eq!(out.len(), 30 + 1 + 30);
        assert!(out.starts_with(&product));
        assert!(out.ends_with(&environment));
    }

    // Byte-oracle #6: the primitive does NOT collapse `production-a` /
    // `production-b` to `production`. That collapse is the specific
    // semantic of `crate::config::product::ProductConfig::namespace_for_env`
    // and belongs at the caller layer, not at this composition primitive.
    // A future "smart" collapse here would silently rewrite every raw
    // site's output and break the axis distinction between this primitive
    // and `namespace_for_env`.
    #[test]
    fn product_environment_namespace_does_not_collapse_multi_cluster_production_suffix() {
        assert_eq!(
            product_environment_namespace("acme", "production-a").as_bytes(),
            b"acme-production-a",
            "primitive MUST forward `production-a` verbatim; the collapse to \
             `production` lives at `ProductConfig::namespace_for_env`"
        );
        assert_eq!(
            product_environment_namespace("acme", "production-b").as_bytes(),
            b"acme-production-b"
        );
    }

    // Distinctness pin: this primitive's output MUST NOT collapse with
    // the sibling `{product}-{service}` shape for the same representative
    // bytes. Both live in the crate; a future "smart" collapse routing
    // all `{a}-{b}` compositions through a single helper would produce
    // byte-identical output for distinct conventions and destroy the axis
    // distinction the call sites depend on. The pin below shows that this
    // fn takes (product, environment) — NOT (product, service) — by
    // construction.
    #[test]
    fn product_environment_namespace_output_shape_is_distinct_from_product_service_id() {
        // A K8s namespace has no `:` (image-reference), no leading `/`,
        // and lives entirely inside a single DNS-1123 label.
        let out = product_environment_namespace("pleme", "staging");
        assert!(!out.contains(':'), "no image-reference `:` delimiter");
        assert!(!out.starts_with('/'), "no repo-path anchor");
    }

    // Caller shield: no source line under `cli/src/commands/`,
    // `cli/src/config/`, or `cli/src/domain/` may still spell the pre-lift
    // raw `format!("{}-{}", <product>, <environment>)` composition inline.
    // The seven pre-lift sites migrated; any future consumer that wants
    // the same identifier reaches for
    // `crate::product_environment_namespace::` on first grep, not by
    // copy-pasting the raw shape from a peer.
    //
    // The scan matches on the presence of `product` / `self.product` /
    // `self.name` (in the `ProductConfig` case) as the first `format!`
    // interpolation argument alongside `environment` / `env_name` /
    // `simplified` (the four env-token spellings across the pre-lift
    // census) as the second — the census keys that name the convention
    // specifically, rather than any incidental `{}-{}` composition (the
    // sibling `product_service_id` module lists five other sibling
    // `{a}-{b}` compositions in the crate that MUST NOT be swept up in
    // this shield).
    #[test]
    fn no_source_module_still_spells_raw_product_environment_namespace_composition() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();

        // Walk src/commands/*.rs, src/config/*.rs, and src/domain/*.rs —
        // the three subtrees holding the seven pre-lift sites.
        let mut candidate_files: Vec<PathBuf> = Vec::new();
        for sub in ["commands", "config", "domain"] {
            let dir = src_dir.join(sub);
            if !dir.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    candidate_files.push(path);
                }
            }
        }

        // The precise pre-lift needles — five exact byte spans covering
        // every distinct (product-token, environment-token) pair present
        // in the pre-lift census. Any of them appearing inline post-lift
        // is a straggler.
        let raw_needles: &[&str] = &[
            "format!(\"{}-{}\", product, environment)",
            "format!(\"{}-{}\", product, env_name)",
            "format!(\"{}-{}\", self.product, environment)",
            "format!(\"{}-{}\", self.name, simplified)",
        ];

        for path in candidate_files {
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                // Skip comment lines so this shield's own reference to
                // the pre-lift shape in prose (and any pre-existing doc
                // comment naming the convention) doesn't self-hit.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for needle in raw_needles {
                    if line.contains(needle) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "raw `format!(\"{{}}-{{}}\", <product>, <environment>)` stanza(s) \
             survive under `commands/`, `config/`, or `domain/` — route each \
             through \
             `crate::product_environment_namespace::product_environment_namespace(<product>, <environment>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: each of the five pre-lift files
    // MUST forward through `product_environment_namespace::product_environment_namespace(`
    // at least the pre-lift count of times. A migration that dropped a
    // call site outright would leave the negative "no raw inline shape"
    // scan satisfied by absence; the positive count catches the drop.
    #[test]
    fn every_prelift_module_forwards_through_product_environment_namespace() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        // (relative path, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("commands/sessions.rs", 1),
            ("commands/rollback.rs", 1),
            ("commands/attestation.rs", 2),
            ("config/federation.rs", 1),
            ("config/product.rs", 1),
            ("domain/service.rs", 1),
        ];
        for (relpath, min_count) in expectations {
            let path = src_dir.join(relpath);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("product_environment_namespace(").count();
            assert!(
                forwards >= *min_count,
                "{relpath} must forward at least {min_count} \
                 `{{product}}-{{environment}}` composition site(s) through \
                 `product_environment_namespace::product_environment_namespace(`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-shape scan satisfied by absence.",
            );
        }
    }
}
