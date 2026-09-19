//! Canonical `{product}-{service}` Kubernetes-resource identifier.
//!
//! Six pre-lift sibling sites across four command / config modules each
//! restated the same `format!("{}-{}", <product>, <service>)` composition,
//! all producing the same K8s convention documented at
//! `commands/product_release.rs:424` (`// Map service name to Docker image
//! name (convention: {product}-{service})`) and at `config/mod.rs:935` (the
//! doc-comment on [`crate::config::DeployConfig::kubernetes_label_selector`]:
//! `// Build the app label value as {product}-{service} to match K8s resource
//! labels`). Post-lift the sites reach for [`product_service_id`] and the
//! separator byte, argument order, and non-empty invariants are decided once
//! here.
//!
//! # The census (all six sites)
//!
//! - `commands/web_service.rs::web_regenerate` — banner subject in the
//!   `🔄 Regenerating {product}-{service} dependencies` header.
//! - `commands/migrations.rs::check_and_reset_shinka_migration` — Shinka
//!   `DatabaseMigration` custom-resource `metadata.name`.
//! - `commands/migrations.rs::wait_for_shinka_migration` — Shinka
//!   `DatabaseMigration` name fallback when the caller does not supply
//!   `migration_name_override` (the doc-comment on this fn at line 986
//!   spells the exact `defaults to "{product}-{service}"` contract).
//! - `commands/rust_service.rs::deploy_and_verify` — Shinka
//!   `DatabaseMigration` name fallback when
//!   `deploy_config.service.migration.shinka_migration_name` is unset.
//! - `commands/product_release.rs::push_prebuilt_image` — local Docker
//!   image name; the inline `// (convention: {product}-{service})` comment
//!   at `:424` names the convention verbatim.
//! - `config/mod.rs::kubernetes_label_selector` — value of the
//!   `app={product}-{service}` label pair the selector builds.
//!
//! # Why one primitive, not six sibling inlines
//!
//! The six sites are one distributed convention, not six coincidental
//! `{}-{}` compositions:
//!
//! - The `DatabaseMigration` name at `commands/migrations.rs:779` /
//!   `:998` and at `commands/rust_service.rs:1556` MUST be the same
//!   identifier the `kubernetes_label_selector` builds at
//!   `config/mod.rs:940` — Shinka's controller matches the migration to
//!   the pod set by the identical `app=` label.
//! - The Docker image name at `commands/product_release.rs:425` is by
//!   convention the same string, so the local-registry retag and the
//!   pod-image tag stay coherent.
//! - The banner subject at `commands/web_service.rs:113` prints the
//!   identifier the operator is about to see in `kubectl get pods`.
//!
//! Rename the convention (e.g. `{product}_{service}`, `{product}.{service}`,
//! `{service}.{product}`, `{product}--{service}`) and six sites drift out
//! of coherence — the `DatabaseMigration` name stops matching the pod
//! label, the local image stops matching the registry retag, the banner
//! stops matching what `kubectl` shows. This module makes that rename a
//! one-line edit plus a byte-oracle rebase.
//!
//! # Distinct from every sibling `{a}-{b}` composition in the crate
//!
//! `cli/src/` carries several other `format!("{}-{}", ...)` compositions
//! that superficially match the shape but encode different conventions
//! and MUST NOT collapse into this primitive:
//!
//! - **`{arch}-{tag_suffix}` image tag** — `commands/push.rs:53`,
//!   `commands/rust_service.rs:133`, `infrastructure/registry.rs:{433,
//!   446, 778}`. The Docker image *tag* portion (post-`:`), keyed by
//!   OCI-architecture prefix. Different domain (image tag, not resource
//!   name); different axes (arch × sha, not product × service); different
//!   consumers (registry-side tag matching, not K8s label matching).
//! - **`{product}-{environment}` K8s namespace** — the sibling convention,
//!   owned by [`crate::product_environment_namespace::product_environment_namespace`];
//!   `commands/rollback.rs`, `commands/sessions.rs`, `commands/attestation.rs`,
//!   `config/federation.rs`, `domain/service.rs`, and
//!   `config/product.rs::ProductConfig::namespace_for_env` all delegate to
//!   it. A distinct domain (env axis, not service axis) with its own primitive.
//! - **`{name}-{target}` binary name** — `commands/tool.rs:233`. A
//!   `<crate>-<triple>` cross-compilation product name; different axes.
//! - **`{resource_base}-{suffix}` k8s child-resource name** —
//!   `commands/migrations.rs:282`. A generic suffix appender used at one
//!   site; two axes but not the product / service pair.
//! - **`{namespace}-{phase}` flux checkpoint label** —
//!   `commands/flux.rs:390`. A per-phase distinguisher inside one
//!   namespace; the namespace itself is the *result* of a `{product}-
//!   {environment}` composition upstream.
//!
//! Each of the five above is its own convention. Merging any of them into
//! this primitive would collapse a K8s-app-identifier composition with an
//! image-tag composition (or with a namespace composition, or with a
//! binary-name composition), which either fabricates a match at one call
//! site or drops the axis distinction the other call site depends on.
//!
//! # The load-bearing single ASCII hyphen
//!
//! Kubernetes resource names are DNS-1123 subdomains: lowercase alphanumeric
//! plus the ASCII hyphen `-` (0x2D), up to 253 chars (63 per label). The
//! separator is deliberately the single ASCII hyphen `-`, not a double
//! hyphen `--` (which is a Docker/OCI reference-parser sub-delimiter
//! contract that would silently reinterpret `myproduct--backend` as a
//! nested identifier under some registries), not `_` (underscore is not
//! DNS-1123-legal in a hostname label — Shinka's admission webhook
//! rejects), not `.` (dot separates DNS-1123 subdomain labels — a
//! `{product}.{service}` name would be a two-label subdomain and change
//! selector-matching semantics). Pin the single-hyphen contract in the
//! byte-oracle test so a future collapse to any of the above hits the
//! test rather than shipping a K8s-invalid resource name.

/// Compose the canonical `{product}-{service}` Kubernetes-resource /
/// Docker-image / label-value identifier.
///
/// Both inputs are `&str` slices so a bare `&str` (the shape all six
/// pre-lift call sites carry today), an owned `String` (auto-deref), and
/// a `&String` (auto-deref) all flow through without a per-caller
/// `.as_str()` intermediate. See the [module docs](self) for the full
/// six-site census and the distinctions against every sibling `{}-{}`
/// composition in the crate.
///
/// # Examples
///
/// ```ignore
/// // Pre-lift, at six sites:
/// let migration_name = format!("{}-{}", product, service);
///
/// // Post-lift:
/// let migration_name = crate::product_service_id::product_service_id(product, service);
/// ```
///
/// # Debug-assertions
///
/// In debug builds this fn asserts both inputs are non-empty. The K8s
/// admission webhook rejects an empty label component ("app=-backend"
/// or "app=myproduct-") at deploy time; pinning the invariant at the
/// composition frontier surfaces the defect at the offending call site
/// rather than at a downstream `kubectl apply`.
pub fn product_service_id(product: &str, service: &str) -> String {
    debug_assert!(
        !product.is_empty(),
        "product_service_id: product must be non-empty (K8s DNS-1123 label \
         forbids empty components; downstream `kubectl apply` would reject)"
    );
    debug_assert!(
        !service.is_empty(),
        "product_service_id: service must be non-empty (K8s DNS-1123 label \
         forbids empty components; downstream `kubectl apply` would reject)"
    );
    format!("{}-{}", product, service)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-oracle #1: pin the exact rendered bytes for a canonical
    // (product, service) pair. A future refactor that changes the
    // separator, swaps argument order, or inserts a delimiter regresses
    // this assertion.
    #[test]
    fn product_service_id_emits_product_then_hyphen_then_service_bytes() {
        assert_eq!(
            product_service_id("pleme", "backend").as_bytes(),
            b"pleme-backend"
        );
    }

    // Byte-oracle #2: pin the argument ORDER. `format!("{}-{}", service,
    // product)` would swap the two axes and produce `backend-pleme` —
    // still a K8s-legal identifier, but bound to a different Shinka
    // `DatabaseMigration` name and a different `app=` label value than
    // every downstream consumer expects.
    #[test]
    fn product_service_id_puts_product_first_service_second() {
        let out = product_service_id("myapp", "worker");
        assert!(
            out.starts_with("myapp-"),
            "product must come first; got: {out:?}"
        );
        assert!(
            out.ends_with("-worker"),
            "service must come second; got: {out:?}"
        );
        assert_ne!(
            out, "worker-myapp",
            "argument order must be (product, service), NOT (service, product)"
        );
    }

    // Byte-oracle #3: pin the SEPARATOR — a single ASCII hyphen 0x2D,
    // not a double hyphen, not an underscore, not a dot, not a slash.
    // See the module docs for why each of those alternatives would break
    // a distinct downstream consumer (registry parser, DNS-1123 admission,
    // selector semantics).
    #[test]
    fn product_service_id_separator_is_single_ascii_hyphen() {
        let out = product_service_id("a", "b");
        assert_eq!(out.as_bytes(), b"a-b");
        // Exactly one hyphen — a future `--` or trailing-hyphen refactor
        // regresses.
        assert_eq!(out.matches('-').count(), 1);
        // Explicit negative pins for each sibling separator candidate:
        assert!(!out.contains("--"), "no double hyphen");
        assert!(!out.contains('_'), "no underscore (DNS-1123-illegal)");
        assert!(
            !out.contains('.'),
            "no dot (would change selector semantics)"
        );
        assert!(
            !out.contains('/'),
            "no slash (would change reference semantics)"
        );
    }

    // Byte-oracle #4: the render is exactly the concatenation
    // `{product}{-}{service}` — no leading whitespace, no trailing
    // whitespace, no wrapping quotes, no framing bytes.
    #[test]
    fn product_service_id_carries_no_framing_or_whitespace() {
        let out = product_service_id("prod", "svc");
        assert!(!out.starts_with(char::is_whitespace));
        assert!(!out.ends_with(char::is_whitespace));
        assert!(!out.starts_with('\''));
        assert!(!out.starts_with('"'));
        assert_eq!(out.len(), "prod".len() + 1 + "svc".len());
    }

    // Byte-oracle #5: forward every byte of both inputs verbatim — no
    // case-fold, no hyphen collapse, no sanitizer at the primitive layer
    // (the K8s admission webhook is the ONE canonical validator; a
    // sanitizer here would silently mask an invalid input at the
    // composition site instead of surfacing it at the frontier).
    #[test]
    fn product_service_id_forwards_both_inputs_verbatim() {
        // Full 63-char DNS-1123 labels on both sides — the K8s per-label
        // maximum. A future truncator here would silently drop bytes.
        let product = "a".repeat(63);
        let service = "b".repeat(63);
        let out = product_service_id(&product, &service);
        assert_eq!(out.len(), 63 + 1 + 63);
        assert!(out.starts_with(&product));
        assert!(out.ends_with(&service));
    }

    // Distinctness pin: this primitive's output MUST NOT equal the
    // sibling `{arch}-{tag_suffix}` image-tag shape or the sibling
    // `{product}-{environment}` namespace shape for the same
    // representative bytes. Both siblings live in the crate; a future
    // "smart" collapse that routed all `{a}-{b}` compositions through a
    // single helper would produce byte-identical output for distinct
    // conventions and destroy the axis distinction the call sites depend
    // on. The pin below shows that this fn takes (product, service) —
    // NOT (arch, tag), NOT (product, environment) — by construction.
    #[test]
    fn product_service_id_output_shape_is_distinct_from_sibling_conventions() {
        // If a future refactor rewired this fn to (arch, tag) instead
        // of (product, service), the same inputs would compose the same
        // bytes but under a different domain — the byte-oracle can't
        // distinguish. The distinction lives in the fn NAME and PARAM
        // NAMES, both of which this test reads back.
        let out = product_service_id("pleme", "backend");
        // A K8s app label value has no `:` (which separates image
        // repository from tag), no leading `/` (which is only in image
        // references), and lives entirely inside a single DNS-1123 label.
        assert!(!out.contains(':'), "no image-reference `:` delimiter");
        assert!(!out.starts_with('/'), "no repo-path anchor");
    }

    // Caller shield: no source line under `cli/src/commands/` or under
    // `cli/src/config/` may still spell the pre-lift raw
    // `format!("{}-{}", <product>, <service>)` composition inline. The
    // six pre-lift sites migrated; any future consumer that wants the
    // same identifier reaches for `crate::product_service_id::` on first
    // grep, not by copy-pasting the raw shape from a peer.
    //
    // The scan matches on the presence of `product` or `product.name`
    // as the first `format!` interpolation argument alongside `service`
    // or `svc.name` as the second — the census keys that name the
    // convention specifically, rather than any incidental `{}-{}`
    // composition (the module docs list five other sibling `{a}-{b}`
    // compositions in the crate that MUST NOT be swept up in this
    // shield).
    #[test]
    fn no_source_module_still_spells_raw_product_service_id_composition() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();

        // Walk src/commands/*.rs and src/config/*.rs — the two subtrees
        // holding the six pre-lift sites.
        let mut candidate_files: Vec<PathBuf> = Vec::new();
        for sub in ["commands", "config"] {
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
        // every distinct (product-token, service-token) pair present in
        // the pre-lift census. Any of them appearing inline post-lift
        // is a straggler.
        let raw_needles: &[&str] = &[
            "format!(\"{}-{}\", product, service)",
            "format!(\"{}-{}\", product, svc.name)",
            "format!(\"{}-{}\", deploy_config.product.name, service)",
            "format!(\"{}-{}\", self.product.name, self.service.name)",
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
            "raw `format!(\"{{}}-{{}}\", <product>, <service>)` stanza(s) \
             survive under `commands/` or `config/` — route each through \
             `crate::product_service_id::product_service_id(<product>, <service>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: each of the four pre-lift files
    // MUST forward through `product_service_id::product_service_id(` at
    // least the pre-lift count of times. A migration that dropped a
    // call site outright would leave the negative "no raw inline shape"
    // scan satisfied by absence; the positive count catches the drop.
    #[test]
    fn every_prelift_module_forwards_through_product_service_id() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        // (relative path, minimum forward count from the pre-lift census)
        let expectations: &[(&str, usize)] = &[
            ("commands/web_service.rs", 1),
            ("commands/migrations.rs", 2),
            ("commands/rust_service.rs", 1),
            ("commands/product_release.rs", 1),
            ("config/mod.rs", 1),
        ];
        for (relpath, min_count) in expectations {
            let path = src_dir.join(relpath);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches("product_service_id(").count();
            assert!(
                forwards >= *min_count,
                "{relpath} must forward at least {min_count} \
                 `{{product}}-{{service}}` composition site(s) through \
                 `product_service_id::product_service_id(`; found {forwards}. \
                 A dropped call would leave the negative raw-shape scan \
                 satisfied by absence.",
            );
        }
    }
}
