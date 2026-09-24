//! `<repo_root>/{product-dir}/{service_path}` filesystem-string primitive
//! — the two-line composition that resolves a service's on-disk directory
//! under a product tree and projects it to an owned lossy-UTF-8 [`String`]
//! for `--service-dir` argv forwarding.
//!
//! # Pre-lift census — two sibling composition sites
//!
//! Two pre-lift sites each spelled the same two-line stanza verbatim
//! immediately before handing the `service_dir: String` to
//! [`crate::commands::orchestrate_release_deploy_only_argv::orchestrate_release_deploy_only_single_env_argv`]:
//!
//! 1. `commands/product_release.rs::execute` (~L705-707) — Phase-2 deploy
//!    loop. The pre-lift stanza is:
//!    ```ignore
//!    let product_dir =
//!        crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
//!    let service_dir = crate::repo::path_to_string_lossy(&product_dir.join(&svc.path));
//!    ```
//! 2. `commands/rollback.rs::execute` (~L228-230) — Deploy-previous-tags
//!    loop. The pre-lift stanza is byte-identical except the service-path
//!    binding is `&entry.path` (a field of the module-local `RollbackEntry`
//!    plan struct) rather than `&svc.path` (a field of the
//!    `ProductServiceConfig` sourced from `deploy.yaml`).
//!
//! Both stanzas bind an intermediate `product_dir: PathBuf` that is used
//! at exactly one place — the `product_dir.join(service_path)` on the
//! second line — and then dropped. Post-lift the intermediate disappears
//! at both callers, and the fused composition lives at ONE typed body.
//!
//! # Peer to `crate::product_environment_namespace`
//!
//! Sibling of [`crate::product_environment_namespace::product_environment_namespace`]
//! on the product-scoped-identifier surface: that primitive owns the
//! `{product}-{environment}` K8s namespace composition; this one owns the
//! `<repo_root>/{product-dir}/{service_path}` filesystem-string
//! composition. Both take `&str` args (matching the pre-lift call sites
//! that pass owned `String` fields by borrow) so a bare `&str`, an owned
//! `String` (auto-deref), and a `&String` (auto-deref) all flow through
//! without a per-caller `.as_str()` intermediate.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `resolve_product_dir` +
//! `path_to_string_lossy` fusion lives at ONE construction surface so a
//! future rename of the product-tree layout (a promotion of the standalone
//! deploy.yaml probe, a swap of the monorepo `pkgs/products/{product}`
//! prefix, a change from `.to_string_lossy().into_owned()` to
//! `.to_str().unwrap().to_string()` at the string-projection layer)
//! reaches both `orchestrate-release --deploy-only` self-re-invocation
//! sites by construction rather than through a per-caller edit.

/// Compose the `<product-dir>/<service_path>` filesystem path under the
/// caller-provided repository root and project it to an owned lossy-UTF-8
/// [`String`] — the exact byte shape both pre-lift consumer sites bind
/// into their `service_dir` local before handing to
/// [`crate::commands::orchestrate_release_deploy_only_argv::orchestrate_release_deploy_only_single_env_argv`].
///
/// The product-dir resolution delegates to
/// [`crate::config::resolve_product_dir`], so the standalone-repo
/// deploy.yaml probe and the monorepo `pkgs/products/{product}` fallback
/// are both inherited unchanged. The string projection delegates to
/// [`crate::repo::path_to_string_lossy`], so the one-alloc
/// `.to_string_lossy().into_owned()` canonical shape is preserved.
///
/// # Pre-lift shape
///
/// ```ignore
/// let product_dir =
///     crate::config::resolve_product_dir(std::path::Path::new(&repo_root), &product);
/// let service_dir = crate::repo::path_to_string_lossy(&product_dir.join(&<entry|svc>.path));
/// ```
///
/// # Post-lift shape
///
/// ```ignore
/// let service_dir = crate::product_service_dir_string::product_service_dir_string(
///     &repo_root,
///     &product,
///     &<entry|svc>.path,
/// );
/// ```
pub fn product_service_dir_string(repo_root: &str, product: &str, service_path: &str) -> String {
    let product_dir = crate::config::resolve_product_dir(std::path::Path::new(repo_root), product);
    crate::repo::path_to_string_lossy(&product_dir.join(service_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Byte-oracle #1: with no root-level `deploy.yaml`, the primitive
    // returns `<repo_root>/pkgs/products/<product>/<service_path>` —
    // the monorepo fallback branch of `resolve_product_dir` composed
    // with the caller-supplied `service_path` tail. Pin the exact bytes
    // so a future refactor that (a) dropped the `pkgs/products` prefix,
    // (b) swapped the argument order, or (c) inserted a delimiter flips
    // this assertion.
    #[test]
    fn product_service_dir_string_monorepo_fallback_composes_pkgs_products_product_service_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root = tmp.path().to_string_lossy().into_owned();
        let out = product_service_dir_string(&repo_root, "acme", "services/rust/backend");
        let expected: PathBuf = PathBuf::from(&repo_root)
            .join("pkgs")
            .join("products")
            .join("acme")
            .join("services")
            .join("rust")
            .join("backend");
        assert_eq!(out, expected.to_string_lossy());
    }

    // Byte-oracle #2: with a root-level `deploy.yaml` whose `name:` field
    // matches the product argument, `resolve_product_dir` short-circuits
    // to `repo_root` itself (the standalone-repo layout), so the primitive
    // returns `<repo_root>/<service_path>` without the `pkgs/products/…`
    // prefix. Pin the standalone branch so a future refactor that dropped
    // the deploy.yaml probe (or inverted its match condition) flips this
    // assertion rather than silently changing the resolved path.
    #[test]
    fn product_service_dir_string_standalone_repo_short_circuits_pkgs_products_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("deploy.yaml"), "name: acme\n").expect("write deploy.yaml");
        let repo_root = tmp.path().to_string_lossy().into_owned();
        let out = product_service_dir_string(&repo_root, "acme", "web");
        let expected = PathBuf::from(&repo_root).join("web");
        assert_eq!(out, expected.to_string_lossy());
        assert!(
            !out.contains("pkgs/products"),
            "standalone-repo branch must NOT prepend `pkgs/products/…`; got: {out:?}"
        );
    }

    // Byte-oracle #3: the primitive returns an OWNED [`String`], not a
    // borrowed `&str` bound to the caller's arg lifetimes. Both pre-lift
    // consumers bind the result into a local `let service_dir` and then
    // hand `&service_dir` to `orchestrate_release_deploy_only_single_env_argv`
    // slots that must outlive the arg — an owned return is the only shape
    // that composes.
    #[test]
    fn product_service_dir_string_returns_owned_string() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root = tmp.path().to_string_lossy().into_owned();
        let owned: String = product_service_dir_string(&repo_root, "acme", "svc");
        assert!(owned.ends_with("svc"));
        drop(tmp);
        // `owned` still valid — the returned String outlives its inputs.
        assert!(owned.ends_with("svc"));
    }

    // Argument-order pin: the primitive takes `(repo_root, product,
    // service_path)` — NOT `(product, repo_root, service_path)` or any
    // other permutation. Both pre-lift consumers spell the args in this
    // order at the composition site; a swap here would produce a bogus
    // path that begins with the product name rather than the repo root.
    #[test]
    fn product_service_dir_string_argument_order_is_repo_root_product_service_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root = tmp.path().to_string_lossy().into_owned();
        let out = product_service_dir_string(&repo_root, "acme", "web");
        assert!(
            out.starts_with(&repo_root),
            "output must begin with the repo_root prefix — got: {out:?}"
        );
        assert!(
            out.ends_with("web"),
            "output must end with the service_path tail — got: {out:?}"
        );
    }

    // Composition pin: the primitive is BYTE-IDENTICAL to the pre-lift
    // two-line stanza. Rebuild the pre-lift shape here and compare — a
    // future drift in either delegate (`resolve_product_dir` or
    // `path_to_string_lossy`) that broke the byte-for-byte equivalence
    // would flip this assertion rather than silently diverging one of
    // the two consumers from the other.
    #[test]
    fn product_service_dir_string_matches_pre_lift_two_line_stanza_byte_for_byte() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_root = tmp.path().to_string_lossy().into_owned();
        for (product, service_path) in [
            ("acme", "services/rust/backend"),
            ("myapp", "web"),
            ("pleme", "services/typescript/gateway"),
        ] {
            let via_primitive = product_service_dir_string(&repo_root, product, service_path);
            let via_prelift = {
                let product_dir =
                    crate::config::resolve_product_dir(std::path::Path::new(&repo_root), product);
                crate::repo::path_to_string_lossy(&product_dir.join(service_path))
            };
            assert_eq!(
                via_primitive, via_prelift,
                "primitive must be byte-identical to the pre-lift two-line stanza \
                 for (product={product}, service_path={service_path})",
            );
        }
    }

    // Caller shield (negative half): neither the two original consumer
    // files (`commands/{product_release,rollback}.rs`) nor the fused
    // dispatch module that supersedes them may spell the pre-lift raw
    // `path_to_string_lossy(&product_dir.join(` fusion inline. The two
    // pre-lift sites migrated onto [`product_service_dir_string`] (via
    // the fused
    // `commands/orchestrate_release_deploy_only_dispatch::dispatch_orchestrate_release_deploy_only_single_env`
    // adapter that now owns the sole caller); the original files are
    // retained in this scan to prevent a re-inlining regression. Any
    // future consumer that wants the same fused composition reaches
    // for the primitive on first grep, not by copy-pasting the
    // two-line stanza from a peer. Doc-comment mentions (`//! …`) are
    // exempt via the leading-`//` filter — they cite the shape, they
    // do not compose it.
    //
    // Scoping to the pre-tests module body via
    // [`crate::test_support::module_body_before_first_cfg_test`] keeps
    // both this shield's own docstring mention above AND any test-support
    // reference to the pre-lift fusion out of the count.
    #[test]
    fn no_prelift_caller_still_spells_raw_product_dir_join_path_to_string_lossy_fusion() {
        const NEEDLE: &str = "path_to_string_lossy(&product_dir.join(";
        const CALLERS: &[(&str, &str)] = &[
            (
                include_str!("commands/product_release.rs"),
                "commands/product_release.rs",
            ),
            (include_str!("commands/rollback.rs"), "commands/rollback.rs"),
            (
                include_str!("commands/orchestrate_release_deploy_only_dispatch.rs"),
                "commands/orchestrate_release_deploy_only_dispatch.rs",
            ),
        ];
        for (source, module_path) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            let hits = crate::test_support::code_line_hits(body, NEEDLE);
            assert!(
                hits.is_empty(),
                "{module_path} pre-tests body must NOT spell the raw \
                 `{NEEDLE}...)` two-line fusion any more — route each \
                 through \
                 `crate::product_service_dir_string::product_service_dir_string(&repo_root, &product, &<entry|svc>.path)` \
                 instead. Offending line(s): {hits:#?}"
            );
        }
    }

    // Caller shield (positive half): the fused dispatch module that now
    // owns the sole deploy-only self-re-invoke caller MUST forward
    // through [`product_service_dir_string`] at least once, so a
    // migration that dropped its `product_service_dir_string(` call
    // outright leaves the negative "no raw fusion" scan trivially
    // satisfied by absence but the positive count still fails.
    //
    // Pre-lift the two Phase-2 / Deploy-previous-tags loop sites in
    // `commands/{product_release,rollback}.rs::execute` each called
    // this primitive directly. Post-lift both sites route through
    // `commands/orchestrate_release_deploy_only_dispatch::dispatch_orchestrate_release_deploy_only_single_env`,
    // which owns the sole call to this primitive from the deploy-only
    // self-re-invoke pipeline. Mirrors the sibling
    // `every_prelift_module_forwards_through_product_environment_namespace`
    // shield in [`crate::product_environment_namespace`].
    #[test]
    fn every_prelift_caller_forwards_through_product_service_dir_string() {
        const NEEDLE: &str = "product_service_dir_string(";
        const CALLERS: &[(&str, &str, usize)] = &[(
            include_str!("commands/orchestrate_release_deploy_only_dispatch.rs"),
            "commands/orchestrate_release_deploy_only_dispatch.rs",
            1,
        )];
        for (source, module_path, min_count) in CALLERS {
            let body = crate::test_support::module_body_before_first_cfg_test(source, module_path);
            let hits = crate::test_support::code_line_hits(body, NEEDLE);
            assert!(
                hits.len() >= *min_count,
                "{module_path} pre-tests body must forward at least \
                 {min_count} `<product-dir>/<service_path>` fusion \
                 site(s) through `{NEEDLE}...)`; found {} hit(s). A \
                 dropped call would leave the negative raw-fusion scan \
                 satisfied by absence.",
                hits.len(),
            );
        }
    }
}
