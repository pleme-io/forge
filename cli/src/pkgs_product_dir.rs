//! `<repo_root>/pkgs/products/<product>` directory-path primitive —
//! the fixed-layout composition every consumer that hardcodes the
//! per-product source-tree location under a monorepo `pkgs/products/`
//! namespace shares.
//!
//! # Pre-lift census — four sibling composition sites
//!
//! Four pre-lift sites each restated
//! `repo_root.join("pkgs").join("products").join(<product>)` verbatim
//! before appending the caller-specific tail:
//!
//! 1. `commands/web_service.rs::web_regenerate` (~L116) —
//!    `service_dir = <repo_root>/pkgs/products/<product>/<service>`.
//!    Tail: `.join(&service)`. `<product>` and `<service>` are the
//!    command-arg `String`s.
//! 2. `commands/rust_service.rs` federation-tests release site
//!    (~L2513) — `service_dir =
//!    <repo_root>/pkgs/products/<product>/services/rust/<service>`.
//!    Tail: `.join("services").join("rust").join(&service)`.
//!    `<product>` is `&deploy_config.product.name`.
//! 3. `commands/rust_service.rs` federation-tests directory
//!    (~L2522) — `federation_tests_dir =
//!    <repo_root>/pkgs/products/<product>/tests/federation`.
//!    Tail: `.join("tests").join("federation")`. Same `<product>`
//!    binding as (2).
//! 4. `commands/rust_service.rs` federation-tests deploy.yaml
//!    rewrite site (~L2580) — `fed_product_dir =
//!    <repo_root>/pkgs/products/<product>`. No tail — the shared
//!    prefix IS the terminal path here.
//!
//! Every site composes the same three-segment
//! `<repo_root>/pkgs/products/<product>` prefix against a caller-provided
//! `repo_root: &Path` and a caller-provided product name. Post-lift the
//! prefix lives at ONE construction surface — [`pkgs_product_dir`] —
//! and each consumer forwards through it then `.join(...)`s its
//! caller-specific tail.
//!
//! # Distinct from the sibling `pkgs/platform/<component>` composition
//!
//! [`crate::hanabi_dir::hanabi_dir`] and
//! [`crate::bootstrap_dir::bootstrap_dir`] each compose
//! `<repo_root>/pkgs/platform/<component>` for a shared platform
//! component (BFF, bootstrap flake). This primitive composes
//! `<repo_root>/pkgs/products/<product>` for a per-product source
//! tree. The two shapes share the `<repo_root>/pkgs/<class>/<name>`
//! grammar but are distinct by `<class>` (`products` vs `platform`),
//! distinct in whether the `<name>` slot is a run-time argument
//! (products yes, platform closed enum), and distinct in semantics
//! (per-product source vs shared platform component).
//!
//! # Distinct from the sibling deploy-resolving accessor
//!
//! [`crate::config::resolve_product_dir`] composes the same
//! `<repo_root>/pkgs/products/<product>` shape BUT first probes for a
//! matching `<repo_root>/deploy.yaml` and returns `<repo_root>` in the
//! monorepo-root case. That accessor is the right choice for callers
//! that resolve "which directory holds the product's deploy.yaml,
//! whether monorepo-root or nested"; this primitive is the right
//! choice for callers that specifically want the fixed
//! `<repo_root>/pkgs/products/<product>` layout without the fallback.
//! The four pre-lift sites all hardcoded the fixed layout — the
//! federation-tests sub-tree lives at `pkgs/products/<product>/tests/
//! federation` unconditionally, and switching in the fallback would
//! silently break the monorepo case. Post-lift they still hardcode
//! the fixed layout; they just route the three-segment prefix through
//! one body.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `pkgs/products` prefix lives at
//! ONE construction surface so a future refinement (a rename of
//! `pkgs/products` to `products/`, a promotion to
//! `PathBuf::from(env!("PRODUCTS_DIR"))` for hermetic
//! Nix-derivation-pinned paths, a swap to a `<product>.pkgset`
//! namespace) lands in one place rather than at every consumer.
//! §VI.1 duplication-is-a-bug (PRIME DIRECTIVE): four identical
//! `.join("pkgs").join("products").join(...)` bodies past the
//! zero-duplication threshold, closed at the shared accessor.
//! §II.1 typed-entry: the `product` slot is a run-time `&str`, but the
//! `pkgs/products` slot pair is compile-time; a consumer cannot
//! silently rename `products` to `product` at one site and drift.

use std::path::{Path, PathBuf};

/// Compose the per-product directory path under a caller-provided
/// repository root: `<repo_root>/pkgs/products/<product>`.
///
/// The four consumer sites in
/// `commands/web_service.rs::web_regenerate` and
/// `commands/rust_service.rs`'s federation-tests release body each
/// spelled `repo_root.join("pkgs").join("products").join(<product>)`
/// pre-lift; post-lift they all forward through this function then
/// `.join(...)` their caller-specific tail.
///
/// # Byte shape
///
/// Returns
/// `repo_root.join("pkgs").join("products").join(product)` byte-for-
/// byte. The three-segment composition is preserved via chained
/// `.join(...)` calls, matching the pre-lift shape at every consumer.
/// The [`tests::test_pkgs_product_dir_matches_pre_lift_chained_joins`]
/// byte-oracle pins this equivalence.
///
/// # Ownership discipline
///
/// The returned [`PathBuf`] is heap-allocated and independent of the
/// input `repo_root` lifetime — a caller can drop `repo_root`
/// immediately after the call. Matches the pre-lift chained-`.join`
/// behavior at all four consumers.
pub fn pkgs_product_dir(repo_root: &Path, product: &str) -> PathBuf {
    repo_root.join("pkgs").join("products").join(product)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`pkgs_product_dir`] returns the pre-lift chained-
    /// `.join` composition. A future refactor that (a) swapped the
    /// `products` segment to `product` or `pkgset`, (b) dropped the
    /// `pkgs` middle segment, (c) reordered the three segments, or
    /// (d) added a trailing slash would flip this assertion.
    #[test]
    fn test_pkgs_product_dir_matches_pre_lift_chained_joins() {
        let repo_root = Path::new("/home/user/forge");
        let expected = repo_root.join("pkgs").join("products").join("myapp");
        assert_eq!(pkgs_product_dir(repo_root, "myapp"), expected);
        assert_eq!(
            pkgs_product_dir(repo_root, "myapp"),
            PathBuf::from("/home/user/forge/pkgs/products/myapp")
        );
    }

    /// Component-sequence pin: the returned [`PathBuf`] has exactly
    /// three appended components after the `<repo_root>` prefix —
    /// none of `pkgs`, `products`, and the product-name segment may
    /// collapse into another. A drift that fused `pkgs/products` into
    /// a single `pkgs-products` segment would fail here, as would a
    /// drift that dropped the product-name segment.
    #[test]
    fn test_pkgs_product_dir_appends_exactly_three_named_segments() {
        let repo_root = Path::new("/repo");
        let full = pkgs_product_dir(repo_root, "acme");
        let full_components: Vec<_> = full
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let root_components: Vec<_> = repo_root
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let appended: Vec<_> = full_components[root_components.len()..].to_vec();
        assert_eq!(
            appended,
            vec![
                "pkgs".to_string(),
                "products".to_string(),
                "acme".to_string()
            ],
            "pkgs_product_dir must append exactly the three-segment \
             `pkgs/products/<product>` tail — got {appended:?}"
        );
    }

    /// Ownership pin: the primitive returns an OWNED [`PathBuf`], not
    /// a borrowed `&Path` bound to the caller's `repo_root` lifetime.
    /// A future signature change that returned `&Path` would refuse
    /// every pre-lift consumer site, all of which bind the result
    /// into a local `let` and hand it to downstream `.join(...)` /
    /// `.exists()` / `resolve_deploy_yaml_path` calls that must
    /// outlive the arg.
    #[test]
    fn test_pkgs_product_dir_returns_owned_pathbuf() {
        let owned: PathBuf = pkgs_product_dir(Path::new("/x"), "svc");
        assert_eq!(owned, PathBuf::from("/x/pkgs/products/svc"));
    }

    /// Relative-root pin: a caller-provided relative `repo_root`
    /// composes a relative product path — the primitive does NOT
    /// silently absolutize. The pre-lift sites accept relative or
    /// absolute `repo_root` alike, and none spelled a
    /// `.canonicalize()` step, so the primitive stays as literal as
    /// the pre-lift chained `.join`.
    #[test]
    fn test_pkgs_product_dir_preserves_relative_root() {
        assert_eq!(
            pkgs_product_dir(Path::new("workspace"), "app"),
            PathBuf::from("workspace/pkgs/products/app")
        );
        assert_eq!(
            pkgs_product_dir(Path::new("."), "app"),
            PathBuf::from("./pkgs/products/app")
        );
    }

    /// Product-name slot pin: the `<product>` segment is the caller-
    /// provided `&str` verbatim, not transformed (no `.to_lowercase`,
    /// no `.replace('-', "_")`, no path-safe rewrite). All four
    /// pre-lift sites passed the product name unchanged; this
    /// assertion catches a drift that would insert a silent
    /// normalization at the primitive body.
    #[test]
    fn test_pkgs_product_dir_appends_product_verbatim() {
        assert_eq!(
            pkgs_product_dir(Path::new("/r"), "My-App_v2"),
            PathBuf::from("/r/pkgs/products/My-App_v2")
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may spell the pre-lift raw
    /// `.join("pkgs").join("products").join(...)` chained composition
    /// inline any more. The four pre-lift sites migrated; any future
    /// consumer that wants the same product-directory path reaches
    /// for [`pkgs_product_dir`] on first grep, not by copy-pasting
    /// the chained-`.join` literal.
    ///
    /// Scans by looking for a line that mentions BOTH `"pkgs"` and
    /// `"products"` as string literals — the pre-lift shape's two
    /// closed-segment anchors — and does not forward through the
    /// primitive. Comments (`//`, `///`, `//!`) and block-comment
    /// runs are skipped so a narrative aside can still mention the
    /// canonical form. Test-fixture literals in
    /// `commands/*.rs` (`.join("pkgs").join("products").join("foo")`
    /// under `#[cfg(test)]`) route through the primitive too so this
    /// shield covers them.
    #[test]
    fn no_command_module_still_spells_raw_pkgs_products_join_chain() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(StdPathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
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
                let mentions_pkgs = line.contains("\"pkgs\"");
                let mentions_products = line.contains("\"products\"");
                let forwards_through_primitive = line.contains("pkgs_product_dir(");
                if mentions_pkgs && mentions_products && !forwards_through_primitive {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `.join(\"pkgs\").join(\"products\").join(...)` chained \
             composition(s) survive under `commands/` — route each through \
             `crate::pkgs_product_dir::pkgs_product_dir(<repo_root>, <product>)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift modules that housed
    /// the four sites MUST forward through [`pkgs_product_dir`] at
    /// least the pre-lift count of times, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count
    /// still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_pkgs_product_dir() {
        use std::path::PathBuf as StdPathBuf;
        let commands_dir = StdPathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("web_service.rs", 1), ("rust_service.rs", 3)];
        let needle = "pkgs_product_dir(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 `pkgs/products/<product>` composition site(s) through \
                 `{needle}`; found {forwards}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
            );
        }
    }
}
