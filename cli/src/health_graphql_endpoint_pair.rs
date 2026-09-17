//! Health / GraphQL endpoint-pair composition primitive — the pre-lift
//! fused
//! `(format!("{}/health", <base>), format!("{}/graphql", <base>))`
//! two-line stanza that composes the `(health_endpoint,
//! graphql_endpoint)` tuple every post-deploy verification consumer
//! reaches for.
//!
//! # Duplication being lifted
//!
//! Three pre-lift sibling stanzas each spelled the same fused
//! `(format!("{base}/health", …), format!("{base}/graphql", …))`
//! two-line pair, diverging only on the base-URL composition:
//!
//! 1. `commands/post_deploy_verification.rs::get_product_endpoints`
//!    (~L502) — the `"production"` arm composed the pair against a
//!    bare `<product_domain>` base:
//!    ```ignore
//!    "production" => (
//!        format!("https://{}/health", product_domain),
//!        format!("https://{}/graphql", product_domain),
//!    ),
//!    ```
//! 2. `commands/post_deploy_verification.rs::get_product_endpoints`
//!    (~L506) — the non-production arm composed the pair against an
//!    `<env>.<product_domain>` base:
//!    ```ignore
//!    env => (
//!        format!("https://{}.{}/health", env, product_domain),
//!        format!("https://{}.{}/graphql", env, product_domain),
//!    ),
//!    ```
//! 3. `main.rs::Commands::PostDeployVerify` (~L1326) — the `--domain`-
//!    missing fallback composed the pair against an
//!    `<env>.<service>.app` base:
//!    ```ignore
//!    (
//!        format!("https://{}.{}.app/health", environment, service),
//!        format!("https://{}.{}.app/graphql", environment, service),
//!    )
//!    ```
//!
//! All three stanzas render the same fused byte shape: a single base
//! URL, one suffix `/health` on the first element, one suffix
//! `/graphql` on the second. The three diverge ONLY in the base-URL
//! composition, which is the caller's concern; the shape of the pair
//! itself — the two path suffixes and their tuple order — is what
//! this primitive pins at exactly ONE body.
//!
//! # The drift class the lift forecloses
//!
//! A drift at ONE of the three fused stanzas would silently split the
//! contract in one of these ways:
//!
//! - **Suffix typo.** A copy-paste `/heath` (missing `l`) or
//!   `/graphgl` (letter-swap) at one site leaves the sibling two
//!   correct; the drifted site returns 404 at deploy time with no
//!   structural link back to the composition. Post-lift the suffixes
//!   live in the two [`HEALTH_PATH`] / [`GRAPHQL_PATH`] consts, so a
//!   drift lands in one place or nowhere.
//! - **Tuple-order swap.** A refactor at one site that renders
//!   `(graphql, health)` instead of `(health, graphql)` silently
//!   retargets the caller's `health_endpoint` field to the GraphQL
//!   URL and vice-versa — a swap that a plain smoke test with both
//!   URLs live would MASK because both endpoints answer HTTP 200 on
//!   the successful path. The typed pair returned by
//!   [`health_graphql_endpoint_pair`] carries the two elements in a
//!   named tuple with the health-first, graphql-second order pinned
//!   at ONE body.
//! - **Separator drift.** A drift that omitted the `/` between the
//!   base and the suffix (rendering `<base>health`) or that used a
//!   different separator (`?health`, `#health`) lands at ONE body
//!   post-lift rather than three.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the `<base>/health` and
//! `<base>/graphql` composition lives at ONE surface so a future
//! refinement — swapping the suffix to `/livez` and `/readyz`, adding
//! a version-prefix `/v1/health`, promoting the pair to a
//! `HealthGraphqlEndpointPair` struct with named fields — lands in one
//! place rather than in every consumer.
//!
//! §VI.1 three-is-a-law: three sites today (two arms of the
//! `get_product_endpoints` match + the `--domain`-missing fallback in
//! `main.rs`), so the lift clears the duplication threshold three
//! times over.

use std::io;

/// The path suffix appended to the base URL to compose the health
/// endpoint. Pinned as an associated const so a drift that renamed
/// the health probe path (e.g. Kubernetes-style `/healthz`, service-
/// mesh-style `/livez`) lands at ONE code line rather than three.
pub const HEALTH_PATH: &str = "/health";

/// The path suffix appended to the base URL to compose the GraphQL
/// endpoint. Pinned as an associated const so a drift that renamed
/// the GraphQL endpoint (a versioning bump to `/v1/graphql`, a
/// namespace prefix `/api/graphql`, a routing swap to `/query`) lands
/// at ONE code line rather than three.
pub const GRAPHQL_PATH: &str = "/graphql";

/// Compose the fused `(health_endpoint, graphql_endpoint)` tuple from
/// a caller-composed base URL.
///
/// # Element layout
///
/// The returned tuple has TWO slots in a fixed order:
/// - Slot 0 — the health endpoint: `<base>` + [`HEALTH_PATH`].
/// - Slot 1 — the GraphQL endpoint: `<base>` + [`GRAPHQL_PATH`].
///
/// The order (`health` first, `graphql` second) matches every pre-
/// lift consumer's destructuring `let (health, graphql) = …`. A drift
/// that swapped the tuple order would MASK on a smoke test where both
/// endpoints answer HTTP 200 on the successful path, so the order is
/// pinned by the [`health_graphql_endpoint_pair_places_health_first`]
/// oracle below.
///
/// # `<base>` composition
///
/// This primitive does NOT compose the base URL — that is the
/// caller's concern (see the three pre-lift sites at the module docs
/// for the three composition variants). The primitive owns ONLY the
/// `<base>` → `(<base>/health, <base>/graphql)` fusion, so the two
/// path suffixes and the tuple order live at ONE body.
///
/// # Returned type
///
/// A fresh owned `(String, String)` on every call. Both endpoints
/// are consumed by [`crate::commands::post_deploy_verification::PostDeployConfig`]
/// as owned `String` fields on distinct control paths (the `.unwrap_or(default_health)`
/// fallback in `main.rs`, the fully-composed pair in
/// `get_product_endpoints`), so returning owned strings lets each
/// consumer choose its own lifetime.
pub fn health_graphql_endpoint_pair(base: &str) -> (String, String) {
    let mut health_buf: Vec<u8> = Vec::with_capacity(base.len() + HEALTH_PATH.len());
    // Cannot fail: `Vec<u8>` never returns an `io::Error` on write.
    write_health_endpoint(&mut health_buf, base).expect("Vec<u8> write is infallible");
    let health =
        String::from_utf8(health_buf).expect("composition of &str + ASCII `/health` is UTF-8");

    let mut graphql_buf: Vec<u8> = Vec::with_capacity(base.len() + GRAPHQL_PATH.len());
    write_graphql_endpoint(&mut graphql_buf, base).expect("Vec<u8> write is infallible");
    let graphql =
        String::from_utf8(graphql_buf).expect("composition of &str + ASCII `/graphql` is UTF-8");

    (health, graphql)
}

/// Writer-taking sibling of [`health_graphql_endpoint_pair`]'s slot 0
/// — emits `<base>` + [`HEALTH_PATH`] to a [`io::Write`] sink. The
/// byte-oracle surface for tests that pin the health-endpoint suffix
/// against a drift (a `/healthz` swap, a suffix-omission bug that
/// rendered a bare `<base>`) without allocating an intermediate
/// [`String`].
pub fn write_health_endpoint<W: io::Write>(w: &mut W, base: &str) -> io::Result<()> {
    write!(w, "{}{}", base, HEALTH_PATH)
}

/// Writer-taking sibling of [`health_graphql_endpoint_pair`]'s slot 1
/// — emits `<base>` + [`GRAPHQL_PATH`] to a [`io::Write`] sink. The
/// byte-oracle surface for tests that pin the GraphQL-endpoint suffix
/// against a drift (a `/query` rewrite, a version-prefix bump) without
/// allocating an intermediate [`String`].
pub fn write_graphql_endpoint<W: io::Write>(w: &mut W, base: &str) -> io::Result<()> {
    write!(w, "{}{}", base, GRAPHQL_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`health_graphql_endpoint_pair`] renders the pre-
    /// lift fused shape byte-for-byte across the three
    /// pre-lift base-URL compositions the three call sites carry
    /// (bare `<product_domain>`, `<env>.<product_domain>`,
    /// `<env>.<service>.app`). A drift that (a) renamed either
    /// suffix, (b) added framing, (c) swapped the tuple order, or
    /// (d) upcased any component would fail these assertions.
    #[test]
    fn health_graphql_endpoint_pair_emits_pre_lift_literals_byte_for_byte() {
        // Site 1 (post_deploy_verification.rs, `"production"` arm):
        // bare `<product_domain>` base.
        let (health, graphql) = health_graphql_endpoint_pair("https://example.com");
        assert_eq!(health, "https://example.com/health");
        assert_eq!(graphql, "https://example.com/graphql");

        // Site 2 (post_deploy_verification.rs, `env` arm):
        // `<env>.<product_domain>` base.
        let (health, graphql) = health_graphql_endpoint_pair("https://staging.example.com");
        assert_eq!(health, "https://staging.example.com/health");
        assert_eq!(graphql, "https://staging.example.com/graphql");

        // Site 3 (main.rs, `--domain`-missing fallback):
        // `<env>.<service>.app` base.
        let (health, graphql) = health_graphql_endpoint_pair("https://staging.api.app");
        assert_eq!(health, "https://staging.api.app/health");
        assert_eq!(graphql, "https://staging.api.app/graphql");
    }

    /// Byte-oracle sibling: [`write_health_endpoint`] emits the same
    /// bytes [`health_graphql_endpoint_pair`]'s slot 0 returns, with
    /// no trailing newline and no framing punctuation. A refactor
    /// that promoted the writer to a `writeln!` (adding a `\n`) or
    /// that wrapped the endpoint in quotes / brackets would flip this
    /// assertion.
    #[test]
    fn write_health_endpoint_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_health_endpoint(&mut buf, "https://example.com").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "https://example.com/health");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             endpoint is consumed as a single URL string, not as a \
             stand-alone log line; got {out:?}"
        );
    }

    /// Byte-oracle sibling: [`write_graphql_endpoint`] emits the same
    /// bytes [`health_graphql_endpoint_pair`]'s slot 1 returns, with
    /// no trailing newline and no framing punctuation.
    #[test]
    fn write_graphql_endpoint_emits_pre_lift_literal_byte_for_byte() {
        let mut buf: Vec<u8> = Vec::new();
        write_graphql_endpoint(&mut buf, "https://example.com").unwrap();
        let out = String::from_utf8(buf).expect("writer emits valid UTF-8");
        assert_eq!(out, "https://example.com/graphql");
        assert!(
            !out.ends_with('\n'),
            "writer must NOT emit a trailing `\\n` — the composed \
             endpoint is consumed as a single URL string, not as a \
             stand-alone log line; got {out:?}"
        );
    }

    /// Suffix pin: the two path constants carry the exact pre-lift
    /// byte sequences `"/health"` and `"/graphql"`. A drift that
    /// (a) renamed either constant to a Kubernetes-style `/healthz`
    /// / a mesh-style `/livez`, (b) added a version prefix
    /// (`/v1/health`), or (c) swapped the leading `/` for a `?` or
    /// `#` would flip these assertions before the pair-composition
    /// oracle above ever runs.
    #[test]
    fn suffix_constants_pin_pre_lift_byte_sequences() {
        assert_eq!(HEALTH_PATH, "/health");
        assert_eq!(GRAPHQL_PATH, "/graphql");
        assert!(
            HEALTH_PATH.starts_with('/'),
            "HEALTH_PATH must begin with `/` so the base-URL join \
             renders `<base>/health`, not `<base>health`; got \
             {HEALTH_PATH:?}"
        );
        assert!(
            GRAPHQL_PATH.starts_with('/'),
            "GRAPHQL_PATH must begin with `/` so the base-URL join \
             renders `<base>/graphql`, not `<base>graphql`; got \
             {GRAPHQL_PATH:?}"
        );
    }

    /// Tuple-order pin: the health endpoint lands FIRST in the
    /// returned tuple, the GraphQL endpoint SECOND. A refactor that
    /// swapped the two would silently retarget every consumer's
    /// `health_endpoint` field to the GraphQL URL (and vice-versa),
    /// a drift a plain HTTP-200 smoke test would MASK because both
    /// endpoints answer on the successful path. Two distinct suffix
    /// substrings make the swap observable at the assertion level.
    #[test]
    fn health_graphql_endpoint_pair_places_health_first() {
        let (health, graphql) = health_graphql_endpoint_pair("https://svc.example");
        assert!(
            health.ends_with(HEALTH_PATH),
            "slot 0 must be the health endpoint (ending in {HEALTH_PATH}); \
             got {health:?}"
        );
        assert!(
            graphql.ends_with(GRAPHQL_PATH),
            "slot 1 must be the GraphQL endpoint (ending in {GRAPHQL_PATH}); \
             got {graphql:?}"
        );
        assert!(
            !health.contains(GRAPHQL_PATH),
            "slot 0 must NOT carry the GraphQL suffix — tuple-order \
             swap would silently retarget the health-endpoint field \
             to the GraphQL URL; got {health:?}"
        );
        assert!(
            !graphql.contains(HEALTH_PATH),
            "slot 1 must NOT carry the health suffix — tuple-order \
             swap would silently retarget the GraphQL-endpoint field \
             to the health URL; got {graphql:?}"
        );
    }

    /// Empty-base discipline: the primitive owns COMPOSITION, not
    /// validation. Callers that hand an empty `base` receive a
    /// syntactically-empty half of the endpoint (e.g. `"/health"`,
    /// `"/graphql"`), NOT a bail nor a default. The HTTP client
    /// downstream rejects the malformed URL; validation belongs at
    /// the boundary that owns the empty-check invariant, not at this
    /// shape-only composition primitive. Pins the contract so a
    /// future refactor cannot silently insert a default-base fallback
    /// or a `.unwrap_or(...)` guard here.
    #[test]
    fn health_graphql_endpoint_pair_composes_empty_base_verbatim() {
        let (health, graphql) = health_graphql_endpoint_pair("");
        assert_eq!(health, "/health");
        assert_eq!(graphql, "/graphql");
    }

    /// Post-lift shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/main.rs` may still spell the
    /// pre-lift raw
    /// `format!("<...>/health", …)` / `format!("<...>/graphql", …)`
    /// shape inline on a health-graphql-endpoint-pair site. Every
    /// consumer reaches for [`health_graphql_endpoint_pair`] on first
    /// grep, not by copy-pasting the raw `format!` from an existing
    /// sibling.
    ///
    /// Anchored on the three pre-lift base-URL composition strings
    /// verbatim so a rename to an unrelated URL slot (e.g. a Grafana
    /// `/health` probe) does not trip the shield, keeping any future
    /// sibling health-endpoint primitive at its own home.
    #[test]
    fn no_module_still_spells_raw_health_graphql_endpoint_format() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        // The six pre-lift shape strings (three sites × two suffixes),
        // spelled verbatim without any `format!` variant that a future
        // refactor might introduce.
        let pre_lift_shapes: &[&str] = &[
            // post_deploy_verification.rs `"production"` arm:
            "format!(\"https://{}/health\", product_domain)",
            "format!(\"https://{}/graphql\", product_domain)",
            // post_deploy_verification.rs `env` arm:
            "format!(\"https://{}.{}/health\", env, product_domain)",
            "format!(\"https://{}.{}/graphql\", env, product_domain)",
            // main.rs `--domain`-missing fallback:
            "format!(\"https://{}.{}.app/health\", environment, service)",
            "format!(\"https://{}.{}.app/graphql\", environment, service)",
        ];
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        let mut files: Vec<PathBuf> = Vec::new();
        walk(&src_dir, &mut files);
        for path in files {
            // Skip this module — the shape strings live in its
            // shield needles and its docstring.
            if path.file_name().and_then(|n| n.to_str()) == Some("health_graphql_endpoint_pair.rs")
            {
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
                for shape in pre_lift_shapes {
                    if line.contains(shape) {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `format!(\"<base>/health\", …)` or `format!(\"<base>/graphql\", …)` \
             literal(s) survive on a health-graphql-endpoint-pair site — route \
             each through \
             `crate::health_graphql_endpoint_pair::health_graphql_endpoint_pair(base)` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Post-lift shield (positive half): the two pre-lift modules
    /// that housed the composition MUST each forward through
    /// [`health_graphql_endpoint_pair`] at least once, so a migration
    /// that dropped a call site outright leaves the negative "no raw
    /// inline shape" scan trivially satisfied by absence but the
    /// positive count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed primitive.
    #[test]
    fn every_prelift_module_forwards_through_health_graphql_endpoint_pair() {
        use std::path::PathBuf;
        let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(&[&str], usize)] = &[
            (&["commands", "post_deploy_verification.rs"], 1),
            (&["main.rs"], 1),
        ];
        let needle = "health_graphql_endpoint_pair(";
        for (segments, min_count) in expectations {
            let mut path = src_dir.clone();
            for s in *segments {
                path.push(s);
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {min_count} \
                 health-graphql-endpoint-pair composition(s) through \
                 `{needle}`; found {forwards}. A dropped call would leave \
                 the negative raw-shape scan satisfied by absence.",
                path.display(),
            );
        }
    }
}
