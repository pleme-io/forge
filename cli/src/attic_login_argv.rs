//! Fixed-arity `attic login <cache> <server_url> <token>` argv slice
//! used at every attic-login spawn site across the crate.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites inside
//! [`crate::infrastructure::attic::AtticClient`] each spelled the same
//! 4-element `["login", <cache>, <server>, <token>]` argv literal
//! verbatim on their `attic` builder, diverging only on the surrounding
//! spawn / retry / classify wiring:
//!
//! 1. [`crate::infrastructure::attic::AtticClient::login`] — the
//!    single-shot login path (~L572), routed through
//!    `cmd.output().await` + [`crate::retry::classify_capture`] with the
//!    typed [`crate::error::AtticError::LoginFailed`] variant on
//!    failure. Consumed by
//!    [`crate::infrastructure::attic::AtticClient::login_optional`] on
//!    the non-fatal wrapper surface (`commands/build.rs::execute`'s
//!    pre-Nix-build cache configuration step).
//! 2. [`crate::infrastructure::attic::AtticClient::login_with_retries`]
//!    — the retry-loop login path (~L699), routed through
//!    [`crate::retry::retry_command_logged`] with
//!    [`crate::retry::RetryPolicy::network_with_max_attempts`] and
//!    [`crate::infrastructure::attic::classify_attic_login_failure`] on
//!    the exhausted-budget arm. Consumed by
//!    `commands/github_runner_ci.rs`'s attic-login-with-retry migration
//!    (which retired the pre-migration inline `attic_command_with_retry`
//!    stringly `args: &[&str]` wrapper).
//!
//! Both consumers pass `.args(["login", <cache>, <server_url>, <token>])`
//! byte-for-byte; the only pre-lift divergence is in the surrounding
//! spawn adapter (`cmd.output().await` vs
//! [`crate::retry::retry_command_logged`]), the error classifier
//! ([`crate::retry::classify_capture`] vs
//! [`crate::infrastructure::attic::classify_attic_login_failure`]),
//! and the closure ownership dance the retry loop needs (each site
//! `.clone()`s the four owned strings inside the retry closure). None
//! of those axes touch the argv slice itself.
//!
//! A drift in the argv shape — a rename of the `login` verb by a future
//! attic upstream, an argv-order shuffle placing `<server>` before
//! `<cache>` or `<token>` before either, a promotion of `<token>` to a
//! `--token <token>` flag pair (unifying with the alternative
//! `ATTIC_TOKEN` env-var contract), or a swap for `<cache-alias>` in
//! the crate::attic_cache_alias `<server>:<cache>` shape ahead of a
//! `<server>` + `<token>` pair — pre-lift had to hit two sites in
//! lockstep or diverge; post-lift it hits ONE typed body and every
//! consumer inherits the change from
//! `.args(crate::attic_login_argv::attic_login_argv(cache, server_url,
//! token))`.
//!
//! # Why an argv slice, not a spawn wrapper
//!
//! The two consumers differ AFTER the argv slice on three axes that
//! don't fit under a single spawn wrapper:
//!
//! - **Retry envelope.** Site 1 issues a single `.output().await`;
//!   site 2 wraps the spawn in
//!   [`crate::retry::retry_command_logged`] with a
//!   [`crate::retry::RetryPolicy`] and a per-attempt closure that
//!   re-owns the four argv strings (`attic_bin`, `cache`,
//!   `server_url_owned`, `token_owned`). A spawn wrapper would have to
//!   thread the retry policy through as a parameter and expose the
//!   per-attempt closure interface, or fork into two nearly-identical
//!   siblings.
//! - **Error classifier.** Site 1 dispatches through
//!   [`crate::retry::classify_capture`] with two closures
//!   ([`crate::error::AtticError::exec_failed`] on spawn-failure,
//!   [`crate::error::AtticError::LoginFailed`] on non-zero exit);
//!   site 2 dispatches through
//!   [`crate::infrastructure::attic::classify_attic_login_failure`]
//!   on the exhausted-budget arm. Both surface the same typed
//!   [`crate::error::AtticError`] discriminants, but through distinct
//!   classifier bodies.
//! - **Token discipline pin.** Both sites deliberately pass the token
//!   as a positional CLI argument rather than as the
//!   `ATTIC_TOKEN` env var — an operator-observability discriminator
//!   this primitive preserves at both sites by construction (the
//!   `token` slot is a `&str` positional, never an env-pair). See
//!   [`crate::infrastructure::attic::AtticClient::login`]'s docstring
//!   for the rationale.
//!
//! A `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape both
//! `tokio::process::Command`'s `.args()` and any `&[&str]`-taking
//! helper consume identically. Modeled on
//! [`crate::docker_tag_argv::docker_tag_argv`],
//! [`crate::doca_inspect_digest_argv::doca_inspect_digest_only_argv`],
//! and [`crate::kubectl_annotate_overwrite_argv::kubectl_annotate_overwrite_argv`]
//! — argv-slice primitives that partition their tool's duplication
//! budget without collapsing the spawn / classify / retry layers that
//! legitimately diverge downstream.
//!
//! # Distinct from the sibling `<server>:<cache>` cache-alias shape
//!
//! [`crate::attic_cache_alias::attic_cache_alias`] composes the
//! `<server>:<cache>` positional alias every `attic push` /
//! `attic use` subcommand consumes as ONE positional argument (a
//! colon-separated 2-slot composition). This primitive composes the
//! attic-login argv, which threads `<cache>`, `<server_url>`, and
//! `<token>` as THREE distinct positional arguments after the `login`
//! verb — the login surface does not use the colon-joined alias
//! shape. The two primitives are distinct by attic-subcommand
//! (`push`/`use` vs `login`), distinct by argv arity, and distinct in
//! whether the server + cache-name pair collapses into a single
//! positional or stays split across two.
//!
//! # THEORY grounding
//!
//! §V solve-once-at-the-primitive: the attic-login argv shape lives at
//! ONE construction surface so a future refinement (a rename of the
//! `login` verb, a promotion of `<token>` to a `--token <token>` flag
//! pair, a swap onto the `<server>:<cache>` alias shape ahead of a
//! `<token>`-only tail) lands in one place rather than at every
//! consumer.

/// The pre-lift 4-element `login <cache> <server_url> <token>` argv
/// slice used at every attic-login spawn site.
///
/// Callers assemble the surrounding builder chain
/// (`Command::new(<attic_bin>)`, the retry / classify envelope, and
/// the `.piped_child_stdio()` extension) themselves — those axes vary
/// across the two consumers. This primitive owns ONLY the 4-element
/// argv shape.
///
/// # Element layout
///
/// - `argv[0] = "login"` — attic subcommand.
/// - `argv[1] = <cache>` — caller-supplied cache name (bound to
///   `self.cache_name` on the enclosing
///   [`crate::infrastructure::attic::AtticClient`] at both call sites).
/// - `argv[2] = <server_url>` — caller-supplied attic server URL
///   (an `https://` or `http://` scheme with a hostname; the trailing
///   slash / path is preserved verbatim, matching pre-lift).
/// - `argv[3] = <token>` — caller-supplied bearer token. Deliberately
///   passed as a positional argument (not as `ATTIC_TOKEN` env var) so
///   both sites' `ps`-observable argv shape stays uniform. See
///   [`crate::infrastructure::attic::AtticClient::login`]'s docstring
///   for the rationale.
///
/// # Lifetime discipline
///
/// The returned array borrows `cache`, `server_url`, and `token` under
/// a single `'a` bound. Every current caller binds all three strings
/// ahead of the spawn (the single-shot path binds `self.cache_name` +
/// two `&str` parameters; the retry path clones all three into the
/// per-attempt closure) and holds them alive across the `.args(...)`
/// call; the `[&'a str; 4]` return type pins that requirement at the
/// type level (a caller cannot silently extend the array past any of
/// the three inputs' scopes).
pub fn attic_login_argv<'a>(cache: &'a str, server_url: &'a str, token: &'a str) -> [&'a str; 4] {
    ["login", cache, server_url, token]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`attic_login_argv`] returns the pre-lift 4-element
    /// slice element-for-element (`"login"`, `<cache>`, `<server_url>`,
    /// `<token>`) in the pre-lift order, with no extra element and no
    /// rewritten value. A future refactor that (a) reordered the slice,
    /// (b) added a `--force` / `-f` / `--json` companion flag,
    /// (c) renamed `"login"` to a hypothetical `"auth"` alias,
    /// (d) promoted `<token>` to a `--token <token>` flag pair, or
    /// (e) collapsed any element regresses this assertion.
    #[test]
    fn test_attic_login_argv_emits_pre_lift_four_element_slice() {
        let argv = attic_login_argv("my-cache", "https://attic.example.com", "tk_abc123");
        assert_eq!(argv[0], "login");
        assert_eq!(argv[1], "my-cache");
        assert_eq!(argv[2], "https://attic.example.com");
        assert_eq!(argv[3], "tk_abc123");
        assert_eq!(argv.len(), 4);
    }

    /// The return type is a fixed-arity `[&str; 4]`, NOT a `Vec<&str>`
    /// or a `&[&str]`. A type change to a `Vec<String>` would allow a
    /// caller to `.push` a stray argument without touching this
    /// module; a change to a slice reference would allow an
    /// unsized-length pattern that a variadic future refactor might
    /// silently exploit. Pin the fixed arity at compile time via a
    /// destructured binding — if the returned type ever loses its
    /// `[_; 4]` shape, this line fails to type-check.
    #[test]
    fn test_attic_login_argv_returns_fixed_arity_four() {
        let argv: [&str; 4] = attic_login_argv("cache", "server", "token");
        let [a0, a1, a2, a3] = argv;
        assert_eq!(a0, "login");
        assert_eq!(a1, "cache");
        assert_eq!(a2, "server");
        assert_eq!(a3, "token");
    }

    /// Interpolation-position pin: `cache` lands at index 1,
    /// `server_url` at index 2, `token` at index 3. A future refactor
    /// that swapped any pair would silently send the server URL to
    /// attic as the cache-name slot (or the bearer token as the
    /// server-URL slot, leaking the token into an error message or a
    /// registration failure), a wire-visible defect that a mere length
    /// check would not catch. Three distinct string arguments make any
    /// swap observable at the assertion level.
    #[test]
    fn test_attic_login_argv_places_each_input_at_its_pre_lift_index() {
        let argv = attic_login_argv("cache-alpha", "server-beta", "token-gamma");
        assert_eq!(
            argv[1], "cache-alpha",
            "index 1 must carry the cache-name argument"
        );
        assert_eq!(
            argv[2], "server-beta",
            "index 2 must carry the server-URL argument"
        );
        assert_eq!(
            argv[3], "token-gamma",
            "index 3 must carry the bearer-token argument"
        );
        assert_ne!(argv[1], argv[2], "cache and server must not collide");
        assert_ne!(argv[2], argv[3], "server and token must not collide");
        assert_ne!(argv[1], argv[3], "cache and token must not collide");
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/infrastructure/` or `cli/src/commands/` may spell the
    /// pre-lift raw 4-element `["login", <cache>, <server>, <token>]`
    /// argv literal inline any more. The two pre-lift sites in
    /// `infrastructure/attic.rs` migrated; any future consumer that
    /// wants the same `attic login <cache> <server> <token>` shape
    /// reaches for [`attic_login_argv`] on first grep, not by
    /// copy-pasting the raw literal from the existing attic module.
    ///
    /// Anchored on `.args(["login", ` opening the argv literal, plus a
    /// same-line check that the args slice carries at least two `, `
    /// separators after the `"login", ` opening (a 4-element shape has
    /// three inter-element separators; the sibling 2-element `["tag",
    /// <ref>]` git-tag shape at `commands/helm.rs` has zero, and any
    /// hypothetical 3-element `attic <verb> <arg1> <arg2>` shape has
    /// one). The scan skips this module's own `#[cfg(test)]` region so
    /// the shield's own byte-oracle constants don't self-match.
    #[test]
    fn no_infrastructure_or_command_module_still_spells_raw_attic_login_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("infrastructure"), crate_src.join("commands")];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        let open_needle = ".args([\"login\", ";
        for dir in scan_dirs.iter() {
            let read = match std::fs::read_dir(dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for entry in read.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
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
                    let Some(open_pos) = line.find(open_needle) else {
                        continue;
                    };
                    let rest = &line[open_pos + open_needle.len()..];
                    let Some(close_pos) = rest.find("])") else {
                        continue;
                    };
                    let inner = &rest[..close_pos];
                    // A 4-element `.args(["login", <a>, <b>, <c>])` shape
                    // carries at least two `, ` separators inside the
                    // args-slice section (three inter-element commas, two
                    // of which sit between the three post-`"login"` slots).
                    if inner.matches(", ").count() >= 2 {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"login\", <cache>, <server>, <token>]` argv literal(s) \
             survive under `infrastructure/` or `commands/` — route each \
             through `crate::attic_login_argv::attic_login_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the pre-lift module that housed
    /// the two sites MUST forward through [`attic_login_argv`] at
    /// least the pre-lift count of times, so a migration that dropped
    /// a call site outright leaves the negative "no raw inline shape"
    /// scan trivially satisfied by absence but the positive count
    /// still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_*` shields the crate
    /// carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_attic_login_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] =
            &[(crate_src.join("infrastructure").join("attic.rs"), 2)];
        let needle = "attic_login_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} `attic login` spawn site(s) \
                 through `{}`; found {}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
