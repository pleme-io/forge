//! Fixed-arity `doca inspect --ref <image_ref> --digest-only` argv slice
//! used at every doca-inspect-for-manifest-digest spawn site across the
//! crate.
//!
//! # Pre-lift census — two sibling stanzas, one argv shape
//!
//! Two consumer sites each spelled the same 4-element argv literal
//! verbatim on their `doca` builder, both threading a
//! [`crate::oci_manifest::image_reference`]-composed `<registry>:<tag>`
//! reference into position 2 and pairing the spawn with
//! [`crate::infrastructure::registry::doca_source_creds_env_pairs`] on
//! the env layer:
//!
//! 1. `commands/rust_service.rs::verify_image_in_registry` (post-push
//!    registry-side verification that the just-pushed `<registry>:<tag>`
//!    exists and carries an OCI manifest digest; the returned
//!    `sha256:…` string threads into the deploy path's cryptographic
//!    guarantee that "the image the deploy points at is byte-for-byte
//!    the image we pushed"; `Command::new(&doca).args(["inspect",
//!    "--ref", &full_tag, "--digest-only"]).envs(
//!    doca_source_creds_env_pairs(organization, &github_token)).output()
//!    .await` around line 779).
//! 2. `infrastructure/registry.rs::RegistryClient::verify_tag_exists`
//!    (pre-deploy precondition check on an existing `<registry>:<tag>`
//!    ahead of a rollout, returning either the manifest digest or the
//!    typed `RegistryError::RemoteImageNotFound` variant; `Command::
//!    new(&doca).args(["inspect", "--ref", &full_ref, "--digest-only"])
//!    .envs(doca_source_creds_env_pairs(&self.credentials.organization,
//!    &self.credentials.token)).output().await` around line 362).
//!
//! A doca-inspect argv drift — a `--digest-only` rename by the doca
//! upstream project (whose `--digest-only` flag replaces skopeo's
//! `--format {{.Digest}}` — both print the OCI manifest digest and
//! nothing else, so the caller's parsing is unchanged), an argv-order
//! swap between the `--ref <ref>` pair and the `--digest-only` flag, a
//! future `--tag-only` companion that drops the manifest digest for the
//! tag string, or a switch to a `--json` output surface that adds
//! surrounding structure — pre-lift had to hit both sites in lockstep
//! or diverge; post-lift it hits ONE typed body and every consumer
//! inherits the change from
//! `Command::args(doca_inspect_digest_only_argv(&full_ref))`.
//!
//! # Why an argv slice, not a `Command` builder
//!
//! The two consumers differ AFTER the argv slice on three axes:
//!
//! - **Error envelope.** Site 1 bails through `anyhow::bail!` with a
//!   multi-line "image not found in registry" diagnostic keyed on the
//!   `full_tag` string. Site 2 routes through
//!   [`crate::retry::classify_capture_query`] and emits a typed
//!   `RegistryError::RemoteImageNotFound { registry, tag }` variant on
//!   op-failure and `RegistryError::ExecFailed { operation, message }`
//!   on spawn-failure.
//! - **Credential source.** Site 1 discovers the token via
//!   `RegistryCredentials::discover_token(None)` and derives the
//!   organization from `RegistryRef::parse(registry)` at call time.
//!   Site 2 reads both from `self.credentials` on the enclosing
//!   `RegistryClient` (pre-bound by the constructor).
//! - **Success-path emit.** Site 1 prints a `🔍 Verifying image in
//!   registry` announce ahead of the spawn (`println!` with a
//!   `.dimmed()`-styled `full_tag`), and returns the trimmed digest
//!   string to a deploy-plumbing caller that pairs it with a subsequent
//!   pull-side verification. Site 2 emits nothing and returns the raw
//!   digest string into a typed rollout precondition path.
//!
//! A `Command`-builder primitive would have to expose all three axes as
//! parameters; the argv slice owns only the shape both `tokio::process`
//! and `std::process` `Command`s' `.args()` (and any `&[&str]`-taking
//! helper) consume identically. Modeled on
//! [`crate::infrastructure::registry::doca_push_argv`] (9-element push
//! argv across four sites), [`crate::docker_tag_argv`] (3-element
//! `docker tag <src> <dst>` argv across two sites), and
//! [`crate::kubectl_annotate_overwrite_argv`] (7-element `kubectl
//! annotate` argv across two sites), argv-slice primitives that
//! partition their tool's duplication budget without collapsing the
//! spawn / classify / env layers that legitimately diverge downstream.
//!
//! # Borrows from inputs, not `&'static`
//!
//! Unlike [`crate::bun_argv::bun_install_frozen_lockfile_argv`], whose
//! two elements are compile-time literals, this primitive interpolates
//! the caller-supplied `image_ref` string (the composed
//! `<registry>:<tag>` reference) into element position 2. Following
//! [`crate::infrastructure::registry::doca_push_argv`] (which
//! interpolates four caller strings), the return type is
//! `[&'a str; 4]` with the input lifetime `'a` bound to the reference
//! — the returned array borrows from the input, so the caller must
//! hold it alive across the `.args(...)` call. This matches both
//! current call sites, each of which binds the reference to a local
//! `full_ref` / `full_tag` right before the spawn and holds it alive
//! for the whole enclosing expression.
//!
//! # Distinct from the sibling `doca_bin()` sigil and the credentials-env pair
//!
//! Every consumer already resolves the `doca` binary through the
//! module-scoped
//! [`crate::infrastructure::registry::doca_bin`] sigil (or the
//! sibling `get_tool_path("DOCA_BIN", "oci-push")` accessor on the
//! `rust_service` path), and threads registry credentials through
//! [`crate::infrastructure::registry::doca_source_creds_env_pairs`] on
//! the `.envs(...)` layer. Those two sigils own *which* binary spawns
//! and *how* it authenticates; this primitive owns *which arguments*
//! it receives on the manifest-digest-inspect phase. The three concerns
//! compose:
//! `Command::new(&doca).args(doca_inspect_digest_only_argv(&full_ref))
//! .envs(doca_source_creds_env_pairs(<org>, <token>))`.
//!
//! # Sibling doca-inspect argv shapes that stay direct
//!
//! Two other doca-inspect argv shapes appear in the crate and are
//! deliberately NOT collapsed onto this primitive:
//!
//! - `commands/attestation.rs::compute_build_attestation` at line 724
//!   spells the 3-element `["inspect", "--ref", &full_ref]` argv (no
//!   `--digest-only` companion) — the attestation surface consumes the
//!   full JSON manifest via `canonical_manifest_fingerprint`, not just
//!   the digest string.
//! - `commands/image_release.rs::verify_workspace_deps` at line 496
//!   spells the 3-element `["inspect", "--tarball", <image_path>]`
//!   argv — the input source is a local OCI tarball on disk, not a
//!   remote `<registry>:<tag>` reference, so no credentials env pair
//!   applies and no `--digest-only` toggle is meaningful.
//!
//! Both are single-site argv shapes past their own THEORY §VI.1
//! three-times threshold; either one graduating to a lift target would
//! reach for its own sibling primitive in this module (a
//! `doca_inspect_manifest_argv(ref)` for the JSON-consumer, a
//! `doca_inspect_tarball_argv(path)` for the on-disk consumer) rather
//! than reshape this one.

/// The pre-lift 4-element `inspect --ref <image_ref> --digest-only`
/// argv slice used at every doca-inspect-for-manifest-digest spawn
/// site.
///
/// Callers assemble the surrounding builder chain (`Command::new(&doca)`,
/// `.envs(doca_source_creds_env_pairs(...))`, `.output().await`,
/// post-spawn classification, and the diagnostic-emit shape) themselves
/// — those axes vary across the two consumers. This primitive owns
/// ONLY the 4-element argv shape.
///
/// # Element layout
///
/// - `argv[0] = "inspect"` — doca verb.
/// - `argv[1] = "--ref"` — remote-reference-source flag pair opener.
/// - `argv[2] = <image_ref>` — caller-supplied `<registry>:<tag>`
///   reference, produced by
///   [`crate::oci_manifest::image_reference`] at both call sites (the
///   ONE crate-canonical site for building this `<repository>:<tag>`
///   shape). The doca subcommand parses this positional as the remote
///   image reference to inspect against the caller-supplied
///   credentials env pair.
/// - `argv[3] = "--digest-only"` — output-mode toggle. Reduces the
///   inspect surface's stdout from a full OCI manifest JSON down to
///   the manifest digest string (`sha256:…`) and nothing else, so the
///   caller's `String`-consuming `output.stdout` parse is a trim and
///   nothing more. Replaces skopeo's `--format {{.Digest}}` — both
///   emit the same digest, so a future migration back to skopeo would
///   need to translate `--digest-only` to the format-string spelling
///   here in the primitive body, and every consumer inherits the
///   translation.
///
/// # Lifetime discipline
///
/// The returned array borrows `image_ref` under a `'a` bound. Every
/// current caller binds the reference ahead of the spawn (via
/// [`crate::oci_manifest::image_reference`]) and holds it alive across
/// the `.args(...)` call; the `[&'a str; 4]` return type pins that
/// requirement at the type level (a caller cannot silently extend the
/// array past the reference's scope).
pub fn doca_inspect_digest_only_argv<'a>(image_ref: &'a str) -> [&'a str; 4] {
    ["inspect", "--ref", image_ref, "--digest-only"]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`doca_inspect_digest_only_argv`] returns the
    /// pre-lift 4-element slice element-for-element (`"inspect"`,
    /// `"--ref"`, `<image_ref>`, `"--digest-only"`) in the pre-lift
    /// order, with no extra element and no rewritten value. A future
    /// refactor that (a) reordered the slice, (b) added a `--json` /
    /// `--tls-verify` companion flag, (c) renamed `--digest-only` to a
    /// doca-project alias, (d) swapped `--ref` for `--reference`, or
    /// (e) collapsed any element regresses this assertion.
    #[test]
    fn test_doca_inspect_digest_only_argv_emits_pre_lift_four_element_slice() {
        let argv = doca_inspect_digest_only_argv("ghcr.io/pleme-io/api:v1.2.3");
        assert_eq!(argv[0], "inspect");
        assert_eq!(argv[1], "--ref");
        assert_eq!(argv[2], "ghcr.io/pleme-io/api:v1.2.3");
        assert_eq!(argv[3], "--digest-only");
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
    fn test_doca_inspect_digest_only_argv_returns_fixed_arity_four() {
        let argv: [&str; 4] = doca_inspect_digest_only_argv("ref");
        let [a0, a1, a2, a3] = argv;
        assert_eq!(a0, "inspect");
        assert_eq!(a1, "--ref");
        assert_eq!(a2, "ref");
        assert_eq!(a3, "--digest-only");
    }

    /// Interpolation-position pin: `image_ref` lands at index 2. A
    /// future refactor that swapped positions with `--ref` or
    /// `--digest-only` would send the flag string as the remote
    /// reference against the registry — a wire-visible defect that a
    /// mere length check would not catch. A distinctive
    /// `<registry>:<tag>`-shaped literal makes the swap observable at
    /// the assertion level.
    #[test]
    fn test_doca_inspect_digest_only_argv_places_image_ref_at_index_2() {
        let argv = doca_inspect_digest_only_argv("registry.example:v9");
        assert_eq!(
            argv[2], "registry.example:v9",
            "index 2 must carry the <registry>:<tag> reference argument"
        );
        assert_ne!(
            argv[2], argv[1],
            "reference must not collide with --ref flag"
        );
        assert_ne!(
            argv[2], argv[3],
            "reference must not collide with --digest-only flag"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` or `cli/src/infrastructure/` may spell the
    /// pre-lift raw 4-element `["inspect", "--ref", ..., "--digest-only"]`
    /// argv literal inline any more. The two pre-lift sites migrated;
    /// any future consumer that wants the same doca-manifest-digest
    /// inspect shape reaches for [`doca_inspect_digest_only_argv`] on
    /// first grep, not by copy-pasting the raw literal from an
    /// existing module.
    ///
    /// Anchored on the joined pair `"inspect", "--ref"` plus a
    /// same-line `"--digest-only"` occurrence — the pair-adjacency +
    /// trailing flag combination is what every pre-lift stanza
    /// carried, and no post-lift consumer will (the typed primitive
    /// owns both inside its body). A future consumer of the sibling
    /// 3-element `["inspect", "--ref", <ref>]` argv (documented on the
    /// `attestation.rs` full-JSON path) can still spell the
    /// `"inspect", "--ref"` pair alone without the `"--digest-only"`
    /// companion; a future consumer of the sibling
    /// `["inspect", "--tarball", <path>]` argv (documented on the
    /// `image_release.rs` on-disk path) can still spell `"inspect"`
    /// with a different second-flag token — neither trips the shield.
    #[test]
    fn no_command_or_infrastructure_module_still_spells_raw_doca_inspect_digest_only_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let scan_dirs = [crate_src.join("commands"), crate_src.join("infrastructure")];

        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for dir in scan_dirs.iter() {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
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
                    // Anchor on the joined pair `"inspect", "--ref"`
                    // plus a same-line `"--digest-only"` occurrence.
                    // A future consumer of the 3-element sibling
                    // shape (`["inspect", "--ref", <ref>]` without
                    // `--digest-only`) can still spell either token
                    // alone without tripping the shield.
                    if line.contains("\"inspect\", \"--ref\"") && line.contains("\"--digest-only\"")
                    {
                        offenders.push((path.clone(), idx + 1, line.to_string()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `[\"inspect\", \"--ref\", ..., \"--digest-only\"]` argv \
             literal(s) survive under `commands/` or `infrastructure/` — \
             route each through \
             `crate::doca_inspect_digest_argv::doca_inspect_digest_only_argv()` \
             instead:\n{:#?}",
            offenders
        );
    }

    /// Caller shield (positive half): the two pre-lift modules that
    /// housed the two sites MUST each forward through
    /// [`doca_inspect_digest_only_argv`] at least once, so a
    /// migration that dropped a call site outright leaves the
    /// negative "no raw inline shape" scan trivially satisfied by
    /// absence but the positive count still fails. Mirrors the
    /// sibling `every_prelift_module_forwards_through_*` shields the
    /// crate carries against every other typed argv primitive.
    #[test]
    fn every_prelift_module_forwards_through_doca_inspect_digest_only_argv() {
        use std::path::PathBuf;
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let expectations: &[(PathBuf, usize)] = &[
            (crate_src.join("commands").join("rust_service.rs"), 1),
            (crate_src.join("infrastructure").join("registry.rs"), 1),
        ];
        let needle = "doca_inspect_digest_only_argv(";
        for (path, min_count) in expectations {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("expected {} to exist", path.display()));
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{} must forward at least {} doca-inspect-for-manifest-digest \
                 spawn site(s) through `{}`; found {}. A dropped call would \
                 leave the negative raw-shape scan satisfied by absence.",
                path.display(),
                min_count,
                needle,
                forwards,
            );
        }
    }
}
