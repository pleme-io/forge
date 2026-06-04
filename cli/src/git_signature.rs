//! Typed `git log --format=%G?` commit-signature probe outcome for
//! forge's Phase 1 source attestation — the source-side peer of
//! [`crate::cosign`] (image-signature probe),
//! [`crate::helm_provenance`] (chart-signature probe),
//! [`crate::helm_lint`] (chart-quality probe),
//! [`crate::kensa_policy`] (chart-policy probe),
//! [`crate::oci_architecture`] (image-architecture probe),
//! [`crate::oci_manifest`] (manifest-identity oracle),
//! [`crate::openpgp_signature`] (OpenPGP v4 signature packet parser),
//! and [`crate::security_scan`] (SBOM / vuln-scan probes).
//!
//! ## What this module closes
//!
//! `commands/attestation.rs::compute_source_attestation` previously
//! folded the `git log -1 --format=%G?` probe through the silent
//! pattern:
//!
//! ```ignore
//! let commit_signed =
//!     run_command_output(repo_root, "git", &["log", "-1", "--format=%G?", git_sha])
//!         .await
//!         .map(|s| s.trim() == "G" || s.trim() == "U")
//!         .unwrap_or(false);
//! ```
//!
//! Nine operational worlds (eight `%G?` codes per git-log(1) plus the
//! probe-failed world) flattened into a single boolean — the canonical
//! "silent fallback" shape every recent claude-routine commit has
//! systematically ground in typed primitives. The
//! `s.trim() == "G" || s.trim() == "U"` collapse silently routes the
//! `B` (bad signature — cryptographic verification *failed*),
//! `X` (good signature that has expired), `Y` (good signature made by
//! an expired key), `R` (good signature made by a revoked key),
//! `E` (signature cannot be checked, e.g. missing public key), and
//! `N` (no signature at all) cases into the same negative bucket as a
//! probe failure — a downstream verifier reading
//! `commit_signed: false` on the Phase 1 source attestation cannot
//! recover whether the operator never signed (`N`), signed with a key
//! whose chain of trust expired (`X` / `Y`), signed with a revoked
//! key (`R`), produced a signature that cryptographically *failed
//! verification* (`B` — actively malicious), or the certification
//! function could not even probe git for an answer (probe-failed).
//!
//! The `B` case is the most load-bearing collapse: a `B` from `%G?`
//! is GPG's report of "this signature was verified against the
//! claimed key AND DID NOT MATCH". A Phase 1 source attestation that
//! reports `commit_signed: false` for both a `B` and an `N` cannot
//! drive a sekiban admission webhook that fails-closed on bad
//! signatures but admits unsigned commits in dev / staging — both
//! collapse to the same value at the attestation layer (THEORY §V.2:
//! attestation is cryptographic evidence, not a wish; the bool that
//! flattens "no evidence" and "evidence of compromise" cannot
//! substantiate either claim).
//!
//! This is the same false-by-construction shape commit c1e83d5
//! closed for `policy_passed` (`true` →
//! [`crate::kensa_policy::KensaPolicyOutcome`]), commit d81f639
//! closed for `linter_passed` (`true` →
//! [`crate::helm_lint::HelmLintOutcome`]), commit 2f3a7dc closed for
//! `signer_key_id` (`None` →
//! [`crate::openpgp_signature::SignaturePacketOutcome`]), commit
//! b98eb5a closed for the SBOM / vuln-scan hashes (name-keyed
//! constants → [`crate::security_scan::SbomProbeOutcome`] /
//! [`crate::security_scan::VulnScanProbeOutcome`]), commit fffca30
//! closed for the image `architecture` field (`"amd64"` literal →
//! [`crate::oci_architecture::OciArchitectureOutcome`]), commit
//! b8a1d8a closed for the chart `provenance_verified` bool
//! (`false` hardcode →
//! [`crate::helm_provenance::HelmProvenanceOutcome`]), and commits
//! 9c5a99f / 443bd22 / e8a2df7 closed for the source-tree / manifest
//! / chart hashes (silent fallbacks → per-kind probe-absent
//! sentinels).
//!
//! ## The nine operational worlds
//!
//! `git log -1 --format=%G?` against a commit distinguishes eight
//! codes documented in git-log(1) — the probe-failed world is a
//! ninth distinct operational state the prior silent
//! `unwrap_or(false)` flattened into the same bucket as the
//! evidence-bearing negative codes:
//!
//! 1. **G** — good (valid) signature: GPG verified the signature
//!    against the signer's key AND the key chain resolved into the
//!    operator's trust path. The Phase 1 source attestation can
//!    honestly claim `commit_signed: true` only in this arm and the
//!    `U` arm.
//! 2. **U** — good signature with unknown validity: GPG verified the
//!    cryptographic signature, but the signer's key is not in any
//!    keyring path the operator trusts. A signed-but-trust-unknown
//!    state is structurally distinct from a signed-and-trusted
//!    state — a future enrichment commit could surface the
//!    discriminator on the attestation rather than collapsing both
//!    to `true`.
//! 3. **X** — good signature that has expired: the signature itself
//!    is well-formed and GPG verified it, but the signature carried
//!    an expiration that has now passed. The operator *did* author
//!    a cryptographic signature; the trust dimension has aged out.
//!    Distinct from `N` (no signature ever) and from `B` (bad
//!    signature).
//! 4. **Y** — good signature made by an expired key: the signature
//!    verifies, but the key that made it has expired. Same author-
//!    side authentication as `X` with a different aging boundary.
//! 5. **R** — good signature made by a revoked key: the signature
//!    verifies, but the key that made it was actively revoked by
//!    the operator. The strongest "signed but no longer trusted"
//!    signal — a downstream verifier may want to treat this as a
//!    structurally-distinct negative claim from `N` (operator
//!    explicitly *withdrew* trust, vs operator never signed).
//! 6. **B** — bad signature: GPG verified the signature against the
//!    claimed key AND it DID NOT MATCH. Cryptographic verification
//!    failure. The most load-bearing collapse the prior silent
//!    fallback lost — a downstream sekiban admission webhook
//!    fails-closed differently on `B` (evidence of compromise) than
//!    on `N` (no signing discipline configured).
//! 7. **E** — signature cannot be checked (e.g. missing public
//!    key): the signature is present and well-formed, but GPG could
//!    not resolve the signer's key to verify against. Distinct from
//!    `B` (key resolved AND verification failed) and from `N`
//!    (no signature at all).
//! 8. **N** — no signature: the commit was authored without
//!    `commit.gpgsign` enabled or `git commit -S`. No evidence
//!    either way of *what the operator would have signed*; just
//!    confirmation that the operator did not sign this commit.
//! 9. **ProbeAbsent** — `git` could not be spawned (git not on
//!    PATH, repo not initialized, I/O error), the commit could not
//!    be resolved (the `git_sha` argument is not a known
//!    commit-ish), or the captured output was not a recognized
//!    single-character `%G?` code (version drift broke the
//!    grammar). No probe ran successfully; no evidence was
//!    collected. The prior `unwrap_or(false)` reported the same
//!    value here as for `N` (no signature), conflating "the
//!    certification function could not probe" with "the operator
//!    chose not to sign this commit".
//!
//! ## Why nine arms, not two
//!
//! The pre-fix call site mapped nine worlds to a single bool. The
//! typed primitive preserves each distinctly so a downstream
//! verifier or future enrichment commit can recover the
//! kind-of-claim from the variant alone (THEORY §V.1: make invalid
//! states unrepresentable — a `commit_signed: false` that conflates
//! `B`, `X`, `Y`, `R`, `E`, `N`, and probe-failed is a flat state
//! that cannot drive a verifier that wants to treat any of them
//! differently). The `is_signed()` collapse pins the prior
//! behaviour exactly — `G` and `U` collapse to `true`, every other
//! arm collapses to `false` — so this commit is a pure honesty
//! refactor at the bool surface and an arm-distinguishing widening
//! at the type surface.
//!
//! A future enrichment commit may add `is_well_formed()` that
//! returns `true` for `G | U | X | Y | R | B | E` (every arm where
//! the operator *authored* a signature, including bad ones), or
//! `is_actively_trusted()` that returns `true` for `G` alone (the
//! strictest definition for production gating). Both compose over
//! the same nine arms without revisiting the parser surface.
//!
//! ## Why no `Malformed` arm
//!
//! `git log --format=%G?` emits one of eight fixed single-character
//! codes by construction. Any other captured output is, by the time
//! it reaches forge, indistinguishable from a probe failure: the
//! certification function got something back from `git` that does
//! not parse as a `%G?` code, so it has no evidence to record.
//! Folding "version drift" / "garbage stdout" into `ProbeAbsent`
//! mirrors the `KensaPolicyOutcome::ProbeAbsent` discipline (commit
//! c1e83d5) — a probe that returned an unparseable response yields
//! the same no-evidence state as a probe that did not run at all,
//! both at the bool surface and at the verifier-reconstruction
//! surface.
//!
//! ## What this commit does NOT do
//!
//! This commit introduces the typed primitive and routes the
//! `compute_source_attestation` call site through
//! `GitCommitSignatureOutcome::from_format_code` /
//! `is_signed()`. The Phase 1 source attestation's `commit_signed`
//! bool retains its pre-fix value on every input the pre-fix
//! parser would have accepted — `G` and `U` still collapse to
//! `true`, every other case still collapses to `false`. The
//! discriminators are now structurally distinct at the type level
//! so a future enrichment commit can widen `SourceAttestation` to
//! carry the verdict directly (a `signature_verdict` field whose
//! `Bad` / `Expired` / `Revoked` / `Unsigned` distinction
//! sekiban / in-toto-verify could escalate differently). Same
//! deferral shape as commit b98eb5a's
//! [`crate::security_scan::SbomProbeOutcome::Collected`] arm and
//! commit d81f639's [`crate::helm_lint::HelmLintOutcome::Passed`]
//! arm (typed primitive available, downstream enrichment in a
//! follow-up).
//!
//! ## Frontier inspiration
//!
//! git-log(1)'s own `%G?` grammar is the canonical commit-signature
//! probe surface — eight evidence-bearing codes plus the
//! probe-failed world the GPG verification layer reports. SLSA
//! v1.0 §"Source" requires commit-signature evidence to carry the
//! verifier's verdict (good / expired / revoked / bad), not a
//! single bool that collapses every negative state into one bucket.
//! in-toto's link grammar §"Materials" and sigstore's
//! `gitsign verify` flow both surface the per-key validity dimension
//! distinctly from the well-formedness dimension. An attestation
//! that records `commit_signed: false` against a commit whose
//! signature is `B` (cryptographic verification failure — evidence
//! of compromise) fails every reconciliation a `gitsign verify` /
//! `git verify-commit` re-run could surface against the same bytes.
//! The typed primitive names the gap honestly rather than inflating
//! it with a constant fold — the same discipline
//! [`crate::cosign::CosignVerifyOutcome::ProbeAbsent`],
//! [`crate::helm_provenance::HelmProvenanceOutcome::ProbeAbsent`],
//! [`crate::helm_lint::HelmLintOutcome::ProbeAbsent`],
//! [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`],
//! [`crate::security_scan::SbomProbeOutcome::Absent`], and
//! [`crate::security_scan::VulnScanProbeOutcome::Absent`] apply at
//! the image-signature, chart-signature, chart-quality,
//! chart-policy, SBOM, and vuln-scan layers.

/// Outcome of probing `git log -1 --format=%G?` for a commit's
/// signature verdict. The nine arms preserve the eight `%G?` codes
/// documented in git-log(1) plus the probe-failed world the prior
/// silent `unwrap_or(false)` collapsed into the same value as the
/// evidence-bearing negative codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitCommitSignatureOutcome {
    /// `%G?` reported `G`: good (valid) signature. GPG verified the
    /// signature against the signer's key AND the key chain
    /// resolved into the operator's trust path. The Phase 1 source
    /// attestation can honestly claim `commit_signed: true` here
    /// and in the `GoodUnknownValidity` arm; every other arm
    /// collapses to `false`.
    Good,
    /// `%G?` reported `U`: good signature with unknown validity.
    /// GPG verified the cryptographic signature, but the signer's
    /// key is not in any keyring path the operator trusts.
    /// Structurally distinct from `Good` so a future enrichment
    /// commit can surface the trust discriminator on the
    /// attestation (a signed-but-trust-unknown state is a different
    /// claim from a signed-and-trusted state for any verifier
    /// gating on trust-path resolution).
    GoodUnknownValidity,
    /// `%G?` reported `X`: good signature that has expired. The
    /// signature is well-formed and GPG verified it, but the
    /// signature itself carried an expiration that has now passed.
    /// The operator did author a cryptographic signature; the
    /// trust dimension has aged out. Distinct from `NotSigned` (no
    /// signature ever) and from `BadSignature` (signature did not
    /// verify).
    ExpiredSignature,
    /// `%G?` reported `Y`: good signature made by an expired key.
    /// The signature verifies, but the key that made it has
    /// expired. Same author-side authentication evidence as
    /// `ExpiredSignature` with a different aging boundary (the
    /// key vs the signature itself).
    ExpiredKey,
    /// `%G?` reported `R`: good signature made by a revoked key.
    /// The signature verifies, but the key that made it was
    /// actively revoked by the operator. The strongest "signed but
    /// no longer trusted" signal — distinct from `NotSigned`
    /// because the operator explicitly *withdrew* trust in this
    /// key after using it to sign.
    RevokedKey,
    /// `%G?` reported `B`: bad signature. GPG verified the
    /// signature against the claimed key AND it DID NOT MATCH —
    /// the cryptographic verification step failed outright. The
    /// most load-bearing collapse the prior silent fallback lost:
    /// a downstream sekiban admission webhook would fail-closed
    /// differently on `B` (evidence of compromise) than on
    /// `NotSigned` (no signing discipline configured), but the
    /// pre-fix `commit_signed: false` for both flattened the
    /// distinction at the attestation surface.
    BadSignature,
    /// `%G?` reported `E`: the signature cannot be checked (e.g.
    /// missing public key). The signature is present and
    /// well-formed, but GPG could not resolve the signer's key to
    /// verify against. Distinct from `BadSignature` (key resolved
    /// AND verification failed) and from `NotSigned` (no signature
    /// at all).
    Uncheckable,
    /// `%G?` reported `N`: no signature on the commit. The
    /// canonical "unsigned commit" state — the operator authored
    /// the commit without `commit.gpgsign` enabled or
    /// `git commit -S`. No evidence either way of *what the
    /// operator would have signed*; just confirmation that this
    /// commit carries no signature.
    NotSigned,
    /// `git` could not be spawned (git not on PATH, repo not
    /// initialized, I/O error), the commit could not be resolved
    /// (the `git_sha` argument is not a known commit-ish), or the
    /// captured output was not a recognized single-character
    /// `%G?` code (version drift broke the grammar). No probe ran
    /// successfully; no evidence was collected. The prior
    /// `unwrap_or(false)` reported the same value here as for
    /// `NotSigned`, conflating "the certification function could
    /// not probe git" with "the operator chose not to sign this
    /// commit".
    ProbeAbsent,
}

impl GitCommitSignatureOutcome {
    /// Parse the captured `git log -1 --format=%G?` stdout into a
    /// typed outcome. The grammar is one single-character code per
    /// git-log(1) — anything else (empty string, multi-character
    /// blob, version-drift output) collapses to [`ProbeAbsent`] so
    /// a probe whose response could not be parsed yields the same
    /// no-evidence state as a probe that could not run.
    ///
    /// Whitespace around the code is trimmed; git emits a trailing
    /// newline by default which the trim discipline removes before
    /// matching.
    ///
    /// [`ProbeAbsent`]: Self::ProbeAbsent
    pub fn from_format_code(captured: &str) -> Self {
        match captured.trim() {
            "G" => Self::Good,
            "U" => Self::GoodUnknownValidity,
            "X" => Self::ExpiredSignature,
            "Y" => Self::ExpiredKey,
            "R" => Self::RevokedKey,
            "B" => Self::BadSignature,
            "E" => Self::Uncheckable,
            "N" => Self::NotSigned,
            _ => Self::ProbeAbsent,
        }
    }

    /// True iff the `%G?` probe reported a code substantiating an
    /// actively-trusted commit signature — `G` (good and trusted)
    /// or `U` (good but unknown trust path). Every other arm
    /// collapses to `false` at this surface so the Phase 1
    /// `commit_signed` bool retains the pre-fix semantics exactly:
    /// `G` and `U` → `true`, `X` / `Y` / `R` / `B` / `E` / `N` /
    /// `ProbeAbsent` → `false`.
    ///
    /// A future enrichment commit may add `is_well_formed()` for
    /// `G | U | X | Y | R | B | E` (every arm with author-side
    /// signing evidence, including expired / revoked / bad), or
    /// `is_actively_trusted()` for `G` alone (the strictest
    /// definition). Both compose over the nine arms without
    /// changing this method.
    pub fn is_signed(&self) -> bool {
        matches!(self, Self::Good | Self::GoodUnknownValidity)
    }
}

crate::impl_probe_outcome!(GitCommitSignatureOutcome, ProbeAbsent);

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the nine-arm `is_signed` truth table: only `Good` and
    /// `GoodUnknownValidity` collapse to `true`. The other seven
    /// arms collapse to `false` at the bool surface but stay
    /// structurally distinct at the enum level — same shape as
    /// `test_is_passed_pins_all_arms` for
    /// [`crate::kensa_policy::KensaPolicyOutcome`] one layer over,
    /// and `test_is_verified_pins_all_arms` for
    /// [`crate::cosign::CosignVerifyOutcome`] two layers over.
    ///
    /// The pin is load-bearing for the honesty refactor: a future
    /// regression that widened `is_signed()` to accept `X` / `Y` /
    /// `R` (the "signed but trust-aged-out" arms) without an
    /// explicit attestation-surface widening would silently
    /// re-inflate Phase 1 claims against commits whose trust path
    /// has lapsed. A future regression that *narrowed* it to `G`
    /// alone would silently drop trust-unknown signatures that the
    /// pre-fix call site accepted.
    #[test]
    fn test_is_signed_pins_all_arms() {
        assert!(GitCommitSignatureOutcome::Good.is_signed());
        assert!(GitCommitSignatureOutcome::GoodUnknownValidity.is_signed());
        assert!(!GitCommitSignatureOutcome::ExpiredSignature.is_signed());
        assert!(!GitCommitSignatureOutcome::ExpiredKey.is_signed());
        assert!(!GitCommitSignatureOutcome::RevokedKey.is_signed());
        assert!(!GitCommitSignatureOutcome::BadSignature.is_signed());
        assert!(!GitCommitSignatureOutcome::Uncheckable.is_signed());
        assert!(!GitCommitSignatureOutcome::NotSigned.is_signed());
        assert!(!GitCommitSignatureOutcome::ProbeAbsent.is_signed());
    }

    /// Pin the eight-code `%G?` parser against every documented
    /// git-log(1) output. A future regression that re-orders the
    /// match arms or drops a code would fail one of these — the
    /// pin makes the eight evidence-bearing arms structurally
    /// inseparable from the parser surface.
    #[test]
    fn test_parser_recognizes_every_documented_g_code() {
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("G"),
            GitCommitSignatureOutcome::Good,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("U"),
            GitCommitSignatureOutcome::GoodUnknownValidity,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("X"),
            GitCommitSignatureOutcome::ExpiredSignature,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("Y"),
            GitCommitSignatureOutcome::ExpiredKey,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("R"),
            GitCommitSignatureOutcome::RevokedKey,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("B"),
            GitCommitSignatureOutcome::BadSignature,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("E"),
            GitCommitSignatureOutcome::Uncheckable,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("N"),
            GitCommitSignatureOutcome::NotSigned,
        );
    }

    /// `git log` emits a trailing newline by default and may pad
    /// captured output with surrounding whitespace — the parser
    /// must trim before matching so a `"G\n"` capture lands in the
    /// `Good` arm rather than collapsing to `ProbeAbsent` on the
    /// length mismatch. Mirrors the same trim discipline
    /// [`crate::kensa_policy::KensaPolicyOutcome::from_*`] would
    /// apply over `kensa verify chart`'s captured stdout if it
    /// were parsed at the text surface (it's not — kensa emits a
    /// typed report — but the discipline is the same).
    #[test]
    fn test_parser_trims_whitespace_around_code() {
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("G\n"),
            GitCommitSignatureOutcome::Good,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code(" U "),
            GitCommitSignatureOutcome::GoodUnknownValidity,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("\tB\r\n"),
            GitCommitSignatureOutcome::BadSignature,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("N\n\n\n"),
            GitCommitSignatureOutcome::NotSigned,
        );
    }

    /// Anything that is not a documented `%G?` code collapses to
    /// `ProbeAbsent` — empty captured output (probe spawned but
    /// produced nothing), unrecognized single-character codes
    /// (version drift), multi-character blobs (the grammar
    /// broke). The fold mirrors
    /// [`crate::kensa_policy::KensaPolicyOutcome::ProbeAbsent`]'s
    /// "probe-returned-something-unparseable = no-evidence" rule:
    /// a probe whose response cannot be parsed yields the same
    /// state as a probe that did not run, because in either case
    /// no evidence was collected.
    #[test]
    fn test_unrecognized_output_collapses_to_probe_absent() {
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code(""),
            GitCommitSignatureOutcome::ProbeAbsent,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("\n"),
            GitCommitSignatureOutcome::ProbeAbsent,
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("Z"),
            GitCommitSignatureOutcome::ProbeAbsent,
            "Z is not a documented %G? code; treat as probe-absent",
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("g"),
            GitCommitSignatureOutcome::ProbeAbsent,
            "lowercase g is not a documented %G? code; %G? codes \
             are uppercase per git-log(1)",
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("GG"),
            GitCommitSignatureOutcome::ProbeAbsent,
            "multi-character output is unparseable; collapse to \
             probe-absent rather than guessing the first code",
        );
        assert_eq!(
            GitCommitSignatureOutcome::from_format_code("fatal: ambiguous argument 'HEAD'"),
            GitCommitSignatureOutcome::ProbeAbsent,
            "git's error envelope leaking into stdout is a probe \
             failure; collapse to probe-absent",
        );
    }

    /// The nine arms are mutually distinct under structural
    /// equality. Pins the load-bearing discriminator-preservation
    /// invariant the typed primitive exists to enforce: a `B`
    /// (bad signature — evidence of compromise) and an `N` (no
    /// signature ever) collapse to the same `false` at the bool
    /// surface but remain structurally distinct at the enum
    /// level. A downstream verifier walking the enum recovers
    /// the kind-of-claim from the variant alone, where the
    /// pre-fix `unwrap_or(false)` collapsed seven negative arms
    /// into one indistinguishable bool.
    ///
    /// Pinning every arm against every other arm (not just the
    /// trust-positive vs trust-negative split) catches the
    /// regression where a future commit conflated `ExpiredKey`
    /// with `RevokedKey` (similar enough at the trust-aging
    /// surface that someone could merge them) — keeping them
    /// distinct preserves the operator-revoked-trust discriminator
    /// a future `sekiban` admission webhook may want to escalate.
    #[test]
    fn test_arms_are_structurally_distinct() {
        let arms = [
            GitCommitSignatureOutcome::Good,
            GitCommitSignatureOutcome::GoodUnknownValidity,
            GitCommitSignatureOutcome::ExpiredSignature,
            GitCommitSignatureOutcome::ExpiredKey,
            GitCommitSignatureOutcome::RevokedKey,
            GitCommitSignatureOutcome::BadSignature,
            GitCommitSignatureOutcome::Uncheckable,
            GitCommitSignatureOutcome::NotSigned,
            GitCommitSignatureOutcome::ProbeAbsent,
        ];
        for (i, a) in arms.iter().enumerate() {
            for (j, b) in arms.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(
                        a, b,
                        "arms {i} and {j} must be structurally distinct \
                         to preserve the verdict discriminator a downstream \
                         verifier walks; the pre-fix unwrap_or(false) \
                         collapsed seven of these into one bucket",
                    );
                }
            }
        }
    }

    /// Load-bearing honesty pin: the `B` (bad signature —
    /// cryptographic verification failed, evidence of compromise)
    /// arm and the `N` (no signature ever — operator chose not to
    /// sign) arm BOTH collapse to `commit_signed: false` at the
    /// pre-fix bool surface, but represent fundamentally distinct
    /// security claims. The pre-fix `unwrap_or(false)` fold lost
    /// the distinction; the typed primitive preserves it
    /// structurally so a future enrichment commit can route them
    /// to distinct attestation fields (e.g. a sekiban policy that
    /// fails-closed on `B` in any environment but admits `N` in
    /// dev / staging cannot be expressed against the pre-fix
    /// boolean). The pin catches a future regression that would
    /// conflate `B` and `N` at the type level (merging into a
    /// single `Unsigned` arm "for simplicity") or that would
    /// silently flip `is_signed()` to return `true` for `B` /
    /// `N` / `ProbeAbsent`.
    #[test]
    fn test_bad_signature_distinct_from_unsigned() {
        let bad = GitCommitSignatureOutcome::BadSignature;
        let unsigned = GitCommitSignatureOutcome::NotSigned;
        let absent = GitCommitSignatureOutcome::ProbeAbsent;
        assert_ne!(
            bad, unsigned,
            "BadSignature (cryptographic verification failed) and \
             NotSigned (no signature ever) must be structurally \
             distinct — the pre-fix unwrap_or(false) collapsed both \
             to the same value, losing the evidence-of-compromise \
             discriminator a downstream sekiban policy needs",
        );
        assert_ne!(
            bad, absent,
            "BadSignature and ProbeAbsent must be structurally \
             distinct — a probe that ran and reported cryptographic \
             failure is fundamentally different evidence from a \
             probe that did not run at all",
        );
        assert_ne!(
            unsigned, absent,
            "NotSigned and ProbeAbsent must be structurally \
             distinct — a probe that ran and confirmed the absence \
             of any signature is fundamentally different from a \
             probe that could not run to check",
        );
        // All three collapse to the same `commit_signed` bool at
        // the Phase 1 attestation surface (the pre-fix behaviour
        // this commit preserves at the bool layer); the
        // structural distinction is what a future enrichment
        // walks.
        assert!(!bad.is_signed());
        assert!(!unsigned.is_signed());
        assert!(!absent.is_signed());
    }

    /// Pin the `X` / `Y` / `R` (trust-aged-out) arms collapse to
    /// `is_signed() == false`. The pre-fix `s.trim() == "G" || s
    /// .trim() == "U"` collapse dropped each of these into the
    /// "false" bucket at the bool surface, matching the
    /// strictest "actively trusted right now" semantics for
    /// Phase 1. The typed primitive preserves that exact
    /// behaviour at the bool surface (this is a pure honesty
    /// refactor, not a semantic widening) while making the three
    /// trust-aged arms structurally distinct so a future
    /// enrichment commit can surface them on the attestation
    /// (e.g. a `signature_verdict: "expired-key"` field).
    ///
    /// The pin catches a future regression that widened
    /// `is_signed()` to accept `X` / `Y` / `R` without an
    /// explicit attestation-surface widening — which would
    /// silently re-inflate Phase 1 claims for commits whose
    /// trust path has lapsed.
    #[test]
    fn test_trust_aged_arms_collapse_to_unsigned_at_bool_surface() {
        // Each of these arms represents "the operator did
        // author a cryptographic signature, but the trust
        // dimension is no longer current". They are
        // structurally distinct from `Good` / `GoodUnknownValidity`
        // (still-trusted) and from `NotSigned` (no signature
        // ever). At the bool surface they collapse to `false`
        // matching pre-fix semantics; at the enum surface they
        // remain distinct so a future enrichment can recover them.
        for aged in [
            GitCommitSignatureOutcome::ExpiredSignature,
            GitCommitSignatureOutcome::ExpiredKey,
            GitCommitSignatureOutcome::RevokedKey,
        ] {
            assert!(
                !aged.is_signed(),
                "{aged:?} must collapse to is_signed()=false at the \
                 bool surface to preserve pre-fix semantics; the \
                 enum-level distinction from NotSigned / BadSignature \
                 is what a future enrichment walks",
            );
            assert_ne!(aged, GitCommitSignatureOutcome::Good);
            assert_ne!(aged, GitCommitSignatureOutcome::GoodUnknownValidity);
            assert_ne!(aged, GitCommitSignatureOutcome::NotSigned);
            assert_ne!(aged, GitCommitSignatureOutcome::BadSignature);
        }
    }

    /// End-to-end load-bearing pin: every documented `%G?` code
    /// parses into the arm whose `is_signed()` matches the
    /// pre-fix `s.trim() == "G" || s.trim() == "U"` collapse,
    /// for every documented code. This is the bool-surface
    /// equivalence the honesty refactor preserves — any future
    /// regression that drifted the parser AND the bool collapse
    /// in opposite directions would fail this pin even if the
    /// individual `from_format_code` and `is_signed()` tests
    /// still passed.
    #[test]
    fn test_parser_to_is_signed_matches_pre_fix_collapse() {
        // Mirrors the pre-fix expression `s.trim() == "G" || s.trim() == "U"`
        // against every documented `%G?` code and against the
        // probe-failed sentinels the pre-fix `unwrap_or(false)`
        // would have driven into the false bucket.
        let expected = |code: &str| matches!(code.trim(), "G" | "U");
        for code in [
            "G",
            "U",
            "X",
            "Y",
            "R",
            "B",
            "E",
            "N",
            "G\n",
            "U ",
            " B\n",
            "",
            "Z",
            "g",
            "GG",
            "fatal: ambiguous argument 'HEAD'",
        ] {
            assert_eq!(
                GitCommitSignatureOutcome::from_format_code(code).is_signed(),
                expected(code),
                "parser→is_signed must match the pre-fix bool collapse \
                 exactly for code {code:?}; the honesty refactor \
                 preserves bool-surface semantics while widening the \
                 type surface",
            );
        }
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent; the
    /// eight format-code arms (`Good` / `GoodUnknownValidity` /
    /// `ExpiredSignature` / `ExpiredKey` / `RevokedKey` / `BadSignature`
    /// / `Uncheckable` / `NotSigned`) all identify as not-absent.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(GitCommitSignatureOutcome::ProbeAbsent.is_probe_absent());
        for arm in [
            GitCommitSignatureOutcome::Good,
            GitCommitSignatureOutcome::GoodUnknownValidity,
            GitCommitSignatureOutcome::ExpiredSignature,
            GitCommitSignatureOutcome::ExpiredKey,
            GitCommitSignatureOutcome::RevokedKey,
            GitCommitSignatureOutcome::BadSignature,
            GitCommitSignatureOutcome::Uncheckable,
            GitCommitSignatureOutcome::NotSigned,
        ] {
            assert!(
                !arm.is_probe_absent(),
                "{arm:?} must not identify as absent"
            );
        }
    }
}
