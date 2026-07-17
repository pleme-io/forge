//! Typed cosign-verify probe outcome for forge's Phase 1 image attestation.
//!
//! `cosign verify <image>` distinguishes three operational worlds, and the
//! prior call site (`commands/attestation.rs::compute_image_attestation`)
//! collapsed all three into a single `is_ok()` boolean before writing
//! `cosign_verified` into the Phase 1 image attestation:
//!
//! 1. **Probe absent** — cosign is not on PATH / the spawn surface itself
//!    fails. No probe ran. There is no evidence either way.
//! 2. **Verify failed** — cosign ran and returned a non-zero exit. The
//!    probe ran and reported a negative result: the image is not signed,
//!    or the signature did not verify against the expected key/identity.
//! 3. **Verified** — cosign returned exit 0 with a structured payload
//!    (the `SimpleContainerImage` envelope cosign emits under `--output
//!    json`) that names the cosigned manifest digest and, for keyless
//!    signatures, the OIDC signer Subject/Issuer.
//!
//! The Phase 1 image attestation can only honestly claim `cosign_verified:
//! true` in case (3). Cases (1) and (2) describe distinct worlds — *no
//! evidence collected* vs *negative evidence collected* — and the prior
//! `is_ok()` fold conflated them with each other AND with case (3) when
//! the probe returned exit 0 against arbitrary stdout, even an empty bag.
//!
//! ## Why a typed enum, not a bool
//!
//! THEORY §V.4 Phase 1 attestation pattern-matches on a structural-record
//! tuple `(operation, exit_code, stderr)` to recover the probe shape. A
//! collapsed `bool` discards two of the three discriminators. This module
//! is the typed peer of [`crate::oci_manifest`] (manifest-identity oracle)
//! and [`crate::tree_listing`] / [`crate::store_path`] (source / build
//! identity oracles): each names the canonical shape of one external probe
//! the attestation chain depends on, so a call site cannot accidentally
//! lose a discriminator at the boundary. The spawn-vs-op-vs-empty
//! distinction lives at the type level via [`CosignVerifyOutcome`]; the
//! call site flows the three arms through [`crate::retry::classify_capture
//! _query`] (the canonical sync/async-agnostic spawn-vs-op primitive)
//! directly, so the boolean field on `ImageAttestation` is computed once
//! by [`CosignVerifyOutcome::is_verified`] over the typed shape — never
//! by a `Result::is_ok` over an opaque envelope.
//!
//! ## Frontier inspiration
//!
//! `sigstore`'s own verifier (cosign / Rekor) emits the `SimpleContainer
//! Image` envelope as its canonical attestation receipt — a JSON array
//! whose entries each carry `critical.image.docker-manifest-digest` (the
//! cosigned blob identity) and `optional.{Subject,Issuer}` (the keyless
//! OIDC identity, for Fulcio-issued certificates). A downstream verifier
//! that asks "is this image signed?" answers it by parsing this envelope
//! and recovering both the manifest digest AND the signer identity. The
//! prior `is_ok()` fold silently asserted "yes" on the existence of *any*
//! exit-0 stdout, including the empty array `[]` cosign emits for some
//! upstream-stripped manifests — false by construction whenever the
//! upstream registry's sigstore tooling does not actually issue a
//! signature receipt.

use serde::Deserialize;

/// Outcome of probing `cosign verify --output json` against a registry
/// image reference. The four arms preserve the spawn-vs-op-vs-empty-vs-
/// verified distinction the Phase 1 image attestation depends on; the
/// prior `Result<_,_>::is_ok()` collapse conflated all four.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignVerifyOutcome {
    /// cosign ran AND returned a structurally-valid signature payload.
    /// The Phase 1 image attestation can honestly claim
    /// `cosign_verified: true` only in this arm. `signer_identity` carries
    /// the parsed OIDC Subject (preferred) or Issuer (fallback) from the
    /// first valid payload, populating the `ImageAttestation::
    /// signer_identity` field that previously hardcoded `None`.
    /// `manifest_digest` carries the cosigned manifest digest from the
    /// first valid payload — the cross-check a downstream verifier
    /// reconciles against the `manifest_hash` field on the same record.
    Verified {
        signer_identity: Option<String>,
        manifest_digest: Option<String>,
    },
    /// cosign ran (spawn succeeded, exit 0) but the parsed output carried
    /// no structurally-valid signature payload — empty array, missing
    /// `critical.image.docker-manifest-digest`, malformed JSON, etc. The
    /// probe ran, found nothing. The prior `is_ok()` fold incorrectly
    /// reported `true` here.
    Unverified,
    /// cosign ran (spawn succeeded) but returned non-zero exit. The probe
    /// ran and reported negative: the image is not signed, or the
    /// signature did not verify against the requested identity/key. The
    /// prior `is_ok()` fold reported `false` here (correctly), but lost
    /// the discriminator that distinguishes negative evidence from absent
    /// evidence — both flowed into one `false`.
    VerifyFailed,
    /// cosign could not be spawned (not on PATH, absent absolute path,
    /// permission error, OS-level fork failure). No probe was made; no
    /// evidence was collected. The prior `is_ok()` fold reported `false`
    /// here, but a Phase 1 attestation that records `cosign_verified:
    /// false` without distinguishing "absent probe" from "explicit
    /// negative" is ambiguous to a downstream verifier — the call site
    /// can now log the absent-probe arm distinctly.
    ProbeAbsent,
}

impl CosignVerifyOutcome {
    /// True iff the cosign probe ran AND returned a structurally-valid
    /// signature attestation. The boolean the Phase 1 image attestation's
    /// `cosign_verified` field carries. The other three arms collapse to
    /// `false` at this surface — they remain distinct at the enum level
    /// so the call site can record them separately if needed.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The parsed signer identity for the verified arm, or `None`
    /// otherwise. Drives the `ImageAttestation::signer_identity` field
    /// the prior code hardcoded to `None` because the boolean fold had
    /// nowhere to recover the identity from.
    pub fn signer_identity(&self) -> Option<&str> {
        match self {
            Self::Verified {
                signer_identity, ..
            } => signer_identity.as_deref(),
            _ => None,
        }
    }
}

crate::impl_probe_outcome!(CosignVerifyOutcome, ProbeAbsent);
crate::impl_verified_outcome!(CosignVerifyOutcome);

/// Parse the stdout of a successful `cosign verify --output json` probe
/// into a [`CosignVerifyOutcome`].
///
/// cosign emits a JSON array of `SimpleContainerImage` envelopes; each
/// envelope's `critical.image.docker-manifest-digest` is the cosigned
/// blob identity, and `optional.{Subject,Issuer}` are the keyless OIDC
/// signer identity (for Fulcio-issued certificates). A payload whose
/// `docker-manifest-digest` does not parse as a well-formed
/// [`crate::oci_manifest::ContentDigest`] — missing, whitespace-only,
/// bare `sha256:garbage`, uppercase-hex, wrong-length hex,
/// unsupported-algorithm (`md5:...`, `sha1:...`), or internal
/// whitespace at the algo/hex boundary — is structurally invalid as a
/// signature receipt and is dropped from the valid-payload set. This
/// mirrors the `oci_manifest::canonical_manifest_fingerprint` skip-
/// malformed discipline (the image-side peer), the
/// `oci_architecture::EmbeddedInConfig` gate (arm 3 of the manifest
/// detection ladder), and the `helm_provenance::find_tarball_sha256`
/// route (chart-side `.prov` peer): every Phase 1 attestation surface
/// that consumes a `<algorithm>:<hex>` digest string validates via
/// [`crate::oci_manifest::ContentDigest::parse`] at the extraction
/// frontier, not via a per-consumer restatement of "well-formed
/// digest". An empty valid-payload set collapses to
/// [`CosignVerifyOutcome::Unverified`] — the probe ran, found nothing.
///
/// The signer identity is taken from the first valid payload that
/// carries a non-empty `Subject` (the human principal); a Fulcio-only
/// receipt without Subject falls back to `Issuer` (the OIDC provider).
/// `None` here means the receipt was keyless-bare or key-based without
/// a public identity attached.
pub fn parse_verify_output(stdout: &str) -> CosignVerifyOutcome {
    let Ok(payloads) = serde_json::from_str::<Vec<SimpleContainerImage>>(stdout.trim()) else {
        return CosignVerifyOutcome::Unverified;
    };
    let valid: Vec<(&SimpleContainerImage, crate::oci_manifest::ContentDigest)> = payloads
        .iter()
        .filter_map(|p| {
            let raw = p.critical.image.docker_manifest_digest.as_deref()?;
            let digest = crate::oci_manifest::ContentDigest::parse(raw).ok()?;
            Some((p, digest))
        })
        .collect();
    let Some((_, first_digest)) = valid.first() else {
        return CosignVerifyOutcome::Unverified;
    };
    let manifest_digest = Some(first_digest.as_str().to_string());
    let signer_identity = valid
        .iter()
        .find_map(|(p, _)| p.optional.as_ref().and_then(pick_identity));
    CosignVerifyOutcome::Verified {
        signer_identity,
        manifest_digest,
    }
}

/// Pick the OIDC identity from a SimpleContainerImage `optional` block:
/// prefer `Subject` (the human / service principal), fall back to
/// `Issuer` (the OIDC provider URL). Whitespace-only entries are treated
/// as absent so a registry that emits empty strings does not leak them
/// into the attestation.
fn pick_identity(o: &Optional) -> Option<String> {
    let nonblank = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    o.subject
        .as_deref()
        .and_then(nonblank)
        .or_else(|| o.issuer.as_deref().and_then(nonblank))
}

#[derive(Deserialize)]
struct SimpleContainerImage {
    critical: Critical,
    #[serde(default)]
    optional: Option<Optional>,
}

#[derive(Deserialize)]
struct Critical {
    #[serde(default)]
    image: Image,
}

#[derive(Default, Deserialize)]
struct Image {
    #[serde(rename = "docker-manifest-digest", default)]
    docker_manifest_digest: Option<String>,
}

#[derive(Deserialize)]
struct Optional {
    #[serde(rename = "Subject", default)]
    subject: Option<String>,
    #[serde(rename = "Issuer", default)]
    issuer: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic cosign keyless receipt: one SimpleContainerImage
    /// envelope with a sha256 manifest digest and a Fulcio-issued
    /// Subject/Issuer. Parses to [`CosignVerifyOutcome::Verified`] with
    /// the Subject preferred over the Issuer.
    #[test]
    fn test_parse_keyless_receipt_extracts_subject_and_digest() {
        let stdout = r#"[
            {
                "critical": {
                    "identity": {"docker-reference": "ghcr.io/example/svc"},
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                    "type": "cosign container image signature"
                },
                "optional": {
                    "Subject": "user@example.com",
                    "Issuer": "https://accounts.example.com"
                }
            }
        ]"#;
        let out = parse_verify_output(stdout);
        assert!(out.is_verified(), "structured receipt must verify");
        let CosignVerifyOutcome::Verified {
            signer_identity,
            manifest_digest,
        } = out
        else {
            panic!("expected Verified");
        };
        assert_eq!(
            signer_identity.as_deref(),
            Some("user@example.com"),
            "Subject is preferred over Issuer as the signer identity"
        );
        assert_eq!(
            manifest_digest.as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    /// A Fulcio-only receipt without a Subject falls back to Issuer as
    /// the signer identity — better than `None` whenever any public
    /// identity rode the receipt.
    #[test]
    fn test_parse_falls_back_to_issuer_when_subject_absent() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
                    "type": "cosign container image signature"
                },
                "optional": {"Issuer": "https://token.actions.githubusercontent.com"}
            }
        ]"#;
        let CosignVerifyOutcome::Verified {
            signer_identity, ..
        } = parse_verify_output(stdout)
        else {
            panic!("expected Verified");
        };
        assert_eq!(
            signer_identity.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
    }

    /// Empty `Subject` AND empty `Issuer` (whitespace-only) is treated
    /// as no identity — the attestation must not leak empty strings
    /// into `signer_identity`. The receipt still verifies (the manifest
    /// digest is present) but the identity field is honest `None`.
    #[test]
    fn test_parse_whitespace_identity_is_none() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
                },
                "optional": {"Subject": "   ", "Issuer": "\t\n"}
            }
        ]"#;
        let CosignVerifyOutcome::Verified {
            signer_identity, ..
        } = parse_verify_output(stdout)
        else {
            panic!("expected Verified");
        };
        assert_eq!(signer_identity, None);
    }

    /// **Load-bearing fail-before/pass-after pin.** An empty JSON array
    /// `[]` is what cosign emits when invoked against an image whose
    /// upstream registry stripped sigstore receipts — exit 0, but no
    /// payload. The prior `is_ok()` fold reported `cosign_verified:
    /// true` here because the spawn succeeded and the exit was 0. The
    /// typed parser correctly collapses to [`CosignVerifyOutcome::
    /// Unverified`], so [`CosignVerifyOutcome::is_verified`] returns
    /// `false` and the Phase 1 image attestation does not assert a
    /// signature it never witnessed.
    #[test]
    fn test_parse_empty_array_is_unverified() {
        let out = parse_verify_output("[]");
        assert_eq!(out, CosignVerifyOutcome::Unverified);
        assert!(!out.is_verified(), "empty bag must not claim verification");
    }

    /// A payload missing `critical.image.docker-manifest-digest` is
    /// structurally invalid as a signature receipt — it cannot be
    /// cross-checked against the image's manifest hash. The parser
    /// drops it from the valid set and the outcome is `Unverified`.
    /// Same load-bearing property as the empty-array case: a malformed
    /// receipt must not claim verification.
    #[test]
    fn test_parse_missing_digest_is_unverified() {
        let stdout = r#"[
            {
                "critical": {"image": {}, "type": "cosign container image signature"},
                "optional": {"Subject": "user@example.com"}
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// Malformed JSON (truncated probe output, registry-error HTML
    /// page leaked into stdout, garbage) collapses to `Unverified` —
    /// the parser cannot recover a signature receipt from non-JSON,
    /// and the prior `is_ok()` fold dangerously reported `true` for
    /// any exit-0 stdout regardless of content.
    #[test]
    fn test_parse_malformed_json_is_unverified() {
        assert_eq!(parse_verify_output(""), CosignVerifyOutcome::Unverified);
        assert_eq!(
            parse_verify_output("not json at all"),
            CosignVerifyOutcome::Unverified
        );
        assert_eq!(
            parse_verify_output("[{\"critical\":"),
            CosignVerifyOutcome::Unverified
        );
        // A top-level object (not an array, as cosign emits) is also
        // not a valid receipt envelope.
        assert_eq!(
            parse_verify_output("{\"critical\":{\"image\":{}}}"),
            CosignVerifyOutcome::Unverified
        );
    }

    /// When multiple payloads ride the same receipt (cosign emits one
    /// per signature when an image carries several), the manifest digest
    /// and signer identity come from the first valid payload. The
    /// signer-identity scan still walks all payloads so an earlier
    /// payload missing identity but a later one carrying it does not
    /// silently lose the identity — but the manifest-digest claim is
    /// pinned to the first payload, matching the receipt convention.
    #[test]
    fn test_parse_multi_payload_takes_first_digest_and_first_identity() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"}
                }
            },
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
                },
                "optional": {"Subject": "later-signer@example.com"}
            }
        ]"#;
        let CosignVerifyOutcome::Verified {
            signer_identity,
            manifest_digest,
        } = parse_verify_output(stdout)
        else {
            panic!("expected Verified");
        };
        assert_eq!(
            manifest_digest.as_deref(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
            "manifest digest pinned to first payload"
        );
        assert_eq!(
            signer_identity.as_deref(),
            Some("later-signer@example.com"),
            "signer identity recovered from a later payload when the first lacks one"
        );
    }

    /// `is_verified` returns the boolean every Phase 1 image attestation
    /// writes into `ImageAttestation::cosign_verified`. Pin all four
    /// arms so a future refactor that flips an arm's truthiness fails
    /// loudly rather than silently inflating / deflating the Phase 1
    /// claim.
    #[test]
    fn test_is_verified_pins_all_arms() {
        assert!(CosignVerifyOutcome::Verified {
            signer_identity: None,
            manifest_digest: None,
        }
        .is_verified());
        assert!(!CosignVerifyOutcome::Unverified.is_verified());
        assert!(!CosignVerifyOutcome::VerifyFailed.is_verified());
        assert!(!CosignVerifyOutcome::ProbeAbsent.is_verified());
    }

    /// `signer_identity` returns `None` for every non-Verified arm —
    /// the attestation cannot recover an identity from a probe that
    /// found no payload, that returned negative, or that never ran.
    #[test]
    fn test_signer_identity_none_for_non_verified_arms() {
        assert_eq!(CosignVerifyOutcome::Unverified.signer_identity(), None);
        assert_eq!(CosignVerifyOutcome::VerifyFailed.signer_identity(), None);
        assert_eq!(CosignVerifyOutcome::ProbeAbsent.signer_identity(), None);
        assert_eq!(
            CosignVerifyOutcome::Verified {
                signer_identity: Some("u@e".to_string()),
                manifest_digest: None,
            }
            .signer_identity(),
            Some("u@e")
        );
    }

    /// `ProbeOutcome` impl pin: `ProbeAbsent` identifies as absent;
    /// `Verified`, `Unverified`, and `VerifyFailed` do not.
    #[test]
    fn test_probe_outcome_impl() {
        use crate::probe_outcome::ProbeOutcome;
        assert!(CosignVerifyOutcome::ProbeAbsent.is_probe_absent());
        assert!(!CosignVerifyOutcome::Verified {
            signer_identity: None,
            manifest_digest: None,
        }
        .is_probe_absent());
        assert!(!CosignVerifyOutcome::Unverified.is_probe_absent());
        assert!(!CosignVerifyOutcome::VerifyFailed.is_probe_absent());
    }

    /// **Load-bearing fail-before / pass-after pin.** A cosign receipt
    /// whose `docker-manifest-digest` names an unsupported algorithm
    /// (`md5:...`, `sha1:...`) is structurally invalid as an OCI /
    /// Docker content digest: the registry cannot be asked to fetch a
    /// blob under that name via the standard blob API. The prior
    /// `!s.trim().is_empty()` gate admitted the payload and inflated
    /// the Phase 1 `manifest_digest` claim with a digest no verifier
    /// can substantiate. Routing the filter through
    /// [`crate::oci_manifest::ContentDigest::parse`] collapses this
    /// receipt to [`CosignVerifyOutcome::Unverified`] — the probe ran,
    /// no well-formed digest witnessed.
    #[test]
    fn test_parse_unsupported_algorithm_digest_is_unverified() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "md5:0123456789abcdef0123456789abcdef"}
                },
                "optional": {"Subject": "u@e"}
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// A `sha256:` prefix with a body that is not lowercase-hex of the
    /// algorithm's canonical length — here 32 chars, half the sha256
    /// hex length — is malformed. The old gate admitted it; the
    /// `ContentDigest::parse` route rejects it and the outcome
    /// collapses to `Unverified`. Same drift class as the last
    /// commit's chart-side peer (`helm_provenance` `find_tarball_sha256`).
    #[test]
    fn test_parse_wrong_length_sha256_hex_is_unverified() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef"}
                }
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// An uppercase-hex body under a valid algorithm is malformed per
    /// the OCI Distribution Spec: content-addressed digests are
    /// lowercase-hex. The prior gate admitted it (it was non-empty
    /// after trim); the typed parse rejects it.
    #[test]
    fn test_parse_uppercase_hex_digest_is_unverified() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"}
                }
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// A non-hex byte inside an otherwise correctly-shaped 64-char body
    /// (here `g` at position 4) fails the lowercase-hex predicate. The
    /// prior string-non-empty gate admitted it.
    #[test]
    fn test_parse_non_hex_byte_in_digest_is_unverified() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123g56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
                }
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// A bare `garbage` string with no `<algorithm>:<hex>` separator
    /// is not a digest by any grammar. The prior gate admitted it and
    /// wrote `manifest_digest: Some("garbage")` into the Phase 1
    /// receipt. The typed parse rejects it.
    #[test]
    fn test_parse_missing_algorithm_separator_is_unverified() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "garbage"}
                }
            }
        ]"#;
        assert_eq!(parse_verify_output(stdout), CosignVerifyOutcome::Unverified);
    }

    /// Per-payload filter: when the first payload's digest is
    /// malformed and a later payload carries a well-formed one, the
    /// receipt is still verified — the malformed payload is dropped
    /// from the valid set and the second one becomes the "first
    /// valid". The manifest digest and signer identity come from
    /// that payload. This pins that the invalid-digest filter is
    /// per-payload, not receipt-wide, so a partially-corrupted
    /// receipt still recovers what it structurally can.
    #[test]
    fn test_parse_skips_invalid_first_payload_uses_next_valid() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:short"}
                },
                "optional": {"Subject": "dropped@example.com"}
            },
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
                },
                "optional": {"Subject": "kept@example.com"}
            }
        ]"#;
        let CosignVerifyOutcome::Verified {
            signer_identity,
            manifest_digest,
        } = parse_verify_output(stdout)
        else {
            panic!("expected Verified");
        };
        assert_eq!(
            manifest_digest.as_deref(),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
            "malformed first payload is dropped; second payload's digest is the receipt's"
        );
        assert_eq!(signer_identity.as_deref(), Some("kept@example.com"));
    }

    /// The `manifest_digest` field on the verified arm round-trips
    /// through `ContentDigest::parse` — i.e. any value that appears
    /// there could be re-parsed by a downstream cross-checker without
    /// error. Pins the invariant explicitly so a future refactor that
    /// reverts the filter to a string-non-empty check fails this test.
    #[test]
    fn test_verified_manifest_digest_round_trips_through_content_digest_parse() {
        let stdout = r#"[
            {
                "critical": {
                    "image": {"docker-manifest-digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
                }
            }
        ]"#;
        let CosignVerifyOutcome::Verified {
            manifest_digest, ..
        } = parse_verify_output(stdout)
        else {
            panic!("expected Verified");
        };
        let raw = manifest_digest.expect("verified arm must carry a digest");
        let round_tripped = crate::oci_manifest::ContentDigest::parse(&raw)
            .expect("verified manifest_digest must re-parse via ContentDigest::parse");
        assert_eq!(round_tripped.algorithm(), "sha256");
        assert_eq!(round_tripped.as_str(), raw);
    }
}
