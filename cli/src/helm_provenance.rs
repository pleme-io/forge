//! Typed Helm `.prov` provenance probe outcome for forge's Phase 1 chart
//! attestation.
//!
//! `helm package --sign` writes a sibling `<chart-name>-<version>.tgz.prov`
//! next to the packaged chart tarball: an OpenPGP cleartext-signed
//! document (RFC 4880 §7) whose signed body carries the `Chart.yaml`
//! metadata AND a `files:` map keyed by tarball name → `sha256:<hex>`
//! digest of the tarball bytes. The probe distinguishes the four
//! operational worlds the prior `provenance: false` hardcode in
//! `commands/attestation.rs::compute_chart_attestation` flattened into a
//! single negative claim:
//!
//! 1. **Probe absent** — no `.prov` file exists alongside the chart
//!    tarball. No probe ran. There is no evidence either way.
//! 2. **Verify failed** — a file exists at the `.prov` location, but its
//!    OpenPGP cleartext framing did not parse (missing markers,
//!    truncated, garbage). The probe ran and the file did not
//!    structurally validate as a Helm provenance document — negative
//!    evidence.
//! 3. **Unverified** — the cleartext framing parses, but no
//!    `files:` entry naming the expected `<chart-name>-<version>.tgz`
//!    carried a `sha256:<hex>` digest. The probe ran, the file is a
//!    well-formed provenance document, but it does not name the chart
//!    whose attestation we are sealing.
//! 4. **Verified** — the cleartext framing parses AND the `files:` map
//!    yields a `sha256:<hex>` for the expected tarball name. The Phase 1
//!    chart attestation can honestly claim `provenance_verified: true`
//!    only in this arm. `signed_chart_hash` is the recovered hex digest —
//!    the cross-check a downstream verifier reconciles against the
//!    `chart_hash` field on the same record (and against the actual
//!    tarball bytes on disk, when re-verification runs).
//!
//! ## Why a typed enum, not a bool
//!
//! THEORY §V.4 Phase 1 attestation pattern-matches on the structural
//! record of one external probe to recover the probe shape (probe-absent
//! vs probe-found-nothing vs probe-found-malformed vs
//! probe-found-evidence). The prior `false` hardcode discarded all four
//! discriminators and lied by construction whenever the chart WAS
//! signed and the `.prov` file DID name the tarball — a downstream
//! verifier reconciling the Phase 1 chart record against the actual
//! `.prov` artifact would find a signed `sha256:<hex>` claim the
//! attestation said was absent.
//!
//! This module is the chart-side peer of [`crate::cosign`]
//! ([`crate::cosign::CosignVerifyOutcome`], the four-arm `cosign verify`
//! probe outcome over sigstore's `SimpleContainerImage` envelope), and
//! the typed-outcome idiom is the one [`crate::oci_manifest`] /
//! [`crate::tree_listing`] / [`crate::store_path`] /
//! [`crate::chart_listing`] established for the four canonical-form
//! identity oracles. Each names the structured shape of one external
//! probe the attestation chain depends on so the call site cannot
//! accidentally lose a discriminator at the boundary.
//!
//! ## What this commit does NOT do
//!
//! This is a Phase 1 *evidence-collection* primitive: it parses the
//! cleartext framing Helm writes and recovers the signed-chart-hash
//! claim. It does NOT cryptographically verify the OpenPGP signature
//! itself against a keyring (`helm verify` does that with a configured
//! `--keyring`). A future commit can layer a `helm verify` shell-out
//! with the same four-arm typed-outcome shape — `Verified` would then
//! mean the signature itself verified against the keyring, not merely
//! that the framing parsed. The `signer_key_id` field on the `Verified`
//! arm is reserved for that future packet parser (OpenPGP v4 signature
//! packet issuer subpacket); for now it is always `None`.
//!
//! ## Frontier inspiration
//!
//! Helm's own provenance verification (`helm verify`, `cmd/helm/verify.
//! go`) reads the `.prov` exactly the way this parser does: locate the
//! cleartext-signed framing, recover the signed body, parse the
//! `files:` map, cross-check the named tarball's sha256 against the
//! `.tgz` bytes on disk. The parsing layer here mirrors that read so a
//! downstream re-verifier finds the attestation claims the Phase 1
//! record makes structurally consistent with what Helm itself would
//! recover from the same `.prov`.

/// Outcome of probing a Helm `.prov` provenance file alongside a
/// packaged chart tarball. The four arms preserve the
/// probe-absent vs framing-failed vs framing-ok-no-digest vs verified
/// distinction the Phase 1 chart attestation depends on; the prior
/// `provenance: false` hardcode conflated all four into a single
/// negative claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelmProvenanceOutcome {
    /// `.prov` exists AND its OpenPGP cleartext framing parses AND its
    /// `files:` map carries a `sha256:<hex>` digest for the expected
    /// tarball name. The Phase 1 chart attestation can honestly claim
    /// `provenance_verified: true` only in this arm.
    ///
    /// `signed_chart_hash` carries the recovered `sha256:<hex>` (no
    /// algorithm prefix, lowercase hex), the cross-check a downstream
    /// verifier reconciles against the chart tarball bytes.
    ///
    /// `signer_key_id` is reserved for a future OpenPGP v4 signature
    /// packet parser that extracts the issuer key id from the binary
    /// signature subpacket; for now it is always `None`. The arm still
    /// preserves the field so a future enrichment commit does not have
    /// to widen the type.
    Verified {
        signed_chart_hash: Option<String>,
        signer_key_id: Option<String>,
    },
    /// `.prov` exists AND its OpenPGP cleartext framing parses, but no
    /// `files:` entry for the expected `<chart-name>-<version>.tgz`
    /// carried a `sha256:<hex>` digest. The probe ran, the document is
    /// well-formed, but it does not name the chart whose attestation we
    /// are sealing. The prior `false` hardcode reported `false` here
    /// (correctly), but lost the discriminator that distinguishes
    /// "well-framed but irrelevant" from "ill-framed" from "absent".
    Unverified,
    /// A file exists at the `.prov` location AND its OpenPGP cleartext
    /// framing failed to parse (missing `-----BEGIN PGP SIGNED
    /// MESSAGE-----` / `-----BEGIN PGP SIGNATURE-----` / `-----END PGP
    /// SIGNATURE-----` markers, malformed structure). The probe ran and
    /// the file is not a Helm provenance document — negative evidence.
    VerifyFailed,
    /// No `.prov` file exists at the expected location alongside the
    /// chart tarball. No probe was made; no evidence was collected.
    /// The prior `false` hardcode could not distinguish this from
    /// the well-framed-but-irrelevant or ill-framed cases.
    ProbeAbsent,
}

impl HelmProvenanceOutcome {
    /// True iff the `.prov` probe ran AND the cleartext framing parsed
    /// AND the `files:` map yielded a digest for the expected tarball.
    /// The boolean the Phase 1 chart attestation's `provenance_verified`
    /// field carries. The other three arms collapse to `false` at this
    /// surface — they remain structurally distinct at the enum level so
    /// the call site can log them separately if needed.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The recovered chart-tarball `sha256:<hex>` digest for the
    /// `Verified` arm, or `None` otherwise. Drives a downstream
    /// reconciliation against the `.tgz` bytes a re-verifier reads.
    #[allow(dead_code)]
    pub fn signed_chart_hash(&self) -> Option<&str> {
        match self {
            Self::Verified {
                signed_chart_hash, ..
            } => signed_chart_hash.as_deref(),
            _ => None,
        }
    }
}

/// Parse the contents of a Helm `.prov` provenance file into a
/// [`HelmProvenanceOutcome`].
///
/// The OpenPGP cleartext-signed envelope (RFC 4880 §7) has three
/// regions:
///
/// 1. `-----BEGIN PGP SIGNED MESSAGE-----` header, optional
///    `Hash: <alg>` armor lines, blank line.
/// 2. The dash-escaped signed body (lines starting with `- ` are
///    escaped; the parser un-escapes them per RFC 4880 §7.1).
/// 3. `-----BEGIN PGP SIGNATURE-----` ... `-----END PGP SIGNATURE-----`
///    ASCII-armored binary signature packet.
///
/// All three markers must be present in canonical order or the outcome
/// is [`HelmProvenanceOutcome::VerifyFailed`]. Within the signed body,
/// the parser scans for a `files:` block whose indented children carry
/// `<tarball-name>: sha256:<hex>` entries, looks up
/// `expected_tarball_name`, and recovers the lowercase-hex digest.
///
/// An empty digest, a non-sha256 algorithm, or no `files:` entry for
/// the expected tarball collapses to
/// [`HelmProvenanceOutcome::Unverified`] — the document is well-formed
/// but does not name the chart we are sealing.
pub fn parse_provenance(contents: &str, expected_tarball_name: &str) -> HelmProvenanceOutcome {
    const SIGNED_MSG_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
    const SIG_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
    const SIG_END: &str = "-----END PGP SIGNATURE-----";

    let Some(header_pos) = contents.find(SIGNED_MSG_HEADER) else {
        return HelmProvenanceOutcome::VerifyFailed;
    };
    let after_header = &contents[header_pos + SIGNED_MSG_HEADER.len()..];

    let Some(sig_pos) = after_header.find(SIG_BEGIN) else {
        return HelmProvenanceOutcome::VerifyFailed;
    };
    let body_armor = &after_header[..sig_pos];
    let after_sig = &after_header[sig_pos + SIG_BEGIN.len()..];

    if !after_sig.contains(SIG_END) {
        return HelmProvenanceOutcome::VerifyFailed;
    }

    let signed_body = strip_armor_headers(body_armor);
    let unescaped = dash_unescape(&signed_body);

    match find_tarball_sha256(&unescaped, expected_tarball_name) {
        Some(hex) => HelmProvenanceOutcome::Verified {
            signed_chart_hash: Some(hex),
            signer_key_id: None,
        },
        None => HelmProvenanceOutcome::Unverified,
    }
}

/// Strip the optional `Hash: <alg>` armor headers and the blank line
/// that separates them from the signed body (RFC 4880 §7.1: armor
/// headers appear immediately after the BEGIN marker, terminated by a
/// blank line, before the signed text begins). Returns the signed-body
/// region only.
fn strip_armor_headers(body_armor: &str) -> String {
    let mut in_headers = true;
    let mut out = String::with_capacity(body_armor.len());
    for line in body_armor.lines() {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            // Armor headers are `Key: Value`; a line lacking `:` ends
            // the header region (defensive — Helm always emits the
            // canonical blank separator).
            if !line.contains(':') {
                in_headers = false;
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Apply RFC 4880 §7.1 dash-unescaping: a body line that begins with
/// `- ` was dash-escaped by the signer to disambiguate it from the
/// `-----BEGIN PGP SIGNATURE-----` marker; the verifier removes the
/// leading `- ` before processing.
fn dash_unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("- ") {
            out.push_str(rest);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Scan a YAML-shaped signed body for a `files:` block, find the
/// indented child entry whose key equals `expected_tarball_name`, and
/// recover the `sha256:<hex>` digest. Returns the lowercase-hex digest
/// (no algorithm prefix) on a positive match, or `None` if no `files:`
/// block is present, the expected entry is absent, the algorithm is
/// not `sha256`, the hex payload is empty, or the hex payload is not
/// well-formed lowercase hex.
///
/// The parser deliberately rejects non-`sha256` algorithms and
/// malformed hex so a future cross-check against the tarball bytes
/// cannot be fed garbage from a corrupt `.prov`.
fn find_tarball_sha256(body: &str, expected_tarball_name: &str) -> Option<String> {
    let mut in_files = false;
    let mut files_indent: Option<usize> = None;
    for line in body.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let leading = line.len() - line.trim_start().len();
        if !in_files {
            // `files:` is a top-level key (zero indent in Helm's
            // emitted .prov, but be lenient and accept any indent ≤ 0
            // explicit). The key matches exactly `files:` with no
            // value on the same line.
            if line.trim_start() == "files:" {
                in_files = true;
                files_indent = Some(leading);
            }
            continue;
        }
        // Inside files: child entries are indented strictly more than
        // the `files:` key; a line at or below that indent ends the
        // block.
        let parent = files_indent.unwrap_or(0);
        if leading <= parent {
            in_files = false;
            continue;
        }
        let entry = line.trim_start();
        // entry shape: `<tarball-name>: sha256:<hex>`
        let Some((name, value)) = entry.split_once(':') else {
            continue;
        };
        if name.trim() != expected_tarball_name {
            continue;
        }
        let value = value.trim();
        let Some(hex) = value.strip_prefix("sha256:") else {
            // A non-sha256 algorithm is not the digest we cross-check;
            // skip rather than misreport. Future commit can widen.
            return None;
        };
        let hex = hex.trim();
        if hex.is_empty() || !is_lowercase_hex(hex) {
            return None;
        }
        return Some(hex.to_string());
    }
    None
}

/// A sha256 digest's hex payload is exactly 64 lowercase-hex chars.
/// The parser pins the length AND the lowercase discipline so a
/// truncated, uppercase, or non-hex string cannot enter the
/// attestation as if it were a valid digest.
fn is_lowercase_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHART_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A realistic Helm `.prov` document: cleartext signed message with
    /// a `Hash:` armor header, Chart.yaml-shaped body, a `files:` map
    /// keyed by the tarball name → `sha256:<hex>`, and the signature
    /// block. Parses to [`HelmProvenanceOutcome::Verified`] with the
    /// digest recovered.
    fn realistic_prov(tarball: &str, digest: &str) -> String {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             apiVersion: v2\n\
             description: Example chart\n\
             name: example\n\
             type: application\n\
             version: 0.1.0\n\
             \n\
             ...\n\
             files:\n  \
             {}: sha256:{}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             \n\
             wsBcBAABCgAQBQJlxxxxFiEEabcdef==\n\
             =xyz1\n\
             -----END PGP SIGNATURE-----\n",
            tarball, digest
        )
    }

    #[test]
    fn test_parse_realistic_prov_recovers_digest() {
        let prov = realistic_prov("example-0.1.0.tgz", CHART_DIGEST);
        let out = parse_provenance(&prov, "example-0.1.0.tgz");
        assert!(out.is_verified(), "well-formed .prov must verify");
        let HelmProvenanceOutcome::Verified {
            signed_chart_hash,
            signer_key_id,
        } = out
        else {
            panic!("expected Verified");
        };
        assert_eq!(signed_chart_hash.as_deref(), Some(CHART_DIGEST));
        assert_eq!(
            signer_key_id, None,
            "signer_key_id is reserved for a future OpenPGP packet parser"
        );
    }

    /// **Load-bearing fail-before/pass-after pin.** A `.prov` that
    /// names a *different* tarball than the chart we are sealing must
    /// NOT claim `provenance_verified: true`. The prior `false`
    /// hardcode was already `false` here (correctly by accident); the
    /// typed parser distinguishes this case from `VerifyFailed`/
    /// `ProbeAbsent`/`Verified` so a downstream verifier sees the
    /// "well-framed but irrelevant" arm directly.
    #[test]
    fn test_parse_well_framed_but_wrong_tarball_is_unverified() {
        let prov = realistic_prov("other-2.0.0.tgz", CHART_DIGEST);
        let out = parse_provenance(&prov, "example-0.1.0.tgz");
        assert_eq!(out, HelmProvenanceOutcome::Unverified);
        assert!(!out.is_verified(), "wrong tarball must not claim verified");
        assert_eq!(out.signed_chart_hash(), None);
    }

    /// Missing `-----BEGIN PGP SIGNED MESSAGE-----` framing collapses
    /// to `VerifyFailed`: the document is not an OpenPGP
    /// cleartext-signed envelope.
    #[test]
    fn test_parse_missing_signed_message_header_fails() {
        let prov = "apiVersion: v2\nname: example\nfiles:\n  example-0.1.0.tgz: sha256:abc\n";
        assert_eq!(
            parse_provenance(prov, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::VerifyFailed
        );
    }

    /// Missing `-----BEGIN PGP SIGNATURE-----` framing collapses to
    /// `VerifyFailed`: the document was truncated mid-signed-body.
    #[test]
    fn test_parse_missing_signature_begin_fails() {
        let prov = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             files:\n  example-0.1.0.tgz: sha256:{}\n",
            CHART_DIGEST
        );
        assert_eq!(
            parse_provenance(&prov, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::VerifyFailed
        );
    }

    /// Missing `-----END PGP SIGNATURE-----` framing collapses to
    /// `VerifyFailed`: the signature block was truncated mid-armor.
    #[test]
    fn test_parse_missing_signature_end_fails() {
        let prov = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             files:\n  example-0.1.0.tgz: sha256:{}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             wsBcBAAB\n",
            CHART_DIGEST
        );
        assert_eq!(
            parse_provenance(&prov, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::VerifyFailed
        );
    }

    /// Empty input is not a provenance document — `VerifyFailed`.
    #[test]
    fn test_parse_empty_input_fails() {
        assert_eq!(
            parse_provenance("", "example-0.1.0.tgz"),
            HelmProvenanceOutcome::VerifyFailed
        );
    }

    /// A well-framed `.prov` with no `files:` block at all collapses
    /// to `Unverified` — the framing is structurally valid but no
    /// digest claim is present to cross-check.
    #[test]
    fn test_parse_well_framed_no_files_block_is_unverified() {
        let prov = "-----BEGIN PGP SIGNED MESSAGE-----\n\
                    Hash: SHA512\n\
                    \n\
                    apiVersion: v2\n\
                    name: example\n\
                    version: 0.1.0\n\
                    -----BEGIN PGP SIGNATURE-----\n\
                    \n\
                    wsBcBAABCgAQ==\n\
                    -----END PGP SIGNATURE-----\n";
        assert_eq!(
            parse_provenance(prov, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::Unverified
        );
    }

    /// A non-sha256 algorithm (e.g. `sha512:...`) under the expected
    /// tarball collapses to `Unverified` — the parser pins sha256 so a
    /// future cross-check against `tarball-content-blake3` (or a
    /// dedicated sha512 path) cannot be fed the wrong algorithm. A
    /// future commit can widen the discriminator.
    #[test]
    fn test_parse_non_sha256_algorithm_is_unverified() {
        let prov = "-----BEGIN PGP SIGNED MESSAGE-----\n\
                    Hash: SHA512\n\
                    \n\
                    files:\n  example-0.1.0.tgz: sha512:abc\n\
                    -----BEGIN PGP SIGNATURE-----\n\
                    \n\
                    wsBcBAAB\n\
                    -----END PGP SIGNATURE-----\n";
        assert_eq!(
            parse_provenance(prov, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::Unverified
        );
    }

    /// A truncated hex payload (not 64 lowercase-hex chars) collapses
    /// to `Unverified` — the parser pins the exact sha256 length AND
    /// the lowercase discipline so a malformed digest cannot enter the
    /// attestation as if it were valid.
    #[test]
    fn test_parse_malformed_hex_digest_is_unverified() {
        let short = "-----BEGIN PGP SIGNED MESSAGE-----\n\
                     Hash: SHA512\n\
                     \n\
                     files:\n  example-0.1.0.tgz: sha256:abc\n\
                     -----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     wsBcBAAB\n\
                     -----END PGP SIGNATURE-----\n";
        assert_eq!(
            parse_provenance(short, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::Unverified
        );

        let uppercase = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             files:\n  example-0.1.0.tgz: sha256:{}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             \n\
             wsBcBAAB\n\
             -----END PGP SIGNATURE-----\n",
            CHART_DIGEST.to_uppercase()
        );
        assert_eq!(
            parse_provenance(&uppercase, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::Unverified
        );

        let nonhex = "-----BEGIN PGP SIGNED MESSAGE-----\n\
                     Hash: SHA512\n\
                     \n\
                     files:\n  example-0.1.0.tgz: sha256:zzzz0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab\n\
                     -----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     wsBcBAAB\n\
                     -----END PGP SIGNATURE-----\n";
        assert_eq!(
            parse_provenance(nonhex, "example-0.1.0.tgz"),
            HelmProvenanceOutcome::Unverified
        );
    }

    /// Dash-escaped body lines (RFC 4880 §7.1) are un-escaped before
    /// scanning. Helm's `.prov` does not currently emit dash-escaped
    /// lines (its signed body has no leading `- `), but the parser
    /// implements the spec discipline so a forward-compatible writer
    /// emitting a line that needs escaping does not break recovery.
    #[test]
    fn test_parse_dash_escaped_body_is_unescaped() {
        let prov = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA512\n\
             \n\
             - files:\n  \
             example-0.1.0.tgz: sha256:{}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             \n\
             wsBcBAAB\n\
             -----END PGP SIGNATURE-----\n",
            CHART_DIGEST
        );
        let out = parse_provenance(&prov, "example-0.1.0.tgz");
        let HelmProvenanceOutcome::Verified {
            signed_chart_hash, ..
        } = out
        else {
            panic!("expected Verified after dash-unescape");
        };
        assert_eq!(signed_chart_hash.as_deref(), Some(CHART_DIGEST));
    }

    /// `is_verified` returns the boolean every Phase 1 chart
    /// attestation writes into `ChartAttestation::provenance_verified`.
    /// Pin all four arms so a future refactor that flips an arm's
    /// truthiness fails loudly rather than silently inflating /
    /// deflating the Phase 1 claim.
    #[test]
    fn test_is_verified_pins_all_arms() {
        assert!(HelmProvenanceOutcome::Verified {
            signed_chart_hash: None,
            signer_key_id: None,
        }
        .is_verified());
        assert!(!HelmProvenanceOutcome::Unverified.is_verified());
        assert!(!HelmProvenanceOutcome::VerifyFailed.is_verified());
        assert!(!HelmProvenanceOutcome::ProbeAbsent.is_verified());
    }

    /// `signed_chart_hash` returns `None` for every non-Verified arm
    /// — the attestation cannot recover a digest from a probe that
    /// found no matching entry, that failed to parse, or that never
    /// ran.
    #[test]
    fn test_signed_chart_hash_none_for_non_verified_arms() {
        assert_eq!(HelmProvenanceOutcome::Unverified.signed_chart_hash(), None);
        assert_eq!(
            HelmProvenanceOutcome::VerifyFailed.signed_chart_hash(),
            None
        );
        assert_eq!(HelmProvenanceOutcome::ProbeAbsent.signed_chart_hash(), None);
        assert_eq!(
            HelmProvenanceOutcome::Verified {
                signed_chart_hash: Some(CHART_DIGEST.to_string()),
                signer_key_id: None,
            }
            .signed_chart_hash(),
            Some(CHART_DIGEST)
        );
    }
}
