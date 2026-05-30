//! Typed OpenPGP v4 signature packet probe for the binary signature
//! block carried inside a Helm `.prov` cleartext-signed envelope.
//!
//! `helm package --sign` writes a sibling `<chart>-<version>.tgz.prov`
//! whose final region is the ASCII-armored binary signature packet
//! (RFC 4880 §6.2 armor framing of an RFC 4880 §5.2.3 signature packet).
//! That packet carries the **Issuer** subpacket (RFC 4880 §5.2.3.5,
//! type 16, 8 bytes — the low 64 bits of the signing key's fingerprint)
//! or, on newer GnuPG / sequoia / OpenPGP-crypto-refresh writers, the
//! **Issuer Fingerprint** subpacket (type 33, 21 bytes for v4 keys = 1
//! version + 20 fingerprint). Either lets a downstream verifier name
//! WHO signed the chart, the field [`crate::helm_provenance::
//! HelmProvenanceOutcome::Verified::signer_key_id`] reserved for this
//! parser and which the prior commit (b8a1d8a) explicitly named as
//! "the next enrichment of the chart-provenance typed shape" and the
//! commit before that (b98eb5a, sbom/vuln-scan) re-named as the
//! remaining "typed primitive [...] with this shape" in the
//! chart-provenance arc.
//!
//! The four-arm typed outcome mirrors the
//! [`crate::cosign::CosignVerifyOutcome`] /
//! [`crate::helm_provenance::HelmProvenanceOutcome`] /
//! [`crate::oci_architecture::OciArchitectureOutcome`] /
//! [`crate::security_scan::SbomProbeOutcome`] discipline: every
//! external probe the attestation chain depends on has a typed shape
//! that preserves the probe-found-evidence vs probe-found-no-evidence
//! vs probe-found-unsupported vs probe-malformed distinction, never
//! collapsing into `Option<String>` whose `None` arm conflates four
//! operational worlds.
//!
//! ## What this module does NOT do
//!
//! This is a Phase 1 *evidence-collection* primitive: it parses the
//! packet stream and recovers the Issuer key ID claim. It does NOT
//! cryptographically verify the signature itself (no MPI parsing, no
//! RSA / ECDSA / EdDSA verification, no keyring resolution). A future
//! commit can layer a `helm verify` shell-out or a sequoia-openpgp
//! integration that adds keyring-anchored verification on top of the
//! key-ID-only evidence this commit collects; the typed outcome stays
//! the same shape so that future enrichment fits within the existing
//! [`crate::helm_provenance::HelmProvenanceOutcome::Verified`] arm.
//!
//! ## Frontier inspiration
//!
//! sequoia-openpgp's `Packet::Signature` parser and rpm-sequoia's
//! `extract_key_id` recover the Issuer / Issuer Fingerprint subpackets
//! the same way: walk the packet stream, find a tag-2 packet, parse
//! the v4 body, scan both hashed and unhashed subpacket areas. SLSA
//! v1.0 §"Build Provenance" and in-toto §4 link both name the signing
//! identity as a content-addressed claim distinct from the signature
//! verification — the key ID is WHO signed, the signature
//! verification is WHETHER the signed bytes match. The typed primitive
//! here grounds the WHO so a downstream
//! reconciler / sekiban admission has the field to consult.

use base64::engine::general_purpose;
use base64::Engine as _;

/// Outcome of probing an ASCII-armored OpenPGP signature block for an
/// Issuer key ID. The four arms preserve the
/// recovered-with-issuer vs recovered-without-issuer vs
/// unsupported-version vs malformed distinction the Phase 1 chart
/// attestation depends on; the prior unconditional `None` in
/// [`crate::helm_provenance::HelmProvenanceOutcome::Verified::
/// signer_key_id`] conflated all four into a single absent claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignaturePacketOutcome {
    /// V4 signature packet found AND its subpacket area carried an
    /// Issuer (RFC 4880 §5.2.3.5, type 16, 8 bytes) or Issuer
    /// Fingerprint (RFC 4880-bis §5.2.3.28 / OpenPGP-crypto-refresh
    /// §5.2.3.35, type 33) subpacket from which an 8-byte key ID was
    /// recovered. `key_id_hex` is the 16-char lowercase-hex key ID —
    /// the low 64 bits of the signer's fingerprint, the field a
    /// downstream verifier resolves against a keyring.
    RecoveredV4 { key_id_hex: String },
    /// V4 signature packet found, but neither hashed nor unhashed
    /// subpacket area carried a recoverable Issuer or Issuer
    /// Fingerprint subpacket. Honest probe-found-nothing record — the
    /// signature exists but it does not name its signer in a typed
    /// subpacket. (A v4 signature without an Issuer subpacket is
    /// well-formed per RFC 4880 §5.2.3.1 — implementations SHOULD
    /// include one but are not required to.)
    RecoveredV4NoIssuer,
    /// Signature packet found, but its version byte is not 4. v3
    /// signatures (RFC 4880 §5.2.2) carry the Issuer Key ID at a
    /// fixed offset in the packet header rather than in a subpacket;
    /// v5/v6 signatures (OpenPGP-crypto-refresh) use different
    /// subpacket structural conventions. Both are out of scope for
    /// this parser; the discriminator is preserved so a future
    /// enrichment commit can widen.
    UnsupportedVersion { version: u8 },
    /// Armor failed to base64-decode, packet stream is truncated /
    /// malformed, or no signature packet was found in the stream.
    /// Distinct from `RecoveredV4NoIssuer` so a downstream verifier
    /// can distinguish "signature exists but does not name its
    /// signer" (well-formed but minimal) from "armor or packet stream
    /// is structurally broken" (collected no evidence).
    Malformed,
}

impl SignaturePacketOutcome {
    /// The recovered key ID (16 lowercase-hex chars) for the
    /// `RecoveredV4` arm, or `None` for the three non-recovered arms.
    /// The string [`crate::helm_provenance::HelmProvenanceOutcome::
    /// Verified::signer_key_id`] carries.
    pub fn key_id_hex(&self) -> Option<&str> {
        match self {
            Self::RecoveredV4 { key_id_hex } => Some(key_id_hex),
            _ => None,
        }
    }
}

/// Parse an ASCII-armored OpenPGP signature block — the
/// `-----BEGIN PGP SIGNATURE-----` ... `-----END PGP SIGNATURE-----`
/// envelope Helm's `.prov` cleartext-signed document carries as its
/// final region — and recover the Issuer key ID from the v4 signature
/// packet's subpacket area.
///
/// Per RFC 4880 §6.2, the armor block has: header line, optional
/// `Key: Value` armor headers terminated by a blank line, base64-
/// encoded body (line-wrapped), a line beginning with `=` carrying
/// the CRC24 checksum, and a footer line. This parser extracts only
/// the base64 body (everything between the blank-line header
/// terminator and the CRC24 line), decodes it, then walks the packet
/// stream looking for the first signature packet (tag 2).
pub fn parse_signature_armor(armor: &str) -> SignaturePacketOutcome {
    let Some(body_b64) = extract_armor_body(armor) else {
        return SignaturePacketOutcome::Malformed;
    };
    let Ok(bytes) = general_purpose::STANDARD.decode(body_b64.as_bytes()) else {
        return SignaturePacketOutcome::Malformed;
    };
    let Some(sig_body) = find_signature_packet_body(&bytes) else {
        return SignaturePacketOutcome::Malformed;
    };
    parse_v4_signature_packet(sig_body)
}

/// Extract the base64-encoded body from an ASCII armor block. Returns
/// the contiguous concatenation of all non-empty body lines (whitespace
/// stripped) between the blank-line armor-header terminator and either
/// the CRC24 footer (line starting with `=`) or the END marker —
/// whichever comes first.
fn extract_armor_body(armor: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
    const END: &str = "-----END PGP SIGNATURE-----";
    let begin_pos = armor.find(BEGIN)?;
    let after_begin = &armor[begin_pos + BEGIN.len()..];
    let end_pos = after_begin.find(END)?;
    let between = &after_begin[..end_pos];

    // Skip armor-header lines (`Key: Value`, per RFC 4880 §6.2) and
    // blank lines until the body begins. The base64 alphabet (A-Z,
    // a-z, 0-9, +, /, =) does not include `:`, so any line containing
    // `:` is unambiguously an armor header. The CRC24 footer (line
    // starting with `=`) terminates the body.
    let mut body = String::new();
    let mut in_body = false;
    for line in between.lines() {
        let trimmed = line.trim();
        if !in_body {
            if trimmed.is_empty() || trimmed.contains(':') {
                continue;
            }
            in_body = true;
        }
        if trimmed.starts_with('=') {
            break;
        }
        if !trimmed.is_empty() {
            body.push_str(trimmed);
        }
    }
    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

/// Walk an OpenPGP packet stream (RFC 4880 §4) and return the body of
/// the first signature packet (tag 2), or `None` if no signature
/// packet is present or the stream is structurally malformed.
fn find_signature_packet_body(bytes: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    while pos < bytes.len() {
        let tag_byte = bytes[pos];
        pos += 1;
        // RFC 4880 §4.2: bit 7 of the packet header is always 1.
        if tag_byte & 0x80 == 0 {
            return None;
        }
        let (tag, body_len) = if tag_byte & 0x40 != 0 {
            parse_new_format_header(tag_byte, bytes, &mut pos)?
        } else {
            parse_old_format_header(tag_byte, bytes, &mut pos)?
        };
        if pos.checked_add(body_len)? > bytes.len() {
            return None;
        }
        if tag == 2 {
            return Some(&bytes[pos..pos + body_len]);
        }
        pos += body_len;
    }
    None
}

/// RFC 4880 §4.2.2 new-format packet header: bits 5..0 of the tag
/// octet name the packet tag; the length is encoded in the following
/// 1, 2, or 5 octets depending on the first length octet's value.
/// Partial body length (224..=254) is not supported here — none of
/// the OpenPGP packets the Helm `.prov` carries use it.
fn parse_new_format_header(tag_byte: u8, bytes: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    let tag = tag_byte & 0x3F;
    let first = *bytes.get(*pos)?;
    *pos += 1;
    let len = if first < 192 {
        first as usize
    } else if first < 224 {
        let next = *bytes.get(*pos)?;
        *pos += 1;
        ((first as usize - 192) << 8) + (next as usize) + 192
    } else if first == 255 {
        if bytes.len() < *pos + 4 {
            return None;
        }
        let l = u32::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
        ]) as usize;
        *pos += 4;
        l
    } else {
        return None;
    };
    Some((tag, len))
}

/// RFC 4880 §4.2.1 old-format packet header: bits 5..2 of the tag
/// octet name the packet tag; bits 1..0 name the length type (1, 2,
/// or 4 octets; indeterminate length is not supported here).
fn parse_old_format_header(tag_byte: u8, bytes: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    let tag = (tag_byte >> 2) & 0x0F;
    let len_type = tag_byte & 0x03;
    let len = match len_type {
        0 => {
            let l = *bytes.get(*pos)? as usize;
            *pos += 1;
            l
        }
        1 => {
            if bytes.len() < *pos + 2 {
                return None;
            }
            let l = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
            *pos += 2;
            l
        }
        2 => {
            if bytes.len() < *pos + 4 {
                return None;
            }
            let l = u32::from_be_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
            ]) as usize;
            *pos += 4;
            l
        }
        _ => return None,
    };
    Some((tag, len))
}

/// Parse the body of a v4 signature packet (RFC 4880 §5.2.3) and scan
/// both subpacket areas for an Issuer or Issuer Fingerprint subpacket.
/// The hashed area is searched first (RFC 4880-bis SHOULD-emit
/// position for Issuer Fingerprint), then the unhashed area (the
/// canonical Issuer subpacket position GnuPG emits).
fn parse_v4_signature_packet(body: &[u8]) -> SignaturePacketOutcome {
    if body.is_empty() {
        return SignaturePacketOutcome::Malformed;
    }
    let version = body[0];
    if version != 4 {
        return SignaturePacketOutcome::UnsupportedVersion { version };
    }
    // v4 header: [ver, sig_type, pubkey_algo, hash_algo, h_len_hi, h_len_lo, ...hashed, u_len_hi, u_len_lo, ...unhashed, ...]
    if body.len() < 6 {
        return SignaturePacketOutcome::Malformed;
    }
    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let hashed_start: usize = 6;
    let Some(hashed_end) = hashed_start.checked_add(hashed_len) else {
        return SignaturePacketOutcome::Malformed;
    };
    if body.len() < hashed_end + 2 {
        return SignaturePacketOutcome::Malformed;
    }
    let unhashed_len = u16::from_be_bytes([body[hashed_end], body[hashed_end + 1]]) as usize;
    let unhashed_start = hashed_end + 2;
    let Some(unhashed_end) = unhashed_start.checked_add(unhashed_len) else {
        return SignaturePacketOutcome::Malformed;
    };
    if body.len() < unhashed_end {
        return SignaturePacketOutcome::Malformed;
    }

    let hashed_area = &body[hashed_start..hashed_end];
    let unhashed_area = &body[unhashed_start..unhashed_end];
    if let Some(key_id_hex) = scan_subpackets_for_issuer(hashed_area)
        .or_else(|| scan_subpackets_for_issuer(unhashed_area))
    {
        SignaturePacketOutcome::RecoveredV4 { key_id_hex }
    } else {
        SignaturePacketOutcome::RecoveredV4NoIssuer
    }
}

/// Walk a subpacket area (RFC 4880 §5.2.3.1) looking for an Issuer
/// (type 16, 8-byte body) or Issuer Fingerprint (type 33; v4 = 1
/// version + 20 fingerprint, key ID = low 8 bytes) subpacket. The
/// type byte's high bit is the "critical" flag and is masked off
/// before comparing against known types.
fn scan_subpackets_for_issuer(area: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < area.len() {
        let first = area[pos];
        pos += 1;
        let sp_len = if first < 192 {
            first as usize
        } else if first < 255 {
            let next = *area.get(pos)?;
            pos += 1;
            ((first as usize - 192) << 8) + (next as usize) + 192
        } else {
            if area.len() < pos + 4 {
                return None;
            }
            let l = u32::from_be_bytes([area[pos], area[pos + 1], area[pos + 2], area[pos + 3]])
                as usize;
            pos += 4;
            l
        };
        if sp_len == 0 || pos + sp_len > area.len() {
            return None;
        }
        let sp_type = area[pos] & 0x7F;
        let sp_body = &area[pos + 1..pos + sp_len];
        match sp_type {
            16 if sp_body.len() == 8 => return Some(hex_encode(sp_body)),
            33 if sp_body.len() == 21 && sp_body[0] == 4 => {
                return Some(hex_encode(&sp_body[13..21]));
            }
            _ => {}
        }
        pos += sp_len;
    }
    None
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic minimal v4 signature packet with the given
    /// 8-byte Issuer key ID in its unhashed subpacket area, wrap it
    /// in ASCII armor. Mirrors the canonical shape `gpg --detach-sign`
    /// emits — Issuer in unhashed, hashed area empty.
    fn build_v4_sig_armor_issuer_unhashed(key_id: &[u8; 8]) -> String {
        let mut body = Vec::new();
        body.push(4); // version
        body.push(0); // sig type
        body.push(1); // pubkey algo (RSA)
        body.push(8); // hash algo (SHA-256)
        body.extend_from_slice(&[0, 0]); // hashed subpacket area length = 0
        body.extend_from_slice(&[0, 10]); // unhashed subpacket area length = 10
        body.push(9); // subpacket length octet (1 type + 8 body)
        body.push(16); // subpacket type = Issuer
        body.extend_from_slice(key_id);
        body.extend_from_slice(&[0, 0]); // left 16 bits of hash
        body.extend_from_slice(&[0, 1, 0]); // trivial MPI
        wrap_packet_in_armor(&body)
    }

    /// Build a v4 sig packet with an Issuer Fingerprint subpacket
    /// (type 33) in the hashed area — the RFC 4880-bis preferred
    /// position. The v4 fingerprint is 20 bytes; the recovered key
    /// ID is its low 8 bytes per RFC 4880 §12.2.
    fn build_v4_sig_armor_fingerprint_hashed(fingerprint: &[u8; 20]) -> String {
        let mut hashed = Vec::new();
        hashed.push(22); // subpacket length octet (1 type + 21 body)
        hashed.push(33); // subpacket type = Issuer Fingerprint
        hashed.push(4); // key version
        hashed.extend_from_slice(fingerprint);
        let hashed_len = hashed.len() as u16;

        let mut body = Vec::new();
        body.push(4); // version
        body.push(0); // sig type
        body.push(1); // pubkey algo
        body.push(8); // hash algo
        body.extend_from_slice(&hashed_len.to_be_bytes());
        body.extend_from_slice(&hashed);
        body.extend_from_slice(&[0, 0]); // unhashed area length = 0
        body.extend_from_slice(&[0, 0]); // left 16 bits of hash
        body.extend_from_slice(&[0, 1, 0]); // trivial MPI
        wrap_packet_in_armor(&body)
    }

    /// Build a sig packet with a non-4 version byte, wrap in armor.
    fn build_sig_armor_version(version: u8) -> String {
        let mut body = vec![version, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        // pad to a non-trivial body so packet length encoding works
        body.resize(20, 0);
        wrap_packet_in_armor(&body)
    }

    /// Wrap a signature-packet body (no header) in a new-format
    /// packet header (tag 2) and ASCII-armor it.
    fn wrap_packet_in_armor(sig_body: &[u8]) -> String {
        let mut packet = vec![0xC2];
        let len = sig_body.len();
        assert!(len < 192, "test sig body should fit one-byte length");
        packet.push(len as u8);
        packet.extend_from_slice(sig_body);
        let encoded = general_purpose::STANDARD.encode(&packet);
        format!(
            "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2\n\n{}\n=AAAA\n-----END PGP SIGNATURE-----\n",
            encoded
        )
    }

    /// **Load-bearing fail-before / pass-after pin** at the bottom of
    /// the chart-attestation arc: a v4 sig packet with an Issuer
    /// subpacket in its unhashed area yields the 16-char lowercase-hex
    /// key ID — the field the prior commit (b8a1d8a) wired into the
    /// [`HelmProvenanceOutcome::Verified::signer_key_id`] slot but
    /// always populated with `None` because no parser existed.
    #[test]
    fn test_recovers_issuer_key_id_from_v4_unhashed_subpacket() {
        let key_id = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
        let armor = build_v4_sig_armor_issuer_unhashed(&key_id);
        let outcome = parse_signature_armor(&armor);
        assert_eq!(
            outcome,
            SignaturePacketOutcome::RecoveredV4 {
                key_id_hex: "abcdef0123456789".to_string()
            }
        );
        assert_eq!(outcome.key_id_hex(), Some("abcdef0123456789"));
    }

    /// Issuer Fingerprint (type 33) in the hashed area: the v4
    /// fingerprint's low 8 bytes ARE the key ID (RFC 4880 §12.2).
    /// The parser searches the hashed area first so this position is
    /// preferred when both subpackets exist.
    #[test]
    fn test_recovers_key_id_from_v4_issuer_fingerprint_hashed_subpacket() {
        let mut fingerprint = [0u8; 20];
        for (i, b) in fingerprint.iter_mut().enumerate() {
            *b = i as u8;
        }
        // low 8 bytes of fingerprint = bytes 12..20 = [12..20]
        let armor = build_v4_sig_armor_fingerprint_hashed(&fingerprint);
        let outcome = parse_signature_armor(&armor);
        assert_eq!(
            outcome,
            SignaturePacketOutcome::RecoveredV4 {
                key_id_hex: "0c0d0e0f10111213".to_string()
            }
        );
    }

    /// A v4 sig packet with empty hashed AND unhashed subpacket areas
    /// is well-formed per RFC 4880 §5.2.3.1 (subpackets are
    /// recommended but not required) — the typed outcome distinguishes
    /// this from `Malformed` so a downstream verifier can see "the
    /// signature exists but does not name its signer."
    #[test]
    fn test_v4_sig_with_no_subpackets_is_recovered_no_issuer() {
        let body = vec![4, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let armor = wrap_packet_in_armor(&body);
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::RecoveredV4NoIssuer
        );
    }

    /// A v3 signature packet (RFC 4880 §5.2.2) carries Issuer Key ID
    /// at a fixed packet-header offset, not in subpackets — out of
    /// scope here. The discriminator is preserved so a future commit
    /// can widen the parser.
    #[test]
    fn test_v3_signature_packet_is_unsupported_version() {
        let armor = build_sig_armor_version(3);
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::UnsupportedVersion { version: 3 }
        );
    }

    /// A v5 sig packet (OpenPGP-crypto-refresh) uses different
    /// subpacket conventions than v4 — also out of scope, also
    /// preserved as a distinct discriminator.
    #[test]
    fn test_v5_signature_packet_is_unsupported_version() {
        let armor = build_sig_armor_version(5);
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::UnsupportedVersion { version: 5 }
        );
    }

    /// No armor at all → Malformed. Distinct from
    /// `RecoveredV4NoIssuer` (which means the probe found a v4 sig
    /// packet that does not name its signer).
    #[test]
    fn test_no_armor_block_is_malformed() {
        assert_eq!(parse_signature_armor(""), SignaturePacketOutcome::Malformed);
        assert_eq!(
            parse_signature_armor("not an armor block"),
            SignaturePacketOutcome::Malformed
        );
    }

    /// Armor present but base64 body cannot be decoded → Malformed.
    #[test]
    fn test_garbage_base64_body_is_malformed() {
        let armor = "-----BEGIN PGP SIGNATURE-----\n\n!!!not-base64!!!\n=AAAA\n-----END PGP SIGNATURE-----\n";
        assert_eq!(
            parse_signature_armor(armor),
            SignaturePacketOutcome::Malformed
        );
    }

    /// Armor base64 decodes BUT the byte stream has no packet whose
    /// first byte has bit 7 set → Malformed. RFC 4880 §4.2 requires
    /// every packet header to have bit 7 of the tag octet set.
    #[test]
    fn test_packet_stream_with_invalid_tag_bit_is_malformed() {
        // 0x40 has bit 7 = 0 → invalid
        let bytes = vec![0x40, 0x01, 0x00];
        let encoded = general_purpose::STANDARD.encode(&bytes);
        let armor = format!(
            "-----BEGIN PGP SIGNATURE-----\n\n{}\n=AAAA\n-----END PGP SIGNATURE-----\n",
            encoded
        );
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::Malformed
        );
    }

    /// Packet length claims more bytes than the stream holds →
    /// Malformed. The truncation discipline ensures a corrupt armor
    /// cannot be silently truncated into a "recovered" outcome with
    /// junk as the key ID.
    #[test]
    fn test_truncated_packet_body_is_malformed() {
        // new format, tag 2, length = 100 — but body is only a few
        // bytes
        let bytes = vec![0xC2, 100, 4, 0, 1, 8];
        let encoded = general_purpose::STANDARD.encode(&bytes);
        let armor = format!(
            "-----BEGIN PGP SIGNATURE-----\n\n{}\n=AAAA\n-----END PGP SIGNATURE-----\n",
            encoded
        );
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::Malformed
        );
    }

    /// The four arms collapse to `Some` only on `RecoveredV4`. Pin
    /// all four arms so a future refactor that flips truthiness
    /// fails loudly rather than silently inflating /deflating the
    /// signer-identity claim.
    #[test]
    fn test_key_id_hex_pins_all_four_arms() {
        assert_eq!(
            SignaturePacketOutcome::RecoveredV4 {
                key_id_hex: "0123456789abcdef".to_string()
            }
            .key_id_hex(),
            Some("0123456789abcdef")
        );
        assert_eq!(
            SignaturePacketOutcome::RecoveredV4NoIssuer.key_id_hex(),
            None
        );
        assert_eq!(
            SignaturePacketOutcome::UnsupportedVersion { version: 3 }.key_id_hex(),
            None
        );
        assert_eq!(SignaturePacketOutcome::Malformed.key_id_hex(), None);
    }

    /// **Mutual-distinctness invariant.** The four arms cannot
    /// conflate at the boundary: a `RecoveredV4NoIssuer` (well-formed
    /// sig, no Issuer subpacket) must NOT compare equal to a
    /// `Malformed` (armor broke) — the prior unconditional `None` at
    /// the call site lost exactly this discriminator.
    #[test]
    fn test_four_arms_are_mutually_distinct() {
        let a = SignaturePacketOutcome::RecoveredV4 {
            key_id_hex: "0123456789abcdef".to_string(),
        };
        let b = SignaturePacketOutcome::RecoveredV4NoIssuer;
        let c = SignaturePacketOutcome::UnsupportedVersion { version: 3 };
        let d = SignaturePacketOutcome::Malformed;
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(b, c);
        assert_ne!(b, d);
        assert_ne!(c, d);
    }

    /// Critical-bit (high bit of subpacket type) is masked off before
    /// comparing types — RFC 4880 §5.2.3.1 reserves the high bit as
    /// the critical flag; an Issuer subpacket marked critical
    /// (type = 144 = 0x90 = 0x80 | 16) is still type-16 for scanning
    /// purposes.
    #[test]
    fn test_critical_bit_does_not_mask_issuer_type() {
        let key_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut body = Vec::new();
        body.push(4);
        body.push(0);
        body.push(1);
        body.push(8);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0, 10]);
        body.push(9);
        body.push(0x80 | 16); // critical bit set; type is still Issuer
        body.extend_from_slice(&key_id);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0, 1, 0]);
        let armor = wrap_packet_in_armor(&body);
        assert_eq!(
            parse_signature_armor(&armor),
            SignaturePacketOutcome::RecoveredV4 {
                key_id_hex: "1122334455667788".to_string()
            }
        );
    }
}
