//! Multi-arch OCI image release
//!
//! Replaces image-release.nix::mkImageReleaseApp.
//! Builds (or uses pre-built) images for amd64/arm64, pushes via skopeo,
//! and creates a multi-arch manifest index.

use anyhow::{bail, Context, Result};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use tracing::info;

use crate::git;
use crate::nix::build_flake_attr_in;
use crate::tools::get_tool_path;

/// Release a multi-arch OCI image.
///
/// If `--amd64-attr` or `--arm64-attr` are provided, the image is built via `nix build` first.
/// Otherwise, `--amd64-image` / `--arm64-image` must point to pre-built image tarballs.
///
/// When `verify_elf` is true (the default), each resolved image is gated through
/// [`verify_image_arch`] *before* push — so an image whose binary can't run on the
/// arch it is being tagged under is refused at the gate, never shipped to crashloop
/// with `exec format error` (the hanabi 2026-06-14 amd64-tag-holding-aarch64 class).
pub async fn execute(
    name: &str,
    registry: &str,
    amd64_attr: Option<&str>,
    arm64_attr: Option<&str>,
    amd64_image: Option<&str>,
    arm64_image: Option<&str>,
    working_dir: &str,
    verify_elf: bool,
) -> Result<()> {
    let sha = git::get_short_sha()?;
    let skopeo = get_tool_path("skopeo");

    // Resolve amd64 image path
    let amd64_path = match (amd64_image, amd64_attr) {
        (Some(path), _) => path.to_string(),
        (None, Some(attr)) => build_nix_image(attr, working_dir).await?,
        (None, None) => bail!("Either --amd64-image or --amd64-attr is required"),
    };

    // Resolve arm64 image path (optional)
    let arm64_path = match (arm64_image, arm64_attr) {
        (Some(path), _) => Some(path.to_string()),
        (None, Some(attr)) => Some(build_nix_image(attr, working_dir).await?),
        (None, None) => None,
    };

    // Push amd64 — gate the loader before the push (default on).
    if verify_elf {
        info!("Verifying {} (amd64) image loader before push...", name);
        verify_image_arch(&skopeo, &amd64_path, "amd64")?;
    }
    let amd64_tag = format!("amd64-{}", sha);
    info!("Pushing {} (amd64) as {}:{}...", name, registry, amd64_tag);
    push_image(&skopeo, &amd64_path, registry, &amd64_tag)?;
    push_image(&skopeo, &amd64_path, registry, "amd64-latest")?;

    // Push arm64 if available
    if let Some(ref arm64) = arm64_path {
        if verify_elf {
            info!("Verifying {} (arm64) image loader before push...", name);
            verify_image_arch(&skopeo, arm64, "arm64")?;
        }
        let arm64_tag = format!("arm64-{}", sha);
        info!("Pushing {} (arm64) as {}:{}...", name, registry, arm64_tag);
        push_image(&skopeo, arm64, registry, &arm64_tag)?;
        push_image(&skopeo, arm64, registry, "arm64-latest")?;
    }

    // Create multi-arch manifest index if both architectures are present.
    //
    // Uses modern regctl `index create` (which accepts source per-arch
    // images via repeated `--ref` flags). The legacy `manifest put`
    // syntax — which took source refs as positional args — was removed
    // and now reads manifest content from stdin only.
    if arm64_path.is_some() {
        info!("Creating multi-arch manifest index...");

        let regctl = get_tool_path("regctl");

        // SHA-pinned multi-arch index.
        let status = Command::new(&regctl)
            .args([
                "index",
                "create",
                &format!("{}:{}", registry, sha),
                "--ref",
                &format!("{}:{}", registry, amd64_tag),
                "--ref",
                &format!("{}:arm64-{}", registry, sha),
            ])
            .status()
            .context("Failed to create multi-arch index (sha)")?;

        if !status.success() {
            bail!("regctl index create (sha) failed");
        }

        // Floating `latest` multi-arch index.
        let status = Command::new(&regctl)
            .args([
                "index",
                "create",
                &format!("{}:latest", registry),
                "--ref",
                &format!("{}:amd64-latest", registry),
                "--ref",
                &format!("{}:arm64-latest", registry),
            ])
            .status()
            .context("Failed to create multi-arch index (latest)")?;

        if !status.success() {
            bail!("regctl index create (latest) failed");
        }
    }

    // Build the actual list of tags pushed so the summary is accurate.
    // The previous summary printed a single misleading tag (`:sha`) which
    // didn't always exist (e.g. when arm64_path is None, no multi-arch
    // index is created and the unprefixed tag never gets created).
    let mut tags_pushed = vec![
        format!("{}:amd64-{}", registry, sha),
        format!("{}:amd64-latest", registry),
    ];
    if arm64_path.is_some() {
        tags_pushed.push(format!("{}:arm64-{}", registry, sha));
        tags_pushed.push(format!("{}:arm64-latest", registry));
        tags_pushed.push(crate::oci_manifest::image_reference(registry, &sha));
        tags_pushed.push(crate::oci_manifest::image_reference(registry, "latest"));
    }
    info!(
        "Image release complete — {} tags pushed for {}:",
        tags_pushed.len(),
        name
    );
    for tag in &tags_pushed {
        info!("  {}", tag);
    }
    Ok(())
}

// --- Helpers ---

/// Build a sub-flake attribute inside `working_dir` and return the resulting
/// store path. Thin wrapper that prepends the canonical `.#` prefix to the
/// caller-supplied `flake_attr` and delegates to the canonical
/// [`build_flake_attr_in`] primitive — the typed `NixBuildError`
/// `(BuildFailed | EmptyStorePath | ExecFailed)` discrimination is
/// recoverable across the anyhow boundary.
async fn build_nix_image(flake_attr: &str, working_dir: &str) -> Result<String> {
    info!("Building .#{}...", flake_attr);
    let result =
        build_flake_attr_in(&format!(".#{}", flake_attr), Some(Path::new(working_dir))).await?;
    Ok(result.store_path)
}

fn push_image(skopeo: &str, image_path: &str, registry: &str, tag: &str) -> Result<()> {
    let status = Command::new(skopeo)
        .args([
            "copy",
            "--insecure-policy",
            &format!("docker-archive:{}", image_path),
            &format!("docker://{}:{}", registry, tag),
        ])
        .status()
        .with_context(|| format!("Failed to push {}:{}", registry, tag))?;

    if !status.success() {
        bail!("skopeo copy failed for {}:{}", registry, tag);
    }

    Ok(())
}

// --- Loader verification (pre-push gate) ---

/// Why an image cannot be proven runnable on the arch it is being tagged under.
///
/// `ArchMismatch` / `MissingArchitecture` (from `skopeo inspect`'s declared
/// `Architecture`) and `BinaryArchMismatch` / `NotAnElf` (from reading the
/// REAL magic/e_machine bytes of every executable file in every layer) are
/// both implemented — two independent layers of the same guard.
///
/// The manifest-metadata check alone is NOT sufficient: it catches the
/// original hanabi 2026-06-14 class (a genuinely-arm64-built image whose OCI
/// manifest correctly says `arm64`, pushed under an `amd64-<sha>` tag — a
/// labeling mistake at the push call site). It does NOT catch a build
/// producing an image whose manifest metadata says `amd64` (because that's
/// what the Nix target system requested) while the actual binary content
/// inside is not real, runnable amd64 machine code — confirmed live
/// 2026-07-16 (pitr-tools, `amd64-886774d`): `skopeo inspect` reported
/// `"Architecture":"amd64"`, the OCI-declared metadata forge's existing check
/// already trusted, while every binary a real amd64 k3s pod tried to exec
/// failed with `exec format error` and turned out on direct inspection to be
/// a Darwin Mach-O arm64 executable — a build-host artifact that ended up in
/// a Linux image, not a mislabeled build. Never trust self-reported metadata
/// over the actual bytes when the two are cheap to cross-check.
///
/// THE DESTINATION (named next milestone, not yet built): also parse each
/// ELF's `PT_INTERP` + `DT_NEEDED` (via the `object` crate) and confirm each
/// is present in the image's layer closure — the gaveta r19/r20
/// glibc-loader-not-in-the-minimal-image class. Reserved as
/// `MissingInterpreter` / `MissingNeededLib` below; not built in this pass
/// (pitr-tools' binaries are `CGO_ENABLED=0` static Go — no dynamic loader to
/// check — so the case that forced this fix didn't need it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    /// The image declares an architecture other than the tag it is about to be
    /// pushed under (e.g. an `arm64` image about to become `amd64-<sha>`).
    ArchMismatch { expected: String, found: String },
    /// `skopeo inspect` returned no usable `Architecture` field.
    MissingArchitecture,
    /// A regular, executable-permission file inside the image's layers has a
    /// real ELF `e_machine` that does not match `expected_arch` — the image's
    /// OCI metadata may claim the right architecture; the actual bytes don't.
    BinaryArchMismatch {
        path: String,
        expected: String,
        found: String,
    },
    /// A regular, executable-permission file inside the image's layers is not
    /// an ELF at all (e.g. a macOS Mach-O binary, or a Windows PE) — a
    /// build-host artifact that leaked into a Linux image.
    NotAnElf { path: String, magic: String },
    /// Reserved, not yet built — see the type doc comment above.
    #[allow(dead_code)]
    MissingInterpreter { path: String, interp: String },
    /// Reserved, not yet built — see the type doc comment above.
    #[allow(dead_code)]
    MissingNeededLib { path: String, lib: String },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::ArchMismatch { expected, found } => write!(
                f,
                "image architecture mismatch: about to push as '{expected}' but the image \
                 declares '{found}' — pushing it would crashloop with `exec format error`. \
                 Build the '{expected}' image attribute on a native-'{expected}' runner."
            ),
            LoaderError::MissingArchitecture => write!(
                f,
                "`skopeo inspect` returned no Architecture field — not a usable single-arch OCI image"
            ),
            LoaderError::BinaryArchMismatch {
                path,
                expected,
                found,
            } => write!(
                f,
                "binary architecture mismatch: {path} is real ELF machine-type '{found}', not \
                 '{expected}' — the image's OCI metadata may claim '{expected}' but this file \
                 would crashloop with `exec format error` on a real '{expected}' node. This is a \
                 build-pipeline bug (likely a cross-compile or host-vs-target mixup), not a \
                 tagging mistake — the metadata-only check would have missed this."
            ),
            LoaderError::NotAnElf { path, magic } => write!(
                f,
                "{path} is not a Linux ELF binary (magic bytes: {magic}) — likely a build-host \
                 artifact (e.g. a macOS Mach-O or Windows PE binary) that leaked into this Linux \
                 image. It would crashloop with `exec format error` regardless of which \
                 architecture the image is tagged under."
            ),
            LoaderError::MissingInterpreter { path, interp } => write!(
                f,
                "{path} declares PT_INTERP={interp} but that interpreter is not present in this \
                 image's layer closure"
            ),
            LoaderError::MissingNeededLib { path, lib } => write!(
                f,
                "{path} declares DT_NEEDED={lib} but that library is not present in this image's \
                 layer closure"
            ),
        }
    }
}

impl std::error::Error for LoaderError {}

/// Pure arch check over `skopeo inspect` JSON. Factored out from the skopeo
/// invocation so it is unit-testable without a registry or a real tarball.
fn check_inspect_arch(inspect_json: &[u8], expected_arch: &str) -> Result<(), LoaderError> {
    let v: serde_json::Value =
        serde_json::from_slice(inspect_json).map_err(|_| LoaderError::MissingArchitecture)?;
    let found = v
        .get("Architecture")
        .and_then(|a| a.as_str())
        .ok_or(LoaderError::MissingArchitecture)?;
    if found == expected_arch {
        Ok(())
    } else {
        Err(LoaderError::ArchMismatch {
            expected: expected_arch.to_string(),
            found: found.to_string(),
        })
    }
}

/// Verify that `image_path` (a docker-archive tarball) is actually runnable on
/// `expected_arch` before it is pushed under an `<expected_arch>-<sha>` tag —
/// two independent checks, both must pass (see the [`LoaderError`] type doc
/// for why one alone is not sufficient):
///   1. the OCI manifest's declared `Architecture` (via `skopeo inspect`,
///      catches the tagging-mistake class);
///   2. every regular, executable-permission file in every layer is a real
///      ELF whose `e_machine` matches `expected_arch` (catches the
///      wrong-binary-content class metadata alone can't see).
/// Bails with the typed [`LoaderError`] so a bad image is refused at the gate
/// instead of shipped to crashloop.
fn verify_image_arch(skopeo: &str, image_path: &str, expected_arch: &str) -> Result<()> {
    let output = Command::new(skopeo)
        .args(["inspect", &format!("docker-archive:{}", image_path)])
        .output()
        .with_context(|| format!("Failed to run skopeo inspect on {}", image_path))?;

    if !output.status.success() {
        bail!(
            "skopeo inspect failed for {}: {}",
            image_path,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    check_inspect_arch(&output.stdout, expected_arch)
        .map_err(|e| anyhow::anyhow!("{} (image: {})", e, image_path))?;

    verify_binary_contents_arch(image_path, expected_arch)
        .map_err(|e| anyhow::anyhow!("{} (image: {})", e, image_path))
}

/// ELF `e_machine` values relevant here (ELF spec, EM_* constants).
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Map an `expected_arch` string (as used throughout this module: "amd64" /
/// "arm64") to the ELF `e_machine` value a real binary for that arch carries.
fn expected_em_machine(expected_arch: &str) -> Option<u16> {
    match expected_arch {
        "amd64" => Some(EM_X86_64),
        "arm64" => Some(EM_AARCH64),
        _ => None,
    }
}

fn em_machine_name(em: u16) -> String {
    match em {
        EM_X86_64 => "amd64 (EM_X86_64)".to_string(),
        EM_AARCH64 => "arm64 (EM_AARCH64)".to_string(),
        other => format!("unknown (e_machine={other})"),
    }
}

/// Classify the first ~20 bytes of a file as ELF (with its real e_machine),
/// a known non-ELF executable format, or "not a recognized binary format"
/// (scripts, symlinks-as-regular-files misread, etc. — not this check's
/// concern, skipped rather than flagged).
enum Magic {
    Elf { e_machine: u16 },
    MachO,
    Pe,
    Other,
}

fn classify_magic(head: &[u8]) -> Magic {
    if head.len() >= 20 && head[0..4] == [0x7f, b'E', b'L', b'F'] {
        // e_machine is a 2-byte field at offset 18; endianness comes from
        // EI_DATA at offset 5 (1 = little-endian, 2 = big-endian). Every
        // arch this gate cares about (x86_64, aarch64) is little-endian in
        // practice, but read it honestly rather than assume.
        let le = head[5] != 2;
        let bytes = [head[18], head[19]];
        let e_machine = if le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        };
        return Magic::Elf { e_machine };
    }
    if head.len() >= 4 {
        let magic4 = [head[0], head[1], head[2], head[3]];
        // Mach-O: 32/64-bit, both endiannesses, plus the fat/universal magic.
        const MACHO_MAGICS: [[u8; 4]; 6] = [
            [0xfe, 0xed, 0xfa, 0xce], // MH_MAGIC (32-bit BE)
            [0xce, 0xfa, 0xed, 0xfe], // MH_CIGAM (32-bit LE)
            [0xfe, 0xed, 0xfa, 0xcf], // MH_MAGIC_64 (64-bit BE)
            [0xcf, 0xfa, 0xed, 0xfe], // MH_CIGAM_64 (64-bit LE)
            [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC (universal binary, BE)
            [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM (universal binary, LE)
        ];
        if MACHO_MAGICS.contains(&magic4) {
            return Magic::MachO;
        }
    }
    if head.len() >= 2 && head[0..2] == [b'M', b'Z'] {
        return Magic::Pe;
    }
    Magic::Other
}

fn magic_hex(head: &[u8]) -> String {
    head.iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Walk every layer tar inside the docker-archive `image_path`, and for every
/// regular, executable-permission entry of non-trivial size, read its magic
/// bytes and confirm it is a real ELF for `expected_arch` — not a Mach-O/PE
/// build-host artifact, and not an ELF for the wrong machine type. Small
/// files (shebang scripts, etc.) below `MIN_BINARY_SIZE` are skipped — this
/// gate is about compiled binaries, not glue scripts (which are themselves
/// against the fleet's own no-shell rule, a separate concern).
fn verify_binary_contents_arch(image_path: &str, expected_arch: &str) -> Result<(), LoaderError> {
    const MIN_BINARY_SIZE: u64 = 4096;

    let expected_em = expected_em_machine(expected_arch);

    let manifest =
        read_docker_archive_manifest(image_path).map_err(|_| LoaderError::MissingArchitecture)?;

    for layer_name in &manifest.layers {
        let mut outer = tar::Archive::new(
            File::open(image_path).map_err(|_| LoaderError::MissingArchitecture)?,
        );
        let entries = match outer.entries() {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let mut entry = entry;
            let path_in_outer = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if path_in_outer != *layer_name {
                continue;
            }
            // Found the layer tar as an entry inside the outer archive —
            // read it fully (layers are typically tens of MB, fine to
            // buffer) and walk it as a nested tar.
            let mut layer_bytes = Vec::new();
            if entry.read_to_end(&mut layer_bytes).is_err() {
                continue;
            }
            let mut layer_archive = tar::Archive::new(layer_bytes.as_slice());
            let layer_entries = match layer_archive.entries() {
                Ok(e) => e,
                Err(_) => continue,
            };
            for layer_entry in layer_entries.flatten() {
                let mut layer_entry = layer_entry;
                if layer_entry.header().entry_type() != tar::EntryType::Regular {
                    continue;
                }
                let mode = layer_entry.header().mode().unwrap_or(0);
                let size = layer_entry.header().size().unwrap_or(0);
                if mode & 0o111 == 0 || size < MIN_BINARY_SIZE {
                    continue;
                }
                let entry_path = layer_entry
                    .path()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mut head = [0u8; 20];
                let n = layer_entry.read(&mut head).unwrap_or(0);
                match classify_magic(&head[..n]) {
                    Magic::Elf { e_machine } => {
                        if let Some(expected) = expected_em {
                            if e_machine != expected {
                                return Err(LoaderError::BinaryArchMismatch {
                                    path: format!("/{entry_path}"),
                                    expected: expected_arch.to_string(),
                                    found: em_machine_name(e_machine),
                                });
                            }
                        }
                    }
                    Magic::MachO | Magic::Pe => {
                        return Err(LoaderError::NotAnElf {
                            path: format!("/{entry_path}"),
                            magic: magic_hex(&head[..n]),
                        });
                    }
                    Magic::Other => {
                        // Not a recognized compiled-binary magic (script,
                        // truncated read, etc.) — outside this check's scope.
                    }
                }
            }
        }
    }

    Ok(())
}

struct DockerArchiveManifest {
    layers: Vec<String>,
}

/// Read and parse `manifest.json` from the top level of a docker-archive
/// tarball (the standard `[{"Config": "...", "Layers": ["a/layer.tar", ...]}]`
/// shape skopeo/docker produce).
fn read_docker_archive_manifest(image_path: &str) -> Result<DockerArchiveManifest> {
    let file = File::open(image_path)
        .with_context(|| format!("Failed to open image tarball {}", image_path))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries()?.flatten() {
        let mut entry = entry;
        let path = entry.path()?.to_string_lossy().to_string();
        if path == "manifest.json" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            let parsed: serde_json::Value = serde_json::from_str(&contents)
                .context("manifest.json in docker-archive tarball is not valid JSON")?;
            let first = parsed
                .as_array()
                .and_then(|a| a.first())
                .context("manifest.json has no entries")?;
            let layers = first
                .get("Layers")
                .and_then(|l| l.as_array())
                .context("manifest.json entry has no Layers array")?
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            return Ok(DockerArchiveManifest { layers });
        }
    }
    bail!(
        "manifest.json not found at the top level of docker-archive tarball {}",
        image_path
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_match_passes() {
        let json = br#"{"Name":"x","Architecture":"amd64","Os":"linux"}"#;
        assert!(check_inspect_arch(json, "amd64").is_ok());
    }

    #[test]
    fn arch_mismatch_is_typed() {
        // The hanabi class: an arm64 image about to be tagged amd64-<sha>.
        let json = br#"{"Architecture":"arm64","Os":"linux"}"#;
        let err = check_inspect_arch(json, "amd64").unwrap_err();
        assert_eq!(
            err,
            LoaderError::ArchMismatch {
                expected: "amd64".to_string(),
                found: "arm64".to_string(),
            }
        );
        // Display names the runtime symptom so the gate message is actionable.
        assert!(err.to_string().contains("exec format error"));
    }

    #[test]
    fn arm64_match_passes() {
        let json = br#"{"Architecture":"arm64"}"#;
        assert!(check_inspect_arch(json, "arm64").is_ok());
    }

    #[test]
    fn missing_architecture_field_is_typed() {
        let json = br#"{"Name":"x","Os":"linux"}"#;
        assert_eq!(
            check_inspect_arch(json, "amd64").unwrap_err(),
            LoaderError::MissingArchitecture
        );
    }

    #[test]
    fn non_json_inspect_output_is_typed() {
        assert_eq!(
            check_inspect_arch(b"not json at all", "amd64").unwrap_err(),
            LoaderError::MissingArchitecture
        );
    }

    // --- classify_magic: pure, no I/O ---

    fn elf_header(e_machine: u16) -> Vec<u8> {
        let mut h = vec![0x7f, b'E', b'L', b'F'];
        h.push(2); // EI_CLASS: 64-bit (irrelevant to this check)
        h.push(1); // EI_DATA: little-endian
        h.extend_from_slice(&[0u8; 12]); // pad to offset 18
        h.extend_from_slice(&e_machine.to_le_bytes());
        h
    }

    #[test]
    fn classify_elf_x86_64() {
        let head = elf_header(EM_X86_64);
        match classify_magic(&head) {
            Magic::Elf { e_machine } => assert_eq!(e_machine, EM_X86_64),
            _ => panic!("expected Elf"),
        }
    }

    #[test]
    fn classify_elf_aarch64() {
        let head = elf_header(EM_AARCH64);
        match classify_magic(&head) {
            Magic::Elf { e_machine } => assert_eq!(e_machine, EM_AARCH64),
            _ => panic!("expected Elf"),
        }
    }

    #[test]
    fn classify_macho_64_le_is_not_elf() {
        // The exact bytes this fix was written against: a Darwin Mach-O
        // 64-bit LE binary (`file` reported "Mach-O 64-bit executable arm64")
        // found inside a Linux image tagged amd64.
        let head = [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        assert!(matches!(classify_magic(&head), Magic::MachO));
    }

    #[test]
    fn classify_macho_fat_is_not_elf() {
        let head = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        assert!(matches!(classify_magic(&head), Magic::MachO));
    }

    #[test]
    fn classify_pe_is_not_elf() {
        let head = [b'M', b'Z', 0x90, 0x00];
        assert!(matches!(classify_magic(&head), Magic::Pe));
    }

    #[test]
    fn classify_shebang_script_is_other_not_flagged() {
        let head = b"#!/bin/sh\nset -e\n";
        assert!(matches!(classify_magic(head), Magic::Other));
    }

    #[test]
    fn em_machine_name_is_readable() {
        assert!(em_machine_name(EM_X86_64).contains("amd64"));
        assert!(em_machine_name(EM_AARCH64).contains("arm64"));
        assert!(em_machine_name(9999).contains("unknown"));
    }

    // --- verify_binary_contents_arch: end-to-end against a real tarball ---

    /// Builds a minimal, real docker-archive-shaped tarball: an outer tar
    /// containing `manifest.json` (pointing at one layer) and the layer tar
    /// itself (containing one executable-permission regular file whose
    /// content is `payload`). Mirrors exactly what `skopeo`/`dockerTools`
    /// produce, at the level this check reads.
    fn build_fake_docker_archive(payload: &[u8]) -> tempfile::NamedTempFile {
        // Build the inner layer tar first.
        let mut layer_buf = Vec::new();
        {
            let mut layer_tar = tar::Builder::new(&mut layer_buf);
            let mut header = tar::Header::new_gnu();
            header.set_path("reap").unwrap();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            layer_tar.append(&header, payload).unwrap();
            layer_tar.finish().unwrap();
        }

        let manifest = serde_json::json!([
            {
                "Config": "config.json",
                "RepoTags": [],
                "Layers": ["layer1/layer.tar"],
            }
        ]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let out = tempfile::NamedTempFile::new().unwrap();
        {
            let mut outer_tar = tar::Builder::new(out.reopen().unwrap());

            let mut mheader = tar::Header::new_gnu();
            mheader.set_path("manifest.json").unwrap();
            mheader.set_size(manifest_bytes.len() as u64);
            mheader.set_mode(0o644);
            mheader.set_cksum();
            outer_tar
                .append(&mheader, manifest_bytes.as_slice())
                .unwrap();

            let mut lheader = tar::Header::new_gnu();
            lheader.set_path("layer1/layer.tar").unwrap();
            lheader.set_size(layer_buf.len() as u64);
            lheader.set_mode(0o644);
            lheader.set_cksum();
            outer_tar.append(&lheader, layer_buf.as_slice()).unwrap();

            outer_tar.finish().unwrap();
        }
        out
    }

    #[test]
    fn verify_binary_contents_arch_passes_matching_elf() {
        let mut payload = elf_header(EM_X86_64);
        payload.resize(4096 + 100, 0); // past MIN_BINARY_SIZE
        let tmp = build_fake_docker_archive(&payload);
        let path = tmp.path().to_string_lossy().to_string();
        assert!(verify_binary_contents_arch(&path, "amd64").is_ok());
    }

    #[test]
    fn verify_binary_contents_arch_catches_wrong_elf_machine() {
        let mut payload = elf_header(EM_AARCH64);
        payload.resize(4096 + 100, 0);
        let tmp = build_fake_docker_archive(&payload);
        let path = tmp.path().to_string_lossy().to_string();
        let err = verify_binary_contents_arch(&path, "amd64").unwrap_err();
        assert!(matches!(err, LoaderError::BinaryArchMismatch { .. }));
        assert!(err.to_string().contains("exec format error"));
    }

    #[test]
    fn verify_binary_contents_arch_catches_macho_leak() {
        // Reproduces the exact live bug this fix closes: a Mach-O binary
        // shipped inside a Linux image whose OCI metadata still says amd64.
        let mut payload = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        payload.resize(4096 + 100, 0);
        let tmp = build_fake_docker_archive(&payload);
        let path = tmp.path().to_string_lossy().to_string();
        let err = verify_binary_contents_arch(&path, "amd64").unwrap_err();
        assert!(matches!(err, LoaderError::NotAnElf { .. }));
    }

    #[test]
    fn verify_binary_contents_arch_ignores_small_files() {
        // Below MIN_BINARY_SIZE — even a Mach-O magic should be skipped
        // (this check targets compiled binaries, not every tiny file).
        let payload = vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        let tmp = build_fake_docker_archive(&payload);
        let path = tmp.path().to_string_lossy().to_string();
        assert!(verify_binary_contents_arch(&path, "amd64").is_ok());
    }
}
