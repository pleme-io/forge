//! Fused `print_diag_section_header` + `probe_and_dump_docker_ps_<mode>`
//! sibling-stanza primitive.
//!
//! # Pre-lift census — 4 sibling stanzas across e2e.rs and prerelease.rs
//!
//! Both `commands/e2e.rs::print_failure_diagnostics`
//! (`DiagSink::Stderr`, `""` outer indent, `"  "` inner indent) and
//! `commands/prerelease.rs::print_e2e_diagnostics` (`DiagSink::Stdout`,
//! `"   "` outer indent, `"     "` inner indent) each restated the same
//! two consecutive header+probe pairs — one for the docker-ps
//! `running` diagnostic and one for the docker-ps `-a --filter
//! status=exited --since 15m` diagnostic:
//!
//! ```ignore
//! print_diag_section_header(sink, outer, DiagSectionHeader::DockerContainersRunning);
//! probe_and_dump_docker_ps_running(bin, sink, inner);
//!
//! print_diag_section_header(sink, outer, DiagSectionHeader::DockerContainersRecentlyExited);
//! probe_and_dump_docker_ps_exited_since_15m(bin, sink, inner);
//! ```
//!
//! The (header variant, probe function) pair is a correlated choice —
//! `DockerContainersRunning` always precedes the `running` probe and
//! `DockerContainersRecentlyExited` always precedes the `exited` probe.
//! A caller cannot legitimately pair the `running` label with the
//! `exited` probe, so the section identity closes onto a single
//! two-variant enum ([`DockerPsDiagSection`]) whose two accessors
//! ([`DockerPsDiagSection::header`] and the match inside
//! [`print_docker_ps_diag_section`]) are the inverse of the pattern
//! that identified it.
//!
//! Post-lift each of the four sites collapses from a 12-line
//! header+probe pair to a single 6-arg call.

use crate::probe_dump::{
    print_diag_section_header, probe_and_dump_docker_ps_exited_since_15m,
    probe_and_dump_docker_ps_running, DiagSectionHeader, DiagSink,
};

/// Which of the two docker-ps diagnostic sections a caller is emitting.
///
/// The closed 2-variant enum pins the (header label, probe function)
/// correlation exhaustively — a caller cannot spell a third `docker ps`
/// diagnostic mode without adding a variant here, and both the header
/// projection and the probe dispatch below stay total by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerPsDiagSection {
    /// `docker ps --format <Names,Status,Ports>` — the "still running"
    /// containers snapshot. Pairs with
    /// [`DiagSectionHeader::DockerContainersRunning`] and
    /// [`probe_and_dump_docker_ps_running`].
    Running,
    /// `docker ps -a --filter status=exited --since 15m --format
    /// <Names,Status,Image>` — the "recently died" containers
    /// snapshot. Pairs with
    /// [`DiagSectionHeader::DockerContainersRecentlyExited`] and
    /// [`probe_and_dump_docker_ps_exited_since_15m`].
    RecentlyExited,
}

impl DockerPsDiagSection {
    /// The [`DiagSectionHeader`] variant that labels this section.
    ///
    /// Correlated-adjective projection: one row per variant, byte-oracle
    /// pinned by [`docker_ps_diag_section_header_projection_matches_pre_lift`]
    /// below. A future re-decision on which header labels which probe
    /// lands at this one match rather than at the four pre-lift sites.
    pub fn header(self) -> DiagSectionHeader {
        match self {
            Self::Running => DiagSectionHeader::DockerContainersRunning,
            Self::RecentlyExited => DiagSectionHeader::DockerContainersRecentlyExited,
        }
    }
}

/// Fused header+probe primitive: emit the section header to `sink`
/// under `outer_indent`, then run the matching docker-ps probe against
/// `docker_bin` and dump its rows under `inner_indent`.
///
/// The `outer_indent` prefixes the section header label; the
/// `inner_indent` prefixes each row the docker `--format` template
/// echoes and the `"(none)"` fallback the ternary emits on an empty
/// capture. Both indents are honored independently — the pre-lift
/// census carries `("", "  ")` at the E2E-failure block and
/// `("   ", "     ")` at the prerelease block, and the inner indent is
/// always a strict superset of the outer to keep rows visually nested.
///
/// A probe failure (spawn error, non-existent `docker` binary) is
/// silently skipped by the underlying
/// [`crate::probe_dump::probe_and_dump_or_none_sync`] contract, matching
/// the pre-lift `if let Some(stdout) = …` discipline: an unreachable
/// docker binary produces no diagnostics rather than a hard error
/// inside the enclosing failure handler.
pub fn print_docker_ps_diag_section(
    docker_bin: &str,
    sink: DiagSink,
    outer_indent: &str,
    inner_indent: &str,
    section: DockerPsDiagSection,
) {
    print_diag_section_header(sink, outer_indent, section.header());
    match section {
        DockerPsDiagSection::Running => {
            probe_and_dump_docker_ps_running(docker_bin, sink, inner_indent)
        }
        DockerPsDiagSection::RecentlyExited => {
            probe_and_dump_docker_ps_exited_since_15m(docker_bin, sink, inner_indent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle over the header-projection axis: each
    /// [`DockerPsDiagSection`] variant maps to the exact
    /// [`DiagSectionHeader`] variant its pre-lift stanza carried. A
    /// future swap that reversed the two arms (accidentally labeling
    /// the `running` snapshot with the "recently exited" header)
    /// regresses this assertion — a visually subtle failure downstream
    /// where the diagnostic label lies about the probe's data.
    #[test]
    fn docker_ps_diag_section_header_projection_matches_pre_lift() {
        assert_eq!(
            DockerPsDiagSection::Running.header(),
            DiagSectionHeader::DockerContainersRunning,
        );
        assert_eq!(
            DockerPsDiagSection::RecentlyExited.header(),
            DiagSectionHeader::DockerContainersRecentlyExited,
        );
    }

    /// Shield: [`DockerPsDiagSection`] stays a closed 2-variant enum.
    /// A future third docker-ps mode (`Paused`, `AllIncludingStopped`)
    /// is a deliberate design decision — this shield forces it through
    /// review rather than sliding in via a defaulted match arm.
    /// Mirrors the sibling `diag_sink_stays_closed_two_variants` and
    /// `diag_section_header_stays_closed_three_variants` shields in
    /// [`crate::probe_dump`].
    #[test]
    fn docker_ps_diag_section_stays_closed_two_variants() {
        for section in [
            DockerPsDiagSection::Running,
            DockerPsDiagSection::RecentlyExited,
        ] {
            match section {
                DockerPsDiagSection::Running => (),
                DockerPsDiagSection::RecentlyExited => (),
            }
        }
    }

    /// Shield: the two [`DockerPsDiagSection`] variants project onto
    /// distinct [`DiagSectionHeader`] variants. A future addition that
    /// accidentally collapsed both arms onto the same header — a
    /// copy-paste that dropped the discriminating arm — would collapse
    /// two visually distinct diagnostic sections into one. This shield
    /// makes the collapse a hard test failure.
    #[test]
    fn docker_ps_diag_section_header_projection_is_pairwise_distinct() {
        assert_ne!(
            DockerPsDiagSection::Running.header(),
            DockerPsDiagSection::RecentlyExited.header(),
        );
    }

    /// Caller shield: no source line under `cli/src/commands/` may
    /// spell either of the two pre-lift bare
    /// `crate::probe_dump::probe_and_dump_docker_ps_<mode>(` calls
    /// inline any more. The four pre-lift sites
    /// (`commands/e2e.rs::print_failure_diagnostics` × 2,
    /// `commands/prerelease.rs::print_e2e_diagnostics` × 2) each
    /// migrated onto [`print_docker_ps_diag_section`]; any future
    /// consumer that wants the header+probe pair reaches for the fused
    /// primitive on first grep, not by copy-pasting the header and
    /// probe stanzas as two separate calls from an existing command
    /// module. Mirrors the negative-half discipline of the sibling
    /// caller shields elsewhere in this crate.
    #[test]
    fn no_command_module_still_spells_raw_docker_ps_probe_and_dump_call() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        // Reconstruct the needles at runtime so this test file itself
        // does not spell either bare call inline and get flagged by
        // its own shield when the test source is scanned by editor
        // tooling that follows string literals.
        let running_needle = format!("crate::probe_dump::probe_and_dump_docker_ps_{}(", "running");
        let exited_needle = format!(
            "crate::probe_dump::probe_and_dump_docker_ps_exited_since_{}(",
            "15m"
        );
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (idx, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                if line.contains(&running_needle) || line.contains(&exited_needle) {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `probe_and_dump_docker_ps_<mode>(...)` call(s) survive \
             under `commands/` — route each header+probe pair through \
             `crate::docker_ps_diag_section::print_docker_ps_diag_section(...)` \
             with a `DockerPsDiagSection::{{Running|RecentlyExited}}` \
             variant instead:\n{:#?}",
            offenders
        );
    }

    /// Positive delegation shield: the two pre-lift files MUST each
    /// forward through [`print_docker_ps_diag_section`] at least twice
    /// (one call per docker-ps mode). A migration that dropped a call
    /// site outright — leaving the negative "no raw probe call" scan
    /// trivially satisfied by absence — regresses this floor. Mirrors
    /// the sibling `every_prelift_module_forwards_through_probe_and_dump_primitive`
    /// positive-half discipline in [`crate::probe_dump`].
    #[test]
    fn every_prelift_module_forwards_through_print_docker_ps_diag_section() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("e2e.rs", 2), ("prerelease.rs", 2)];
        let needle = "crate::docker_ps_diag_section::print_docker_ps_diag_section(";
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source.matches(needle).count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} docker-ps \
                 header+probe site(s) through \
                 `crate::docker_ps_diag_section::print_docker_ps_diag_section(...)`; \
                 found {forwards}. A dropped call would leave the negative \
                 raw-probe-call scan satisfied by absence.",
            );
        }
    }
}
