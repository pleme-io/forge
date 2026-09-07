//! Redis `KEYS <prefix>:<kind>:*` probe stanza for the ReBAC validator's
//! Redis connectivity check.
//!
//! # Pre-lift census — two sibling stanzas, byte-identical modulo the
//! `(kind, description)` correlated pair
//!
//! Two consumer sites inside
//! `commands/rebac_validation.rs::check_redis_connectivity` each restated
//! the same 12-line stanza:
//!
//! ```ignore
//! // 1. relation-tuple scan
//! let rel_glob = format!("{}:rel:*", config.redis_key_prefix);
//! let keys_output = Command::new(&redis_cli)
//!     .args(["-u", &redis_url, "KEYS", &rel_glob])
//!     .output()
//!     .await;
//! if let Ok(keys) = keys_output {
//!     let key_count = String::from_utf8_lossy(&keys.stdout)
//!         .lines()
//!         .filter(|l| !l.is_empty())
//!         .count();
//!     if !config.quiet {
//!         println!("   Found {} relation keys", key_count);
//!     }
//! }
//!
//! // 2. permission-cache scan
//! let perm_glob = format!("{}:perm:*", config.redis_key_prefix);
//! let perm_output = Command::new(&redis_cli)
//!     .args(["-u", &redis_url, "KEYS", &perm_glob])
//!     .output()
//!     .await;
//! if let Ok(keys) = perm_output {
//!     let key_count = String::from_utf8_lossy(&keys.stdout)
//!         .lines()
//!         .filter(|l| !l.is_empty())
//!         .count();
//!     if !config.quiet {
//!         println!("   Found {} permission cache keys", key_count);
//!     }
//! }
//! ```
//!
//! The two sites differ in one correlated pair: the glob infix (`"rel"` /
//! `"perm"`) and the report description (`"relation"` / `"permission
//! cache"`). That pair is closed under the [`RebacKeyKind`] enum here,
//! whose `glob_infix()` / `report_description()` methods are the two
//! projections. Adding a third key family is a single-variant edit to
//! the enum plus one new call site — no consumer needs to be re-checked
//! for exhaustiveness.
//!
//! # The three primitives this module owns
//!
//! - [`format_rebac_keys_glob`] — the pure `"{prefix}:{infix}:*"` byte-
//!   oracle formatter. No I/O; no Redis client dependency. Testable
//!   without a running Redis.
//! - [`count_non_empty_stdout_lines`] — the pure UTF-8 line-count reducer
//!   over the `KEYS` command's stdout buffer. Same
//!   `String::from_utf8_lossy → lines → filter non-empty → count` chain
//!   both pre-lift sites carried, hoisted so a future refactor (say, to
//!   `.trim().is_empty()`) lands once.
//! - [`probe_and_report_rebac_key_count`] — the async fusion primitive
//!   that spawns `redis-cli`, counts the keys, and prints the
//!   fleet-standard report line under a `quiet` gate. Both call sites
//!   collapse to a single line each.
//!
//! # The byte-oracle writer sibling
//!
//! [`write_rebac_keys_count_report`] captures the exact bytes the
//! terminal `println!` would emit (three-ASCII-space indent, `Found`
//! verb, decimal count, single-space gap on each side of the description,
//! `keys` noun, trailing newline) so the report grammar is pinned by
//! byte assertion — a future indent, verb, or word-order drift hits
//! the test rather than shipping. Same split
//! [`crate::zone_id_field::write_zone_id_field`] carries against its
//! `info_zone_id_field!` macro sibling.

use std::io;
use tokio::process::Command;

/// Which family of ReBAC keys to scan.
///
/// The two variants pin the correlated `(glob-infix, report-description)`
/// pair under one closed type. The infix is spliced into the KEYS glob
/// via [`format_rebac_keys_glob`]; the description is spliced into the
/// `"   Found {N} <desc> keys"` report line by
/// [`probe_and_report_rebac_key_count`].
///
/// Every match on this enum is exhaustive at compile time — a future
/// variant (say, `Session`) forces every projection here (glob_infix,
/// report_description) to answer, but leaves every consumer of the
/// enum's `Copy` value untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebacKeyKind {
    /// Relation tuples — glob infix `"rel"`, reported as
    /// `"N relation keys"`. Pre-lift site: `commands/rebac_validation.rs`
    /// line 504's `let rel_glob = format!("{}:rel:*", …)` block.
    Relation,
    /// Permission cache entries — glob infix `"perm"`, reported as
    /// `"N permission cache keys"`. Pre-lift site:
    /// `commands/rebac_validation.rs` line 520's
    /// `let perm_glob = format!("{}:perm:*", …)` block.
    Permission,
}

impl RebacKeyKind {
    /// The colon-delimited glob infix — `"rel"` for [`Self::Relation`],
    /// `"perm"` for [`Self::Permission`]. Spliced between the caller's
    /// prefix and the trailing `":*"` by [`format_rebac_keys_glob`].
    #[must_use]
    pub const fn glob_infix(self) -> &'static str {
        match self {
            Self::Relation => "rel",
            Self::Permission => "perm",
        }
    }

    /// The human-readable description spliced into the
    /// `"   Found {N} <description> keys"` report line.
    ///
    /// Distinct from [`Self::glob_infix`]: the pre-lift sites diverged
    /// on the two projections (`"rel"` glob vs. `"relation"` description;
    /// `"perm"` glob vs. `"permission cache"` description) so the pair
    /// is correlated but not identical. Merging the two into one
    /// projection would either mis-glob (`KEYS <prefix>:relation:*`
    /// hits nothing) or misread (`"Found N rel keys"` breaks the report
    /// grammar).
    #[must_use]
    pub const fn report_description(self) -> &'static str {
        match self {
            Self::Relation => "relation",
            Self::Permission => "permission cache",
        }
    }
}

/// Format the `KEYS` glob for a given prefix and key kind:
/// `"{prefix}:{infix}:*"`.
///
/// Pure byte-oracle — no I/O, no dependency on the Redis client. A caller
/// hands the returned `String` to
/// `Command::args(["-u", &url, "KEYS", &glob])`.
///
/// The pre-lift sibling stanzas both spelled `format!("{}:<infix>:*", …)`
/// inline, one per kind. Post-lift both sites read the infix out of the
/// closed [`RebacKeyKind`] enum, so a re-decision on the glob shape
/// (say, `<prefix>:<infix>:key:*`) lands in one place.
#[must_use]
pub fn format_rebac_keys_glob(prefix: &str, kind: RebacKeyKind) -> String {
    format!("{}:{}:*", prefix, kind.glob_infix())
}

/// Count the non-empty lines in a Redis `KEYS` command's stdout buffer.
///
/// The pre-lift sibling stanzas each rebuilt this same
/// `String::from_utf8_lossy → lines → filter non-empty → count` chain
/// against their local `keys_output.stdout`. This owns the counter so
/// a future refactor (say, `.trim().is_empty()` instead of `.is_empty()`,
/// or a switch to a byte-slice split that avoids the UTF-8 lossy pass)
/// lands in one place.
///
/// `String::from_utf8_lossy` matches the pre-lift shape verbatim: a
/// stray non-UTF-8 byte in a Redis key name gets replaced with `U+FFFD`
/// (which is 3 bytes, but not empty, so the line still counts). Redis
/// key names are conventionally UTF-8, so the lossy path is unreachable
/// on well-formed input and this primitive stays faithful to the pre-
/// lift behavior on the pathological input.
#[must_use]
pub fn count_non_empty_stdout_lines(stdout: &[u8]) -> usize {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .count()
}

/// Emit the fleet-standard `"   Found {N} {description} keys"` report
/// line to the supplied writer.
///
/// The byte-oracle sibling of the terminal `println!` inside
/// [`probe_and_report_rebac_key_count`]. Tests capture the exact
/// rendered bytes (three-ASCII-space indent, `Found` verb, decimal
/// count, single-space gap on each side of the description, `keys`
/// noun, trailing `\n`) so a future indent, verb, or word-order drift
/// hits the assertion rather than shipping.
///
/// Same split
/// [`crate::zone_id_field::write_zone_id_field`] carries against
/// [`crate::info_zone_id_field!`] and
/// [`crate::success_step::write_success_step`] carries against
/// [`crate::info_success!`].
#[allow(dead_code)] // Peer of the `println!`-routed
                    // `probe_and_report_rebac_key_count`, retained for
                    // the byte-oracle tests and for a future
                    // summary-report consumer that would emit the same
                    // grammar into a captured buffer.
pub fn write_rebac_keys_count_report<W: io::Write>(
    w: &mut W,
    description: &str,
    count: usize,
) -> io::Result<()> {
    writeln!(w, "   Found {} {} keys", count, description)
}

/// Query Redis for `KEYS <prefix>:<kind>:*`, count the returned key
/// names, and print `"   Found {N} {description} keys"` to stdout — the
/// full 12-line probe stanza both pre-lift sibling call sites carried,
/// collapsed to one function call each.
///
/// - `redis_cli` — the resolved `redis-cli` binary path (from
///   `commands::rebac_validation::redis_cli_bin`).
/// - `redis_url` — the connection URL.
/// - `prefix` — the ReBAC key-namespace prefix (e.g. `"myapp"`).
/// - `kind` — which family of keys to scan; the closed
///   [`RebacKeyKind`] enum's `glob_infix()` and `report_description()`
///   projections drive the glob and the report line respectively.
/// - `quiet` — suppress the report line when `true`, matching the pre-
///   lift `if !config.quiet` guard. The KEYS scan still runs regardless
///   because both pre-lift sites did — the scan is the check.
///
/// On any spawn error the probe is silently skipped — the pre-lift
/// `if let Ok(keys) = keys_output` pattern deliberately treated a spawn
/// failure as a soft skip, since this probe runs inside a best-effort
/// `check_redis_connectivity` block that already logged a top-level
/// warning if `redis-cli` was unreachable.
pub async fn probe_and_report_rebac_key_count(
    redis_cli: &str,
    redis_url: &str,
    prefix: &str,
    kind: RebacKeyKind,
    quiet: bool,
) {
    let glob = format_rebac_keys_glob(prefix, kind);
    let output = Command::new(redis_cli)
        .args(["-u", redis_url, "KEYS", &glob])
        .output()
        .await;
    if let Ok(keys) = output {
        let count = count_non_empty_stdout_lines(&keys.stdout);
        if !quiet {
            // Route through the byte-oracle writer sibling so the emitted
            // grammar is the one pinned by the `write_rebac_keys_count_report_*`
            // tests below — a future drift in the writer flows through
            // both this production path and every test invocation in
            // lockstep.
            let mut stdout = io::stdout().lock();
            let _ = write_rebac_keys_count_report(&mut stdout, kind.report_description(), count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RebacKeyKind projections ────────────────────────────────────

    /// Byte-oracle: [`RebacKeyKind::glob_infix`] returns the exact
    /// pre-lift glob-infix literals. A future refactor that pluralized
    /// (`"rels"` / `"perms"`), stemmed (`"relation"` for the glob),
    /// or reordered the two variants regresses this assertion.
    #[test]
    fn rebac_key_kind_glob_infix_returns_prelift_literals() {
        assert_eq!(RebacKeyKind::Relation.glob_infix(), "rel");
        assert_eq!(RebacKeyKind::Permission.glob_infix(), "perm");
    }

    /// Byte-oracle: [`RebacKeyKind::report_description`] returns the
    /// exact pre-lift report-description literals. A future rewrite to
    /// `"relations"` / `"permissions"` (plural), `"perm cache"`
    /// (abbreviated), or a merge with `glob_infix` regresses this.
    #[test]
    fn rebac_key_kind_report_description_returns_prelift_literals() {
        assert_eq!(RebacKeyKind::Relation.report_description(), "relation");
        assert_eq!(
            RebacKeyKind::Permission.report_description(),
            "permission cache"
        );
    }

    /// Pin that the two projections DIVERGE for [`RebacKeyKind::Permission`]:
    /// the glob infix is `"perm"` but the report description is
    /// `"permission cache"`. A future refactor that collapsed the two
    /// projections into one method — the classic "one variant, one
    /// string" reduction — would silently break either the KEYS scan
    /// (glob becomes `<prefix>:permission cache:*`, hits nothing) or
    /// the report line (`"Found N perm keys"`, drops the `cache` word).
    /// Fail-before-pass-after: without the correlated-pair enum design,
    /// this divergence has no home.
    #[test]
    fn rebac_key_kind_permission_glob_infix_diverges_from_report_description() {
        let k = RebacKeyKind::Permission;
        assert_ne!(k.glob_infix(), k.report_description());
        assert_eq!(k.glob_infix(), "perm");
        assert_eq!(k.report_description(), "permission cache");
    }

    // ── format_rebac_keys_glob ──────────────────────────────────────

    /// Byte-oracle: [`format_rebac_keys_glob`] emits the pre-lift
    /// `"{prefix}:{infix}:*"` shape for both kinds. A future refactor
    /// that (a) reordered the three segments, (b) changed the delimiter
    /// (`.` instead of `:`), or (c) dropped the trailing `:*` glob
    /// regresses this assertion.
    #[test]
    fn format_rebac_keys_glob_emits_prelift_colon_delimited_glob_shape() {
        assert_eq!(
            format_rebac_keys_glob("myapp", RebacKeyKind::Relation),
            "myapp:rel:*"
        );
        assert_eq!(
            format_rebac_keys_glob("myapp", RebacKeyKind::Permission),
            "myapp:perm:*"
        );
    }

    /// The prefix is passed through verbatim, including hyphens, dots,
    /// and empty prefixes — no sanitization. Pre-lift `format!("{}:…", …)`
    /// did the same. Pin that a future "helpful" prefix-normalizer
    /// (say, `to_lowercase()` or stripping trailing colons) hits the
    /// test rather than silently rewriting a ProductConfig-supplied
    /// namespace.
    #[test]
    fn format_rebac_keys_glob_passes_prefix_through_verbatim() {
        assert_eq!(
            format_rebac_keys_glob("my-app.v2", RebacKeyKind::Relation),
            "my-app.v2:rel:*"
        );
        // Empty prefix is a degenerate but legitimate input — the
        // ProductConfig loader could plausibly yield an empty string;
        // the pre-lift `format!` would emit `":rel:*"` and we preserve
        // that shape.
        assert_eq!(format_rebac_keys_glob("", RebacKeyKind::Relation), ":rel:*");
    }

    // ── count_non_empty_stdout_lines ────────────────────────────────

    /// Byte-oracle: the counter matches the pre-lift chain on a
    /// canonical multi-key stdout — three key names, one per line,
    /// each `\n`-terminated.
    #[test]
    fn count_non_empty_stdout_lines_counts_three_newline_terminated_keys() {
        let stdout = b"myapp:rel:user1:doc1\nmyapp:rel:user2:doc2\nmyapp:rel:user3:doc3\n";
        assert_eq!(count_non_empty_stdout_lines(stdout), 3);
    }

    /// Empty stdout — no keys returned — is the zero case. Pre-lift
    /// `String::from_utf8_lossy(b"").lines()` yields no items;
    /// `.count()` returns 0.
    #[test]
    fn count_non_empty_stdout_lines_returns_zero_on_empty_stdout() {
        assert_eq!(count_non_empty_stdout_lines(b""), 0);
    }

    /// Empty lines inside the stdout are skipped by the pre-lift
    /// `filter(|l| !l.is_empty())` predicate. A double `\n\n` between
    /// two key names must not inflate the count. Pin the pre-lift
    /// behavior so a future counter refactor (say, `.lines().count()`
    /// unfiltered) hits the assertion.
    #[test]
    fn count_non_empty_stdout_lines_skips_empty_lines_between_keys() {
        let stdout = b"myapp:rel:a\n\nmyapp:rel:b\n\n\nmyapp:rel:c\n";
        assert_eq!(count_non_empty_stdout_lines(stdout), 3);
    }

    /// A trailing newline is the conventional Redis shape; a stdout
    /// WITHOUT a trailing newline (single key, no `\n`) still counts
    /// as one line. `str::lines()` yields the tail as a line whether
    /// or not it ends with `\n`.
    #[test]
    fn count_non_empty_stdout_lines_counts_tail_line_with_no_trailing_newline() {
        assert_eq!(count_non_empty_stdout_lines(b"single-key"), 1);
    }

    /// Non-UTF-8 bytes are `U+FFFD`-replaced by
    /// `String::from_utf8_lossy` (the pre-lift path), which is 3 bytes
    /// but not empty — so a line consisting entirely of a stray
    /// non-UTF-8 byte still counts. Redis key names are conventionally
    /// UTF-8, so this input shape is unreachable in practice, but pin
    /// the lossy-pass behavior so a future migration to a strict
    /// `str::from_utf8` boundary is a visible refactor rather than a
    /// silent count change.
    #[test]
    fn count_non_empty_stdout_lines_treats_non_utf8_byte_as_non_empty_line() {
        // A stray 0xFF byte on its own line — invalid UTF-8, but not
        // empty after the lossy replacement.
        let stdout: &[u8] = &[b'a', b'\n', 0xFF, b'\n', b'b', b'\n'];
        assert_eq!(count_non_empty_stdout_lines(stdout), 3);
    }

    // ── write_rebac_keys_count_report ───────────────────────────────

    /// Byte-oracle: writer emits three ASCII spaces (0x20 0x20 0x20),
    /// the literal `Found`, one space, the decimal count, one space,
    /// the description verbatim, one space, `keys`, then `\n`. A
    /// future refactor that changes the indent width, drops the
    /// `Found` verb, pluralizes to `keyss`, adds a colon, or drops the
    /// trailing newline regresses this assertion.
    #[test]
    fn write_rebac_keys_count_report_emits_three_space_indent_found_verb_and_keys_noun() {
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, "relation", 42).unwrap();
        assert_eq!(buf, b"   Found 42 relation keys\n");
    }

    /// The `Permission` variant's two-word description carries the
    /// literal space inside the report — `permission cache`, not
    /// `permission_cache` or `permission-cache`. Pin the space.
    #[test]
    fn write_rebac_keys_count_report_preserves_space_inside_permission_cache_description() {
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, "permission cache", 7).unwrap();
        assert_eq!(buf, b"   Found 7 permission cache keys\n");
    }

    /// A zero count still emits a well-formed line — the pre-lift
    /// stanza would `println!("   Found 0 relation keys")` on an
    /// empty-KEYS response, and the pinned grammar admits that shape.
    #[test]
    fn write_rebac_keys_count_report_emits_zero_count_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, "relation", 0).unwrap();
        assert_eq!(buf, b"   Found 0 relation keys\n");
    }

    /// Guard against a two-space or four-space indent drift: the
    /// pre-lift `println!` line carries exactly three ASCII spaces
    /// (matching the sibling `   Zone ID:` / `   Redis Connectivity`
    /// sub-item indent under a `# Check N: <header>` parent). Pin the
    /// three-space width so a future collapse to two or four spaces
    /// hits the byte-oracle test rather than silently misaligning the
    /// sub-item under its parent header.
    #[test]
    fn write_rebac_keys_count_report_uses_three_space_indent_not_two_or_four() {
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, "relation", 1).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("   Found "),
            "must start with three spaces + verb"
        );
        assert!(!s.starts_with("  Found "), "must NOT be two-space indent");
        assert!(
            !s.starts_with("    Found "),
            "must NOT be four-space indent"
        );
    }

    // ── Round-trip fixture: production caller shape ─────────────────

    /// Round-trip: the production fusion primitive splices
    /// [`RebacKeyKind::report_description`] into the writer. Pin that
    /// the composite emitted line matches the pre-lift `println!`
    /// verbatim for both variants — a future divergence between the
    /// enum's description and the writer's grammar hits here.
    #[test]
    fn write_rebac_keys_count_report_composed_with_kind_matches_prelift_println() {
        // Relation arm — pre-lift:
        //   println!("   Found {} relation keys", key_count);
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, RebacKeyKind::Relation.report_description(), 12)
            .unwrap();
        assert_eq!(buf, b"   Found 12 relation keys\n");

        // Permission arm — pre-lift:
        //   println!("   Found {} permission cache keys", key_count);
        let mut buf: Vec<u8> = Vec::new();
        write_rebac_keys_count_report(&mut buf, RebacKeyKind::Permission.report_description(), 5)
            .unwrap();
        assert_eq!(buf, b"   Found 5 permission cache keys\n");
    }

    // ── Caller shield: rebac_validation.rs forwards through the
    //    fusion primitive at both pre-lift call sites ────────────────

    /// Positive shield: `commands/rebac_validation.rs` must forward
    /// through [`probe_and_report_rebac_key_count`] at least twice
    /// (once per pre-lift kind — `Relation` and `Permission`). A
    /// migration that dropped one of the two call sites outright
    /// leaves the negative "no raw `format!(\"{}:rel:*\", …)` inline
    /// shape" scan trivially satisfied by absence but this positive
    /// count still fails. Mirrors the sibling
    /// `every_prelift_module_forwards_through_bun_install_frozen_lockfile_argv`
    /// shield.
    #[test]
    fn rebac_validation_forwards_through_probe_and_report_at_both_call_sites() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("rebac_validation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let needle = "probe_and_report_rebac_key_count(";
        let forwards = source.matches(needle).count();
        assert!(
            forwards >= 2,
            "commands/rebac_validation.rs must forward at least two \
             KEYS-probe call sites through `{needle}`; found {forwards}. \
             A dropped call would leave the negative raw-glob-shape scan \
             satisfied by absence."
        );
    }

    /// Negative shield: no raw `format!("{}:rel:*", …)` /
    /// `format!("{}:perm:*", …)` glob-literal reconstruction may
    /// survive under `commands/rebac_validation.rs`. Every ReBAC
    /// KEYS glob must route through [`format_rebac_keys_glob`] so a
    /// future third-family addition (session, cache) inherits the
    /// closed-enum discipline rather than sprouting a fourth inline
    /// literal. Comment lines are skipped so this test's own prose
    /// (which spells the shape) doesn't self-hit.
    #[test]
    fn rebac_validation_no_longer_spells_raw_prelift_glob_format_literals() {
        use std::path::PathBuf;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands")
            .join("rebac_validation.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut offenders: Vec<(usize, String)> = Vec::new();
        for (idx, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            // The pre-lift raw shape is `format!("{}:rel:*"` or
            // `format!("{}:perm:*"` — pin both.
            if line.contains("format!(\"{}:rel:*\"") || line.contains("format!(\"{}:perm:*\"") {
                offenders.push((idx + 1, line.to_string()));
            }
        }
        assert!(
            offenders.is_empty(),
            "raw pre-lift `format!(\"{{}}:rel:*\"|\"{{}}:perm:*\", …)` glob \
             literal(s) survive under commands/rebac_validation.rs — route each \
             through `crate::rebac_keys_probe::format_rebac_keys_glob(prefix, \
             RebacKeyKind::…)` (via the fusion `probe_and_report_rebac_key_count`) \
             instead:\n{:#?}",
            offenders
        );
    }
}
