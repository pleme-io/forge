//! SQL identifier post-keyword extraction primitive — the shared
//! `.split_whitespace().next()?.trim_matches(<sql quote chars>)` walk
//! every "extract the table name after a SQL keyword" body in
//! [`commands/migration_validation.rs`] restated pre-lift.
//!
//! # Pre-lift census — two byte-identical sibling stanzas
//!
//! Both pre-lift sites in `cli/src/commands/migration_validation.rs`
//! spelled the same three-line body, diverging on nothing but the
//! keyword length used to compute the tail-slice offset (`+ 11` for
//! `"DELETE FROM"`, `+ 14`/`+ 8` for `"TRUNCATE TABLE"` /
//! `"TRUNCATE"`):
//!
//! ```ignore
//! let after_kw = &line[pos + <N>..].trim_start();
//! let table_name = after_kw
//!     .split_whitespace()
//!     .next()?
//!     .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');
//! return Some(table_name.to_string());
//! ```
//!
//! 1. `commands/migration_validation.rs::extract_table_name_from_delete`
//!    (pre-lift ~L550-565) — the SQLx-legacy soft-delete-compliance
//!    scanner's "extract the target of a `DELETE FROM <t>` statement"
//!    entry point.
//! 2. `commands/migration_validation.rs::extract_table_name_from_truncate`
//!    (pre-lift ~L568-589) — the SQLx-legacy soft-delete-compliance
//!    scanner's "extract the target of a `TRUNCATE [TABLE] <t>`
//!    statement" entry point.
//!
//! Each site propagated `Option<String>` (borrow → `to_string`) and named
//! the trimmed slice `table_name`; the post-lift body preserves that
//! propagation shape and the `Option`-return contract at both callers.
//!
//! # Why a shared primitive, not an inline hand-copy at two sites
//!
//! Four load-bearing invariants a future edit would otherwise land at
//! two sites in lockstep:
//!
//! 1. **Which quote characters count as SQL identifier bracketing.**
//!    Pre-lift both sites spelled the four-char closed set
//!    `{"`, `` ` ``, `[`, `]`} inline via the disjunction
//!    `|c| c == '"' || c == '`' || c == '[' || c == ']'`. A future
//!    admission (SQL:2016 permits `⌈`/`⌉` for delimited identifiers in
//!    some dialects; MySQL 8's `ANSI_QUOTES` mode makes `"` a string
//!    literal and demands `` ` `` only; PostgreSQL's `U&"…"` prefix)
//!    lands at ONE closed-set constant, not two disjunctions drifting
//!    on lockstep edits.
//! 2. **Extraction discipline: first whitespace-separated token, or
//!    nothing.** Pre-lift both sites reached for
//!    [`str::split_whitespace`] + `.next()?` verbatim. A future
//!    refinement — swapping to a lexer that respects
//!    parenthesized-column-list boundaries (`DELETE FROM users (id, ...)`
//!    parses to `users`, not `users`), or to a tokenizer that recognizes
//!    schema-qualified identifiers (`myschema.users` as a single logical
//!    token rather than two whitespace tokens) — lands at ONE body.
//! 3. **Ownership boundary: `&str` borrow → owned `String`.** Both
//!    sites return `Option<String>` and reached for `.to_string()` on
//!    the trimmed borrow. A future refinement to `Option<&str>` for
//!    zero-copy propagation into the [`MigrationIssue::HardDelete`]
//!    payload's `suggestion` `format!` would land at ONE body.
//! 4. **Empty-tail semantics: `None`, not `Some("")`.** Both sites
//!    reached [`Option::None`] via the `.next()?` `?`-propagation on an
//!    empty tail (or a tail whose only content is whitespace). A future
//!    refinement — surfacing a typed
//!    `MigrationSqlParseError::MissingIdentifierAfterKeyword` instead of
//!    a silent `None` — lands at ONE body.
//!
//! Pre-lift each of the four invariants above lived at zero sites (no
//! caller carried any of them as a named binding); post-lift each has
//! ONE canonical home the moment a future edit needs to introduce it.
//!
//! # THEORY grounding
//!
//! - `THEORY.md §V.1` (Construction guarantees; Types → Invariants →
//!   Proofs → Render Anywhere): the "first token after a SQL keyword,
//!   stripped of outer identifier quoting" invariant lives at ONE
//!   construction surface — [`extract_first_sql_identifier_token`] —
//!   and its byte-oracle tests below pin the closed-set of quote
//!   characters, the whitespace-tokenization semantics, and the empty-
//!   tail posture as `cargo test`-verifiable invariants rather than as
//!   consumer-site conventions.
//! - `THEORY.md §VI.1` (Generation over composition; two-is-a-
//!   coincidence, three-is-a-law): two sibling occurrences sit at the
//!   coincidence threshold. The compounding-directive corollary —
//!   "every recurring shape becomes a helper before it becomes
//!   duplicated code" — is discharged at both consumers by construction,
//!   and the negative caller shield below forbids the pre-lift raw
//!   disjunction from resurfacing inline under `commands/` where the
//!   third-site drift the two-is-a-coincidence-three-is-a-law theorem
//!   warns against would land.
//! - `THEORY.md §III` (Structure): the "SQL identifier token, bracketed
//!   or bare" concept is a single named terminal in the migration-
//!   validation typescape; both consumers cite
//!   [`extract_first_sql_identifier_token`] rather than restating the
//!   three-line body, so the terminal reads through one named surface
//!   everywhere.

/// The four characters that may bracket a SQL identifier and must be
/// trimmed off when read as a bare identifier: ANSI double-quote (`"`),
/// MySQL/MariaDB backtick (`` ` ``), and the T-SQL bracket pair (`[`
/// and `]`). Pre-lift both consumer sites spelled the same four-char
/// closed set inline via the disjunction `|c| c == '"' || c == '`' ||
/// c == '[' || c == ']'`; post-lift the set has ONE named home.
///
/// # Ordering
///
/// The order is intentional and matches the pre-lift disjunction
/// verbatim: ANSI double-quote first (the most portable dialect),
/// backtick second (MySQL / MariaDB), then the T-SQL pair. A future
/// admission (SQL:2016's `⌈`/`⌉` for delimited identifiers, PostgreSQL's
/// `U&"…"` prefix carrying a separate leading `U&"` bracketing) lands
/// as a new entry here.
pub const SQL_IDENTIFIER_QUOTE_CHARS: [char; 4] = ['"', '`', '[', ']'];

/// Extract the first whitespace-separated token from `tail` and strip
/// its outer SQL identifier quoting.
///
/// `tail` is the byte-slice after a SQL keyword whose identifier the
/// caller wants to read (`&line[pos + keyword.len()..]` at the pre-lift
/// sites). Returns `Some(<owned token>)` on the first non-whitespace
/// run, or `None` on an empty or whitespace-only tail.
///
/// # Semantics
///
/// - [`str::split_whitespace`] skips leading and trailing whitespace
///   and yields non-empty runs, so an explicit `.trim_start()` on the
///   tail is redundant here — pre-lift both consumer sites called it
///   anyway, and this primitive preserves the same observable result
///   without the extra call.
/// - [`str::trim_matches`] strips only the leading and trailing runs
///   of the matching characters; an embedded `"` inside an identifier
///   token (`user"name`) is preserved, which mirrors the pre-lift
///   behavior verbatim.
/// - The returned `String` is an owned copy of the trimmed borrow —
///   a future refinement to `Option<&str>` for zero-copy propagation
///   lands here, at one body.
///
/// # Empty-tail posture
///
/// Returns `None` on `""` and on any tail whose only content is ASCII
/// whitespace. Pre-lift both consumer sites reached `None` via the
/// `.next()?` `?`-propagation on the empty tail; the post-lift body
/// preserves that discipline.
#[allow(dead_code)]
pub fn extract_first_sql_identifier_token(tail: &str) -> Option<String> {
    let token = tail
        .split_whitespace()
        .next()?
        .trim_matches(|c: char| SQL_IDENTIFIER_QUOTE_CHARS.contains(&c));
    Some(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle: [`SQL_IDENTIFIER_QUOTE_CHARS`] is exactly the four-
    /// element closed set `['"', '`', '[', ']']` in that order. Pins
    /// the pre-lift disjunction's char membership AND ordering as
    /// `cargo test`-verifiable invariants: a future edit that dropped
    /// one, added a fifth without discipline, or reordered the pair
    /// (T-SQL `[` and `]` are load-bearing paired — a swap that placed
    /// them non-adjacently would still trim correctly but would
    /// obscure the pairing at readout) would surface here.
    #[test]
    fn sql_identifier_quote_chars_is_exactly_the_four_char_pre_lift_set() {
        assert_eq!(
            SQL_IDENTIFIER_QUOTE_CHARS,
            ['"', '`', '[', ']'],
            "SQL_IDENTIFIER_QUOTE_CHARS must carry the pre-lift disjunction's \
             four-char closed set verbatim in order — ANSI double-quote first, \
             backtick second, T-SQL bracket pair last as an adjacent pair"
        );
        assert_eq!(
            SQL_IDENTIFIER_QUOTE_CHARS.len(),
            4,
            "SQL_IDENTIFIER_QUOTE_CHARS must be exactly the four-char set the \
             pre-lift disjunction spelled — a fifth entry admits a dialect the \
             pre-lift consumers never accepted"
        );
    }

    /// Byte-oracle: a bare unquoted identifier surfaces verbatim as
    /// the first whitespace-separated token, with no quoting stripped
    /// (nothing to strip). Pins the happy-path shape both pre-lift
    /// sites depend on for the common
    /// `DELETE FROM users WHERE ...` / `TRUNCATE TABLE users` cases
    /// where the target identifier is unbracketed.
    #[test]
    fn unquoted_identifier_surfaces_verbatim() {
        assert_eq!(
            extract_first_sql_identifier_token("users WHERE id = 1"),
            Some("users".to_string()),
            "bare unquoted identifier must surface as the first whitespace-\
             separated token verbatim"
        );
    }

    /// Byte-oracle: ANSI double-quote bracketing is stripped from the
    /// identifier token. Pins the SQL:1992 delimited-identifier
    /// dialect's quoting form — the most portable and the one MyISAM /
    /// PostgreSQL / Oracle / SQLite all accept — as a member of the
    /// four-char closed set.
    #[test]
    fn ansi_double_quote_bracketing_is_stripped() {
        assert_eq!(
            extract_first_sql_identifier_token("\"users\" WHERE id = 1"),
            Some("users".to_string()),
            "ANSI double-quote bracketing must be stripped from the identifier"
        );
    }

    /// Byte-oracle: MySQL / MariaDB backtick bracketing is stripped
    /// from the identifier token. Pins the MySQL-native dialect's
    /// quoting form as a member of the four-char closed set: MySQL's
    /// default `sql_mode` reserves `"` for string literals and requires
    /// `` ` `` for identifiers, so a soft-delete-compliance scanner
    /// that missed the backtick form would silently accept
    /// `` DELETE FROM `users` WHERE... `` against a business table.
    #[test]
    fn mysql_backtick_bracketing_is_stripped() {
        assert_eq!(
            extract_first_sql_identifier_token("`users` WHERE id = 1"),
            Some("users".to_string()),
            "MySQL/MariaDB backtick bracketing must be stripped from the \
             identifier — pre-lift both consumers accepted this form"
        );
    }

    /// Byte-oracle: T-SQL bracket bracketing (`[…]`) is stripped from
    /// the identifier token on both ends. Pins the SQL Server /
    /// Sybase dialect's quoting form as a paired member of the four-
    /// char closed set: pre-lift the disjunction admitted `[` and `]`
    /// as independent members but only paired bracketing appears in
    /// real T-SQL migration bodies, so a soft-delete-compliance scanner
    /// that dropped either end would let a T-SQL business-table
    /// DELETE past the audit.
    #[test]
    fn tsql_bracket_bracketing_is_stripped_on_both_ends() {
        assert_eq!(
            extract_first_sql_identifier_token("[users] WHERE id = 1"),
            Some("users".to_string()),
            "T-SQL bracket bracketing must be stripped from both ends of the \
             identifier — pre-lift both consumers admitted `[` and `]` as \
             independent members of the trim set"
        );
    }

    /// Byte-oracle: an empty tail produces `None`, not
    /// `Some("".to_string())`. Pins the pre-lift `.next()?`
    /// `?`-propagation posture so the caller's
    /// `if let Some(table_name) = extract_table_name_from_<X>(...)`
    /// branch stays behind the same gate: a bare `DELETE FROM`
    /// keyword with no following identifier (a malformed migration
    /// line) must not surface as a `Some("")` that a later
    /// [`ALLOWED_HARD_DELETE_TABLES`] check would inadvertently accept
    /// as an empty-string prefix match.
    #[test]
    fn empty_tail_returns_none() {
        assert_eq!(
            extract_first_sql_identifier_token(""),
            None,
            "empty tail must return None so the caller's `if let Some(...)` \
             branch stays behind the gate — not Some(\"\")"
        );
    }

    /// Byte-oracle: a whitespace-only tail produces `None`. Mirrors
    /// [`empty_tail_returns_none`] for the sibling case where the
    /// keyword is followed only by whitespace before the line ends
    /// (a broken split that dropped the identifier onto a
    /// continuation line the scanner does not see).
    #[test]
    fn whitespace_only_tail_returns_none() {
        assert_eq!(
            extract_first_sql_identifier_token("   \t   "),
            None,
            "whitespace-only tail must return None — split_whitespace().next() \
             yields no tokens on a whitespace-only slice"
        );
    }

    /// Byte-oracle: leading whitespace on the tail is skipped by
    /// [`str::split_whitespace`], so the first non-whitespace run
    /// surfaces as the token. Pins the semantics that pre-lift the
    /// two consumer sites relied on via the redundant `.trim_start()`
    /// call — the post-lift primitive omits the explicit trim because
    /// [`str::split_whitespace`] handles it, and this shield pins that
    /// the observable result is unchanged.
    #[test]
    fn leading_whitespace_on_tail_is_skipped() {
        assert_eq!(
            extract_first_sql_identifier_token("   users WHERE id = 1"),
            Some("users".to_string()),
            "leading whitespace on the tail must be skipped — split_whitespace \
             handles it, so the explicit .trim_start() at the pre-lift call \
             sites is redundant and the post-lift result is unchanged"
        );
    }

    /// Byte-oracle: an embedded quote inside an unbracketed identifier
    /// token is NOT stripped — [`str::trim_matches`] only strips
    /// leading and trailing runs. Pins the behavior verbatim: pre-lift
    /// `"user\"name".trim_matches(...)` returned `user\"name` because
    /// neither end starts or ends with a member of the set. A future
    /// refinement that reached for `.replace(...)` here would broaden
    /// the semantic silently past what the two consumers relied on.
    #[test]
    fn embedded_quote_in_middle_of_token_is_preserved() {
        assert_eq!(
            extract_first_sql_identifier_token("user\"name WHERE id = 1"),
            Some("user\"name".to_string()),
            "embedded quote in the middle of the token must be preserved — \
             trim_matches only strips leading/trailing runs, not internal chars"
        );
    }

    /// Byte-oracle: pre-lift both sites called `.trim_start()` on the
    /// tail-slice borrow before `.split_whitespace().next()?`. That
    /// composition is byte-identical to `.split_whitespace().next()?`
    /// alone because [`str::split_whitespace`] already skips leading
    /// whitespace. Pins the equivalence for both a tail with leading
    /// whitespace AND a tail without, so a future reader looking at
    /// the post-lift primitive can trust the omission is intentional.
    // `#[allow(clippy::trim_split_whitespace)]`: this test EXISTS to
    // prove that the pre-lift `.trim_start().split_whitespace()` shape
    // is observationally identical to a bare `.split_whitespace()`, so
    // the primitive body can omit the `.trim_start()` the pre-lift
    // consumer sites carried without changing the observable result.
    // The clippy lint's whole point is to warn readers off the
    // redundant composition; the shield's whole point is to pin the
    // equivalence at test time, and both goals are served by the same
    // code line.
    #[test]
    #[allow(clippy::trim_split_whitespace)]
    fn trim_start_prefix_is_observationally_redundant_with_split_whitespace() {
        for tail in [
            "users WHERE id = 1",
            "   users WHERE id = 1",
            "\t\t users",
            "\n\n users",
        ] {
            let with_trim_start = tail
                .trim_start()
                .split_whitespace()
                .next()
                .map(|s| s.to_string());
            let without_trim_start = tail.split_whitespace().next().map(|s| s.to_string());
            assert_eq!(
                with_trim_start, without_trim_start,
                "trim_start().split_whitespace().next() must equal \
                 split_whitespace().next() on every tail — pre-lift both \
                 consumer sites called .trim_start(), the post-lift primitive \
                 omits it; the observable result must not diverge (tail: {tail:?})"
            );
        }
    }

    /// Delegation shield (positive half): the primitive body reaches
    /// the four-char trim closure `trim_matches(|c: char|
    /// SQL_IDENTIFIER_QUOTE_CHARS.contains(&c))` at exactly one code
    /// line — the primitive body. Pins the one-oracle discipline
    /// THEORY §VI.1 requires: a future refactor that duplicated the
    /// trim closure onto a fallback path or a second projection would
    /// surface here.
    ///
    /// # Self-match discipline
    ///
    /// The needle is reconstructed at test time from three tokens so
    /// this test body's own strings never spell the full literal.
    #[test]
    fn primitive_body_reaches_trim_closure_at_exactly_one_call() {
        let source = include_str!("sql_identifier_first_token.rs");
        let needle = format!(
            "{}{}{}",
            "trim_matches(|c: char| ", "SQL_IDENTIFIER_QUOTE_CHARS", ".contains(&c))"
        );
        let hits = crate::test_support::code_line_hits(source, &needle);
        assert_eq!(
            hits.len(),
            1,
            "sql_identifier_first_token.rs primitive body must reach the \
             trim closure at exactly one code line (the primitive body); \
             got {hits:#?}"
        );
    }

    /// Caller shield (positive half): each of the two pre-lift
    /// consumer sites now reaches
    /// [`extract_first_sql_identifier_token`]. Anchored on the fully
    /// qualified path so a future refactor that renamed the module or
    /// dropped the `crate::sql_identifier_first_token::` prefix on one
    /// call site would regress the count.
    #[test]
    fn command_modules_reach_extract_first_sql_identifier_token_at_expected_forwards() {
        let source = include_str!("commands/migration_validation.rs");
        let hits = crate::test_support::code_line_hits(
            source,
            "crate::sql_identifier_first_token::extract_first_sql_identifier_token(",
        );
        assert_eq!(
            hits.len(),
            2,
            "commands/migration_validation.rs must reach \
             `crate::sql_identifier_first_token::extract_first_sql_identifier_token(` \
             at exactly 2 code lines (extract_table_name_from_delete + \
             extract_table_name_from_truncate); got {hits:#?}"
        );
    }

    /// Caller shield (negative half): no source line under
    /// `cli/src/commands/` may respell the pre-lift raw four-char
    /// disjunction `|c| c == '"' || c == '`' || c == '[' || c == ']'`
    /// inline any more. Both pre-lift sites migrated onto
    /// [`extract_first_sql_identifier_token`]; any future consumer
    /// that wants the same "strip SQL identifier quoting" body reaches
    /// for the primitive on first grep, not by copy-pasting the raw
    /// disjunction from another command module.
    ///
    /// Mirrors the negative-half shield the sibling
    /// [`crate::migration_file_read`] primitive carries on the
    /// `"Failed to read migration file: {}"` envelope literal.
    #[test]
    fn no_command_module_still_spells_raw_sql_quote_disjunction() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let needle = format!(
            "|c| c == '{}' || c == '{}' || c == '{}' || c == '{}'",
            '"', '`', '[', ']'
        );
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
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
                if line.contains(&needle) {
                    offenders.push((path.clone(), idx + 1, line.trim().to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no command module may respell the pre-lift raw four-char SQL \
             quote disjunction inline — reach for \
             `crate::sql_identifier_first_token::extract_first_sql_identifier_token` \
             instead; offenders: {offenders:#?}"
        );
    }
}
