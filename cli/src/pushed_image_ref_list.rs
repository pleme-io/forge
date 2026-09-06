//! Stdout `"   • <registry>:<tag>"` bullet-list-per-tag block grammar for
//! the "images pushed successfully" post-push summary.
//!
//! Two pre-lift sibling sites across `commands/{push (×1: post-
//! `push_tags_with_progress` `print_success("Images pushed successfully!")`
//! summary), bootstrap (×1: post-`push_tags_with_progress` `"✅ Bootstrap
//! image pushed successfully!"` summary in `push_single`)}.rs` each
//! restated the
//!
//! ```ignore
//! for tag in &tags {
//!     println!("   • {}:{}", registry, tag);
//! }
//! println!();
//! ```
//!
//! stanza verbatim — one per-tag `println!` line composed of a THREE-space
//! indent, a U+2022 `•` BULLET glyph, a single ASCII space, and a
//! `<registry>:<tag>` OCI image-reference render, iterated over the
//! `&[String]` tag catalog the pre-push readout already narrated through
//! [`crate::info_tags_field!`], followed by ONE trailing blank
//! `println!()` that separates the summary from whatever the caller
//! narrates next (a kustomization update at `push.rs::execute`, an
//! `Ok(())` return at `bootstrap.rs::push_single`).
//!
//! Post-lift the sites reach for [`print_pushed_image_ref_list`] and the
//! three-space bullet indent, the U+2022 glyph, the `<registry>:<tag>`
//! colon-join grammar, the iteration cadence, and the trailing framing
//! blank are decided once here.
//!
//! # Distinct from every sibling `<indent>•` bullet primitive
//!
//! The crate carries a small family of `<indent>•` bullet-list
//! primitives; each pins ONE indent scope and one visual register:
//!
//! - [`crate::ui::print_bullet_item`] emits a TWO-space-indented
//!   declarative catalog entry (`"  • <message>"`) used by
//!   `commands/{developer_tools, comprehensive_release, deploy,
//!   web_service}.rs` under `println!("Monitor deployment:")` /
//!   `println!("Next steps:")` heading sections. Distinct indent scope
//!   (two-space vs. three-space) and distinct visual register
//!   (declarative catalog vs. resolved-artifact enumeration).
//! - [`crate::ui::print_sub_bullet_item`] emits a FOUR-space-indented
//!   nested leaf entry (`"    • <message>"`) used by
//!   `commands/rust_service.rs::print_deployment_report` under the
//!   `print_report_item` / `print_pending_item` per-head sub-detail
//!   nesting. Distinct indent scope again.
//! - [`print_pushed_image_ref_list`] (this primitive) enumerates a
//!   post-push `<registry>:<tag>` OCI image-reference catalog at
//!   THREE-space indent under an `Images pushed successfully!` summary
//!   header, followed by a framing blank the caller relied on for
//!   separation from downstream narration.
//!
//! The three primitives carry different indent scopes and different
//! visual roles deliberately; a collapse of any two into one primitive
//! would silently merge the sibling indent contracts and misalign the
//! visual hierarchy against every existing consumer.
//!
//! # The three-space indent is load-bearing
//!
//! Both pre-lift sites spell the indent as three ASCII spaces before
//! the U+2022 glyph. This aligns with the fleet's post-summary
//! resolved-artifact enumeration convention (see also
//! [`crate::ui::print_step_ok`], [`crate::ui::print_step_uncheck`],
//! [`crate::ui::print_arrow_hint`] — all three-space indented) and
//! distinguishes the block from the two-space declarative bullet
//! catalog above. A future refactor that narrowed the indent to two
//! spaces (a reader extrapolating from [`crate::ui::print_bullet_item`])
//! would collide with the sibling declarative-catalog grammar; a widen
//! to four spaces (extrapolating from
//! [`crate::ui::print_sub_bullet_item`]) would nest the enumeration
//! under a phantom head the summary does not carry. The byte-oracle
//! pins the three-space width so a silent drift hits the test rather
//! than shipping.
//!
//! # The `<registry>:<tag>` colon-join preserves the OCI reference form
//!
//! Both pre-lift sites spell the per-tag interpolation as
//! `"{}:{}", registry, tag` — a `<registry>` string, a bare ASCII
//! colon (`:`, byte `0x3A`), then a `<tag>` string. This is the
//! canonical OCI / Docker image-reference render that
//! [`crate::oci_manifest::image_reference`] emits and that
//! `skopeo` / `docker pull` accept verbatim, so the operator can
//! copy any line from the summary and paste it directly into a
//! subsequent `docker pull` / `crane pull` invocation. A future
//! refactor that dropped the colon (routing through a bare space or
//! `@` separator) would break paste-and-pull; the byte-oracle pins the
//! colon at the interpolation seam. The primitive stays a bare
//! `writeln!("{}:{}", ...)` (not a call through `image_reference`)
//! because the pre-lift shape emits an unchecked interpolation and
//! [`crate::oci_manifest::image_reference`] carries `debug_assert!`
//! guards on non-empty inputs that would panic on the empty-tag / empty-
//! registry edge — the primitive preserves the pre-lift permissive
//! shape and delegates canonicality to the tag-vector construction
//! upstream.
//!
//! # The trailing framing `println!()` is load-bearing
//!
//! Both pre-lift sites emit a `println!()` immediately after the loop
//! closes; the blank line is the visual separator between the summary
//! catalog and whatever narration follows (a kustomization-update
//! preamble at `push.rs::execute`, the `Ok(())` command completion at
//! `bootstrap.rs::push_single`). A future refactor that dropped the
//! trailing blank would collapse the summary against the next
//! narrator's opening line; the byte-oracle pins the framing blank as
//! part of the primitive's contract, so the caller does not repeat
//! `println!()` post-call to restore it.
//!
//! # No ANSI on the bullet or interpolation
//!
//! Every pre-lift consumer spelled the row plain — no `.dimmed()` /
//! `.green()` / `.cyan()` / `.bright_black()` chain on the bullet, the
//! registry, or the tag. This matches the sibling
//! [`crate::ui::print_bullet_item`] plain-row grammar (which itself
//! pins no-ANSI as a shield against a silent palette promotion). The
//! primitive stays plain so a future migration onto colored image-ref
//! renders is a deliberate visible change (a new primitive named for
//! the palette variant), not a silent recolor of every summary the
//! two consumer sites emit.

use std::io;

/// Prints the `"   • <registry>:<tag>"` (three-space indent + U+2022
/// `•` BULLET glyph + single ASCII space + `<registry>:<tag>` OCI
/// image-reference) bullet-list block for each element of `tags`,
/// followed by ONE trailing framing `println!()` blank line.
///
/// Delegates to [`write_pushed_image_ref_list`] against
/// [`std::io::stdout`]; the writer split exists so the fail-before-
/// pass tests can pin the three-space indent, the U+2022 glyph, the
/// `<registry>:<tag>` colon interpolation, the iteration cadence
/// (exactly one line per tag), the trailing framing blank, and the
/// ABSENCE of every `\x1b[<..>m` ANSI palette sequence by inspecting
/// emitted bytes rather than shelling out and grepping stdout.
///
/// See the [module docs](self) for the sibling site census, the split
/// against [`crate::ui::print_bullet_item`] (two-space declarative
/// catalog) / [`crate::ui::print_sub_bullet_item`] (four-space nested
/// leaf), and the compounding rationale for the three-space indent
/// and the framing blank.
pub fn print_pushed_image_ref_list(registry: &str, tags: &[String]) {
    let _ = write_pushed_image_ref_list(&mut io::stdout().lock(), registry, tags);
}

/// Writer-taking sibling to [`print_pushed_image_ref_list`]. Emits
/// one `"   • <registry>:<tag>\n"` line per element of `tags` via
/// [`writeln!`] against the supplied writer, followed by ONE trailing
/// blank line (an empty `writeln!(w)`). [`print_pushed_image_ref_list`]
/// is the stdout adapter; this variant exists so tests can pin the
/// exact emitted bytes without capturing stdout.
///
/// Iterating an empty `tags` slice emits only the trailing blank —
/// preserving the pre-lift shape's `for tag in &tags { ... }
/// println!();` behavior byte-for-byte on the (structurally
/// unreachable at the two lift sites, but preserved for a future
/// consumer) zero-tag edge.
pub fn write_pushed_image_ref_list<W: io::Write>(
    w: &mut W,
    registry: &str,
    tags: &[String],
) -> io::Result<()> {
    for tag in tags {
        writeln!(w, "   \u{2022} {}:{}", registry, tag)?;
    }
    writeln!(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two tags — the pre-lift multi-tag census. Pin the exact bytes:
    // three ASCII spaces (0x20 0x20 0x20), U+2022 BULLET (0xE2 0x82
    // 0xA2), one ASCII space, `<registry>:<tag>`, `\n`, repeat, then
    // one bare `\n` for the framing blank.
    #[test]
    fn write_pushed_image_ref_list_emits_three_indent_bullet_per_tag_and_framing_blank() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["amd64-abc1234".to_string(), "amd64-latest".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/pleme-io/forge", &tags).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            concat!(
                "   \u{2022} ghcr.io/pleme-io/forge:amd64-abc1234\n",
                "   \u{2022} ghcr.io/pleme-io/forge:amd64-latest\n",
                "\n",
            )
        );
    }

    // Single-tag census (`bootstrap.rs::push_single` reaches this
    // primitive with a `generate_auto_tags(DEFAULT_ARCH)` vector that
    // on a bare-repo test rig can be one element). Pin one bullet + a
    // framing blank.
    #[test]
    fn write_pushed_image_ref_list_renders_single_tag_with_one_bullet_and_framing_blank() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["amd64-latest".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/pleme-io/forge", &tags).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "   \u{2022} ghcr.io/pleme-io/forge:amd64-latest\n\n"
        );
    }

    // Empty tag vector — structurally unreachable at the two lift
    // sites (`push.rs::execute` bails at `if tags.is_empty()` above
    // line 245, `bootstrap.rs::push_single` receives a
    // `generate_auto_tags(...)` vector that is non-empty by
    // construction) but the pre-lift shape's `for tag in &tags { ...
    // } println!();` behavior emits only the framing blank on an
    // empty slice, and this primitive preserves that byte-for-byte
    // so a future consumer reaching for it with an empty catalog
    // sees the plain framing blank rather than a panic or a stray
    // bullet with an empty tag suffix.
    #[test]
    fn write_pushed_image_ref_list_emits_only_framing_blank_on_empty_slice() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = Vec::new();
        write_pushed_image_ref_list(&mut buf, "ghcr.io/pleme-io/forge", &tags).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\n");
    }

    // Multi-tag (three elements) census — a future
    // `--auto-tags`-plus-`--tag` combined invocation at
    // `push.rs::execute` can produce a three-plus catalog. Pin the
    // iteration cadence: exactly N per-tag bullets + one framing
    // blank (N+1 total newlines).
    #[test]
    fn write_pushed_image_ref_list_emits_exactly_n_bullets_plus_one_framing_blank() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec![
            "amd64-abc1234".to_string(),
            "amd64-latest".to_string(),
            "amd64-v1.2.3".to_string(),
        ];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/pleme-io/forge", &tags).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let newlines = s.matches('\n').count();
        assert_eq!(
            newlines, 4,
            "write_pushed_image_ref_list must emit exactly N+1 \
             newlines (one per bullet + one framing blank) for an \
             N-tag catalog; got {newlines} for a 3-tag catalog. \
             Rendered: {s:?}"
        );
        assert!(
            s.ends_with("\n\n"),
            "the last two bytes must be `\\n\\n` — the final bullet's \
             own line terminator immediately followed by the framing \
             blank. A refactor that dropped the framing blank flips \
             this. Rendered: {s:?}"
        );
    }

    // Pin the three-space indent explicitly — NOT two-space (would
    // collide with `crate::ui::print_bullet_item`'s declarative
    // catalog grammar), NOT four-space (would collide with
    // `crate::ui::print_sub_bullet_item`'s nested-leaf grammar). The
    // four-byte prefix `"   \u{2022}"` (three spaces + BULLET) pins
    // both boundaries.
    #[test]
    fn write_pushed_image_ref_list_uses_three_space_indent_before_bullet() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["latest".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/x", &tags).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let first_line = s.lines().next().unwrap();
        assert!(
            first_line.starts_with("   \u{2022} "),
            "line 0 must begin with a THREE-space indent + U+2022 \
             `\u{2022}` BULLET + single ASCII space — every pre-lift \
             consumer spelled `\"   \u{2022} {{}}:{{}}\"` verbatim. A \
             narrow to two-space collides with \
             `crate::ui::print_bullet_item`; a widen to four-space \
             collides with `crate::ui::print_sub_bullet_item`. Got \
             {first_line:?}"
        );
        assert!(
            !first_line.starts_with("  \u{2022}"),
            "line 0 must NOT begin with only two spaces before the \
             bullet — that indent belongs to \
             `crate::ui::print_bullet_item`. Got {first_line:?}"
        );
        assert!(
            !first_line.starts_with("    \u{2022}"),
            "line 0 must NOT begin with four spaces before the bullet \
             — that indent belongs to \
             `crate::ui::print_sub_bullet_item`. Got {first_line:?}"
        );
    }

    // Pin the U+2022 BULLET codepoint (three-byte UTF-8 `E2 80 A2`),
    // NOT U+00B7 `·` middle-dot (two-byte `C2 B7`), NOT ASCII `*`
    // (one-byte `2A`). Silent codepoint drift renders the summary
    // nearly-invisible or collides with markdown list grammar.
    #[test]
    fn write_pushed_image_ref_list_emits_u2022_bullet_codepoint() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["latest".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/x", &tags).unwrap();
        assert!(
            buf.windows(3).any(|w| w == [0xe2, 0x80, 0xa2]),
            "output must carry U+2022 `\u{2022}` BULLET as the \
             three-byte UTF-8 sequence `E2 80 A2` — a swap to U+00B7 \
             `\u{b7}` middle-dot or ASCII `*` silently changes the \
             visual grammar. Bytes: {buf:?}"
        );
    }

    // Pin the bare ASCII colon (`0x3A`) between registry and tag —
    // NOT `@` (would break paste-and-pull; `@digest` is the sibling
    // OCI-manifest-by-digest reference form the summary does not
    // carry), NOT ` ` (would break paste-and-pull outright), NOT `/`
    // (would collide with the path-separator inside the registry
    // itself).
    #[test]
    fn write_pushed_image_ref_list_joins_registry_and_tag_with_ascii_colon() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["v1.2.3".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/pleme-io/forge", &tags).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("ghcr.io/pleme-io/forge:v1.2.3"),
            "output must join registry and tag with a bare ASCII \
             colon (`:`, `0x3A`) — the canonical OCI image-reference \
             form. Got {s:?}"
        );
        assert!(
            !s.contains("ghcr.io/pleme-io/forge@v1.2.3"),
            "output must NOT use `@` — that is the digest-reference \
             sibling form the summary does not carry. Got {s:?}"
        );
    }

    // No ANSI escape byte (0x1B) reaches the writer — every pre-lift
    // consumer emitted the row plain (no `.dimmed()` / `.green()` /
    // `.cyan()` / `.bright_black()`). A silent palette promotion
    // would collide with `crate::ui::print_bullet_item`'s no-ANSI
    // sibling contract and repaint every post-push summary.
    #[test]
    fn write_pushed_image_ref_list_emits_no_ansi_escape() {
        let mut buf: Vec<u8> = Vec::new();
        let tags: Vec<String> = vec!["latest".to_string()];
        write_pushed_image_ref_list(&mut buf, "ghcr.io/x", &tags).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "write_pushed_image_ref_list must emit no ANSI escape \
             (`0x1B`) — every pre-lift consumer emitted the row plain, \
             and a silent palette promotion would collide with the \
             sibling `crate::ui::print_bullet_item` no-ANSI contract. \
             Bytes: {buf:?}"
        );
    }

    // Caller shield: no source line under `cli/src/commands/` may
    // still spell the pre-lift `for tag in &tags {` header
    // immediately followed by `println!("   \u{2022} {}:{}"` on the
    // next non-empty line — the pre-lift stanza's uniquely
    // identifiable fused shape. `github_runner_ci.rs:437-438` spells
    // a hardcoded two-line pair (`{}:latest` + `{}:{}", git_sha`)
    // that is NOT the iterated form and is deliberately left in
    // place; the shield distinguishes by requiring the for-loop
    // header on the preceding line.
    #[test]
    fn no_command_module_still_spells_raw_iterated_pushed_image_ref_bullet_stanza() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
        for entry in std::fs::read_dir(&commands_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = source.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("///") {
                    continue;
                }
                // Look for the pre-lift `for tag in &tags {` header.
                if !line.contains("for tag in &tags {") {
                    continue;
                }
                // Peek the next non-blank line for the sibling
                // `println!("   • {}:{}", registry, tag)` body.
                let body_hit = lines
                    .iter()
                    .skip(idx + 1)
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.contains("println!(\"   \u{2022} {}:{}\""))
                    .unwrap_or(false);
                if body_hit {
                    offenders.push((path.clone(), idx + 1, line.to_string()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw `for tag in &tags {{\\n    println!(\"   \u{2022} \
             {{}}:{{}}\", registry, tag);\\n}}` stanza(s) survive \
             under `commands/` — route each through \
             `crate::pushed_image_ref_list::print_pushed_image_ref_list(\
             &registry, &tags)` instead:\n{:#?}",
            offenders
        );
    }

    // Positive half of the shield: each pre-lift module MUST forward
    // through the primitive at least once, so a migration that
    // dropped a call site outright leaves the negative "no raw
    // inline shape" scan trivially satisfied by absence but the
    // positive count still fails.
    #[test]
    fn every_prelift_module_forwards_through_pushed_image_ref_list_primitive() {
        use std::path::PathBuf;
        let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("commands");
        let expectations: &[(&str, usize)] = &[("push.rs", 1), ("bootstrap.rs", 1)];
        for (basename, min_count) in expectations {
            let path = commands_dir.join(basename);
            let source = std::fs::read_to_string(&path).unwrap();
            let forwards = source
                .matches("crate::pushed_image_ref_list::print_pushed_image_ref_list(")
                .count();
            assert!(
                forwards >= *min_count,
                "{basename} must forward at least {min_count} \
                 post-push summary site(s) through \
                 `crate::pushed_image_ref_list::print_pushed_image_ref_list(`; \
                 found {forwards}. A dropped call would leave the \
                 negative raw-shape scan satisfied by absence."
            );
        }
    }
}
