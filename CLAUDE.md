# Forge

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.

Deployment orchestrator for Nix-based service infrastructure. Replaces fragile bash scripts with a type-safe Rust CLI that handles the full lifecycle: build, push, deploy, rollback, test, and release.

## ★★ Version bumping — one decision here, one adapter per ecosystem

**All SDLC is a config of forge.** A CI action's job is to CALL forge, never to
compute a version. Before adding or touching any `<ecosystem> bump`, read
[`docs/version-bump-adapters.md`](../docs/version-bump-adapters.md) — it carries
the fleet census, the in/out-of-scope table, and the per-ecosystem trap catalog.

Three rules, each paid for by a measured defect:

1. **Route the decision through `version::next_free_version`.** It seeds from
   `max(manifest, highest released tag)` and skips taken tags. Bumping from the
   manifest alone walks a release BACKWARD whenever the manifest lags its tags —
   527 inverted tag pairs across a 937-repo census, i.e. the fleet's normal state.
2. **Detect the literal form, then render THAT form.** A closed enum whose
   `render` is the inverse of the `pattern` that detected it. Ruby
   (`commands/gem.rs`) is the reference implementation: 3 forms across 41 repos,
   and a writer handling only one meant 9 repos could not be bumped at all.
3. **Splice over the matched byte span.** Never rebuild the needle with
   `format!` and pass it to `content.replace` — the regex tolerates whitespace
   the reconstruction does not, so the write silently no-ops **and reports
   success**.

**An ecosystem that versions only by git tag gets NO adapter** (go, swift-spm,
github-action, composer — measured, not assumed). So does a generated manifest:
an in-place bump is reverted by the next generation run, so the write belongs in
the source.
