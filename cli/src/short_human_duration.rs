//! Canonical `<d>d<h>h` / `<h>h<m>m` / `<m>m<s>s` / `<s>s` compact
//! human-display rendering of a [`chrono::Duration`] — the four-way
//! ladder every "how long did / how long ago" surface in
//! `commands/status.rs` speaks.
//!
//! # Pre-lift census — two sibling grammars, one shared tail
//!
//! Two sibling helper functions inside `commands/status.rs` each
//! restated the compact-human-duration rendering inline:
//!
//! 1. `calculate_age(timestamp: &str) -> String` (around line 1209) —
//!    the four-way `<d>d<h>h` / `<h>h<m>m` / `<m>m<s>s` / `<s>s`
//!    ladder against `Utc::now().signed_duration_since(created)` for
//!    the "resource age" column of the status table (Kubernetes
//!    Deployment `metadata.creationTimestamp`, Redis Deployment /
//!    StatefulSet ages).
//! 2. `calculate_duration(start: &str, end: &str) -> Option<String>`
//!    (around line 1234) — the tail two branches of the same ladder
//!    (`<m>m<s>s` / `<s>s`) against
//!    `end_dt.signed_duration_since(start_dt)` for the "elapsed
//!    duration" column of the migration listing (Kubernetes Job
//!    `status.startTime` → `status.completionTime`).
//!
//! Both re-derive the same grammar: the `format!("{}s", …)` seconds-
//! only tail and the `format!("{}m{}s", …, … % 60)` minutes-and-
//! seconds body appear at TWO code lines each. Two sibling sites
//! restating the same compact-duration grammar is past the fleet's
//! duplication threshold (PRIME DIRECTIVE; THEORY §VI.1
//! generation-over-composition).
//!
//! # The load-bearing unification — a single ladder oracle
//!
//! Post-lift both consumers project through
//! [`format_short_human_duration`], the ONE grammar oracle that
//! decides how a caller-supplied [`chrono::Duration`] renders as the
//! compact status-display string. The `calculate_age` and
//! `calculate_duration` bodies each collapse to a two-line
//! chrono-parse + [`format_short_human_duration`] hand-off.
//!
//! # Sharpened promise — long migrations now render `<h>h<m>m`, not
//! `<m>m<s>s`
//!
//! Pre-lift `calculate_duration` truncated at the minutes branch: a
//! Kubernetes Job that ran for 65 minutes and 3 seconds rendered as
//! `"65m3s"`; one that ran for 3 hours and 14 minutes rendered as
//! `"194m14s"`. The `calculate_age` sibling ALREADY spoke the four-
//! way ladder (`"1h5m"`, `"3h14m"`, and `"2d3h"` for a >1-day
//! Deployment age), so the status table's two duration columns
//! disagreed on the same grammar. Routing both through the ONE
//! ladder oracle here makes long-running migrations display the same
//! compact `<h>h<m>m` and `<d>d<h>h` shape a long-lived Deployment's
//! age column already uses.
//!
//! # Why the four-way ladder, not a fixed unit
//!
//! A single `.num_seconds()`-based renderer would spam long
//! deployments' age columns with six- or seven-digit seconds counts
//! (a 30-day-old Deployment reads `2592000s`), and a single
//! `.num_minutes()`-based renderer strips the sub-minute precision
//! the sub-minute migration case needs. The four-way ladder
//! preserves precision AT EACH ORDER OF MAGNITUDE by dropping the
//! next-finer unit's tail only when the coarser unit's magnitude is
//! at least 1 — the same "compact but precise where it matters"
//! grammar `kubectl get pods`'s AGE column speaks.
//!
//! # Distinct from the kubectl-argv [`crate::kubectl_duration_arg`]
//!
//! [`crate::kubectl_duration_arg::kubectl_duration_seconds_arg`]
//! owns the machine-readable `<n>s` seconds-only argv-slot grammar
//! Go's `time.ParseDuration` accepts. This primitive owns the
//! human-readable four-way ladder for stdout display. Two disjoint
//! grammars for two disjoint audiences — the byte-oracle tests below
//! pin this primitive's output against the human-display ladder so a
//! future drift into the kubectl-argv grammar (e.g. dropping the
//! finer-unit tail to render `1h` instead of `1h5m`) trips at the
//! test, not silently in the terminal.

use chrono::Duration;

/// Render a [`chrono::Duration`] as the compact
/// `<d>d<h>h` / `<h>h<m>m` / `<m>m<s>s` / `<s>s` human-display string.
///
/// # Grammar
///
/// The largest non-zero coarse unit picks the branch; the next-finer
/// unit's modular tail rides along.
///
/// | Range                    | Rendered form            |
/// | ------------------------ | ------------------------ |
/// | `d.num_days() > 0`       | `"{d}d{h}h"` (`h % 24`)  |
/// | `d.num_hours() > 0`      | `"{h}h{m}m"` (`m % 60`)  |
/// | `d.num_minutes() > 0`    | `"{m}m{s}s"` (`s % 60`)  |
/// | else                     | `"{s}s"`                 |
///
/// The `num_seconds()` / `num_minutes()` / `num_hours()` /
/// `num_days()` accessors floor toward zero, so a duration of
/// exactly 60 seconds picks the minutes branch (`"1m0s"`, not
/// `"60s"`), and a duration of exactly 3600 seconds picks the hours
/// branch (`"1h0m"`, not `"60m0s"`).
///
/// # Negative durations
///
/// [`chrono::Duration`] is signed. A negative input (`end < start`)
/// falls through all `> 0` guards to the seconds-only tail and
/// renders as `-Ns`. This matches the pre-lift `calculate_duration`
/// body's implicit handling — the two consumers never construct a
/// negative duration (Kubernetes `completionTime >= startTime` by
/// construction on a successful Job; `Utc::now() >= created` for a
/// non-future creation timestamp), but the grammar tolerates the
/// out-of-band case rather than panicking on it.
pub fn format_short_human_duration(d: Duration) -> String {
    if d.num_days() > 0 {
        format!("{}d{}h", d.num_days(), d.num_hours() % 24)
    } else if d.num_hours() > 0 {
        format!("{}h{}m", d.num_hours(), d.num_minutes() % 60)
    } else if d.num_minutes() > 0 {
        format!("{}m{}s", d.num_minutes(), d.num_seconds() % 60)
    } else {
        format!("{}s", d.num_seconds())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-oracle for the sub-minute seconds-only tail:
    /// [`format_short_human_duration`] renders any `0 <=
    /// num_seconds() < 60` as `"{s}s"` byte-for-byte. A future
    /// refactor that dropped the `s` suffix, padded the magnitude,
    /// or interpolated the number in a different position regresses
    /// this assertion.
    #[test]
    fn sub_minute_renders_seconds_only_tail() {
        assert_eq!(format_short_human_duration(Duration::seconds(0)), "0s");
        assert_eq!(format_short_human_duration(Duration::seconds(1)), "1s");
        assert_eq!(format_short_human_duration(Duration::seconds(30)), "30s");
        assert_eq!(format_short_human_duration(Duration::seconds(59)), "59s");
    }

    /// Byte-oracle for the minute-to-hour band:
    /// [`format_short_human_duration`] renders `60 <= num_seconds()
    /// < 3600` as `"{m}m{s % 60}s"`. Boundary case: exactly 60
    /// seconds picks the minutes branch (`"1m0s"`, not `"60s"`).
    #[test]
    fn minute_to_hour_renders_minutes_and_seconds() {
        assert_eq!(format_short_human_duration(Duration::seconds(60)), "1m0s");
        assert_eq!(format_short_human_duration(Duration::seconds(61)), "1m1s");
        assert_eq!(
            format_short_human_duration(Duration::seconds(35 * 60 + 12)),
            "35m12s"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(3599)),
            "59m59s"
        );
    }

    /// Byte-oracle for the hour-to-day band:
    /// [`format_short_human_duration`] renders `3600 <=
    /// num_seconds() < 86400` as `"{h}h{m % 60}m"`. Boundary case:
    /// exactly 3600 seconds picks the hours branch (`"1h0m"`, not
    /// `"60m0s"`). Load-bearing at the sharpened
    /// `calculate_duration` promise: pre-lift a 1h5m migration
    /// rendered as `"65m5s"`; post-lift it renders as `"1h5m"`, the
    /// same shape `calculate_age` already spoke for a >1h-old
    /// Deployment.
    #[test]
    fn hour_to_day_renders_hours_and_minutes() {
        assert_eq!(format_short_human_duration(Duration::seconds(3600)), "1h0m");
        assert_eq!(format_short_human_duration(Duration::seconds(3660)), "1h1m");
        assert_eq!(
            format_short_human_duration(Duration::seconds(65 * 60)),
            "1h5m"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(3 * 3600 + 14 * 60)),
            "3h14m"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(86399)),
            "23h59m"
        );
    }

    /// Byte-oracle for the day-plus band:
    /// [`format_short_human_duration`] renders `num_seconds() >=
    /// 86400` as `"{d}d{h % 24}h"`. Boundary case: exactly 86400
    /// seconds picks the days branch (`"1d0h"`, not `"24h0m"`).
    #[test]
    fn day_plus_renders_days_and_hours() {
        assert_eq!(
            format_short_human_duration(Duration::seconds(86400)),
            "1d0h"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(90000)),
            "1d1h"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(2 * 86400 + 3 * 3600)),
            "2d3h"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(30 * 86400)),
            "30d0h"
        );
    }

    /// Load-bearing boundary shield: the four-way ladder picks the
    /// coarser branch at each 60-second / 3600-second / 86400-second
    /// boundary. A future refactor that swapped one of the `> 0`
    /// guards to `>= 0` (or dropped one branch entirely) would
    /// regress the boundary case's rendering — this shield names
    /// each transition and pins the expected coarser-branch pick.
    #[test]
    fn ladder_picks_coarser_branch_at_each_boundary() {
        // 59s vs 60s — sub-minute vs minute-to-hour boundary.
        assert_eq!(format_short_human_duration(Duration::seconds(59)), "59s");
        assert_eq!(format_short_human_duration(Duration::seconds(60)), "1m0s");
        // 3599s vs 3600s — minute-to-hour vs hour-to-day boundary.
        assert_eq!(
            format_short_human_duration(Duration::seconds(3599)),
            "59m59s"
        );
        assert_eq!(format_short_human_duration(Duration::seconds(3600)), "1h0m");
        // 86399s vs 86400s — hour-to-day vs day-plus boundary.
        assert_eq!(
            format_short_human_duration(Duration::seconds(86399)),
            "23h59m"
        );
        assert_eq!(
            format_short_human_duration(Duration::seconds(86400)),
            "1d0h"
        );
    }

    /// Negative-duration tolerance: a [`chrono::Duration`] with a
    /// negative magnitude falls through every `> 0` guard to the
    /// seconds-only tail and renders as `"-Ns"`. The two consumers
    /// never construct a negative duration by construction (Job
    /// `completionTime >= startTime`; `Utc::now() >= created`), but
    /// the grammar tolerates the out-of-band case rather than
    /// panicking. Pins the fall-through arm at ONE test so a future
    /// refactor that swapped `.num_seconds() > 0` for
    /// `.num_seconds() != 0` regresses here.
    #[test]
    fn negative_duration_falls_through_to_seconds_tail() {
        assert_eq!(format_short_human_duration(Duration::seconds(-5)), "-5s");
        assert_eq!(format_short_human_duration(Duration::seconds(-60)), "-60s");
        assert_eq!(
            format_short_human_duration(Duration::seconds(-3600)),
            "-3600s"
        );
    }
}
