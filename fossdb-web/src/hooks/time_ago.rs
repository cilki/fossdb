use chrono::{DateTime, Utc};
use dioxus::prelude::*;

/// A human-readable "time ago" string that refreshes periodically.
///
/// `datetime` is a plain prop, so it is tracked with `use_reactive!`. Without
/// that, the `use_signal` initializer ran only on first mount and the refresh
/// loop kept formatting the *original* value forever - so when dioxus reused a
/// list item's scope with new props (which happens whenever a websocket event is
/// inserted at the front of the timeline), every card showed the timestamp of
/// the event that previously occupied its slot.
pub fn use_time_ago(datetime: DateTime<Utc>) -> Signal<String> {
    let mut time_str = use_signal(|| format_time_ago(datetime));
    let mut target = use_signal(|| datetime);

    // Recompute immediately whenever the prop changes.
    use_effect(use_reactive!(|datetime| {
        target.set(datetime);
        time_str.set(format_time_ago(datetime));
    }));

    // Exactly one refresh task per component, created via `use_hook` so repeated
    // effect runs cannot pile up additional endless loops.
    use_hook(|| {
        spawn(async move {
            loop {
                gloo_timers::future::sleep(std::time::Duration::from_secs(30)).await;
                let current = *target.peek();
                time_str.set(format_time_ago(current));
            }
        });
    });

    time_str
}

fn format_time_ago(datetime: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(datetime);

    let seconds = duration.num_seconds();
    let minutes = duration.num_minutes();
    let hours = duration.num_hours();
    let days = duration.num_days();

    // A timestamp in the future (clock skew between server and browser) would
    // otherwise render as a negative count, e.g. "-3 minutes ago".
    if seconds < 0 {
        return "just now".to_string();
    }

    if seconds < 60 {
        "just now".to_string()
    } else if minutes < 60 {
        format!(
            "{} minute{} ago",
            minutes,
            if minutes == 1 { "" } else { "s" }
        )
    } else if hours < 24 {
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if days < 30 {
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if days < 365 {
        let months = days / 30;
        format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
    } else {
        let years = days / 365;
        format!("{} year{} ago", years, if years == 1 { "" } else { "s" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn formats_relative_times() {
        let now = Utc::now();
        assert_eq!(format_time_ago(now), "just now");
        assert_eq!(format_time_ago(now - Duration::minutes(1)), "1 minute ago");
        assert_eq!(format_time_ago(now - Duration::minutes(5)), "5 minutes ago");
        assert_eq!(format_time_ago(now - Duration::hours(1)), "1 hour ago");
        assert_eq!(format_time_ago(now - Duration::days(1)), "1 day ago");
        assert_eq!(format_time_ago(now - Duration::days(60)), "2 months ago");
        assert_eq!(format_time_ago(now - Duration::days(400)), "1 year ago");
    }

    /// Clock skew must not produce "-3 minutes ago".
    #[test]
    fn future_timestamps_render_as_just_now() {
        let future = Utc::now() + Duration::minutes(3);
        assert_eq!(format_time_ago(future), "just now");
    }
}
