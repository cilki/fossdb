//! RSS 2.0 and Atom 1.0 rendering for a single account's timeline.
//!
//! Serialisation is delegated to the `rss` and `atom_syndication` crates.
//! Package names, versions and descriptions arrive from third-party
//! registries and are copied verbatim into feed entries, so escaping is not
//! something to hand-roll here: a package named `</title><script>` must not
//! be able to break out of the document.

use chrono::{DateTime, Utc};

use crate::TimelineEvent;

/// Upper bound on entries in a single feed document.
///
/// Feed readers do not need deep history, and an unbounded document would let
/// a heavily subscribed account turn one poll into an arbitrarily large
/// response.
pub const MAX_ENTRIES: usize = 50;

/// One rendered feed, plus the metadata needed to answer a conditional GET.
pub struct Feed {
    pub body: String,
    pub content_type: &'static str,
    /// Timestamp of the newest entry, or `None` for an empty feed.
    pub last_modified: Option<DateTime<Utc>>,
    pub etag: String,
}

/// Inputs for rendering. Borrowed so the caller keeps ownership of the events.
pub struct FeedContext<'a> {
    pub user_id: &'a str,
    pub base_url: &'a str,
    pub events: &'a [TimelineEvent],
}

/// Canonical URL of the feed document itself.
///
/// Both formats require a self-referential link, and readers use it to
/// deduplicate subscriptions.
fn self_url(base_url: &str, user_id: &str, extension: &str) -> String {
    format!("{base_url}/feed/{user_id}/{extension}")
}

/// Stable, globally unique id for one entry.
///
/// Keyed on the event's primary key so that re-rendering the same event
/// always produces the same id; a reader that has already shown an entry must
/// not show it again on the next poll.
fn entry_id(event: &TimelineEvent) -> String {
    format!("urn:fossdb:event:{}", event.id)
}

fn entry_title(event: &TimelineEvent) -> String {
    if event.event_type == crate::EventType::SecurityAlert {
        return format!("Security advisory for {}", event.package_name);
    }
    match &event.version {
        Some(version) => format!("{} {}", event.package_name, version),
        None => event.package_name.clone(),
    }
}

fn entry_link(base_url: &str, event: &TimelineEvent) -> String {
    format!("{base_url}/packages/{}", event.package_id)
}

/// Newest entry timestamp, which drives `Last-Modified`.
fn newest(events: &[TimelineEvent]) -> Option<DateTime<Utc>> {
    events.iter().map(|e| e.created_at).max()
}

/// Weak validator for `ETag`.
///
/// Derived from the entry count and the newest timestamp: any new event
/// changes one or both. Weak (`W/`) because two documents with identical
/// content may still differ byte-for-byte between renders.
fn etag(events: &[TimelineEvent]) -> String {
    let newest = newest(events).map(|t| t.timestamp_micros()).unwrap_or(0);
    format!("W/\"{}-{}\"", events.len(), newest)
}

/// Order newest-first and clamp to [`MAX_ENTRIES`].
fn prepare(events: &[TimelineEvent]) -> Vec<&TimelineEvent> {
    let mut selected: Vec<&TimelineEvent> = events.iter().collect();
    selected.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    selected.truncate(MAX_ENTRIES);
    selected
}

pub fn render_atom(ctx: &FeedContext<'_>) -> Feed {
    use atom_syndication::{Entry, FeedBuilder, LinkBuilder, Person};

    let selected = prepare(ctx.events);
    let self_link = self_url(ctx.base_url, ctx.user_id, "atom.xml");

    let entries: Vec<Entry> = selected
        .iter()
        .map(|event| {
            let mut entry = Entry::default();
            entry.set_id(entry_id(event));
            entry.set_title(entry_title(event));
            entry.set_updated(event.created_at.fixed_offset());
            entry.set_links(vec![
                LinkBuilder::default()
                    .href(entry_link(ctx.base_url, event))
                    .rel("alternate")
                    .build(),
            ]);
            entry.set_summary(Some(event.message.clone().into()));
            entry
        })
        .collect();

    // An Atom feed must carry `updated`; fall back to now when there are no
    // entries rather than emitting an invalid document.
    let updated = newest(ctx.events).unwrap_or_else(Utc::now);

    let feed = FeedBuilder::default()
        .title("FossDB subscriptions")
        .id(self_link.clone())
        .updated(updated.fixed_offset())
        .authors(vec![Person {
            name: "FossDB".to_string(),
            ..Person::default()
        }])
        .links(vec![
            LinkBuilder::default()
                .href(self_link)
                .rel("self")
                .mime_type(Some("application/atom+xml".to_string()))
                .build(),
        ])
        .entries(entries)
        .build();

    Feed {
        body: feed.to_string(),
        content_type: "application/atom+xml; charset=utf-8",
        last_modified: newest(ctx.events),
        etag: etag(ctx.events),
    }
}

pub fn render_rss(ctx: &FeedContext<'_>) -> Feed {
    use rss::{ChannelBuilder, GuidBuilder, Item};

    let selected = prepare(ctx.events);
    let self_link = self_url(ctx.base_url, ctx.user_id, "rss.xml");

    let items: Vec<Item> = selected
        .iter()
        .map(|event| {
            let mut item = Item::default();
            item.set_title(entry_title(event));
            item.set_link(entry_link(ctx.base_url, event));
            item.set_description(event.message.clone());
            item.set_pub_date(event.created_at.to_rfc2822());
            item.set_guid(
                GuidBuilder::default()
                    .value(entry_id(event))
                    // Not a URL; readers must not try to fetch it.
                    .permalink(false)
                    .build(),
            );
            item
        })
        .collect();

    let channel = ChannelBuilder::default()
        .title("FossDB subscriptions")
        .link(self_link)
        .description("New releases of the packages you subscribe to")
        .last_build_date(newest(ctx.events).map(|t| t.to_rfc2822()))
        .items(items)
        .build();

    Feed {
        body: channel.to_string(),
        content_type: "application/rss+xml; charset=utf-8",
        last_modified: newest(ctx.events),
        etag: etag(ctx.events),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;

    fn event(id: u64, name: &str, version: &str, minutes_ago: i64) -> TimelineEvent {
        TimelineEvent {
            inner: fossdb::TimelineEvent {
                id,
                package_id: 1,
                user_id: Some("fdb_3k9x7m2qdv5r8ptw1ny6az4cbf".into()),
                event_type: EventType::NewRelease,
                package_name: name.to_string(),
                version: Some(version.to_string()),
                message: format!("New version {version} released"),
                metadata: None,
                created_at: Utc::now() - chrono::Duration::minutes(minutes_ago),
            },
        }
    }

    fn ctx<'a>(events: &'a [TimelineEvent]) -> FeedContext<'a> {
        FeedContext {
            user_id: "fdb_3k9x7m2qdv5r8ptw1ny6az4cbf",
            base_url: "https://fossdb.example",
            events,
        }
    }

    #[test]
    fn atom_contains_entries_and_self_link() {
        let events = vec![event(1, "serde", "1.0.0", 10)];
        let feed = render_atom(&ctx(&events));

        assert!(feed.body.contains("serde 1.0.0"));
        assert!(feed.body.contains("urn:fossdb:event:1"));
        assert!(
            feed.body
                .contains("https://fossdb.example/feed/fdb_3k9x7m2qdv5r8ptw1ny6az4cbf/atom.xml")
        );
        assert_eq!(feed.content_type, "application/atom+xml; charset=utf-8");
    }

    #[test]
    fn security_alerts_are_titled_as_such() {
        let mut alert = event(1, "openssl", "unused", 1);
        alert.inner.event_type = EventType::SecurityAlert;
        alert.inner.version = None;
        alert.inner.message = "RUSTSEC-2016-0001 (High): MitM. Affects 0.8.3.".into();

        let feed = render_atom(&ctx(std::slice::from_ref(&alert)));

        assert!(feed.body.contains("<title>Security advisory for openssl</title>"), "{}", feed.body);
        assert!(feed.body.contains("RUSTSEC-2016-0001 (High): MitM. Affects 0.8.3."));
    }

    #[test]
    fn rss_contains_items_and_non_permalink_guid() {
        let events = vec![event(7, "tokio", "2.1.0", 5)];
        let feed = render_rss(&ctx(&events));

        assert!(feed.body.contains("tokio 2.1.0"));
        assert!(feed.body.contains("urn:fossdb:event:7"));
        assert!(feed.body.contains("isPermaLink=\"false\""));
        assert_eq!(feed.content_type, "application/rss+xml; charset=utf-8");
    }

    /// Package names come from third-party registries. A name containing
    /// markup must be escaped, not interpolated.
    #[test]
    fn hostile_package_names_are_escaped() {
        let events = vec![event(1, "</title><script>alert(1)</script>", "1.0", 1)];

        for body in [
            render_atom(&ctx(&events)).body,
            render_rss(&ctx(&events)).body,
        ] {
            assert!(
                !body.contains("<script>"),
                "unescaped markup leaked into feed: {body}"
            );
            assert!(body.contains("&lt;script&gt;"), "expected escaped form");
        }
    }

    #[test]
    fn entries_are_newest_first() {
        let events = vec![
            event(1, "old", "1.0", 100),
            event(2, "new", "2.0", 1),
            event(3, "mid", "1.5", 50),
        ];
        let body = render_atom(&ctx(&events)).body;

        let pos = |needle: &str| body.find(needle).expect("entry present");
        assert!(pos("new 2.0") < pos("mid 1.5"));
        assert!(pos("mid 1.5") < pos("old 1.0"));
    }

    #[test]
    fn feeds_are_capped() {
        let events: Vec<_> = (0..MAX_ENTRIES as u64 + 25)
            .map(|i| event(i + 1, "pkg", "1.0", i as i64))
            .collect();

        let body = render_atom(&ctx(&events)).body;
        assert_eq!(body.matches("<entry>").count(), MAX_ENTRIES);
    }

    #[test]
    fn empty_feed_is_still_valid() {
        let feed = render_atom(&ctx(&[]));
        assert!(feed.body.contains("<feed"));
        assert!(feed.last_modified.is_none());

        let feed = render_rss(&ctx(&[]));
        assert!(feed.body.contains("<rss"));
    }

    #[test]
    fn etag_tracks_content() {
        let one = vec![event(1, "a", "1.0", 10)];
        let two = vec![event(1, "a", "1.0", 10), event(2, "b", "1.0", 5)];

        assert_eq!(etag(&one), etag(&one));
        assert_ne!(etag(&one), etag(&two));
        // An empty feed still produces a usable validator.
        assert!(!etag(&[]).is_empty());
    }

    /// The credential is in the feed URL by design, but it must not also be
    /// scattered through the entries.
    #[test]
    fn credential_appears_only_in_the_self_link() {
        let events = vec![event(1, "serde", "1.0.0", 10)];
        let body = render_atom(&ctx(&events));
        assert_eq!(body.body.matches("fdb_3k9x7m2qdv5r8ptw1ny6az4cbf").count(), 2);
    }
}
