use crate::api::types::Package;
use crate::Route;
use crate::components::use_comparison;
use dioxus::prelude::*;
use fossdb::typosquat::PackageLookalike;

/// Tooltip of a card's lookalike marker, e.g. `Name resembles colorama (one
/// character different). Check before installing.`
fn lookalike_marker_title(lookalike: &PackageLookalike) -> String {
    format!(
        "Name resembles {} ({}). Check before installing.",
        lookalike.target_name,
        lookalike.reason.describe()
    )
}

/// `lookalike` marks a package whose name imitates a popular one; the
/// package page explains it in full.
#[component]
pub fn PackageCard(package: Package, #[props(default)] lookalike: Option<PackageLookalike>) -> Element {
    // `ComparisonContext::add` had no caller anywhere in the crate, so the
    // comparison state was always empty and `ComparisonBar` always
    // early-returned - the entire compare feature was unreachable UI.
    let comparison = use_comparison();
    let package_id = package.id;
    let in_comparison = comparison.contains(package_id);
    let package_for_compare = package.clone();

    rsx! {
        Link {
            to: Route::PackageDetail { id: package.id.to_string() },
            class: "bg-gray-800 rounded-xl p-6 border border-gray-700 card-hover block",

            div { class: "flex justify-between items-start mb-3",
                h3 { class: "text-xl font-bold text-gray-100", "{package.name}" }
                if let Some(license) = &package.license {
                    span { class: "px-3 py-1 bg-blue-900 text-blue-300 rounded-full text-xs font-medium",
                        "{license}"
                    }
                }
            }

            if let Some(lookalike) = &lookalike {
                div {
                    class: "mb-3 inline-block px-2 py-1 bg-yellow-900 text-yellow-300 border border-yellow-700 rounded text-xs font-medium",
                    title: "{lookalike_marker_title(lookalike)}",
                    "Possible lookalike of {lookalike.target_name}"
                }
            }

            if let Some(description) = &package.description {
                p { class: "text-gray-400 text-sm mb-4 line-clamp-2", "{description}" }
            }

            div { class: "flex flex-wrap gap-2 mb-4",
                if let Some(language) = &package.language {
                    span { class: "px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs", "{language}" }
                }
                if let Some(platform) = &package.platform {
                    span { class: "px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs", "{platform}" }
                }
            }

            div { class: "flex items-center space-x-4 text-sm text-gray-500",
                if let Some(homepage) = package.homepage.as_deref().and_then(crate::util::safe_external_url) {
                    a {
                        href: "{homepage}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        class: "hover:text-blue-400 transition-colors",
                        onclick: |e| e.stop_propagation(),
                        "Homepage"
                    }
                }
                if let Some(repository) = package.repository.as_deref().and_then(crate::util::safe_external_url) {
                    a {
                        href: "{repository}",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        class: "hover:text-blue-400 transition-colors",
                        onclick: |e| e.stop_propagation(),
                        "Repository"
                    }
                }

                button {
                    class: if in_comparison {
                        "ml-auto text-blue-400 transition-colors"
                    } else {
                        "ml-auto hover:text-blue-400 transition-colors"
                    },
                    onclick: move |e: Event<MouseData>| {
                        // The card is wrapped in a `Link`; without this the
                        // click would also navigate to the detail page.
                        e.stop_propagation();
                        e.prevent_default();
                        let mut comparison = comparison;
                        if comparison.contains(package_id) {
                            comparison.remove(package_id);
                        } else {
                            comparison.add(package_for_compare.clone());
                        }
                    },
                    if in_comparison { "Remove from compare" } else { "Compare" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossdb::typosquat::SquatReason;
    use fossdb::FindingSeverity;

    #[test]
    fn lookalike_marker_title_names_the_target_and_reason() {
        let lookalike = PackageLookalike {
            target_id: 7,
            target_name: "colorama".into(),
            target_dependents: 5000,
            reason: SquatReason::Edit1,
            severity: FindingSeverity::Medium,
        };
        assert_eq!(
            lookalike_marker_title(&lookalike),
            "Name resembles colorama (one character different). Check before installing."
        );
    }
}
