use crate::api::types::Package;
use crate::hooks::{NotificationContext, use_notifications};
use dioxus::prelude::*;
use std::collections::VecDeque;

/// Maximum packages that can be compared at once.
pub const MAX_COMPARISON_PACKAGES: usize = 3;

#[derive(Clone, PartialEq, Default)]
pub struct ComparisonState {
    pub packages: VecDeque<Package>,
}

/// Handle to the comparison state.
///
/// Holds the notification context captured at hook time. Previously `add`
/// called `use_notifications()` itself, i.e. a hook invoked from outside render,
/// which appends to the scope's hook list at an index the render pass does not
/// know about. Re-using that slot with a different type later triggers dioxus's
/// "unable to retrieve the hook initialized at this index" panic.
#[derive(Copy, Clone)]
pub struct ComparisonContext {
    state: Signal<ComparisonState>,
    notifications: NotificationContext,
}

impl ComparisonContext {
    pub fn add(&mut self, package: Package) {
        let mut notif = self.notifications;

        {
            let state = self.state.read();
            if state.packages.len() >= MAX_COMPARISON_PACKAGES {
                drop(state);
                notif.warning(format!(
                    "Maximum {} packages can be compared",
                    MAX_COMPARISON_PACKAGES
                ));
                return;
            }
            if state.packages.iter().any(|p| p.id == package.id) {
                drop(state);
                notif.info("Package already in comparison".to_string());
                return;
            }
        }

        self.state.write().packages.push_back(package);
        notif.success("Package added to comparison".to_string());
    }

    pub fn remove(&mut self, package_id: u64) {
        self.state.write().packages.retain(|p| p.id != package_id);
    }

    pub fn clear(&mut self) {
        self.state.write().packages.clear();
    }

    pub fn contains(&self, package_id: u64) -> bool {
        self.state.read().packages.iter().any(|p| p.id == package_id)
    }
}

pub fn use_comparison() -> ComparisonContext {
    ComparisonContext {
        state: use_context::<Signal<ComparisonState>>(),
        // Called during render, which is where hooks belong.
        notifications: use_notifications(),
    }
}

#[component]
pub fn ComparisonBar() -> Element {
    let comparison = use_comparison();
    let mut show_modal = use_signal(|| false);

    let packages = comparison.state.read().packages.clone();
    if packages.is_empty() {
        return rsx! { div {} };
    }

    let package_count = packages.len();
    let packages_for_modal: Vec<_> = packages.iter().cloned().collect();

    rsx! {
        div { class: "fixed bottom-4 right-4 bg-gray-800 rounded-lg shadow-2xl border border-gray-700 p-4 z-40",
            div { class: "flex items-center space-x-4",
                div { class: "flex items-center space-x-2",
                    svg { class: "w-5 h-5 text-blue-400", fill: "none", stroke: "currentColor", view_box: "0 0 24 24",
                        path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" }
                    }
                    span { class: "text-gray-200 font-medium", "Compare ({package_count}/3)" }
                }

                for pkg in packages.into_iter() {
                    {
                        let pkg_id = pkg.id;
                        let pkg_name = pkg.name.clone();
                        rsx! {
                            div { class: "flex items-center space-x-2 bg-gray-700 rounded px-3 py-1",
                                span { class: "text-sm text-gray-200", "{pkg_name}" }
                                button {
                                    class: "text-red-400 hover:text-red-300",
                                    onclick: move |_| {
                                        let mut comp = comparison;
                                        comp.remove(pkg_id);
                                    },
                                    svg { class: "w-4 h-4", fill: "none", stroke: "currentColor", view_box: "0 0 24 24",
                                        path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M6 18L18 6M6 6l12 12" }
                                    }
                                }
                            }
                        }
                    }
                }

                button {
                    class: "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors",
                    onclick: move |_| show_modal.set(true),
                    "Compare"
                }

                button {
                    class: "px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-500 transition-colors",
                    onclick: move |_| {
                        let mut comp = comparison;
                        comp.clear();
                    },
                    "Clear"
                }
            }
        }

        if show_modal() {
            ComparisonModal { show: show_modal, packages: packages_for_modal }
        }
    }
}

#[component]
fn ComparisonModal(show: Signal<bool>, packages: Vec<Package>) -> Element {
    rsx! {
        div {
            class: "fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4",
            onclick: move |_| show.set(false),
            div {
                class: "bg-gray-800 rounded-2xl w-full max-w-6xl max-h-[90vh] overflow-y-auto shadow-2xl border border-gray-700",
                onclick: move |evt| evt.stop_propagation(),
                div { class: "p-8",
                    h2 { class: "text-3xl font-bold text-gray-100 mb-6", "Package Comparison" }

                    div { class: "overflow-x-auto",
                        table { class: "w-full",
                            thead {
                                tr { class: "border-b border-gray-700",
                                    th { class: "text-left p-4 text-gray-400 font-medium", "Property" }
                                    for pkg in packages.iter() {
                                        th { class: "text-left p-4 text-gray-200 font-bold", "{pkg.name}" }
                                    }
                                }
                            }
                            tbody {
                                tr { class: "border-b border-gray-700",
                                    td { class: "p-4 text-gray-400", "Description" }
                                    for pkg in packages.iter() {
                                        td { class: "p-4 text-gray-200",
                                            if let Some(desc) = &pkg.description {
                                                "{desc}"
                                            } else {
                                                span { class: "text-gray-500", "N/A" }
                                            }
                                        }
                                    }
                                }
                                tr { class: "border-b border-gray-700",
                                    td { class: "p-4 text-gray-400", "Homepage" }
                                    for pkg in packages.iter() {
                                        td { class: "p-4",
                                            if let Some(homepage) = pkg.homepage.as_deref().and_then(crate::util::safe_external_url) {
                                                a { class: "text-blue-400 hover:underline", href: "{homepage}", target: "_blank", rel: "noopener noreferrer", "Visit" }
                                            } else {
                                                span { class: "text-gray-500", "N/A" }
                                            }
                                        }
                                    }
                                }
                                tr { class: "border-b border-gray-700",
                                    td { class: "p-4 text-gray-400", "Repository" }
                                    for pkg in packages.iter() {
                                        td { class: "p-4",
                                            if let Some(repo) = pkg.repository.as_deref().and_then(crate::util::safe_external_url) {
                                                a { class: "text-blue-400 hover:underline", href: "{repo}", target: "_blank", rel: "noopener noreferrer", "Visit" }
                                            } else {
                                                span { class: "text-gray-500", "N/A" }
                                            }
                                        }
                                    }
                                }
                                tr { class: "border-b border-gray-700",
                                    td { class: "p-4 text-gray-400", "Created" }
                                    for pkg in packages.iter() {
                                        td { class: "p-4 text-gray-200", "{pkg.created_at.format(\"%Y-%m-%d\")}" }
                                    }
                                }
                            }
                        }
                    }

                    button {
                        class: "mt-6 w-full bg-gray-600 text-gray-200 px-4 py-3 rounded-lg font-medium hover:bg-gray-500 transition-all",
                        onclick: move |_| show.set(false),
                        "Close"
                    }
                }
            }
        }
    }
}
