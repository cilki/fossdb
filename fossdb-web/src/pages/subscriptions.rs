use crate::api::{types::PackageSubscription, ApiClient};
use crate::hooks::{use_auth, use_notifications};
use dioxus::prelude::*;

#[component]
pub fn Subscriptions() -> Element {
    let auth = use_auth();
    let notif = use_notifications();
    let mut subscriptions = use_signal(Vec::<PackageSubscription>::new);
    let mut loading = use_signal(|| true);

    // Load subscriptions.
    //
    // `auth.token()` is read *inside* the effect so the effect is subscribed to
    // it and re-runs on login/logout. Capturing a cloned `Option<String>`
    // outside meant the effect ran exactly once per mount, leaving the page
    // stuck on the empty state after logging in.
    use_effect(move || {
        let token = auth.token();
        let mut notif = notif;
        spawn(async move {
            match token {
                Some(t) => {
                    let client = ApiClient::new().with_token(Some(t));
                    match client.get_subscriptions().await {
                        Ok(subs) => subscriptions.set(subs),
                        Err(e) => {
                            notif.error(format!("Failed to load subscriptions: {:?}", e));
                            subscriptions.set(Vec::new());
                        }
                    }
                }
                None => subscriptions.set(Vec::new()),
            }
            loading.set(false);
        });
    });

    let auth_token = auth.token();

    rsx! {
        main { class: "min-h-screen bg-gray-900 py-12",
            div { class: "container mx-auto px-6",
                div { class: "text-center mb-12",
                    h1 { class: "text-4xl md:text-5xl font-bold text-gray-100 mb-6", "My Subscriptions" }
                    p { class: "text-xl text-gray-300 max-w-3xl mx-auto",
                        "Manage packages you're following to receive updates"
                    }
                }

                div { class: "max-w-4xl mx-auto",
                    if loading() {
                        div { class: "flex justify-center py-12",
                            div { class: "animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" }
                        }
                    } else if subscriptions().is_empty() {
                        div { class: "text-center py-12",
                            div { class: "bg-gray-800 rounded-2xl p-12 border border-gray-700",
                                svg { class: "w-16 h-16 text-gray-600 mx-auto mb-4", fill: "none", stroke: "currentColor", view_box: "0 0 24 24",
                                    path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" }
                                }
                                h3 { class: "text-xl font-semibold text-gray-300 mb-2", "No Subscriptions Yet" }
                                p { class: "text-gray-400 mb-6", "Start following packages to get updates on new versions and changes" }
                                Link {
                                    to: crate::Route::Packages {},
                                    class: "inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors",
                                    "Browse Packages"
                                }
                            }
                        }
                    } else {
                        div { class: "space-y-4",
                            for sub in subscriptions().iter() {
                                {
                                    let pkg_name = sub.package_name.clone();
                                    let pkg_name_toggle = sub.package_name.clone();
                                    let pkg_name_unsub = sub.package_name.clone();
                                    let notif_enabled = sub.notifications_enabled;
                                    let token_toggle = auth_token.clone();
                                    let token_unsub = auth_token.clone();
                                    rsx! {
                                        div { key: "{pkg_name}", class: "bg-gray-800 rounded-xl p-6 border border-gray-700",
                                            div { class: "flex justify-between items-start",
                                                div { class: "flex-1",
                                                    h3 { class: "text-xl font-bold text-gray-100 mb-2",
                                                        "{pkg_name}"
                                                    }
                                                    Link {
                                                        to: crate::Route::Packages {},
                                                        class: "text-blue-400 hover:text-blue-300 text-sm",
                                                        "Browse packages"
                                                    }
                                                }
                                                div { class: "flex items-center space-x-4",
                                                    label { class: "flex items-center space-x-2 cursor-pointer",
                                                        input {
                                                            r#type: "checkbox",
                                                            class: "w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500",
                                                            checked: notif_enabled,
                                                            onchange: move |evt| {
                                                                let pkg = pkg_name_toggle.clone();
                                                                let token = token_toggle.clone();
                                                                let enabled = evt.checked();
                                                                let mut notif = notif;
                                                                spawn(async move {
                                                                    if let Some(t) = token {
                                                                        let client = ApiClient::new().with_token(Some(t));
                                                                        match client.toggle_notifications(&pkg, enabled).await {
                                                                            // Adopt the server's view so the checkbox
                                                                            // cannot drift from stored state.
                                                                            Ok(updated) => subscriptions.set(updated),
                                                                            Err(e) => notif.error(
                                                                                format!("Failed to update notifications: {:?}", e),
                                                                            ),
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        }
                                                        span { class: "text-sm text-gray-300", "Email Notifications" }
                                                    }
                                                    button {
                                                        class: "px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors",
                                                        onclick: move |_| {
                                                            let pkg = pkg_name_unsub.clone();
                                                            let token = token_unsub.clone();
                                                            let mut notif = notif;
                                                            spawn(async move {
                                                                if let Some(t) = token {
                                                                    let client = ApiClient::new().with_token(Some(t));
                                                                    match client.unsubscribe(&pkg).await {
                                                                        Ok(updated) => subscriptions.set(updated),
                                                                        Err(e) => notif.error(
                                                                            format!("Failed to unsubscribe: {:?}", e),
                                                                        ),
                                                                    }
                                                                }
                                                            });
                                                        },
                                                        "Unsubscribe"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
