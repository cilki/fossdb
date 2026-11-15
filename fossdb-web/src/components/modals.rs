//! Sign-in and sign-up dialogs.
//!
//! Authentication is a single random account id with no password, no email
//! and no recovery. That makes registration unusual: the server mints the
//! credential and discloses it exactly once, so the register dialog is
//! mostly a hand-off screen whose job is to make sure the user actually
//! saves it before closing.

use crate::api::ApiClient;
use crate::hooks::{use_auth, use_notifications};
use dioxus::prelude::*;

/// Copy text to the clipboard, returning whether the call was dispatched.
///
/// The async clipboard API is unavailable on insecure origins and in some
/// embedded webviews, so callers must tolerate failure rather than assume
/// the copy happened.
fn copy_to_clipboard(text: &str) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };

    let clipboard = window.navigator().clipboard();
    let _promise = clipboard.write_text(text);
    true
}

#[component]
pub fn LoginModal(show: Signal<bool>) -> Element {
    let mut input = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut submitting = use_signal(|| false);
    let auth = use_auth();
    let notif = use_notifications();

    let mut reset = move || {
        input.set(String::new());
        error.set(None);
        submitting.set(false);
    };

    let handle_submit = move |evt: Event<FormData>| {
        evt.prevent_default();

        if submitting() {
            return;
        }

        // Normalise before validating so a pasted id with stray whitespace,
        // case or dashes is accepted rather than rejected on cosmetics.
        let candidate = fossdb::user_id::normalize(&input());

        if !fossdb::user_id::is_well_formed(&candidate) {
            error.set(Some(
                "That does not look like an account ID. They start with \"fdb_\" \
                 followed by 26 characters."
                    .to_string(),
            ));
            return;
        }

        let mut auth_copy = auth;
        let mut notif_copy = notif;
        submitting.set(true);
        error.set(None);

        spawn(async move {
            let client = ApiClient::new();
            match client.login(candidate.clone()).await {
                Ok(response) => {
                    auth_copy.login(candidate, response.user);
                    notif_copy.success("Signed in".to_string());
                    show.set(false);
                    reset();
                }
                Err(e) => {
                    submitting.set(false);
                    // A 401 here means the id is wrong or the account was
                    // reaped for having no subscriptions; say both.
                    let message = e.as_string().unwrap_or_default();
                    error.set(Some(if message.contains("401") {
                        "No account with that ID. Check it for typos - and note that \
                         accounts with no subscriptions are deleted automatically."
                            .to_string()
                    } else if message.is_empty() {
                        "Sign-in failed.".to_string()
                    } else {
                        message
                    }));
                }
            }
        });
    };

    if !show() {
        return rsx! { div {} };
    }

    rsx! {
        div {
            class: "fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4",
            onclick: move |_| {
                show.set(false);
                reset();
            },
            div {
                class: "bg-gray-800 rounded-2xl w-full max-w-md shadow-2xl border border-gray-700",
                onclick: move |evt| evt.stop_propagation(),
                div { class: "p-8",
                    h3 { class: "text-2xl font-bold text-gray-100 mb-2 text-center", "Sign in" }
                    p { class: "text-sm text-gray-400 mb-6 text-center",
                        "Paste the account ID you were given when you signed up."
                    }

                    form { onsubmit: handle_submit,
                        div { class: "mb-4",
                            label { class: "block text-sm font-medium text-gray-300 mb-2",
                                "Account ID"
                            }
                            input {
                                class: "w-full px-4 py-3 bg-gray-900 border border-gray-600 rounded-lg text-gray-100 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500",
                                r#type: "text",
                                placeholder: "fdb_...",
                                autocomplete: "off",
                                spellcheck: "false",
                                value: "{input}",
                                oninput: move |evt| {
                                    input.set(evt.value());
                                    error.set(None);
                                },
                            }
                        }

                        if let Some(message) = error() {
                            div { class: "mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg",
                                p { class: "text-sm text-red-300", "{message}" }
                            }
                        }

                        button {
                            class: "w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() { "Signing in..." } else { "Sign in" }
                        }
                    }

                    p { class: "mt-6 text-xs text-gray-500 text-center",
                        "Your account ID is also your password. There is no email address \
                         and no way to recover it."
                    }
                }
            }
        }
    }
}

#[component]
pub fn RegisterModal(show: Signal<bool>) -> Element {
    // `Some` once the server has minted an id: the dialog switches from a
    // confirmation prompt to a hand-off screen.
    let mut issued = use_signal(|| None::<fossdb::RegisterResponse>);
    let mut error = use_signal(|| None::<String>);
    let mut submitting = use_signal(|| false);
    let mut acknowledged = use_signal(|| false);
    let mut copied = use_signal(|| false);

    let auth = use_auth();
    let notif = use_notifications();

    let mut reset = move || {
        issued.set(None);
        error.set(None);
        submitting.set(false);
        acknowledged.set(false);
        copied.set(false);
    };

    let create = move |_| {
        if submitting() {
            return;
        }
        submitting.set(true);
        error.set(None);

        spawn(async move {
            let client = ApiClient::new();
            match client.register().await {
                Ok(response) => {
                    submitting.set(false);
                    issued.set(Some(response));
                }
                Err(e) => {
                    submitting.set(false);
                    error.set(Some(
                        e.as_string()
                            .unwrap_or_else(|| "Could not create an account.".to_string()),
                    ));
                }
            }
        });
    };

    // Only runs once the user has ticked the acknowledgement, so we never
    // close the one screen that shows the credential without consent.
    let finish = move |_| {
        let Some(registered) = issued() else {
            return;
        };

        let mut auth_copy = auth;
        let mut notif_copy = notif;
        let user_id = registered.user_id.clone();

        spawn(async move {
            let client = ApiClient::new();

            // Fetch the account view so the UI has the same shape it would
            // after a normal sign-in.
            let user = match client.login(user_id.clone()).await {
                Ok(response) => response.user,
                Err(_) => fossdb::UserResponse {
                    created_at: registered.created_at.to_rfc3339(),
                    subscription_count: 0,
                    notifications_enabled: true,
                },
            };

            auth_copy.login(user_id, user);
            notif_copy.success("Account created".to_string());
            show.set(false);
            reset();
        });
    };

    if !show() {
        return rsx! { div {} };
    }

    rsx! {
        div {
            class: "fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4",
            // Deliberately no click-outside dismissal once an id has been
            // issued: closing here would lose the credential for good.
            onclick: move |_| {
                if issued().is_none() {
                    show.set(false);
                    reset();
                }
            },
            div {
                class: "bg-gray-800 rounded-2xl w-full max-w-lg shadow-2xl border border-gray-700",
                onclick: move |evt| evt.stop_propagation(),
                div { class: "p-8",

                    if let Some(registered) = issued() {
                        h3 { class: "text-2xl font-bold text-gray-100 mb-2 text-center",
                            "Save your account ID"
                        }
                        p { class: "text-sm text-gray-400 mb-6 text-center",
                            "This is the only time it will be shown."
                        }

                        div { class: "mb-4 p-4 bg-gray-900 border border-gray-600 rounded-lg",
                            code { class: "block text-center text-lg text-blue-300 font-mono break-all select-all",
                                "{registered.user_id}"
                            }
                        }

                        button {
                            class: "w-full mb-5 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm font-medium rounded-lg transition",
                            r#type: "button",
                            onclick: move |_| {
                                if let Some(r) = issued() {
                                    if copy_to_clipboard(&r.user_id) {
                                        copied.set(true);
                                    }
                                }
                            },
                            if copied() { "Copied" } else { "Copy to clipboard" }
                        }

                        div { class: "mb-5 p-4 bg-amber-900/30 border border-amber-700 rounded-lg",
                            p { class: "text-sm text-amber-200 font-semibold mb-2",
                                "There is no account recovery."
                            }
                            ul { class: "text-xs text-amber-200/90 space-y-1 list-disc list-inside",
                                li { "This ID is your username and your password combined." }
                                li { "We hold no email address, so it cannot be reset." }
                                li { "It also appears in your feed URLs - anyone with one of
                                      those URLs can use your account." }
                                li { "Accounts with no subscriptions are deleted automatically,
                                      so subscribe to something to keep this one." }
                            }
                        }

                        label { class: "flex items-start gap-3 mb-5 cursor-pointer",
                            input {
                                class: "mt-1",
                                r#type: "checkbox",
                                checked: acknowledged(),
                                onchange: move |evt| acknowledged.set(evt.checked()),
                            }
                            span { class: "text-sm text-gray-300",
                                "I have saved my account ID somewhere safe."
                            }
                        }

                        button {
                            class: "w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition",
                            r#type: "button",
                            disabled: !acknowledged(),
                            onclick: finish,
                            "Continue"
                        }
                    } else {
                        h3 { class: "text-2xl font-bold text-gray-100 mb-2 text-center",
                            "Create an account"
                        }
                        p { class: "text-sm text-gray-400 mb-6 text-center",
                            "No email address and no password. We generate a single random \
                             ID that is your entire account."
                        }

                        div { class: "mb-6 p-4 bg-gray-900/60 border border-gray-700 rounded-lg",
                            ul { class: "text-xs text-gray-400 space-y-1 list-disc list-inside",
                                li { "You will be shown your ID once, and only once." }
                                li { "Store it like a password - it cannot be recovered." }
                                li { "Subscribe to at least one package, or the account is
                                      deleted automatically." }
                            }
                        }

                        if let Some(message) = error() {
                            div { class: "mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg",
                                p { class: "text-sm text-red-300", "{message}" }
                            }
                        }

                        button {
                            class: "w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition",
                            r#type: "button",
                            disabled: submitting(),
                            onclick: create,
                            if submitting() { "Creating..." } else { "Create account" }
                        }
                    }
                }
            }
        }
    }
}
