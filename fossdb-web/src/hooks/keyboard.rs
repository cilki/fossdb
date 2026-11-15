use dioxus::prelude::*;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{KeyboardEvent, window};

#[derive(Clone, Copy, PartialEq)]
pub struct KeyPress {
    pub key: &'static str,
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
}

pub fn use_keyboard_shortcut<F>(shortcut: KeyPress, callback: F)
where
    F: Fn() + 'static + Clone,
{
    // Registered once and removed on unmount; see `use_scroll_direction` for why
    // `Closure::forget` is not acceptable here.
    let listener: Rc<Closure<dyn FnMut(KeyboardEvent)>> = use_hook(move || {
        let closure = Closure::wrap(Box::new(move |event: KeyboardEvent| {
            let matches = event.key() == shortcut.key
                && event.ctrl_key() == shortcut.ctrl
                && event.shift_key() == shortcut.shift
                && event.alt_key() == shortcut.alt;

            if matches {
                event.prevent_default();
                callback();
            }
        }) as Box<dyn FnMut(KeyboardEvent)>);

        if let Some(win) = window() {
            let _ = win
                .add_event_listener_with_callback("keydown", closure.as_ref().unchecked_ref());
        }

        Rc::new(closure)
    });

    use_drop(move || {
        if let Some(win) = window() {
            let _ = win.remove_event_listener_with_callback(
                "keydown",
                listener.as_ref().as_ref().unchecked_ref(),
            );
        }
    });
}
