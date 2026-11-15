use dioxus::prelude::*;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{Event, window};

pub fn use_scroll_direction() -> Signal<ScrollDirection> {
    let mut direction = use_signal(|| ScrollDirection::None);
    let mut last_scroll = use_signal(|| 0.0);

    // The closure is kept alive by the hook and the listener is removed when the
    // component unmounts.
    //
    // `Closure::forget` leaked a listener on every mount, and the leaked handler
    // kept reading `direction`/`last_scroll`, which are owned by this
    // component's scope. Reading a signal after its owner is dropped panics, and
    // a panic in WASM aborts the whole application.
    let listener: Rc<Closure<dyn FnMut(Event)>> = use_hook(|| {
        let closure = Closure::wrap(Box::new(move |_: Event| {
            if let Some(w) = window() {
                let current_scroll = w.scroll_y().unwrap_or(0.0);
                let last = last_scroll();

                if current_scroll > last && current_scroll > 100.0 {
                    direction.set(ScrollDirection::Down);
                } else if current_scroll < last {
                    direction.set(ScrollDirection::Up);
                }

                last_scroll.set(current_scroll);
            }
        }) as Box<dyn FnMut(Event)>);

        if let Some(win) = window() {
            let _ = win
                .add_event_listener_with_callback("scroll", closure.as_ref().unchecked_ref());
        }

        Rc::new(closure)
    });

    use_drop(move || {
        if let Some(win) = window() {
            let _ = win
                .remove_event_listener_with_callback("scroll", listener.as_ref().as_ref().unchecked_ref());
        }
    });

    direction
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ScrollDirection {
    Up,
    Down,
    None,
}
