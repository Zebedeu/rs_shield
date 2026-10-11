use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
pub enum InputVariant {
    Text,
    Email,
    Password,
    Number,
    Textarea,
}

#[derive(Clone, Copy, PartialEq)]
pub enum InputState {
    Default,
    Filled,
    Error,
    Success,
    Disabled,
    Loading,
}

#[component]
pub fn Input(
    #[props(default = InputVariant::Text)] variant: InputVariant,
    #[props(default = InputState::Default)] state: InputState,
    #[props(default = "".to_string())] placeholder: String,
    #[props(default = "".to_string())] value: String,
    #[props(default = "".to_string())] label: String,
    #[props(default = "".to_string())] helper_text: String,
    #[props(default = false)] disabled: bool,
    #[props(default = None)] oninput: Option<EventHandler<FormEvent>>,
    #[props(default = "".to_string())] class: String,
) -> Element {
    let border_color = match state {
        InputState::Error => {
            "border-red-500 focus:border-red-600 focus:ring-red-100 dark:focus:ring-red-900/30"
        }
        InputState::Success => {
            "border-emerald-500 focus:border-emerald-600 focus:ring-emerald-100 dark:focus:ring-emerald-900/30"
        }
        InputState::Disabled => "border-slate-300 dark:border-slate-600",
        _ => {
            "border-slate-300 dark:border-slate-600 focus:border-indigo-500 focus:ring-indigo-100 dark:focus:ring-indigo-900/30"
        }
    };

    let base_input =
        "w-full px-3 py-2 text-sm rounded-md border transition-all duration-150 ease-in-out";
    let dark_bg = "bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100";
    let disabled_class = if disabled {
        "opacity-50 cursor-not-allowed"
    } else {
        ""
    };

    let final_class = format!(
        "{} {} {} {} {}",
        base_input, dark_bg, border_color, disabled_class, class
    );

    let helper_color = match state {
        InputState::Error => "text-red-600 dark:text-red-400",
        InputState::Success => "text-emerald-600 dark:text-emerald-400",
        _ => "text-slate-500 dark:text-slate-400",
    };

    rsx! {
        div { class: "flex flex-col gap-1.5",
            if !label.is_empty() {
                label { class: "text-sm font-semibold text-slate-700 dark:text-slate-300",
                    "{label}"
                }
            }

            match variant {
                InputVariant::Textarea => {
                    rsx! {
                        textarea {
                            class: "{final_class} min-h-24 resize-vertical font-mono text-sm",
                            placeholder: "{placeholder}",
                            value: "{value}",
                            disabled: disabled,
                            oninput: oninput.unwrap_or_else(|| EventHandler::new(|_| {})),
                        }
                    }
                }
                _ => {
                    let input_type = match variant {
                        InputVariant::Email => "email",
                        InputVariant::Password => "password",
                        InputVariant::Number => "number",
                        _ => "text",
                    };

                    rsx! {
                        input {
                            class: "{final_class}",
                            r#type: "{input_type}",
                            placeholder: "{placeholder}",
                            value: "{value}",
                            disabled: disabled,
                            oninput: oninput.unwrap_or_else(|| EventHandler::new(|_| {})),
                        }
                    }
                }
            }

            if !helper_text.is_empty() {
                p { class: "text-xs {helper_color}",
                    "{helper_text}"
                }
            }
        }
    }
}
