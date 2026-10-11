use dioxus::prelude::*;

#[component]
pub fn EmptyState(
    icon: String,
    title: String,
    description: String,
    action_label: Option<String>,
    on_action: Option<EventHandler<MouseEvent>>,
) -> Element {
    rsx! {
        div { class: "flex flex-col items-center justify-center gap-3 py-6 px-3",
            // Icon
            div { class: "text-4xl",
                "{icon}"
            }

            // Title
            h2 { class: "text-xl font-semibold text-slate-900 dark:text-slate-100 text-center",
                "{title}"
            }

            // Description
            p { class: "text-sm text-slate-600 dark:text-slate-400 text-center max-w-md",
                "{description}"
            }

            // Action Button (optional)
            if let Some(label) = action_label {
                if let Some(handler) = on_action {
                    button {
                        class: "mt-3 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-md transition-all duration-150 ease-in-out",
                        onclick: handler,
                        "{label}"
                    }
                }
            }
        }
    }
}
