use dioxus::prelude::*;

#[component]
pub fn ErrorState(
    title: String,
    description: String,
    details: Option<String>,
    retry_label: Option<String>,
    on_retry: Option<EventHandler<MouseEvent>>,
    dismiss_label: Option<String>,
    on_dismiss: Option<EventHandler<MouseEvent>>,
) -> Element {
    rsx! {
        div { class: "flex flex-col gap-3 p-4 bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 rounded-r-lg",
            // Header
            div { class: "flex items-start gap-2",
                span { class: "text-xl flex-shrink-0", "❌" }
                div { class: "flex-1",
                    h3 { class: "text-base font-bold text-red-900 dark:text-red-300",
                        "{title}"
                    }
                    p { class: "text-sm text-red-800 dark:text-red-400 mt-1",
                        "{description}"
                    }
                }
            }

            // Details (optional)
            if let Some(detail) = details {
                div { class: "p-3 bg-red-100/50 dark:bg-red-900/30 rounded border border-red-200 dark:border-red-800",
                    p { class: "text-xs text-red-900 dark:text-red-300 font-mono",
                        "{detail}"
                    }
                }
            }

            // Actions
            div { class: "flex items-center gap-3 pt-2",
                if let Some(label) = retry_label {
                    if let Some(handler) = on_retry {
                        button {
                            class: "px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm font-semibold rounded-md transition-all duration-150 ease-in-out",
                            onclick: handler,
                            "{label}"
                        }
                    }
                }

                if let Some(label) = dismiss_label {
                    if let Some(handler) = on_dismiss {
                        button {
                            class: "px-3 py-1.5 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-slate-100 text-sm font-semibold rounded-md transition-all duration-150 ease-in-out",
                            onclick: handler,
                            "{label}"
                        }
                    }
                }
            }
        }
    }
}
