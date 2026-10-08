use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadingStyle {
    Spinner,
    Dots,
    ProgressBar,
    Pulse,
    Shimmer,
}

#[component]
pub fn LoadingState(
    message: String,
    #[props(default = LoadingStyle::Spinner)] style: LoadingStyle,
    #[props(default = 0.0)] progress: f64,
    #[props(default = None)] elapsed_time: Option<String>,
    #[props(default = None)] estimated_time: Option<String>,
) -> Element {
    rsx! {
        div { class: "flex flex-col items-center justify-center gap-4 py-8 px-4",
            // Animation
            match style {
                LoadingStyle::Spinner => {
                    rsx! {
                        div { class: "w-8 h-8 border-3 border-indigo-200 dark:border-indigo-900/30 border-t-indigo-600 dark:border-t-indigo-400 rounded-full animate-spin" }
                    }
                }
                LoadingStyle::Dots => {
                    rsx! {
                        div { class: "flex gap-2",
                            span { class: "w-2 h-2 bg-indigo-600 dark:bg-indigo-400 rounded-full animate-pulse" }
                            span { class: "w-2 h-2 bg-indigo-600 dark:bg-indigo-400 rounded-full animate-pulse animation-delay-200" }
                            span { class: "w-2 h-2 bg-indigo-600 dark:bg-indigo-400 rounded-full animate-pulse animation-delay-400" }
                        }
                    }
                }
                LoadingStyle::ProgressBar => {
                    let width_percent = (progress * 100.0).min(100.0).max(0.0);
                    rsx! {
                        div { class: "w-full max-w-xs h-1 bg-indigo-200 dark:bg-indigo-900/30 rounded-full overflow-hidden",
                            div {
                                class: "h-full bg-gradient-to-r from-indigo-600 to-indigo-400 dark:from-indigo-500 dark:to-indigo-300 transition-all duration-300 ease-out",
                                style: "width: {width_percent}%;"
                            }
                        }
                    }
                }
                LoadingStyle::Pulse => {
                    rsx! {
                        div { class: "w-10 h-10 bg-indigo-600 dark:bg-indigo-400 rounded-lg animate-pulse" }
                    }
                }
                LoadingStyle::Shimmer => {
                    rsx! {
                        div { class: "w-full max-w-xs h-20 bg-gradient-to-r from-slate-200 via-slate-100 to-slate-200 dark:from-slate-700 dark:via-slate-600 dark:to-slate-700 rounded-lg animate-pulse" }
                    }
                }
            }

            // Message
            p { class: "text-sm font-medium text-slate-700 dark:text-slate-300 text-center",
                "{message}"
            }

            // Time info
            if let Some(elapsed) = elapsed_time {
                p { class: "text-xs text-slate-500 dark:text-slate-400",
                    "⏱️ {elapsed}"
                }
            }

            if let Some(estimated) = estimated_time {
                p { class: "text-xs text-slate-500 dark:text-slate-400",
                    "≈ {estimated}"
                }
            }

            // Progress percentage
            if style == LoadingStyle::ProgressBar && progress > 0.0 {
                p { class: "text-xs font-semibold text-indigo-600 dark:text-indigo-400",
                    "{((progress * 100.0) as u32)}%"
                }
            }
        }
    }
}

#[component]
pub fn LoadingOverlay(
    is_visible: bool,
    #[props(default = LoadingStyle::Spinner)] style: LoadingStyle,
    message: String,
    #[props(default = 0.0)] progress: f64,
    #[props(default = None)] elapsed_time: Option<String>,
) -> Element {
    if !is_visible {
        return rsx! {
            div {}
        };
    }

    rsx! {
        div { class: "fixed inset-0 bg-black/20 dark:bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 transition-opacity duration-300 ease-in-out",
            div { class: "bg-white dark:bg-slate-800 rounded-lg shadow-2xl p-6 max-w-sm",
                LoadingState {
                    message: message,
                    style: style,
                    progress: progress,
                    elapsed_time: elapsed_time,
                }
            }
        }
    }
}
