// Component showcase/demo screen
// Used to validate Design System components
use crate::ui::components::*;
use dioxus::prelude::*;

#[component]
pub fn ComponentShowcase() -> Element {
    let mut text_value = use_signal(String::new);
    let mut demo_loading = use_signal(|| false);

    rsx! {
        div { class: "flex flex-col gap-8 p-6 bg-slate-50 dark:bg-slate-900 min-h-screen",
            // Header
            div { class: "space-y-2",
                h1 { class: "text-3xl font-bold text-slate-900 dark:text-white", "🎨 Design System Components" }
                p { class: "text-lg text-slate-600 dark:text-slate-400", "All components following DESIGN_SYSTEM.md" }
            }

            // BUTTONS
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Buttons" }

                div { class: "grid grid-cols-1 md:grid-cols-2 gap-3",
                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-3",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Variants" }
                            div { class: "flex gap-2 flex-wrap",
                                Button { variant: ButtonVariant::Primary, onclick: |_| {}, "Primary" }
                                Button { variant: ButtonVariant::Secondary, onclick: |_| {}, "Secondary" }
                                Button { variant: ButtonVariant::Success, onclick: |_| {}, "Success" }
                                Button { variant: ButtonVariant::Warning, onclick: |_| {}, "Warning" }
                                Button { variant: ButtonVariant::Danger, onclick: |_| {}, "Danger" }
                                Button { variant: ButtonVariant::Ghost, onclick: |_| {}, "Ghost" }
                            }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-4",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Sizes" }
                            div { class: "flex gap-2 flex-wrap items-center",
                                Button { variant: ButtonVariant::Primary, size: ButtonSize::XS, onclick: |_| {}, "XS" }
                                Button { variant: ButtonVariant::Primary, size: ButtonSize::SM, onclick: |_| {}, "SM" }
                                Button { variant: ButtonVariant::Primary, size: ButtonSize::MD, onclick: |_| {}, "MD" }
                                Button { variant: ButtonVariant::Primary, size: ButtonSize::LG, onclick: |_| {}, "LG" }
                                Button { variant: ButtonVariant::Primary, size: ButtonSize::XL, onclick: |_| {}, "XL" }
                            }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-4",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "States" }
                            div { class: "flex gap-2 flex-wrap",
                                Button { onclick: |_| {}, "Default" }
                                Button { disabled: true, onclick: |_| {}, "Disabled" }
                                Button { loading: true, onclick: |_| {}, "Loading" }
                            }
                        }
                    }
                }
            }

            // INPUTS
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Inputs" }

                div { class: "grid grid-cols-1 md:grid-cols-2 gap-3",
                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-3",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Text Input" }
                            Input {
                                label: "Email Address".to_string(),
                                placeholder: "you@example.com".to_string(),
                                helper_text: "We'll never share your email".to_string(),
                                oninput: Some(EventHandler::new(move |evt: FormEvent| text_value.set(evt.value()))),
                            }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-4",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Error State" }
                            Input {
                                state: InputState::Error,
                                label: "Password".to_string(),
                                placeholder: "••••••••".to_string(),
                                helper_text: "Password too weak".to_string(),
                                oninput: None,
                            }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-4",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Success State" }
                            Input {
                                state: InputState::Success,
                                label: "Username".to_string(),
                                placeholder: "johndoe".to_string(),
                                helper_text: "Username available".to_string(),
                                oninput: None,
                            }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-4",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Textarea" }
                            Input {
                                variant: InputVariant::Textarea,
                                label: "Description".to_string(),
                                placeholder: "Enter description...".to_string(),
                                helper_text: "Max 500 characters".to_string(),
                                oninput: None,
                            }
                        }
                    }
                }
            }

            // CARDS
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Cards" }

                div { class: "grid grid-cols-1 md:grid-cols-3 gap-3",
                    Card { variant: CardVariant::Elevated,
                        div { class: "space-y-2",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Elevated" }
                            p { class: "text-sm text-slate-600 dark:text-slate-400", "With shadow and border" }
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        div { class: "space-y-2",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Outlined" }
                            p { class: "text-sm text-slate-600 dark:text-slate-400", "With border only" }
                        }
                    }

                    Card { variant: CardVariant::Filled,
                        div { class: "space-y-2",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Filled" }
                            p { class: "text-sm text-slate-600 dark:text-slate-400", "With background color" }
                        }
                    }
                }
            }

            // BADGES
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Badges" }

                Card { variant: CardVariant::Outlined,
                    div { class: "flex gap-3 flex-wrap",
                        Badge { variant: BadgeVariant::Primary, "Primary" }
                        Badge { variant: BadgeVariant::Success, "Success" }
                        Badge { variant: BadgeVariant::Warning, "Warning" }
                        Badge { variant: BadgeVariant::Danger, "Danger" }
                        Badge { variant: BadgeVariant::Neutral, "Neutral" }
                    }
                }
            }

            // EMPTY STATES
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Empty State" }

                Card { variant: CardVariant::Outlined,
                    EmptyState {
                        icon: "📭".to_string(),
                        title: "No backups found".to_string(),
                        description: "Create your first backup to get started".to_string(),
                        action_label: Some("Create Backup".to_string()),
                        on_action: None,
                    }
                }
            }

            // ERROR STATES
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Error State" }

                ErrorState {
                    title: "Backup failed".to_string(),
                    description: "Unable to complete backup operation".to_string(),
                    details: Some("Error: Permission denied on /home/user/documents".to_string()),
                    retry_label: Some("Retry".to_string()),
                    on_retry: None,
                    dismiss_label: Some("Dismiss".to_string()),
                    on_dismiss: None,
                }
            }

            // LOADING STATES
            div { class: "space-y-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "Loading States" }

                div { class: "grid grid-cols-1 md:grid-cols-2 gap-3",
                    Card { variant: CardVariant::Outlined,
                        LoadingState {
                            message: "Creating backup...".to_string(),
                            style: LoadingStyle::Spinner,
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        LoadingState {
                            message: "Processing files...".to_string(),
                            style: LoadingStyle::ProgressBar,
                            progress: 0.65,
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        LoadingState {
                            message: "Uploading to cloud...".to_string(),
                            style: LoadingStyle::Dots,
                        }
                    }

                    Card { variant: CardVariant::Outlined,
                        LoadingState {
                            message: "Verifying integrity...".to_string(),
                            style: LoadingStyle::Pulse,
                        }
                    }
                }
            }

            // DEMO SECTION
            div { class: "space-y-4",
                h2 { class: "text-lg font-bold text-slate-900 dark:text-white", "Interactive Demo" }

                Card { variant: CardVariant::Elevated,
                    div { class: "space-y-6",
                        div { class: "space-y-2",
                            h3 { class: "font-semibold text-slate-900 dark:text-white", "Demo Form" }
                            p { class: "text-sm text-slate-600 dark:text-slate-400", "Try the interactive components" }
                        }

                        Input {
                            label: "Your name".to_string(),
                            placeholder: "John Doe".to_string(),
                            oninput: None,
                        }

                        Input {
                            variant: InputVariant::Email,
                            label: "Email".to_string(),
                            placeholder: "john@example.com".to_string(),
                            oninput: None,
                        }

                        div { class: "flex gap-2",
                            Button {
                                variant: ButtonVariant::Primary,
                                onclick: move |_| demo_loading.toggle(),
                                "Toggle Loading"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                onclick: |_| {},
                                "Cancel"
                            }
                        }

                        if demo_loading() {
                            LoadingOverlay {
                                is_visible: true,
                                style: LoadingStyle::Spinner,
                                message: "Processing your request...".to_string(),
                            }
                        }
                    }
                }
            }
        }
    }
}
