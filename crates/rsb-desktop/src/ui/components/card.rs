use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
pub enum CardVariant {
    Elevated,
    Outlined,
    Filled,
    Flat,
}

impl CardVariant {
    fn classes(&self) -> &'static str {
        match self {
            CardVariant::Elevated => {
                "bg-white dark:bg-slate-800 shadow-sm border border-slate-100 dark:border-slate-700/50"
            }
            CardVariant::Outlined => {
                "bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700"
            }
            CardVariant::Filled => "bg-slate-50 dark:bg-slate-800/50 border border-transparent",
            CardVariant::Flat => "bg-transparent border border-transparent",
        }
    }
}

#[component]
pub fn Card(
    #[props(default = CardVariant::Elevated)] variant: CardVariant,
    #[props(default = false)] interactive: bool,
    #[props(default = "".to_string())] class: String,
    children: Element,
) -> Element {
    let variant_classes = variant.classes();
    let interactive_class = if interactive {
        "hover:shadow-lg hover:border-indigo-200 dark:hover:border-indigo-800/50 transition-all duration-300 ease-in-out cursor-pointer"
    } else {
        ""
    };
    let rounded = "rounded-md"; // MD border-radius
    let padding = "p-3"; // smaller card padding
    let transition = "transition-all duration-300 ease-in-out";

    let final_class = format!(
        "{} {} {} {} {} {}",
        variant_classes, interactive_class, rounded, padding, transition, class
    );

    rsx! {
        div { class: "{final_class}",
            {children}
        }
    }
}

// Card Header - helper component
#[component]
pub fn CardHeader(
    #[props(default = "".to_string())] title: String,
    #[props(default = "".to_string())] subtitle: String,
    #[props(default = "".to_string())] class: String,
    children: Element,
) -> Element {
    rsx! {
        div { class: "flex flex-col gap-1 {class}",
            if !title.is_empty() {
                h3 { class: "text-base font-semibold text-slate-900 dark:text-slate-100",
                    "{title}"
                }
            }
            if !subtitle.is_empty() {
                p { class: "text-sm text-slate-500 dark:text-slate-400",
                    "{subtitle}"
                }
            }
            {children}
        }
    }
}

// Card Content - helper component
#[component]
pub fn CardContent(#[props(default = "".to_string())] class: String, children: Element) -> Element {
    rsx! {
        div { class: "text-sm text-slate-700 dark:text-slate-300 {class}",
            {children}
        }
    }
}

// Card Footer - helper component
#[component]
pub fn CardFooter(#[props(default = "".to_string())] class: String, children: Element) -> Element {
    rsx! {
        div { class: "flex items-center justify-between gap-4 pt-4 border-t border-slate-200 dark:border-slate-700 {class}",
            {children}
        }
    }
}
