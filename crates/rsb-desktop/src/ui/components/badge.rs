use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
pub enum BadgeVariant {
    Primary,
    Success,
    Warning,
    Danger,
    Neutral,
}

#[derive(Clone, Copy, PartialEq)]
pub enum BadgeSize {
    SM,
    MD,
    LG,
}

impl BadgeVariant {
    fn classes(&self) -> &'static str {
        match self {
            BadgeVariant::Primary => {
                "bg-indigo-100 dark:bg-indigo-900/30 text-indigo-800 dark:text-indigo-300"
            }
            BadgeVariant::Success => {
                "bg-emerald-100 dark:bg-emerald-900/30 text-emerald-800 dark:text-emerald-300"
            }
            BadgeVariant::Warning => {
                "bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300"
            }
            BadgeVariant::Danger => "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300",
            BadgeVariant::Neutral => {
                "bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300"
            }
        }
    }
}

impl BadgeSize {
    fn classes(&self) -> &'static str {
        match self {
            BadgeSize::SM => "px-2 py-1 text-xs",
            BadgeSize::MD => "px-3 py-1.5 text-sm",
            BadgeSize::LG => "px-4 py-2 text-base",
        }
    }
}

#[component]
pub fn Badge(
    #[props(default = BadgeVariant::Primary)] variant: BadgeVariant,
    #[props(default = BadgeSize::MD)] size: BadgeSize,
    children: Element,
) -> Element {
    let variant_classes = variant.classes();
    let size_classes = size.classes();
    let rounded = "rounded-full"; // Full border-radius
    let font_weight = "font-semibold";

    let final_class = format!(
        "{} {} {} {}",
        variant_classes, size_classes, rounded, font_weight
    );

    rsx! {
        span { class: "{final_class}",
            {children}
        }
    }
}
