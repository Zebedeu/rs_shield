use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonVariant {
    Primary,
    Secondary,
    Success,
    Warning,
    Danger,
    Ghost,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonSize {
    XS,
    SM,
    MD,
    LG,
    XL,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonState {
    Default,
    Hover,
    Active,
    Disabled,
    Loading,
}

impl ButtonVariant {
    fn base_classes(&self) -> &'static str {
        match self {
            ButtonVariant::Primary => {
                "bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 dark:bg-indigo-500 dark:hover:bg-indigo-600 text-white"
            }
            ButtonVariant::Secondary => {
                "bg-slate-200 hover:bg-slate-300 active:bg-slate-400 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-900 dark:text-slate-100"
            }
            ButtonVariant::Success => {
                "bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 dark:bg-emerald-500 dark:hover:bg-emerald-600 text-white"
            }
            ButtonVariant::Warning => {
                "bg-amber-600 hover:bg-amber-700 active:bg-amber-800 dark:bg-amber-500 dark:hover:bg-amber-600 text-white"
            }
            ButtonVariant::Danger => {
                "bg-red-600 hover:bg-red-700 active:bg-red-800 dark:bg-red-500 dark:hover:bg-red-600 text-white"
            }
            ButtonVariant::Ghost => {
                "bg-transparent hover:bg-slate-100 active:bg-slate-200 dark:hover:bg-slate-800 dark:active:bg-slate-700 text-indigo-600 dark:text-indigo-400"
            }
        }
    }
}

impl ButtonSize {
    fn padding_classes(&self) -> &'static str {
        match self {
            ButtonSize::XS => "px-2 py-1 text-xs",
            ButtonSize::SM => "px-2.5 py-1.5 text-sm",
            ButtonSize::MD => "px-3 py-1.5 text-sm",
            ButtonSize::LG => "px-4 py-2 text-sm",
            ButtonSize::XL => "px-4 py-2.5 text-base",
        }
    }
}

#[component]
pub fn Button(
    #[props(default = ButtonVariant::Primary)] variant: ButtonVariant,
    #[props(default = ButtonSize::MD)] size: ButtonSize,
    #[props(default = false)] disabled: bool,
    #[props(default = false)] loading: bool,
    #[props(default = "".to_string())] class: String,
    children: Element,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    let base = variant.base_classes();
    let padding = size.padding_classes();
    let disabled_class = if disabled || loading {
        "opacity-50 cursor-not-allowed"
    } else {
        "cursor-pointer"
    };
    let transition = "transition-all duration-150 ease-in-out";
    let rounded = "rounded-md"; // MD border-radius (8px)
    let font_weight = "font-medium";
    let flex = "inline-flex items-center justify-center gap-2";

    let final_class = format!(
        "{} {} {} {} {} {} {} {}",
        base, padding, disabled_class, transition, rounded, font_weight, flex, class
    );

    rsx! {
        button {
            class: "{final_class}",
            disabled: disabled || loading,
            onclick: onclick,
            if loading {
                span { class: "inline-block animate-spin", "⟳" }
            }
            {children}
        }
    }
}
