use dioxus::prelude::*;

#[component]
pub fn Fido2ManagerView() -> Element {
    rsx! {
        div { class: "p-4 bg-white rounded-lg shadow-sm border border-gray-200",
            h2 { class: "text-lg font-bold text-gray-800", "🛡️ FIDO2 Manager (compact)" }
            p { class: "text-sm text-gray-600 mt-2", "This is a temporary compact placeholder view. Full FIDO2 manager UI will be restored later." }
        }
    }
}
