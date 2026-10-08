use dioxus::prelude::*;
use crate::ui::{app::AppConfig, i18n::get_texts};
use rsb_sdk::snapshot::repository::SnapshotRepository;
use rsb_sdk::snapshot::snapshot::Snapshot;

#[component]
pub fn SnapshotListScreen() -> Element {
    let app_config = use_context::<AppConfig>();
    let texts = get_texts(app_config.language());
    let mut snapshots = use_signal(Vec::<Snapshot>::new);
    let mut is_loading = use_signal(|| false);

    let load_snapshots = move |_| {
        is_loading.set(true);
        spawn(async move {
             if let Some(mut base) = dirs::home_dir() {
                base.push(".rsb");
                let repo = SnapshotRepository::new(base);
                if let Ok(list) = repo.list() {
                    snapshots.set(list);
                }
            }
            is_loading.set(false);
        });
    };

    use_effect(move || {
        load_snapshots(());
    });

    rsx! {
        div { class: "card",
            div { class: "flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-4",
                h2 { class: "text-xl font-bold text-slate-900 dark:text-white", "📸 {texts.nav_snapshots}" }
                button {
                    class: "btn-secondary py-1.5 px-3 flex items-center gap-1 text-sm",
                    onclick: load_snapshots,
                    disabled: is_loading(),
                    if is_loading() { "⏳ ..." } else { "🔄 Refresh" }
                }
            }

            if snapshots.read().is_empty() {
                div { class: "text-center py-6 bg-slate-50 dark:bg-slate-800/50 rounded-lg border-2 border-dashed border-slate-200 dark:border-slate-700",
                    span { class: "text-xl mb-2 block", "📂" }
                    p { class: "text-slate-500 dark:text-slate-400", "{texts.no_snapshots_found}" }
                }
            } else {
                div { class: "overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700",
                    table { class: "w-full text-sm text-left",
                        thead { class: "text-[10px] text-slate-700 dark:text-slate-300 uppercase bg-slate-100 dark:bg-slate-800",
                            tr {
                                th { class: "px-3 py-2", "{texts.snapshot_id_col}" }
                                th { class: "px-3 py-2", "{texts.snapshot_date_col}" }
                                th { class: "px-3 py-2", "{texts.snapshot_host_col}" }
                                th { class: "px-3 py-2", "{texts.snapshot_files_col}" }
                                th { class: "px-3 py-2 text-right", "{texts.snapshot_size_col}" }
                            }
                        }
                        tbody { class: "divide-y divide-slate-200 dark:divide-slate-700",
                            for s in snapshots.read().iter() {
                                tr { class: "bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors",
                                    td { class: "px-3 py-2 font-mono text-indigo-600 dark:text-indigo-400", "{s.id}" }
                                    td { class: "px-3 py-2 text-slate-600 dark:text-slate-400", "{s.created_at.format(\"%Y-%m-%d %H:%M:%S\")}" }
                                    td { class: "px-3 py-2 text-slate-600 dark:text-slate-400", "{s.hostname}" }
                                    td { class: "px-3 py-2 text-slate-600 dark:text-slate-400", "{s.files_count}" }
                                    td { class: "px-3 py-2 text-right font-medium text-slate-900 dark:text-white", "{human_bytes(s.total_size)}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn human_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;

    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}