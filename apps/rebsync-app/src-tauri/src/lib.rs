#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![validate_key])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}

/// Exercise the shared storage boundary on the target platform.
#[tauri::command]
fn validate_key(key: String) -> Result<String, String> {
    rebsync_core::ObjectKey::parse(&key)
        .map(|key| key.as_str().to_owned())
        .map_err(|error| error.to_string())
}
