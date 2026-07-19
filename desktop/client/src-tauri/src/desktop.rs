use crate::config::{build_node_config_with_base, default_config_string};
use crate::pinger::{probe_nodes, targets_for_nodes};
use crate::preferences::{load_preferences, save_preferences, update_setting, Preferences};
use crate::process::{CommandSpec, ProcessManager};
use crate::subscription::{
    refresh_with, RefreshResult, SubscriptionDocument, SubscriptionNode, MAX_SUBSCRIPTION_BYTES,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use url::Url;

pub struct DesktopState {
    data_dir: PathBuf,
    preferences: Mutex<Preferences>,
    subscription: Mutex<Option<StoredSubscription>>,
    process: Mutex<ProcessManager>,
}

struct StoredSubscription {
    document: SubscriptionDocument,
    fetched_at_ms: u64,
    cached: bool,
}

impl From<RefreshResult> for StoredSubscription {
    fn from(result: RefreshResult) -> Self {
        Self {
            document: result.document,
            fetched_at_ms: result.fetched_at_ms,
            cached: result.cached,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapPayload {
    subscription: Option<SubscriptionPayload>,
    config: String,
    settings: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionPayload {
    url: String,
    name: String,
    updated_at: Option<String>,
    last_synced_at: u64,
    cached: bool,
    cache_age_minutes: u64,
    nodes: Vec<NodePayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodePayload {
    id: String,
    name: String,
    subtitle: String,
    address: String,
    latency_ms: Option<u32>,
    favorite: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectPayload {
    pid: u32,
    network: Value,
}

impl DesktopState {
    fn new(app: &AppHandle) -> Result<Self, String> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|error| error.to_string())?;
        fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
        let preferences = load_preferences(&data_dir.join("preferences.json"))
            .map_err(|error| error.to_string())?;
        let cached = if preferences.subscription_url.is_empty() {
            None
        } else {
            refresh_with(
                &preferences.subscription_url,
                &data_dir.join("subscription-cache.json"),
                |_| Err("startup".into()),
            )
            .ok()
        };
        let subscription = cached.map(StoredSubscription::from);
        let emitter = app.clone();
        let process = ProcessManager::new(move |event| {
            let _ = emitter.emit("client://process", event);
        });
        Ok(Self {
            data_dir,
            preferences: Mutex::new(preferences),
            subscription: Mutex::new(subscription),
            process: Mutex::new(process),
        })
    }

    fn save_preferences(&self, preferences: &Preferences) -> Result<(), String> {
        save_preferences(&self.data_dir.join("preferences.json"), preferences)
            .map_err(|error| error.to_string())
    }
}

#[tauri::command]
fn client_bootstrap(state: State<'_, DesktopState>) -> Result<BootstrapPayload, String> {
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let subscription = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .map(|stored| {
            subscription_payload(
                &stored.document,
                &preferences,
                stored.fetched_at_ms,
                stored.cached,
            )
        });
    Ok(BootstrapPayload {
        subscription,
        config: if preferences.raw_config.is_empty() {
            default_config_string().into()
        } else {
            preferences.raw_config.clone()
        },
        settings: json!({
            "autostart": preferences.settings.autostart,
            "closeToTray": preferences.settings.close_to_tray,
            "disconnectOnExit": preferences.settings.disconnect_on_exit,
            "language": preferences.settings.language,
            "appearance": preferences.settings.appearance,
            "pppPath": preferences.ppp_path,
        }),
    })
}

#[tauri::command]
async fn subscription_refresh(
    url: String,
    state: State<'_, DesktopState>,
) -> Result<SubscriptionPayload, String> {
    let parsed = Url::parse(&url).map_err(|_| "订阅地址无效".to_string())?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("订阅地址只支持 HTTP/HTTPS".into());
    }
    let cache_path = state.data_dir.join("subscription-cache.json");
    let fetch_url = url.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("OpenPPP2/Desktop")
            .build()
            .map_err(|error| error.to_string())?;
        refresh_with(&fetch_url, &cache_path, |target| {
            let mut response = client
                .get(target)
                .header("Accept", "application/json")
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .map_err(|error| error.to_string())?;
            let mut body = Vec::new();
            response
                .by_ref()
                .take((MAX_SUBSCRIPTION_BYTES + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|error| error.to_string())?;
            Ok(body)
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())??;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    preferences.subscription_url = url;
    state.save_preferences(&preferences)?;
    let payload = subscription_payload(
        &result.document,
        &preferences,
        result.fetched_at_ms,
        result.cached,
    );
    *state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())? = Some(StoredSubscription::from(result));
    Ok(payload)
}

#[tauri::command]
async fn client_probe_latency(
    node_ids: Option<Vec<String>>,
    state: State<'_, DesktopState>,
    app: AppHandle,
) -> Result<BTreeMap<String, Option<u32>>, String> {
    let nodes = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .map(|stored| stored.document.nodes.clone())
        .unwrap_or_default();
    let targets = targets_for_nodes(&nodes, node_ids.as_deref());
    let latencies = tauri::async_runtime::spawn_blocking(move || {
        probe_nodes(targets, 4, Duration::from_secs(3)).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())??;
    let _ = app.emit("client://latency", &latencies);
    Ok(latencies)
}

#[tauri::command]
fn client_connect(
    node_id: String,
    state: State<'_, DesktopState>,
) -> Result<ConnectPayload, String> {
    let node = state
        .subscription
        .lock()
        .map_err(|_| "订阅状态锁已损坏".to_string())?
        .as_ref()
        .and_then(|stored| stored.document.nodes.iter().find(|node| node.id == node_id))
        .cloned()
        .ok_or_else(|| "找不到所选节点，请先刷新订阅".to_string())?;
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?
        .clone();
    let config = build_node_config_with_base(&node, Some(&preferences.raw_config))
        .map_err(|error| error.to_string())?;
    let runtime_dir = state.data_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).map_err(|error| error.to_string())?;
    let config_path = runtime_dir.join("appsettings.json");
    write_atomic(
        &config_path,
        &serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?,
    )?;
    let stats_path = runtime_dir.join("stats.ndjson");
    let executable = resolve_ppp_path(&preferences.ppp_path)?;
    let mut spec = CommandSpec::new(
        executable,
        [
            "--mode=client".to_string(),
            format!("--config={}", config_path.display()),
            format!("--stats-json={}", stats_path.display()),
        ],
    );
    append_option_args(&node, &mut spec.args);
    spec.stats_path = Some(stats_path);
    let pid = state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .start(spec)
        .map_err(|error| error.to_string())?;
    Ok(ConnectPayload {
        pid,
        network: network_payload(&node, &config),
    })
}

#[tauri::command]
fn client_disconnect(state: State<'_, DesktopState>) -> Result<(), String> {
    state
        .process
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?
        .stop()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn client_update_config(config: String, state: State<'_, DesktopState>) -> Result<(), String> {
    let value: Value = serde_json::from_str(&config).map_err(|error| error.to_string())?;
    if !value.is_object() {
        return Err("配置根节点必须是 JSON object".into());
    }
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    preferences.raw_config =
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;
    state.save_preferences(&preferences)
}

#[tauri::command]
fn client_update_setting(
    key: String,
    value: Value,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    update_setting(&mut preferences, &key, value).map_err(|error| error.to_string())?;
    state.save_preferences(&preferences)
}

#[tauri::command]
fn client_toggle_favorite(node_id: String, state: State<'_, DesktopState>) -> Result<(), String> {
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "设置状态锁已损坏".to_string())?;
    if !preferences.favorites.remove(&node_id) {
        preferences.favorites.insert(node_id);
    }
    state.save_preferences(&preferences)
}

fn subscription_payload(
    document: &SubscriptionDocument,
    preferences: &Preferences,
    fetched_at_ms: u64,
    cached: bool,
) -> SubscriptionPayload {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    SubscriptionPayload {
        url: preferences.subscription_url.clone(),
        name: document
            .name
            .clone()
            .unwrap_or_else(|| "OPENPPP2 Subscription".into()),
        updated_at: document.updated_at.clone(),
        last_synced_at: fetched_at_ms,
        cached,
        cache_age_minutes: if fetched_at_ms == 0 {
            0
        } else {
            now.saturating_sub(fetched_at_ms) / 60_000
        },
        nodes: document
            .nodes
            .iter()
            .map(|node| NodePayload {
                id: node.id.clone(),
                name: node.name.clone(),
                subtitle: node.subtitle.clone(),
                address: display_address(node.server.as_deref().unwrap_or_default()),
                latency_ms: None,
                favorite: preferences.favorites.contains(&node.id),
            })
            .collect(),
    }
}

fn display_address(server: &str) -> String {
    let body = server.strip_prefix("ppp://").unwrap_or(server);
    let body = body
        .strip_prefix("ws/")
        .or_else(|| body.strip_prefix("wss/"))
        .unwrap_or(body);
    body.split('/').next().unwrap_or(body).to_owned()
}

fn append_option_args(node: &SubscriptionNode, args: &mut Vec<String>) {
    let Some(options) = node.options.as_ref().and_then(Value::as_object) else {
        return;
    };
    for (field, flag) in [
        ("tunIp", "--tun-ip"),
        ("gateway", "--tun-gw"),
        ("tunMask", "--tun-mask"),
    ] {
        if let Some(value) = options
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            args.push(format!("{flag}={value}"));
        }
    }
}

fn network_payload(node: &SubscriptionNode, config: &Value) -> Value {
    let options = node.options.as_ref().and_then(Value::as_object);
    let client = config.get("client");
    let proxy = |name: &str| {
        client
            .and_then(|value| value.get(name))
            .and_then(Value::as_object)
            .map(|value| {
                format!(
                    "{}:{}",
                    value
                        .get("bind")
                        .and_then(Value::as_str)
                        .unwrap_or("127.0.0.1"),
                    value.get("port").and_then(Value::as_u64).unwrap_or(0)
                )
            })
            .filter(|value| !value.ends_with(":0"))
            .unwrap_or_default()
    };
    json!({
        "tunIp": options.and_then(|value| value.get("tunIp")).and_then(Value::as_str).unwrap_or(""),
        "gateway": options.and_then(|value| value.get("gateway")).and_then(Value::as_str).unwrap_or(""),
        "httpProxy": proxy("http-proxy"), "socksProxy": proxy("socks-proxy"),
    })
}

fn resolve_ppp_path(configured: &str) -> Result<PathBuf, String> {
    let path = if configured.trim().is_empty() {
        let name = if cfg!(windows) { "ppp.exe" } else { "ppp" };
        std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .unwrap_or(Path::new("."))
            .join(name)
    } else {
        PathBuf::from(configured)
    };
    if !path.is_file() {
        return Err(format!("找不到 ppp 可执行文件: {}", path.display()));
    }
    Ok(path)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(DesktopState::new(&app.handle())?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            client_bootstrap,
            subscription_refresh,
            client_probe_latency,
            client_connect,
            client_disconnect,
            client_update_config,
            client_update_setting,
            client_toggle_favorite,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run OpenPPP2 Client");
}

#[cfg(test)]
mod tests {
    use super::StoredSubscription;
    use crate::subscription::{parse_subscription, RefreshResult};

    #[test]
    fn stored_subscription_keeps_cache_metadata() {
        let document = parse_subscription(br#"{"type":"openppp2-subscription","version":1,"nodes":[{"id":"n","name":"N","server":"ppp://127.0.0.1:1/","key":{"protocol-key":"p"}}]}"#).unwrap();
        let stored = StoredSubscription::from(RefreshResult {
            document,
            cached: true,
            fetched_at_ms: 42,
        });
        assert!(stored.cached);
        assert_eq!(stored.fetched_at_ms, 42);
    }
}
