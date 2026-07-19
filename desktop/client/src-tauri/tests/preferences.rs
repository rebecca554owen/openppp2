use openppp2_client_desktop::preferences::{
    load_preferences, save_preferences, update_setting, Preferences,
};
use serde_json::json;

#[test]
fn preferences_round_trip_without_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preferences.json");
    let mut preferences = Preferences::default();
    preferences.subscription_url = "https://sub.test/token".into();
    preferences.ppp_path = "C:\\ppp.exe".into();
    preferences.favorites.insert("node-1".into());
    update_setting(&mut preferences, "closeToTray", json!(false)).unwrap();
    save_preferences(&path, &preferences).unwrap();

    let loaded = load_preferences(&path).unwrap();
    assert_eq!(loaded.subscription_url, "https://sub.test/token");
    assert_eq!(loaded.ppp_path, "C:\\ppp.exe");
    assert!(loaded.favorites.contains("node-1"));
    assert!(!loaded.settings.close_to_tray);
    assert!(update_setting(&mut preferences, "invented", json!(true)).is_err());
}

#[test]
fn missing_preferences_use_safe_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = load_preferences(&dir.path().join("missing.json")).unwrap();
    assert!(loaded.subscription_url.is_empty());
    assert!(loaded.ppp_path.is_empty());
    assert!(loaded.settings.close_to_tray);
    assert!(loaded.settings.disconnect_on_exit);
}
