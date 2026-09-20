//! Guards on `tauri.conf.json` and the capability file.
//!
//! Both of these encode a bug that shipped and had to be found by running the
//! app, because nothing in the Rust or TypeScript test suites can see a
//! misconfigured window.

use serde_json::Value;

fn config() -> Value {
    let raw = include_str!("../tauri.conf.json");
    serde_json::from_str(raw).expect("tauri.conf.json should be valid JSON")
}

fn capability() -> Value {
    let raw = include_str!("../capabilities/default.json");
    serde_json::from_str(raw).expect("capabilities/default.json should be valid JSON")
}

fn windows() -> Vec<Value> {
    config()["app"]["windows"]
        .as_array()
        .expect("app.windows should be an array")
        .clone()
}

fn window(label: &str) -> Value {
    windows()
        .into_iter()
        .find(|w| w["label"] == label)
        .unwrap_or_else(|| panic!("no window labelled {label}"))
}

/// The bug: `"url": "popup.html"` 404s under the dev server.
///
/// Vite serves the SvelteKit route at `/popup`; `popup.html` exists only in the
/// built static output. An extension-less URL works in both modes, because
/// Tauri's asset resolver falls back `popup` -> `popup.html` -> `popup/index.html`
/// (see `get_asset` in tauri's manager/mod.rs).
#[test]
fn popup_url_resolves_under_both_the_dev_server_and_embedded_assets() {
    let url = window("popup")["url"]
        .as_str()
        .expect("popup window needs a url")
        .to_string();

    assert!(
        !url.ends_with(".html"),
        "popup url {url:?} is a built-output filename; the dev server serves the \
         route without the extension and will 404"
    );
    assert!(
        !url.starts_with("http"),
        "popup url {url:?} must be relative so it resolves against devUrl in dev \
         and the asset protocol in production"
    );
    assert!(
        !url.contains('.'),
        "popup url {url:?} should be extension-less"
    );
}

/// The bug: a window no capability names gets *no* permissions, so every
/// `invoke` from it is denied — including the ones the popup is built on.
#[test]
fn every_window_is_covered_by_a_capability() {
    let cap = capability();
    let covered: Vec<&str> = cap["windows"]
        .as_array()
        .expect("capability should list windows")
        .iter()
        .filter_map(|w| w.as_str())
        .collect();

    for w in windows() {
        let label = w["label"].as_str().unwrap_or("<unlabelled>");
        assert!(
            covered.contains(&label),
            "window {label:?} is not named by capabilities/default.json, so every \
             invoke from it would be denied at runtime"
        );
    }
}

#[test]
fn the_popup_is_created_hidden_and_stays_on_top() {
    let popup = window("popup");
    // Pre-created and hidden is what keeps the 300 ms budget reachable:
    // creating a window on the shortcut would cost most of it.
    assert_eq!(popup["visible"], Value::Bool(false));
    assert_eq!(popup["alwaysOnTop"], Value::Bool(true));
    assert_eq!(popup["skipTaskbar"], Value::Bool(true));
}

/// The clipboard plugin is used from Rust only. If it ever appears here it
/// means the webview was handed clipboard access, which would let plaintext
/// reach the renderer by a route that bypasses `copy_secret`.
#[test]
fn the_webview_is_not_granted_clipboard_access() {
    let cap = capability();
    let perms = cap["permissions"].as_array().cloned().unwrap_or_default();
    for p in perms {
        let s = p.as_str().unwrap_or_default();
        assert!(
            !s.contains("clipboard"),
            "capability grants {s:?} to the webview; copies are performed in Rust \
             so the renderer must not have clipboard access"
        );
    }
}

#[test]
fn the_csp_allows_no_remote_origins() {
    let csp = config()["app"]["security"]["csp"]
        .as_str()
        .expect("a CSP should be configured")
        .to_string();

    assert!(csp.contains("default-src 'self'"));
    for scheme in ["https://", "http://localhost", "*"] {
        if scheme == "http://localhost" {
            continue;
        }
        assert!(
            !csp.contains(scheme),
            "CSP {csp:?} permits {scheme}; the app is offline in v1 (CLAUDE.md rule 8)"
        );
    }
}

/// The bug: a hardcoded CSP `<meta>` tag in `src/app.html` renders the app as a
/// blank white page.
///
/// SvelteKit bootstraps the entire application from an inline `<script>`. Any
/// policy with a bare `script-src 'self'` blocks it, nothing mounts, and the
/// window shows white. Tauri's own injection handles this — it generates a
/// nonce per inline script and rewrites the policy to match (`replace_csp_nonce`
/// in tauri's manager/mod.rs) — but only for pages it serves. A `<meta>` tag in
/// the HTML applies unconditionally and bypasses that entirely, which breaks
/// dev (where Tauri serves nothing and only the meta tag is in force) and
/// hardcodes a policy that cannot carry a nonce in release.
///
/// The CSP belongs in `tauri.conf.json` under `app.security.csp`, which the
/// `the_csp_allows_no_remote_origins` test above guards.
#[test]
fn app_html_does_not_hardcode_a_content_security_policy() {
    let html = include_str!("../../src/app.html");

    // Strip HTML comments first: the file explains *why* the policy is not set
    // here, and that prose legitimately names the header.
    let mut stripped = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find("<!--") {
        stripped.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => {
                rest = "";
                break;
            }
        }
    }
    stripped.push_str(rest);

    assert!(
        !stripped.to_lowercase().contains("content-security-policy"),
        "src/app.html hardcodes a Content-Security-Policy meta tag. That blocks \
         SvelteKit's inline bootstrap script and renders the app blank. Configure \
         app.security.csp in tauri.conf.json instead and let Tauri inject it."
    );
}

/// The bug: without the `custom-protocol` feature every build — release
/// included — points at the dev server.
///
/// Tauri switches between `devUrl` and the embedded `frontendDist` on this
/// feature, not on the cargo profile (`is_dev()` in tauri-build reads
/// `DEP_TAURI_DEV`, which `tauri/custom-protocol` drives). `cargo tauri dev`
/// builds with `--no-default-features`; `cargo tauri build` leaves the default
/// on. Omit it and `cargo tauri build` produces an app whose window is blank
/// unless a Vite server happens to be listening on 5173.
#[test]
fn the_app_crate_declares_the_custom_protocol_feature() {
    let manifest = include_str!("../Cargo.toml");

    assert!(
        manifest.contains("custom-protocol = [\"tauri/custom-protocol\"]"),
        "src-tauri/Cargo.toml must define custom-protocol = [\"tauri/custom-protocol\"], \
         otherwise release builds load from the dev server and render blank"
    );
    assert!(
        manifest.contains("default = [\"custom-protocol\"]"),
        "custom-protocol must be a default feature so `cargo build --release` \
         embeds the frontend"
    );
}
