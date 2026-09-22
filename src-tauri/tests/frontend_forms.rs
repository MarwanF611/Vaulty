//! Every form in the frontend must submit when the user presses Return.
//!
//! SPEC.md: capture mode is "Enter saves, Escape cancels". The popup shipped
//! with a capture form that ignored Return entirely, and nothing in either test
//! suite could see it — the TypeScript compiled, the Rust passed, and the form
//! was simply dead.
//!
//! The cause is a rule in the HTML spec, not a bug in the code: a form with no
//! submit button performs implicit submission only if it has *at most one*
//! field that blocks implicit submission (text, password, search, email, url,
//! tel, number, date...). The capture form had two — label and tags — and its
//! only button was `type="button"`. So Return did nothing, by design of the
//! platform.
//!
//! This reads every `.svelte` file and holds each `<form>` to that rule.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a parent")
        .to_path_buf()
}

fn svelte_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(svelte_files(&path));
        } else if path.extension().map(|e| e == "svelte").unwrap_or(false) {
            out.push(path);
        }
    }
    out
}

/// Input types that block implicit submission, per the HTML spec. An `<input>`
/// with no `type` is a text field, so it blocks too.
const BLOCKING: [&str; 13] = [
    "text",
    "password",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "date",
    "month",
    "week",
    "time",
    "datetime-local",
    "",
];

/// Why a form cannot be submitted with Return, or `None` if it can.
fn return_blocked(form_body: &str) -> Option<String> {
    let has_submit = form_body.contains(r#"type="submit""#);

    let mut blocking = 0;
    let mut rest = form_body;
    while let Some(i) = rest.find("<input") {
        let after = &rest[i + "<input".len()..];
        // The tag's attributes run until the next element starts. Svelte
        // attribute values can contain `>` (arrow functions), so the next `<`
        // is the reliable end.
        let tag = &after[..after.find('<').unwrap_or(after.len())];
        let kind = tag
            .split(r#"type=""#)
            .nth(1)
            .and_then(|t| t.split('"').next())
            .unwrap_or("");
        if BLOCKING.contains(&kind) {
            blocking += 1;
        }
        rest = after;
    }

    if has_submit || blocking <= 1 {
        None
    } else {
        Some(format!(
            "{blocking} text fields and no submit button — Return does nothing"
        ))
    }
}

/// Every `<form>...</form>` block in `src`, with the line it starts on.
fn forms(src: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(start) = src[offset..].find("<form") {
        let abs = offset + start;
        let Some(len) = src[abs..].find("</form>") else {
            break;
        };
        let line = src[..abs].lines().count() + 1;
        out.push((line, &src[abs..abs + len]));
        offset = abs + len;
    }
    out
}

#[test]
fn every_form_submits_on_return() {
    let root = repo_root();
    let mut offenders = Vec::new();
    let mut seen = 0;

    for file in svelte_files(&root.join("src")) {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (line, body) in forms(&src) {
            seen += 1;
            if let Some(why) = return_blocked(body) {
                offenders.push(format!(
                    "{}:{line}: {why}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
    }

    // Unlock, Onboarding, EntryForm, BiometricsSetting, Settings, and the
    // popup's unlock and capture forms. Fewer means the scan went blind.
    assert!(
        seen >= 7,
        "only {seen} forms found — the check would pass vacuously"
    );
    assert!(
        offenders.is_empty(),
        "forms that ignore Return:\n  {}",
        offenders.join("\n  ")
    );
}

/// The exact shape of the bug that shipped, so the rule is known to catch it.
#[test]
fn the_shipped_bug_is_caught() {
    let capture_form_as_shipped = r#"
        <form onsubmit={doSave}>
          <button type="button" class="plain" onclick={doReveal}>Show</button>
          <input class="big" placeholder="Label" bind:value={label} />
          <select bind:value={kind}></select>
          <input placeholder="tags" bind:value={tagsText} />
          <p class="hint">Return to save · Escape to cancel</p>
    "#;
    assert!(return_blocked(capture_form_as_shipped).is_some());
}

#[test]
fn the_rule_matches_the_html_spec() {
    // One text field, no submit button: implicit submission still works.
    assert!(return_blocked(r#"<input type="password" />"#).is_none());
    // Two text fields with a submit button: fine.
    assert!(return_blocked(r#"<input /><input /><button type="submit">Go</button>"#).is_none());
    // A checkbox does not block; a textarea is not an input at all.
    assert!(return_blocked(
        r#"<input type="password" /><input type="checkbox" /><textarea></textarea>"#
    )
    .is_none());
    // An untyped input is a text field and does block.
    assert!(return_blocked(r#"<input /><input type="text" />"#).is_some());
    // An arrow function in an attribute must not end the tag early.
    assert!(return_blocked(
        r#"<input onchange={(e) => go(e)} type="text" /><input type="email" />"#
    )
    .is_some());
}
