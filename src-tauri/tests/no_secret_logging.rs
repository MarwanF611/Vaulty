//! CLAUDE.md rule 3, enforced rather than promised.
//!
//! > **Never log a secret.** No `println!`, no `dbg!`, no `console.log`, no
//! > error message that embeds key material or plaintext. Check this before
//! > every commit.
//!
//! "Check this before every commit" is a habit, and habits lapse. This walks
//! the source tree and fails the build instead — which is the difference
//! between a rule and a control.
//!
//! The rule is applied with different strictness by layer:
//!
//! * `vault-core` and `vault-platform` handle key material, so they get **no**
//!   print macros at all in shipped code. There is nothing they could
//!   legitimately print that is worth the risk of the next one being careless.
//! * `src-tauri` may report startup failures — it has to say something when a
//!   window will not open — but never `dbg!`, and never on a line that mentions
//!   anything secret-bearing.
//! * The frontend gets no `console.*` at all. Anything it could log is one
//!   devtools screenshot from being public, and Phase 1's exit criterion is
//!   that nothing sensitive appears there.
//!
//! `vault-cli` is exempt: printing a secret is what `vault-cli get` is *for*,
//! and SPEC.md keeps the CLI out of the shipped product.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is src-tauri/.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri should have a parent")
        .to_path_buf()
}

/// Every file under `dir` with one of `exts`, skipping build output.
fn source_files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name == "target" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            out.extend(source_files(&path, exts));
        } else if path
            .extension()
            .map(|e| exts.contains(&e.to_string_lossy().as_ref()))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    out
}

/// Lines of `src` outside any `#[cfg(test)]` module, as (1-based line, text).
///
/// Brace-counting rather than parsing: it only has to be right about where a
/// test module ends, and test modules in this repo are the conventional
/// trailing `mod tests { .. }`.
fn non_test_lines(src: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut in_test = false;
    let mut depth = 0i32;

    for (i, line) in src.lines().enumerate() {
        if !in_test && line.trim_start().starts_with("#[cfg(test)]") {
            in_test = true;
            depth = 0;
            continue;
        }
        if in_test {
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            // Back to zero after having opened at least one brace: module over.
            if depth <= 0 && line.contains('}') {
                in_test = false;
            }
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

/// A line that is only a comment cannot execute.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

const PRINT_MACROS: [&str; 5] = ["println!", "eprintln!", "print!(", "eprint!(", "dbg!"];

/// Identifiers that mean a line is handling something that must never be
/// printed.
const SECRET_BEARING: [&str; 10] = [
    "secret",
    "password",
    "passphrase",
    "plaintext",
    "kek",
    "vault_key",
    "revealed",
    "capture",
    "note",
    "wrapped",
];

#[test]
fn the_key_material_crates_print_nothing() {
    let root = repo_root();
    let mut offenders = Vec::new();

    for crate_dir in ["crates/vault-core/src", "crates/vault-platform/src"] {
        for file in source_files(&root.join(crate_dir), &["rs"]) {
            let Ok(src) = std::fs::read_to_string(&file) else {
                continue;
            };
            for (line_no, line) in non_test_lines(&src) {
                if is_comment(line) {
                    continue;
                }
                for m in PRINT_MACROS {
                    if line.contains(m) {
                        offenders.push(format!(
                            "{}:{line_no}: {m} — {}",
                            file.strip_prefix(&root).unwrap_or(&file).display(),
                            line.trim()
                        ));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "crates that handle key material must not print (CLAUDE.md rule 3):\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_app_layer_never_prints_a_secret_bearing_line() {
    let root = repo_root();
    let mut offenders = Vec::new();

    for file in source_files(&root.join("src-tauri/src"), &["rs"]) {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (line_no, line) in non_test_lines(&src) {
            if is_comment(line) {
                continue;
            }
            let rel = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .display()
                .to_string();

            // `dbg!` is never acceptable in shipped code: it prints the
            // expression it wraps, whatever that turns out to be.
            if line.contains("dbg!") {
                offenders.push(format!("{rel}:{line_no}: dbg! — {}", line.trim()));
                continue;
            }

            let prints = PRINT_MACROS.iter().any(|m| line.contains(m));
            if !prints {
                continue;
            }
            let lower = line.to_lowercase();
            for word in SECRET_BEARING {
                if lower.contains(word) {
                    offenders.push(format!(
                        "{rel}:{line_no}: prints a line mentioning `{word}` — {}",
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the app layer must not print secret-bearing values:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_frontend_logs_nothing_to_the_console() {
    let root = repo_root();
    let mut offenders = Vec::new();

    for file in source_files(&root.join("src"), &["ts", "js", "svelte"]) {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for call in [
                "console.log",
                "console.debug",
                "console.info",
                "console.warn",
                "console.error",
                "console.trace",
                "console.dir",
            ] {
                if line.contains(call) {
                    offenders.push(format!(
                        "{}:{}: {call} — {}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "nothing sensitive may reach the webview console (Phase 1 exit criterion):\n  {}",
        offenders.join("\n  ")
    );
}

/// Source maps hand a reader the original TypeScript, including any comment
/// explaining where a secret flows.
#[test]
fn the_production_bundle_ships_no_source_maps() {
    let root = repo_root();
    let vite =
        std::fs::read_to_string(root.join("vite.config.ts")).expect("vite.config.ts should exist");
    assert!(
        vite.contains("sourcemap: false"),
        "vite must be configured with sourcemap: false"
    );
}

/// The audit only means something if it can see the files it claims to check.
#[test]
fn the_audit_actually_walks_the_tree() {
    let root = repo_root();
    assert!(
        source_files(&root.join("crates/vault-core/src"), &["rs"]).len() >= 8,
        "vault-core sources not found — the audit would pass vacuously"
    );
    assert!(
        source_files(&root.join("src"), &["ts", "svelte"]).len() >= 6,
        "frontend sources not found — the audit would pass vacuously"
    );
    assert!(
        !source_files(&root.join("src-tauri/src"), &["rs"]).is_empty(),
        "app sources not found"
    );
}

/// `non_test_lines` is doing real work; if it silently swallowed everything the
/// audits above would pass on any input.
#[test]
fn test_modules_are_excluded_but_nothing_else_is() {
    let src = r#"
fn shipped() {
    let x = 1;
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        println!("this is fine in a test");
    }
}
"#;
    let lines: Vec<&str> = non_test_lines(src).into_iter().map(|(_, l)| l).collect();
    let joined = lines.join("\n");
    assert!(joined.contains("fn shipped"), "shipped code was dropped");
    assert!(
        !joined.contains("this is fine in a test"),
        "test code was not excluded"
    );
}
