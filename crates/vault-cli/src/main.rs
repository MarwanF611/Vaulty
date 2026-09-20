//! `vault-cli` — a thin CLI over `vault-core`, for manual testing.
//!
//! This is developer tooling, not a shipped product surface: SPEC.md puts a CLI
//! explicitly out of scope for v1.0. It exists so Phase 0 can be exercised by
//! hand before any window exists.
//!
//! Argument parsing is hand-rolled rather than pulling in `clap`. A vault should
//! carry as little dependency surface as it can get away with, and this parser
//! is thirty lines.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use vault_core::{
    default_vault_path, EntryKind, EntryMeta, EntryUpdate, NewEntry, PlaintextAck, Vault,
};
use zeroize::Zeroizing;

const USAGE: &str = "\
vault-cli — manual testing tool for vault-core

USAGE:
    vault-cli [--vault <path>] <command> [args]

COMMANDS:
    init                        Create a new vault
    info                        Show vault id, format version, entry count
    add <label>                 Add an entry (secret is prompted for)
        [--kind password|code|note|card|wifi]
        [--tags a,b,c]
        [--note]                Also prompt for a note
    list [query]                List entries (metadata only)
    get <id-prefix|label>       Reveal one secret on stdout
    rm <id-prefix|label>        Delete an entry, leaving a tombstone
    relabel <id-prefix> <new>   Change an entry's label
    passwd                      Change the master password
    export <path>               Encrypted backup, own password
    export-plaintext <path> --i-understand-this-writes-secrets-in-the-clear
    import <path>               Merge an encrypted backup
    import-plaintext <path>     Merge a plaintext JSON export
    snapshot                    Take a snapshot and rotate
    restore <1|2|3>             Restore a snapshot over the live vault

OPTIONS:
    --vault <path>              Vault file (default: the per-OS app data path)
    -h, --help                  This text
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `vault-core` errors are already scrubbed of secret material.
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    vault_path: PathBuf,
    command: String,
    rest: Vec<String>,
}

fn parse_args() -> Result<Option<Args>> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(None);
    }

    let mut vault_path: Option<PathBuf> = None;
    if let Some(i) = argv.iter().position(|a| a == "--vault") {
        let value = argv
            .get(i + 1)
            .ok_or_else(|| anyhow!("--vault needs a path"))?
            .clone();
        vault_path = Some(PathBuf::from(value));
        argv.drain(i..=i + 1);
    }

    let vault_path = match vault_path {
        Some(p) => p,
        None => default_vault_path()
            .ok_or_else(|| anyhow!("could not determine the default vault path; pass --vault"))?,
    };

    let command = argv
        .first()
        .ok_or_else(|| anyhow!("no command given; try --help"))?
        .clone();

    Ok(Some(Args {
        vault_path,
        command,
        rest: argv[1..].to_vec(),
    }))
}

fn run() -> Result<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    match args.command.as_str() {
        "init" => cmd_init(&args),
        "info" => cmd_info(&args),
        "add" => cmd_add(&args),
        "list" => cmd_list(&args),
        "get" => cmd_get(&args),
        "rm" => cmd_rm(&args),
        "relabel" => cmd_relabel(&args),
        "passwd" => cmd_passwd(&args),
        "export" => cmd_export(&args),
        "export-plaintext" => cmd_export_plaintext(&args),
        "import" => cmd_import(&args),
        "import-plaintext" => cmd_import_plaintext(&args),
        "snapshot" => cmd_snapshot(&args),
        "restore" => cmd_restore(&args),
        other => bail!("unknown command {other:?}; try --help"),
    }
}

// ------------------------------------------------------------------ helpers

/// Prompt for a secret. The result zeroizes on drop.
///
/// With a terminal attached the input is not echoed. Without one — a pipe, a
/// test harness, CI — it falls back to reading a line from stdin, so the tool
/// stays scriptable. The prompt goes to stderr either way, so `get` can be
/// redirected without the prompt landing in the output.
fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead, IsTerminal, Write};

    if std::io::stdin().is_terminal() {
        let s = rpassword::prompt_password(prompt).context("could not read from the terminal")?;
        return Ok(Zeroizing::new(s));
    }

    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = Zeroizing::new(String::new());
    let n = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("could not read from stdin")?;
    if n == 0 {
        bail!("unexpected end of input while reading {prompt:?}");
    }
    eprintln!();
    Ok(Zeroizing::new(
        line.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

fn prompt_new_password(prompt: &str) -> Result<Zeroizing<String>> {
    let first = prompt_secret(prompt)?;
    let again = prompt_secret("Repeat: ")?;
    if first.as_str() != again.as_str() {
        bail!("the two entries did not match");
    }
    if first.is_empty() {
        bail!("the master password must not be empty");
    }
    Ok(first)
}

/// Open the vault and unlock it, prompting for the master password.
fn open_unlocked(args: &Args) -> Result<Vault> {
    let mut vault = Vault::open(&args.vault_path)
        .with_context(|| format!("could not open {}", args.vault_path.display()))?;
    let pw = prompt_secret("Master password: ")?;
    vault
        .unlock(pw.as_bytes())
        .context("could not unlock the vault")?;
    Ok(vault)
}

fn arg<'a>(args: &'a Args, n: usize, what: &str) -> Result<&'a str> {
    args.rest
        .get(n)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing argument: {what}"))
}

fn flag_value(args: &Args, name: &str) -> Option<String> {
    let i = args.rest.iter().position(|a| a == name)?;
    args.rest.get(i + 1).cloned()
}

fn has_flag(args: &Args, name: &str) -> bool {
    args.rest.iter().any(|a| a == name)
}

/// Positional arguments, skipping `--flag value` pairs.
fn positionals(args: &Args) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for a in &args.rest {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--kind" || a == "--tags" {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        out.push(a.clone());
    }
    out
}

/// Find one entry by id prefix or by exact (case-insensitive) label.
fn resolve(vault: &Vault, needle: &str) -> Result<EntryMeta> {
    let all = vault.list_entries()?;
    let lower = needle.to_lowercase();

    let matches: Vec<&EntryMeta> = all
        .iter()
        .filter(|m| m.id.to_string().starts_with(needle) || m.label.to_lowercase() == lower)
        .collect();

    match matches.as_slice() {
        [] => bail!("no entry matches {needle:?}"),
        [one] => Ok((*one).clone()),
        many => {
            let labels: Vec<&str> = many.iter().map(|m| m.label.as_str()).collect();
            bail!(
                "{} entries match {needle:?}: {}",
                many.len(),
                labels.join(", ")
            )
        }
    }
}

/// How much of the id to show. UUIDv7 leads with a millisecond timestamp, so
/// every entry added in the same session shares its first eight characters —
/// a shorter prefix than this is ambiguous in exactly the case you'd paste it.
const ID_PREFIX_LEN: usize = 13;

fn print_meta(m: &EntryMeta) {
    let tags = if m.tags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", m.tags.join(", "))
    };
    let short: String = m.id.to_string().chars().take(ID_PREFIX_LEN).collect();
    println!("{short}  {:<28} {}{tags}", m.label, m.kind);
}

// ----------------------------------------------------------------- commands

fn cmd_init(args: &Args) -> Result<()> {
    println!("Creating a vault at {}", args.vault_path.display());
    println!();
    println!("  There is NO password recovery. If you forget this password, every");
    println!("  secret in the vault is gone permanently. Nobody can reset it.");
    println!();

    let pw = prompt_new_password("Choose a master password: ")?;
    let vault = Vault::create(&args.vault_path, pw.as_bytes())?;
    println!("Created. vault id {}", vault.vault_id());
    println!("Format version {}", vault.format_version());
    Ok(())
}

fn cmd_info(args: &Args) -> Result<()> {
    let vault = open_unlocked(args)?;
    println!("path            {}", vault.path().display());
    println!("vault id        {}", vault.vault_id());
    println!("format version  {}", vault.format_version());
    println!("entries         {}", vault.list_entries()?.len());
    println!("biometric slot  {}", vault.has_biometric_slot());
    println!("snapshots       {}", vault.snapshots().len());
    Ok(())
}

fn cmd_add(args: &Args) -> Result<()> {
    let pos = positionals(args);
    let label = pos
        .first()
        .ok_or_else(|| anyhow!("usage: vault-cli add <label> [--kind K] [--tags a,b] [--note]"))?;

    let kind: EntryKind = match flag_value(args, "--kind") {
        Some(k) => k.parse()?,
        None => EntryKind::Password,
    };
    let tags: Vec<String> = flag_value(args, "--tags")
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let mut vault = open_unlocked(args)?;
    let secret = prompt_secret("Secret: ")?;
    if secret.is_empty() {
        bail!("the secret must not be empty");
    }
    let note = if has_flag(args, "--note") {
        Some(prompt_secret("Note: ")?)
    } else {
        None
    };

    let meta = vault.add_entry(NewEntry {
        label: label.clone(),
        tags,
        kind,
        secret,
        note,
    })?;
    println!("Added {} ({})", meta.label, meta.id);
    Ok(())
}

fn cmd_list(args: &Args) -> Result<()> {
    let vault = open_unlocked(args)?;
    let query = positionals(args).first().cloned().unwrap_or_default();
    let entries = vault.search(&query)?;

    if entries.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    for m in &entries {
        print_meta(m);
    }
    println!(
        "\n{} entr{}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

fn cmd_get(args: &Args) -> Result<()> {
    let needle = arg(args, 0, "<id-prefix|label>")?;
    let vault = open_unlocked(args)?;
    let meta = resolve(&vault, needle)?;

    // This is the explicit reveal path, the CLI equivalent of `reveal_secret`.
    let revealed = vault.get_entry(&meta.id)?;
    println!("label   {}", revealed.meta.label);
    println!("kind    {}", revealed.meta.kind);
    if !revealed.meta.tags.is_empty() {
        println!("tags    {}", revealed.meta.tags.join(", "));
    }
    println!("secret  {}", revealed.secret.as_str());
    if let Some(note) = &revealed.note {
        println!("note    {}", note.as_str());
    }
    Ok(())
}

fn cmd_rm(args: &Args) -> Result<()> {
    let needle = arg(args, 0, "<id-prefix|label>")?;
    let mut vault = open_unlocked(args)?;
    let meta = resolve(&vault, needle)?;
    vault.delete_entry(&meta.id)?;
    println!("Deleted {}", meta.label);
    Ok(())
}

fn cmd_relabel(args: &Args) -> Result<()> {
    let needle = arg(args, 0, "<id-prefix|label>")?;
    let new_label = arg(args, 1, "<new label>")?;
    let mut vault = open_unlocked(args)?;
    let meta = resolve(&vault, needle)?;
    let updated = vault.update_entry(
        &meta.id,
        EntryUpdate {
            label: Some(new_label.to_string()),
            ..Default::default()
        },
    )?;
    println!("Renamed to {}", updated.label);
    Ok(())
}

fn cmd_passwd(args: &Args) -> Result<()> {
    let mut vault = Vault::open(&args.vault_path)?;
    let old = prompt_secret("Current master password: ")?;
    let new = prompt_new_password("New master password: ")?;
    vault.change_master_password(old.as_bytes(), new.as_bytes())?;
    println!("Master password changed. Entries were not re-encrypted.");
    Ok(())
}

fn cmd_export(args: &Args) -> Result<()> {
    let target = arg(args, 0, "<path>")?;
    let vault = open_unlocked(args)?;
    let pw = prompt_new_password("Password for the export: ")?;
    vault.export_encrypted(&PathBuf::from(target), pw.as_bytes())?;
    println!("Encrypted backup written to {target}");
    Ok(())
}

fn cmd_export_plaintext(args: &Args) -> Result<()> {
    const ACK: &str = "--i-understand-this-writes-secrets-in-the-clear";
    let target = positionals(args)
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("usage: vault-cli export-plaintext <path> {ACK}"))?;

    if !has_flag(args, ACK) {
        bail!(
            "refusing to write every secret in this vault to {target} unencrypted.\n\
             If that is really what you want, pass {ACK}"
        );
    }

    let vault = open_unlocked(args)?;
    vault.export_plaintext_json(
        &PathBuf::from(&target),
        PlaintextAck::IUnderstandThisWritesSecretsInTheClear,
    )?;
    println!("Plaintext export written to {target}");
    println!("{}", vault_core::PLAINTEXT_WARNING);
    Ok(())
}

fn cmd_import(args: &Args) -> Result<()> {
    let source = arg(args, 0, "<path>")?;
    let mut vault = open_unlocked(args)?;
    let pw = prompt_secret("Password for the backup: ")?;
    let report = vault.import_encrypted(&PathBuf::from(source), pw.as_bytes())?;
    println!(
        "Imported: {} added, {} updated, {} already current",
        report.added, report.updated, report.skipped
    );
    Ok(())
}

fn cmd_import_plaintext(args: &Args) -> Result<()> {
    let source = arg(args, 0, "<path>")?;
    let mut vault = open_unlocked(args)?;
    let report = vault.import_plaintext_json(&PathBuf::from(source))?;
    println!("Imported {} entries", report.added);
    Ok(())
}

fn cmd_snapshot(args: &Args) -> Result<()> {
    let vault = open_unlocked(args)?;
    let path = vault.snapshot()?;
    println!("Snapshot written to {}", path.display());
    for (i, s) in vault.snapshots().iter().enumerate() {
        println!("  {}. {}", i + 1, s.display());
    }
    Ok(())
}

fn cmd_restore(args: &Args) -> Result<()> {
    let n: usize = arg(args, 0, "<1|2|3>")?
        .parse()
        .context("the snapshot number must be 1, 2 or 3")?;

    // Deliberately does not unlock first: restore has to work when the live
    // vault is too corrupt to open.
    println!(
        "This replaces {} with snapshot {n}.",
        args.vault_path.display()
    );
    println!("The current file is kept alongside it as .prerestore");
    vault_core::atomic::restore_snapshot(&args.vault_path, n)?;
    println!("Restored.");
    Ok(())
}
