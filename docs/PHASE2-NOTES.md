# Phase 2 — global shortcut and capture

## What is where

```
crates/vault-platform/      new. OS integration, per CLAUDE.md's layout.
  src/macos.rs              CGEvent Cmd+C, AXIsProcessTrusted, NSPasteboard.changeCount
  src/windows_impl.rs       SendInput Ctrl+C, GetClipboardSequenceNumber — UNVERIFIED
  src/permissions.rs        PermissionStatus, prompt, open System Settings
src-tauri/src/
  capture.rs                the capture sequence, and the clipboard auto-clear
  popup.rs                  what happens when the shortcut fires
  shortcut.rs               registration, conflict detection, rollback
  settings.rs               shortcut binding + clipboard timeout, persisted
src/routes/popup/           the popup window: capture, search, permission screen
src/lib/components/Settings.svelte
```

`vault-platform` arrives a phase early. `docs/PHASES.md` creates it in Phase 3 for
`BiometricProvider`, but `CLAUDE.md`'s layout assigns "global shortcut, clipboard" to it
too, and putting the `CGEvent`/`NSPasteboard` code in `src-tauri` would have meant moving
it a week later. Phase 3 adds biometrics alongside.

## The clipboard is never cleared

The obvious way to find out whether a synthetic Cmd+C copied anything is to clear the
clipboard first and look. That opens a window in which a crash loses the user's clipboard
permanently — against an exit criterion that says it is *always* restored.

Both platforms expose a monotonic counter that increments on every clipboard write
(`NSPasteboard.changeCount`, `GetClipboardSequenceNumber`). So the question is answered by
observation instead: read the counter, synthesise the copy, watch for it to move. The
clipboard is only ever read and written back.

This also fixes a correctness bug the naive version has. Comparing clipboard *contents*
before and after cannot distinguish "nothing was selected" from "the selection happened to
equal the clipboard" — so pressing the shortcut with nothing selected would capture a stale
clipboard and open in capture mode instead of search mode.

## Restore happens before the window is shown

`docs/PHASES.md`: "The previous clipboard is always restored, including when the user
cancels."

*Including when the user cancels* is the load-bearing half. The restore therefore happens
inside `capture_selection`, before the popup exists — not on close. By the time the user can
press Escape their clipboard is already back, so there is no cancel path, timeout path or
crash path that can skip it.

## The captured text does not enter the webview

`docs/SPEC.md` says capture mode has the "secret pre-filled". Taken literally that puts the
captured secret in the renderer, which is what CLAUDE.md rule 1 exists to prevent.

So the capture stays in `AppState` as `CapturedText` (zeroizing), and the popup is told only
how many characters were captured, enough to render a masked preview. `save_capture` takes a
label, tags and a kind — **not** a secret — and the text is read from Rust-side state. There
is a `reveal_capture` command for when the user wants to check what was grabbed, the same
explicit escape hatch as `reveal_secret`.

This is a deliberate deviation from a literal reading of SPEC.md, and it matches what SPEC
already says elsewhere: "the captured text is held in memory (zeroized if the user cancels)".

## The 300 ms budget

The measurement is built into the app: every capture records how long it took, and the popup
shows the number in its corner. It is not a benchmark that gets run once and forgotten.

The dominant controllable cost is `CAPTURE_DEADLINE` (150 ms) — how long we wait for the
focused app to service the synthetic copy. It is paid *in full* whenever nothing is selected,
because then the counter never moves. `capture_boundary.rs` asserts that the deadline plus a
100 ms window-show reserve still fits inside 300 ms, so raising it later fails a test rather
than quietly blowing the target.

**The real number has not been observed.** See the limitations below.

## Clipboard auto-clear

30 seconds by default, configurable 5-600. The change counter recorded at write time is what
makes it safe: if the user has copied anything since, the counter has moved and we leave
their clipboard alone. Wiping whatever happens to be in the clipboard 30 seconds after an
unrelated action would be its own kind of data loss.

## Shortcut conflicts

Two distinguishable failures, because the UI needs to tell them apart: text that is not an
accelerator (`shortcut_invalid`) and one the OS has already given away (`shortcut_taken`). A
failed rebind rolls the previous binding back, so a bad guess does not cost you your
shortcut. A conflict at startup is not fatal — the app still works from its window and the
settings screen explains why.

## Limitations, stated plainly

1. **The 300 ms criterion is instrumented but not observed.** Granting Accessibility to an
   unsigned `cargo` binary is not practical, and the shortcut has to be pressed by a human
   anyway. Grant permission to a built app and read the number off the popup.

2. **Accessibility is denied for dev builds.** `accessibility_status()` on the debug binary
   returns `denied`, which is correct and expected. macOS grants the permission per binary,
   and `cargo tauri dev` produces a new one on each build. This is the same class of problem
   `KICKOFF.md` flags for Phase 3 signing — worth confirming on a real bundle early rather
   than the week before launch.

3. **The Windows implementation has never been run.** It compiles and follows the documented
   APIs. `docs/PHASES.md` puts Windows verification in Phase 4, on real hardware.

4. **A non-text clipboard cannot be restored.** If the clipboard held an image, the synthetic
   copy has already replaced it by the time we discover it was not text. The clipboard is
   cleared rather than left holding the captured secret. This is inherent to the capture
   design in SPEC.md, not an implementation shortcut.

5. **No auto-lock yet.** Idle timeout, sleep and screen lock are Phase 5. The pending capture
   does expire after five minutes.
