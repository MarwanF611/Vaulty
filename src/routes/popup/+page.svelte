<script lang="ts">
  import '$lib/styles.css';
  import { listen } from '@tauri-apps/api/event';
  import {
    captureState,
    copySecret,
    discardCapture,
    hidePopup,
    openAccessibilitySettings,
    requestAccessibility,
    revealCapture,
    saveCapture,
    searchEntries,
    unlockVault
  } from '$lib/api';
  import {
    CAPTURE_EVENT,
    ENTRY_KINDS,
    errorMessage,
    type CapturePayload,
    type EntryKind,
    type EntryMeta
  } from '$lib/types';

  let payload = $state<CapturePayload | null>(null);
  let error = $state('');
  let busy = $state(false);

  // Capture mode
  let label = $state('');
  let tagsText = $state('');
  let kind = $state<EntryKind>('password');
  /** Plaintext, only while the user is looking at it. Cleared on every close. */
  let revealed = $state<string | null>(null);

  // Search mode
  let query = $state('');
  let results = $state<EntryMeta[]>([]);
  let cursor = $state(0);
  let copiedLabel = $state('');

  // Unlock (the vault can be locked when the shortcut fires)
  let password = $state('');

  let labelInput = $state<HTMLInputElement | null>(null);
  let searchInput = $state<HTMLInputElement | null>(null);
  let passwordInput = $state<HTMLInputElement | null>(null);

  listen<CapturePayload>(CAPTURE_EVENT, (e) => {
    reset();
    payload = e.payload;
    // Focus lands where SPEC.md says: the label field in capture mode, the
    // search box in search mode. This is the "usable cursor" the 300 ms
    // budget is measured to.
    queueMicrotask(focusForMode);
  });

  function reset() {
    error = '';
    busy = false;
    label = '';
    tagsText = '';
    kind = 'password';
    revealed = null;
    query = '';
    results = [];
    cursor = 0;
    copiedLabel = '';
    password = '';
  }

  function focusForMode() {
    if (payload?.locked) passwordInput?.focus();
    else if (payload?.mode === 'capture') labelInput?.focus();
    else searchInput?.focus();
  }

  /** Escape always cancels, and cancelling always zeroizes the capture. */
  async function close() {
    reset();
    payload = null;
    try {
      await discardCapture();
    } catch {
      // Closing must not fail loudly; the Rust side discards on hide too.
    }
    await hidePopup();
  }

  async function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      await close();
    }
  }

  // ----------------------------------------------------------- unlock

  async function doUnlock(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await unlockVault(password);
      password = '';
      // The capture survived the unlock (it lives in Rust), so pick up where
      // the shortcut left off.
      const s = await captureState();
      payload = payload && {
        ...payload,
        locked: false,
        mode: s.hasCapture ? 'capture' : 'search',
        charCount: s.charCount
      };
      queueMicrotask(focusForMode);
    } catch (err) {
      error = errorMessage(err);
      password = '';
    } finally {
      busy = false;
    }
  }

  // ---------------------------------------------------------- capture

  async function doReveal() {
    try {
      revealed = await revealCapture();
    } catch (err) {
      error = errorMessage(err);
    }
  }

  async function doSave(e: SubmitEvent) {
    e.preventDefault();
    if (!label.trim()) {
      error = 'Give it a label.';
      return;
    }
    error = '';
    busy = true;
    try {
      await saveCapture({
        label: label.trim(),
        tags: tagsText.split(',').map((t) => t.trim()).filter(Boolean),
        kind,
        note: null
      });
      await close();
    } catch (err) {
      error = errorMessage(err);
      busy = false;
    }
  }

  // ----------------------------------------------------------- search

  let timer: ReturnType<typeof setTimeout>;
  function onQueryInput() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        results = query.trim() ? await searchEntries(query) : [];
        cursor = 0;
      } catch (err) {
        error = errorMessage(err);
      }
    }, 60);
  }

  async function onSearchKeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      cursor = Math.min(cursor + 1, results.length - 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      cursor = Math.max(cursor - 1, 0);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const hit = results[cursor];
      if (!hit) return;
      try {
        // Copies in Rust; no plaintext comes back here.
        await copySecret(hit.id);
        copiedLabel = hit.label;
        setTimeout(() => void close(), 700);
      } catch (err) {
        error = errorMessage(err);
      }
    }
  }

  // ------------------------------------------------------- permission

  async function grant() {
    try {
      const s = await requestAccessibility();
      if (s.accessibility === 'granted' && payload) {
        payload = { ...payload, mode: 'search', permission: 'granted' };
      }
    } catch (err) {
      error = errorMessage(err);
    }
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="popup">
  {#if !payload}
    <div class="idle muted">Waiting…</div>
  {:else if payload.locked}
    <form onsubmit={doUnlock}>
      <div class="head">
        <strong>Vaulty is locked</strong>
        {#if payload.charCount}
          <span class="muted">{payload.charCount} characters captured and held</span>
        {/if}
      </div>
      {#if error}<div class="error">{error}</div>{/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        bind:this={passwordInput}
        type="password"
        placeholder="Master password"
        bind:value={password}
        autocomplete="off"
        autofocus
        disabled={busy}
      />
      <div class="hint muted">Enter to unlock · Escape to cancel</div>
    </form>
  {:else if payload.mode === 'permission_required'}
    <div class="perm">
      <strong>Vaulty needs Accessibility permission</strong>
      <p class="muted">
        To grab the text you have selected, Vaulty sends a copy keystroke to the app you
        are using. macOS gates that behind Accessibility.
      </p>
      <p class="muted small">
        Without it the shortcut still opens this window, but it can only search — it
        cannot capture a selection. Vaulty does not read your screen or log your keys.
      </p>
      {#if error}<div class="error">{error}</div>{/if}
      <div class="actions">
        <button class="primary" onclick={grant}>Grant permission</button>
        <button onclick={() => openAccessibilitySettings()}>Open System Settings</button>
        <button class="ghost" onclick={close}>Not now</button>
      </div>
    </div>
  {:else if payload.mode === 'capture'}
    <form onsubmit={doSave}>
      <div class="head">
        <strong>Save to Vaulty</strong>
        <span class="muted timing">{payload.elapsedMs} ms</span>
      </div>

      <div class="captured">
        {#if revealed !== null}
          <span class="mono val">{revealed}</span>
        {:else}
          <span class="mono val masked">{'•'.repeat(Math.min(payload.charCount ?? 0, 32))}</span>
          <span class="muted small">{payload.charCount} characters captured</span>
        {/if}
        <button type="button" class="ghost tiny" onclick={revealed === null ? doReveal : () => (revealed = null)}>
          {revealed === null ? 'Show' : 'Hide'}
        </button>
      </div>

      {#if !payload.clipboardRestored}
        <div class="error">Your previous clipboard could not be restored.</div>
      {/if}
      {#if error}<div class="error">{error}</div>{/if}

      <!-- svelte-ignore a11y_autofocus -->
      <input
        bind:this={labelInput}
        placeholder="Label — what is this?"
        bind:value={label}
        autocomplete="off"
        autofocus
        disabled={busy}
      />
      <div class="row">
        <select bind:value={kind} disabled={busy}>
          {#each ENTRY_KINDS as k (k)}<option value={k}>{k}</option>{/each}
        </select>
        <input placeholder="tags, comma separated" bind:value={tagsText} disabled={busy} />
      </div>
      <div class="hint muted">Enter to save · Escape to cancel</div>
    </form>
  {:else}
    <div>
      <div class="head">
        <strong>Search Vaulty</strong>
        <span class="muted timing">{payload.elapsedMs} ms</span>
      </div>
      {#if copiedLabel}
        <div class="notice">Copied {copiedLabel} — clears from the clipboard shortly.</div>
      {/if}
      {#if error}<div class="error">{error}</div>{/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        bind:this={searchInput}
        placeholder="Search labels and tags…"
        bind:value={query}
        oninput={onQueryInput}
        onkeydown={onSearchKeydown}
        autocomplete="off"
        autofocus
      />
      <div class="results">
        {#each results.slice(0, 5) as r, i (r.id)}
          <div class="hit" class:active={i === cursor}>
            <span>{r.label}</span>
            <span class="muted small">{r.kind}</span>
          </div>
        {:else}
          <div class="muted small pad">
            {query.trim() ? 'No matches.' : 'Type to search. Enter copies.'}
          </div>
        {/each}
      </div>
      <div class="hint muted">↑↓ to move · Enter to copy · Escape to close</div>
    </div>
  {/if}
</div>

<style>
  .popup {
    padding: 14px;
    height: 100vh;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .idle { display: grid; place-content: center; height: 100%; }
  .head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .timing { font-size: 11px; font-variant-numeric: tabular-nums; }
  form, .perm, .popup > div { display: flex; flex-direction: column; gap: 8px; }
  .row { display: grid; grid-template-columns: 120px 1fr; gap: 8px; }
  .hint { font-size: 11px; }
  .small { font-size: 11px; }
  .tiny { padding: 2px 8px; font-size: 11px; }
  .pad { padding: 8px 2px; }

  .captured {
    display: flex; align-items: center; gap: 8px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 8px 10px;
  }
  .val { flex: 1; font-size: 12px; word-break: break-all; user-select: text; }
  .masked { letter-spacing: 2px; color: var(--muted); user-select: none; }

  .results { display: flex; flex-direction: column; gap: 2px; min-height: 96px; }
  .hit {
    display: flex; justify-content: space-between; gap: 8px;
    padding: 6px 8px; border-radius: var(--radius);
    border: 1px solid transparent; font-size: 13px;
  }
  .hit.active { background: var(--panel-2); border-color: var(--accent); }

  .perm p { margin: 0; font-size: 12.5px; line-height: 1.5; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
</style>
