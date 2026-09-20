<script lang="ts">
  import '$lib/styles.css';
  import { listen } from '@tauri-apps/api/event';
  import {
    biometricState,
    unlockWithBiometrics,
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
    isCmdError,
    type CapturePayload,
    type EntryKind,
    type EntryMeta,
    type BiometricState
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
  let bio = $state<BiometricState | null>(null);

  /** Offered, never fired automatically: an unprompted Touch ID sheet is startling. */
  async function useBiometrics() {
    if (!bio?.canUnlock) return;
    error = '';
    busy = true;
    try {
      await unlockWithBiometrics();
      const s = await captureState();
      payload = payload && {
        ...payload,
        locked: false,
        mode: s.hasCapture ? 'capture' : 'search',
        charCount: s.charCount
      };
      queueMicrotask(focusForMode);
    } catch (e) {
      // Never a silent unlock: fall through to the password field.
      error = isCmdError(e) && e.code === 'biometric_cancelled' ? '' : errorMessage(e);
    } finally {
      busy = false;
    }
  }

  listen<CapturePayload>(CAPTURE_EVENT, (e) => {
    reset();
    payload = e.payload;
    if (e.payload.locked) void biometricState().then((b) => (bio = b)).catch(() => (bio = null));
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
    <div class="idle t-callout secondary">Waiting…</div>
  {:else if payload.locked}
    <form onsubmit={doUnlock}>
      <div class="head">
        <strong class="t-headline">Vaulty is locked</strong>
        {#if payload.charCount}
          <span class="t-subheadline secondary">{payload.charCount} characters held</span>
        {/if}
      </div>
      {#if error}<div class="error">{error}</div>{/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="big"
        bind:this={passwordInput}
        type="password"
        placeholder="Master password"
        bind:value={password}
        autocomplete="off"
        autofocus
        disabled={busy}
      />
      {#if bio?.canUnlock}
        <button type="button" class="plain bio" onclick={useBiometrics} disabled={busy}>
          Use {bio.displayName ?? 'Touch ID'}
        </button>
      {/if}
      <p class="hint t-footnote tertiary">Return to unlock · Escape to cancel</p>
    </form>
  {:else if payload.mode === 'permission_required'}
    <div class="perm">
      <strong class="t-headline">Vaulty needs Accessibility permission</strong>
      <p class="t-callout secondary">
        To grab the text you have selected, Vaulty sends a copy keystroke to the app you
        are using. macOS gates that behind Accessibility.
      </p>
      <p class="t-subheadline tertiary">
        Without it the shortcut still opens this window, but it can only search — it
        cannot capture a selection. Vaulty does not read your screen or log your keys.
      </p>
      {#if error}<div class="error">{error}</div>{/if}
      <div class="actions">
        <button class="primary" onclick={grant}>Grant permission</button>
        <button onclick={() => openAccessibilitySettings()}>Open System Settings</button>
        <button class="plain" onclick={close}>Not now</button>
      </div>
    </div>
  {:else if payload.mode === 'capture'}
    <form onsubmit={doSave}>
      <div class="head">
        <strong class="t-headline">Save to Vaulty</strong>
        <span class="t-footnote tertiary timing">{payload.elapsedMs} ms</span>
      </div>

      <div class="captured">
        {#if revealed !== null}
          <span class="mono val">{revealed}</span>
        {:else}
          <span class="mono val masked">{'•'.repeat(Math.min(payload.charCount ?? 0, 32))}</span>
          <span class="t-subheadline secondary">{payload.charCount} characters</span>
        {/if}
        <button type="button" class="plain" onclick={revealed === null ? doReveal : () => (revealed = null)}>
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
        class="big" placeholder="Label — what is this?"
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
      <p class="hint t-footnote tertiary">Return to save · Escape to cancel</p>
    </form>
  {:else}
    <div>
      <div class="head">
        <strong class="t-headline">Search Vaulty</strong>
        <span class="t-footnote tertiary timing">{payload.elapsedMs} ms</span>
      </div>
      {#if copiedLabel}
        <div class="notice">Copied {copiedLabel} — clears from the clipboard shortly.</div>
      {/if}
      {#if error}<div class="error">{error}</div>{/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        bind:this={searchInput}
        class="big" placeholder="Search"
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
            <span class="t-subheadline secondary">{r.kind}</span>
          </div>
        {:else}
          <div class="t-callout secondary pad">
            {query.trim() ? 'No matches.' : 'Type to search. Enter copies.'}
          </div>
        {/each}
      </div>
      <p class="hint t-footnote tertiary">↑↓ to move · Return to copy · Escape to close</p>
    </div>
  {/if}
</div>

<style>
  /*
   * A floating panel in the Spotlight idiom: translucent material, one large
   * radius, a hairline, and a heavy shadow. The window itself is transparent
   * and undecorated, so this element *is* the window.
   */
  .popup {
    height: 100vh;
    padding: var(--s4);
    display: flex;
    flex-direction: column;
    gap: var(--s3);
    border-radius: var(--r-panel);
    background: var(--sidebar-bg);
    -webkit-backdrop-filter: saturate(180%) blur(30px);
    backdrop-filter: saturate(180%) blur(30px);
    box-shadow: var(--shadow-panel);
    overflow: hidden;
  }
  .idle { display: grid; place-content: center; height: 100%; }
  .head { display: flex; align-items: baseline; justify-content: space-between; gap: var(--s2); }
  .timing { font-variant-numeric: tabular-nums; }
  form, .perm, .popup > div { display: flex; flex-direction: column; gap: var(--s3); }
  .row { display: grid; grid-template-columns: 120px 1fr; gap: var(--s2); }
  .hint { margin: 0; }
  .big { font-size: 15px; min-height: 30px; }

  .captured {
    display: flex;
    align-items: center;
    gap: var(--s2);
    background: var(--field-bg);
    border: 0.5px solid var(--control-border);
    border-radius: var(--r-field);
    padding: 7px 10px;
  }
  .val { flex: 1; word-break: break-all; }
  .masked { letter-spacing: 2px; color: var(--label-tertiary); }

  .results { display: flex; flex-direction: column; gap: 1px; min-height: 104px; }
  .hit {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--s2);
    padding: 6px var(--s2);
    border-radius: var(--r-control);
  }
  .hit.active { background: var(--accent); color: var(--accent-label); }
  .hit.active .secondary { color: rgba(255, 255, 255, 0.75); }

  .perm p { margin: 0; line-height: 1.5; }
  .actions { display: flex; gap: var(--s2); flex-wrap: wrap; }
  .bio { display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
</style>
