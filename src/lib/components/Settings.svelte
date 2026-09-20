<script lang="ts">
  import {
    getSettings,
    openAccessibilitySettings,
    permissionState,
    requestAccessibility,
    setClipboardClearSeconds,
    setShortcut
  } from '$lib/api';
  import { errorMessage, isCmdError, type PermissionState, type Settings } from '$lib/types';

  let { onClose }: { onClose: () => void } = $props();

  let settings = $state<Settings | null>(null);
  let perms = $state<PermissionState | null>(null);
  let shortcutDraft = $state('');
  let error = $state('');
  let saved = $state('');
  let busy = $state(false);

  $effect(() => {
    void load();
  });

  async function load() {
    try {
      settings = await getSettings();
      shortcutDraft = settings.shortcut;
      perms = await permissionState();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function saveShortcut() {
    error = '';
    saved = '';
    busy = true;
    try {
      settings = await setShortcut(shortcutDraft.trim());
      shortcutDraft = settings.shortcut;
      saved = 'Shortcut updated.';
    } catch (e) {
      // The Rust side distinguishes "not a shortcut" from "another app has
      // it", and rolls the old binding back either way.
      error = isCmdError(e) && e.code === 'shortcut_taken'
        ? `${e.message} Your previous shortcut still works.`
        : errorMessage(e);
      if (settings) shortcutDraft = settings.shortcut;
    } finally {
      busy = false;
    }
  }

  async function saveClipboard(seconds: number) {
    error = '';
    saved = '';
    try {
      settings = await setClipboardClearSeconds(seconds);
      saved = 'Clipboard timeout updated.';
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function grant() {
    try {
      perms = await requestAccessibility();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  const permLabel = (p: PermissionState | null) => {
    if (!p) return '';
    if (!p.captureSupported) return 'Capture is not supported on this platform.';
    switch (p.accessibility) {
      case 'granted': return 'Granted — the shortcut can capture selected text.';
      case 'denied': return 'Not granted — the shortcut can only search.';
      case 'not_required': return 'Not required on this platform.';
      default: return 'Unknown.';
    }
  };
</script>

<div class="settings">
  <header>
    <h2>Settings</h2>
    <button class="ghost" onclick={onClose}>Done</button>
  </header>

  {#if error}<div class="error">{error}</div>{/if}
  {#if saved}<div class="notice">{saved}</div>{/if}

  {#if settings}
    <section>
      <h3>Global shortcut</h3>
      <p class="muted">
        Press this from any app to capture the selected text, or to search when nothing
        is selected.
      </p>
      <div class="row">
        <input bind:value={shortcutDraft} disabled={busy} spellcheck="false" />
        <button onclick={saveShortcut} disabled={busy || shortcutDraft.trim() === settings.shortcut}>
          Rebind
        </button>
      </div>
      <p class="muted small">
        Accelerator syntax, e.g. <code>CmdOrCtrl+Shift+Space</code>. Default is
        <code>{settings.defaultShortcut}</code>.
        {#if settings.defaultShortcut.startsWith('Ctrl')}
          Note that <code>Ctrl+Shift+Space</code> is parameter hints in Visual Studio and
          the JetBrains IDEs — rebind if you use those.
        {/if}
      </p>
    </section>

    <section>
      <h3>Clipboard</h3>
      <p class="muted">
        A copied secret is wiped from the clipboard after this long — unless you have
        copied something else since, in which case it is left alone.
      </p>
      <div class="row">
        <select
          value={settings.clipboardClearSeconds}
          onchange={(e) => saveClipboard(Number(e.currentTarget.value))}
        >
          {#each [10, 30, 60, 120, 300] as s (s)}
            <option value={s}>{s} seconds</option>
          {/each}
        </select>
        <span></span>
      </div>
    </section>

    <section>
      <h3>Accessibility permission</h3>
      <p class="muted">{permLabel(perms)}</p>
      {#if perms?.captureSupported && perms.accessibility === 'denied'}
        <p class="muted small">
          To grab the text you have selected, Vaulty sends a copy keystroke to the app you
          are using. macOS gates that behind Accessibility. Vaulty does not read your
          screen and does not log your keystrokes.
        </p>
        <div class="row">
          <button class="primary" onclick={grant}>Request permission</button>
          <button onclick={() => openAccessibilitySettings()}>Open System Settings</button>
        </div>
        <p class="muted small">
          macOS only shows its prompt once per app. If nothing appears, use System
          Settings.
        </p>
      {/if}
    </section>
  {/if}
</div>

<style>
  .settings { display: flex; flex-direction: column; gap: 18px; max-width: 560px; }
  header { display: flex; align-items: center; justify-content: space-between; }
  h2 { margin: 0; font-size: 17px; }
  h3 { margin: 0 0 4px; font-size: 13px; font-weight: 600; }
  section { display: flex; flex-direction: column; gap: 6px; }
  p { margin: 0; font-size: 12.5px; line-height: 1.5; }
  .small { font-size: 11.5px; }
  .row { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center; }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px; background: var(--bg); padding: 1px 4px;
    border-radius: 4px; border: 1px solid var(--border);
  }
</style>
