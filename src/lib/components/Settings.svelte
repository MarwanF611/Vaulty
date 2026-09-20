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
  import BiometricsSetting from './BiometricsSetting.svelte';

  let { onClose }: { onClose: () => void } = $props();

  let settings = $state<Settings | null>(null);
  let perms = $state<PermissionState | null>(null);
  let shortcutDraft = $state('');
  let error = $state('');
  let notice = $state('');
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
    notice = '';
    busy = true;
    try {
      settings = await setShortcut(shortcutDraft.trim());
      shortcutDraft = settings.shortcut;
      notice = 'Shortcut updated.';
    } catch (e) {
      error =
        isCmdError(e) && e.code === 'shortcut_taken'
          ? `${e.message} Your previous shortcut still works.`
          : errorMessage(e);
      if (settings) shortcutDraft = settings.shortcut;
    } finally {
      busy = false;
    }
  }

  async function saveClipboard(seconds: number) {
    error = '';
    notice = '';
    try {
      settings = await setClipboardClearSeconds(seconds);
      notice = 'Clipboard timeout updated.';
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<div class="settings">
  <header>
    <h2 class="t-title-2">Settings</h2>
    <button onclick={onClose}>Done</button>
  </header>

  {#if error}<div class="banner error">{error}</div>{/if}
  {#if notice}<div class="banner ok">{notice}</div>{/if}

  {#if settings}
    <section>
      <h3 class="t-headline">Global shortcut</h3>
      <div class="group">
        <div class="group-row">
          <div class="grow">
            <div class="t-body">Capture &amp; search</div>
            <div class="t-subheadline secondary">
              Press from any app to save the selected text, or to search when nothing is
              selected.
            </div>
          </div>
          <input class="accel mono" bind:value={shortcutDraft} disabled={busy}
            spellcheck="false" />
          <button onclick={saveShortcut}
            disabled={busy || shortcutDraft.trim() === settings.shortcut}>Set</button>
        </div>
      </div>
      <p class="t-footnote tertiary">
        Default is <span class="mono">{settings.defaultShortcut}</span>.
        {#if settings.defaultShortcut.startsWith('Ctrl')}
          <span class="mono">Ctrl+Shift+Space</span> is parameter hints in Visual Studio and the
          JetBrains IDEs — rebind if you use those.
        {/if}
      </p>
    </section>

    <section>
      <h3 class="t-headline">Clipboard</h3>
      <div class="group">
        <div class="group-row">
          <div class="grow">
            <div class="t-body">Clear a copied secret after</div>
            <div class="t-subheadline secondary">
              Left alone if you have copied something else since.
            </div>
          </div>
          <select class="narrow" value={settings.clipboardClearSeconds}
            onchange={(e) => saveClipboard(Number(e.currentTarget.value))}>
            {#each [10, 30, 60, 120, 300] as s (s)}
              <option value={s}>{s < 60 ? `${s} seconds` : `${s / 60} minutes`}</option>
            {/each}
          </select>
        </div>
      </div>
    </section>

    <BiometricsSetting />

    <section>
      <h3 class="t-headline">Accessibility</h3>
      <div class="group">
        <div class="group-row">
          <div class="grow">
            <div class="t-body">Capture selected text</div>
            <div class="t-subheadline secondary">
              {#if !perms?.captureSupported}
                Not supported on this platform.
              {:else if perms.accessibility === 'granted'}
                Granted — the shortcut can capture a selection.
              {:else if perms.accessibility === 'not_required'}
                Not required on this platform.
              {:else}
                Not granted — the shortcut can only search.
              {/if}
            </div>
          </div>
          {#if perms?.captureSupported && perms.accessibility === 'denied'}
            <button class="primary" onclick={async () => (perms = await requestAccessibility())}>
              Request
            </button>
          {/if}
        </div>
      </div>
      {#if perms?.captureSupported && perms.accessibility === 'denied'}
        <p class="t-footnote tertiary">
          To grab your selection, Vaulty sends a copy keystroke to the app you are using; macOS
          gates that behind Accessibility. Vaulty does not read your screen or log keystrokes.
          macOS shows its prompt once per app — after that use
          <button class="plain inline" onclick={() => openAccessibilitySettings()}>
            System Settings
          </button>.
        </p>
      {/if}
    </section>
  {/if}
</div>

<style>
  .settings {
    display: flex;
    flex-direction: column;
    gap: var(--s5);
    max-width: 520px;
  }
  header { display: flex; align-items: center; justify-content: space-between; }
  h2 { margin: 0; }
  h3 { margin: 0 0 var(--s2); }
  section { display: flex; flex-direction: column; }
  section > p { margin: var(--s2) 0 0; line-height: 1.5; }
  .accel { width: 170px; flex: none; text-align: center; }
  .narrow { width: 130px; flex: none; }
  .inline {
    display: inline;
    padding: 0;
    min-height: 0;
    font-size: inherit;
  }
</style>
