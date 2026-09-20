<script lang="ts">
  import '$lib/styles.css';
  import { listen } from '@tauri-apps/api/event';
  import { listEntries, lockVault, searchEntries, vaultStatus } from '$lib/api';
  import {
    errorMessage,
    isCmdError,
    LOCK_EVENT,
    type EntryMeta,
    type LockedPayload,
    type VaultStatus
  } from '$lib/types';
  import Unlock from '$lib/components/Unlock.svelte';
  import Onboarding from '$lib/components/Onboarding.svelte';
  import Recovery from '$lib/components/Recovery.svelte';
  import EntryForm from '$lib/components/EntryForm.svelte';
  import EntryDetail from '$lib/components/EntryDetail.svelte';
  import Settings from '$lib/components/Settings.svelte';
  import KindIcon from '$lib/components/KindIcon.svelte';

  let status = $state<VaultStatus | null>(null);
  let entries = $state<EntryMeta[]>([]);
  let selectedId = $state<string | null>(null);
  let query = $state('');
  let mode = $state<'view' | 'add' | 'edit' | 'settings'>('view');
  let error = $state('');
  let loading = $state(true);
  /** Why the vault locked itself, shown once on the unlock screen. */
  let lockNotice = $state('');

  // The vault can lock itself at any moment — idle, sleep, screen lock. When it
  // does, clear everything on screen before showing why.
  listen<LockedPayload>(LOCK_EVENT, (e) => {
    entries = [];
    selectedId = null;
    query = '';
    mode = 'view';
    error = '';
    lockNotice = e.payload.message;
    void refreshStatus();
  });

  const selected = $derived(entries.find((e) => e.id === selectedId) ?? null);
  const unlocked = $derived(status !== null && !status.locked);

  $effect(() => {
    void refreshStatus();
  });

  async function refreshStatus() {
    try {
      status = await vaultStatus();
      if (!status.locked) await refreshEntries();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  async function refreshEntries() {
    try {
      entries = query.trim() ? await searchEntries(query) : await listEntries();
      if (selectedId && !entries.some((e) => e.id === selectedId)) {
        selectedId = null;
        if (mode !== 'add') mode = 'view';
      }
    } catch (e) {
      if (isCmdError(e) && e.code === 'locked') {
        entries = [];
        await refreshStatus();
        return;
      }
      error = errorMessage(e);
    }
  }

  let searchTimer: ReturnType<typeof setTimeout>;
  function onSearchInput() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void refreshEntries(), 80);
  }

  async function doLock() {
    entries = [];
    selectedId = null;
    query = '';
    mode = 'view';
    try {
      await lockVault();
    } catch (e) {
      error = errorMessage(e);
    }
    await refreshStatus();
  }

  function onUnlocked(next: VaultStatus) {
    status = next;
    error = '';
    lockNotice = '';
    void refreshEntries();
  }

  function onSaved(m: EntryMeta) {
    mode = 'view';
    selectedId = m.id;
    void refreshEntries();
  }

</script>

<svelte:head><title>Vaulty</title></svelte:head>

{#if loading}
  <div class="center secondary t-callout">Loading…</div>
{:else if status && status.exists && !status.readable}
  <!-- The file is there but unopenable. A password field would be a dead end;
       offer snapshot recovery instead. -->
  <Recovery {status} onRestored={(s) => { status = s; lockNotice = ''; }} />
{:else if status && !status.exists}
  <Onboarding {status} onCreated={onUnlocked} />
{:else if !unlocked && status}
  <Unlock {status} {onUnlocked} {lockNotice} />
{:else if status}
  <div class="app">
    <!-- Sidebar: translucent, like Finder and Mail. The top padding clears the
         traffic lights, which float over it with titleBarStyle: Overlay. -->
    <aside data-tauri-drag-region>
      <div class="toolbar" data-tauri-drag-region>
        <div class="search-wrap">
          <svg class="search-icon" width="12" height="12" viewBox="0 0 16 16" fill="none">
            <circle cx="7" cy="7" r="4.6" stroke="currentColor" stroke-width="1.6" />
            <path d="M10.6 10.6 14 14" stroke="currentColor" stroke-width="1.6"
              stroke-linecap="round" />
          </svg>
          <input class="search" placeholder="Search" bind:value={query}
            oninput={onSearchInput} autocomplete="off" />
        </div>
        <button class="add" title="New entry" aria-label="New entry"
          onclick={() => { mode = 'add'; selectedId = null; }}>
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
            <path d="M8 2.6v10.8M2.6 8h10.8" stroke="currentColor" stroke-width="1.8"
              stroke-linecap="round" />
          </svg>
        </button>
      </div>

      <div class="list">
        {#if entries.length === 0}
          <p class="empty secondary t-callout">
            {query.trim() ? 'No results' : 'No entries yet.'}
          </p>
        {:else}
          {#each entries as e (e.id)}
            <button class="row" class:active={e.id === selectedId && mode === 'view'}
              onclick={() => { selectedId = e.id; mode = 'view'; }}>
              <span class="glyph"><KindIcon kind={e.kind} /></span>
              <span class="row-text">
                <span class="row-label t-body">{e.label}</span>
                <span class="row-sub t-subheadline">
                  {e.kind}{e.tags.length ? ` · ${e.tags.join(', ')}` : ''}
                </span>
              </span>
            </button>
          {/each}
        {/if}
      </div>

      <footer>
        <button class="plain" onclick={doLock}>Lock</button>
        <button class="plain" onclick={() => (mode = 'settings')}>Settings</button>
        <span class="count t-footnote tertiary">{entries.length}</span>
      </footer>
    </aside>

    <main>
      {#if error}<div class="banner error">{error}</div>{/if}

      {#if mode === 'settings'}
        <Settings onClose={() => (mode = 'view')} />
      {:else if mode === 'add'}
        <EntryForm onSaved={onSaved} onCancel={() => (mode = 'view')} />
      {:else if mode === 'edit' && selected}
        {#key selected.id}
          <EntryForm existing={selected} onSaved={onSaved} onCancel={() => (mode = 'view')} />
        {/key}
      {:else if selected}
        <EntryDetail entry={selected} onEdit={() => (mode = 'edit')}
          onDeleted={() => { selectedId = null; void refreshEntries(); }} />
      {:else}
        <div class="placeholder">
          <p class="t-title-3 secondary">No Selection</p>
          <p class="t-footnote tertiary">
            Vault {status.vaultId?.slice(0, 13)} · format v{status.formatVersion}
          </p>
        </div>
      {/if}
    </main>
  </div>
{/if}

<style>
  .center { display: grid; place-content: center; min-height: 100vh; }

  .app {
    display: grid;
    grid-template-columns: 248px 1fr;
    height: 100vh;
    background: var(--content-bg);
  }

  aside {
    display: flex;
    flex-direction: column;
    background: var(--sidebar-bg);
    -webkit-backdrop-filter: saturate(180%) blur(24px);
    backdrop-filter: saturate(180%) blur(24px);
    border-right: 0.5px solid var(--separator);
    min-width: 0;
  }

  /* 28px clears the traffic lights. */
  .toolbar {
    display: flex;
    gap: 6px;
    align-items: center;
    padding: 34px var(--s2) var(--s2);
  }
  .search-wrap { position: relative; flex: 1; min-width: 0; }
  .search-icon {
    position: absolute;
    left: 7px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--label-tertiary);
    pointer-events: none;
  }
  .search { padding-left: 24px; border-radius: var(--r-control); }
  .add { flex: none; padding: 0; width: 24px; display: grid; place-items: center; }

  .list { flex: 1; overflow-y: auto; padding: 0 var(--s2) var(--s2); }
  .empty { padding: var(--s5) var(--s2); text-align: center; margin: 0; }

  .row {
    display: flex;
    align-items: center;
    gap: var(--s2);
    width: 100%;
    text-align: left;
    background: transparent;
    border: none;
    box-shadow: none;
    border-radius: var(--r-control);
    padding: 5px var(--s2);
    margin-bottom: 1px;
    min-height: 34px;
  }
  .row:hover:not(.active) { background: var(--fill-quaternary); }
  /* Selected rows in a macOS sidebar are a filled accent pill. */
  .row.active { background: var(--accent); color: var(--accent-label); }
  .row.active .row-sub { color: rgba(255, 255, 255, 0.72); }
  .glyph { flex: none; display: grid; place-items: center; width: 16px; opacity: 0.72; }
  .row-text { min-width: 0; display: flex; flex-direction: column; }
  .row-label,
  .row-sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-sub { color: var(--label-secondary); }

  footer {
    display: flex;
    align-items: center;
    gap: var(--s1);
    padding: 6px var(--s2);
    border-top: 0.5px solid var(--separator);
  }
  footer .count { margin-left: auto; }

  main {
    padding: 34px var(--s6) var(--s6);
    overflow-y: auto;
    min-width: 0;
    background: var(--content-bg);
  }
  .placeholder {
    display: grid;
    place-content: center;
    height: 100%;
    text-align: center;
    gap: var(--s1);
  }
  .placeholder p { margin: 0; }
</style>
