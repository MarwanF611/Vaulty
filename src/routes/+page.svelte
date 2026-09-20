<script lang="ts">
  import '$lib/styles.css';
  import { listEntries, lockVault, searchEntries, vaultStatus } from '$lib/api';
  import { errorMessage, isCmdError, type EntryMeta, type VaultStatus } from '$lib/types';
  import Unlock from '$lib/components/Unlock.svelte';
  import EntryForm from '$lib/components/EntryForm.svelte';
  import EntryDetail from '$lib/components/EntryDetail.svelte';
  import Settings from '$lib/components/Settings.svelte';

  let status = $state<VaultStatus | null>(null);
  let entries = $state<EntryMeta[]>([]);
  let selectedId = $state<string | null>(null);
  let query = $state('');
  let mode = $state<'view' | 'add' | 'edit' | 'settings'>('view');
  let error = $state('');
  let loading = $state(true);

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
      // Drop a selection that no longer exists (deleted, or filtered out).
      if (selectedId && !entries.some((e) => e.id === selectedId)) {
        selectedId = null;
        if (mode !== 'add') mode = 'view';
      }
    } catch (e) {
      // A locked vault mid-session means something re-locked it; go back
      // to the unlock screen rather than showing a stale list.
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
    // Clear the UI first, so nothing from the session is on screen while the
    // lock round-trips.
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
    void refreshEntries();
  }

  function onSaved(m: EntryMeta) {
    mode = 'view';
    selectedId = m.id;
    void refreshEntries();
  }

  const fmtUsed = (e: EntryMeta) =>
    e.lastUsedAt ? `used ${new Date(e.lastUsedAt * 1000).toLocaleDateString()}` : '';
</script>

<svelte:head><title>Vaulty</title></svelte:head>

{#if loading}
  <div class="center muted">Loading…</div>
{:else if !unlocked && status}
  <Unlock {status} {onUnlocked} />
{:else if status}
  <div class="app">
    <aside>
      <div class="side-head">
        <input
          class="search"
          placeholder="Search labels and tags…"
          bind:value={query}
          oninput={onSearchInput}
          autocomplete="off"
        />
        <button class="primary add" onclick={() => { mode = 'add'; selectedId = null; }}>+</button>
      </div>

      <div class="list">
        {#if entries.length === 0}
          <p class="empty muted">
            {query.trim() ? 'No matches.' : 'No entries yet. Press + to add one.'}
          </p>
        {:else}
          {#each entries as e (e.id)}
            <button
              class="row"
              class:active={e.id === selectedId && mode === 'view'}
              onclick={() => { selectedId = e.id; mode = 'view'; }}
            >
              <span class="row-label">{e.label}</span>
              <span class="row-sub muted">
                {e.kind}{e.tags.length ? ` · ${e.tags.join(', ')}` : ''}
                {#if fmtUsed(e)}<span class="used"> · {fmtUsed(e)}</span>{/if}
              </span>
            </button>
          {/each}
        {/if}
      </div>

      <footer>
        <button class="ghost lock" onclick={doLock}>Lock vault</button>
        <button class="ghost lock" onclick={() => (mode = 'settings')}>Settings</button>
        <span class="count muted">{entries.length}</span>
      </footer>
    </aside>

    <main>
      {#if error}<div class="error">{error}</div>{/if}

      {#if mode === 'settings'}
        <Settings onClose={() => (mode = 'view')} />
      {:else if mode === 'add'}
        <EntryForm onSaved={onSaved} onCancel={() => (mode = 'view')} />
      {:else if mode === 'edit' && selected}
        <!-- Keyed so switching entries always gets a fresh form rather than
             one still holding the previous entry's fields. -->
        {#key selected.id}
          <EntryForm existing={selected} onSaved={onSaved} onCancel={() => (mode = 'view')} />
        {/key}
      {:else if selected}
        <EntryDetail
          entry={selected}
          onEdit={() => (mode = 'edit')}
          onDeleted={() => { selectedId = null; void refreshEntries(); }}
        />
      {:else}
        <div class="center muted">
          <p>Select an entry, or press + to add one.</p>
          <p class="tiny">Vault {status.vaultId?.slice(0, 13)} · format v{status.formatVersion}</p>
        </div>
      {/if}
    </main>
  </div>
{/if}

<style>
  .center { display: grid; place-content: center; min-height: 100vh; text-align: center; gap: 6px; }
  .tiny { font-size: 11px; }

  .app { display: grid; grid-template-columns: 300px 1fr; height: 100vh; }
  aside { display: flex; flex-direction: column; border-right: 1px solid var(--border); background: var(--panel); min-width: 0; }
  .side-head { display: flex; gap: 6px; padding: 12px; border-bottom: 1px solid var(--border); }
  .search { font-size: 13px; }
  .add { padding: 7px 11px; font-size: 16px; line-height: 1; }

  .list { flex: 1; overflow-y: auto; padding: 6px; }
  .empty { padding: 20px 12px; font-size: 13px; text-align: center; }
  .row {
    display: block; width: 100%; text-align: left; background: transparent;
    border: 1px solid transparent; border-radius: var(--radius);
    padding: 8px 10px; margin-bottom: 2px; cursor: pointer;
  }
  .row:hover { background: var(--panel-2); border-color: transparent; }
  .row.active { background: var(--panel-2); border-color: var(--accent); }
  .row-label { display: block; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-sub { display: block; font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .used { opacity: 0.7; }

  footer { display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; border-top: 1px solid var(--border); }
  .lock { font-size: 12.5px; }
  .count { font-size: 12px; }

  main { padding: 24px; overflow-y: auto; min-width: 0; }
</style>
