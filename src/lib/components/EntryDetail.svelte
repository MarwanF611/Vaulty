<script lang="ts">
  import { copySecret, deleteEntry, revealSecret } from '$lib/api';
  import { errorMessage, type EntryMeta, type RevealedSecret } from '$lib/types';

  let {
    entry,
    onEdit,
    onDeleted
  }: { entry: EntryMeta; onEdit: () => void; onDeleted: () => void } = $props();

  /**
   * Plaintext, held only while it is on screen.
   *
   * Never written to a store, localStorage, or the console. Cleared whenever the
   * selected entry changes — see the $effect below — so switching entries cannot
   * leave a previous secret hanging around in memory.
   */
  let revealed = $state<RevealedSecret | null>(null);
  let busy = $state('');
  let error = $state('');
  let copied = $state(false);

  $effect(() => {
    // Depend on the id so this re-runs on selection change.
    void entry.id;
    revealed = null;
    error = '';
    copied = false;
  });

  async function doReveal() {
    error = '';
    busy = 'reveal';
    try {
      revealed = await revealSecret(entry.id);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = '';
    }
  }

  function hide() {
    revealed = null;
  }

  async function doCopy() {
    error = '';
    busy = 'copy';
    copied = false;
    try {
      // The plaintext goes straight to the clipboard from Rust; nothing
      // sensitive comes back across the IPC boundary here.
      await copySecret(entry.id);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = '';
    }
  }

  async function doDelete() {
    if (!confirm(`Delete "${entry.label}"? This cannot be undone.`)) return;
    error = '';
    busy = 'delete';
    try {
      await deleteEntry(entry.id);
      revealed = null;
      onDeleted();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = '';
    }
  }

  const fmt = (ts: number | null) =>
    ts === null ? 'never' : new Date(ts * 1000).toLocaleString();
</script>

<div class="detail">
  <header>
    <div>
      <h2>{entry.label}</h2>
      <div class="tags">
        <span class="kind">{entry.kind}</span>
        {#each entry.tags as t (t)}<span class="tag">{t}</span>{/each}
      </div>
    </div>
    <button class="ghost" onclick={onEdit}>Edit</button>
  </header>

  {#if error}<div class="error">{error}</div>{/if}
  {#if copied}<div class="notice">Copied to the clipboard.</div>{/if}

  <div class="secret-box">
    {#if revealed}
      <div class="value mono">{revealed.secret}</div>
      {#if revealed.note}
        <div class="note-label">Note</div>
        <div class="value mono note">{revealed.note}</div>
      {/if}
    {:else}
      <div class="value hidden mono">••••••••••••••••</div>
    {/if}
  </div>

  <div class="actions">
    {#if revealed}
      <button onclick={hide}>Hide</button>
    {:else}
      <button onclick={doReveal} disabled={busy !== ''}>
        {busy === 'reveal' ? 'Decrypting…' : 'Reveal'}
      </button>
    {/if}
    <button class="primary" onclick={doCopy} disabled={busy !== ''}>
      {busy === 'copy' ? 'Copying…' : 'Copy secret'}
    </button>
    <span class="spacer"></span>
    <button class="danger ghost" onclick={doDelete} disabled={busy !== ''}>Delete</button>
  </div>

  <dl class="meta">
    <div><dt>Created</dt><dd>{fmt(entry.createdAt)}</dd></div>
    <div><dt>Updated</dt><dd>{fmt(entry.updatedAt)}</dd></div>
    <div><dt>Last used</dt><dd>{fmt(entry.lastUsedAt)}</dd></div>
    <div><dt>ID</dt><dd class="mono id">{entry.id}</dd></div>
  </dl>
</div>

<style>
  .detail { display: flex; flex-direction: column; gap: 14px; }
  header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  h2 { margin: 0 0 6px; font-size: 17px; font-weight: 600; word-break: break-word; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .kind, .tag {
    font-size: 11px; padding: 2px 7px; border-radius: 999px;
    border: 1px solid var(--border); color: var(--muted);
  }
  .kind { color: var(--accent); border-color: rgba(96, 165, 250, 0.4); }
  .secret-box { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; }
  .value { font-size: 13px; word-break: break-all; white-space: pre-wrap; user-select: text; }
  .value.hidden { color: var(--muted); letter-spacing: 2px; user-select: none; }
  .note-label { margin: 10px 0 4px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .note { color: var(--muted); }
  .actions { display: flex; gap: 8px; align-items: center; }
  .spacer { flex: 1; }
  .meta { display: grid; gap: 6px; margin: 0; font-size: 12px; }
  .meta > div { display: grid; grid-template-columns: 90px 1fr; }
  dt { color: var(--muted); }
  dd { margin: 0; }
  .id { font-size: 11px; word-break: break-all; user-select: text; }
</style>
