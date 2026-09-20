<script lang="ts">
  import { copySecret, deleteEntry, revealSecret } from '$lib/api';
  import { errorMessage, type EntryMeta, type RevealedSecret } from '$lib/types';
  import KindIcon from './KindIcon.svelte';

  let {
    entry,
    onEdit,
    onDeleted
  }: { entry: EntryMeta; onEdit: () => void; onDeleted: () => void } = $props();

  /**
   * Plaintext, held only while on screen. Never stored, never logged, cleared
   * whenever the selection changes.
   */
  let revealed = $state<RevealedSecret | null>(null);
  let busy = $state('');
  let error = $state('');
  let copied = $state(false);

  $effect(() => {
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

  async function doCopy() {
    error = '';
    busy = 'copy';
    copied = false;
    try {
      // Written to the clipboard in Rust; no plaintext returns here.
      await copySecret(entry.id);
      copied = true;
      setTimeout(() => (copied = false), 2200);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = '';
    }
  }

  async function doDelete() {
    if (!confirm(`Delete “${entry.label}”?\n\nThis cannot be undone.`)) return;
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
    ts === null
      ? 'Never'
      : new Date(ts * 1000).toLocaleString(undefined, {
          dateStyle: 'medium',
          timeStyle: 'short'
        });
</script>

<div class="detail">
  <header>
    <span class="icon"><KindIcon kind={entry.kind} size={19} /></span>
    <div class="grow">
      <h2 class="t-title-2">{entry.label}</h2>
      <div class="tags">
        <span class="tag kind">{entry.kind}</span>
        {#each entry.tags as t (t)}<span class="tag">{t}</span>{/each}
      </div>
    </div>
    <button onclick={onEdit}>Edit</button>
  </header>

  {#if error}<div class="banner error">{error}</div>{/if}
  {#if copied}<div class="banner ok">Copied — clears from the clipboard shortly.</div>{/if}

  <div class="group">
    <div class="group-row secret">
      <div class="grow">
        <div class="t-subheadline secondary">Secret</div>
        {#if revealed}
          <div class="mono value selectable">{revealed.secret}</div>
        {:else}
          <div class="mono value masked">••••••••••••••••</div>
        {/if}
      </div>
      <button class="plain" onclick={revealed ? () => (revealed = null) : doReveal}
        disabled={busy !== ''}>
        {revealed ? 'Hide' : busy === 'reveal' ? 'Decrypting…' : 'Show'}
      </button>
      <button class="primary" onclick={doCopy} disabled={busy !== ''}>
        {busy === 'copy' ? 'Copying…' : 'Copy'}
      </button>
    </div>

    {#if revealed?.note}
      <div class="group-row">
        <div class="grow">
          <div class="t-subheadline secondary">Note</div>
          <div class="mono value note selectable">{revealed.note}</div>
        </div>
      </div>
    {/if}
  </div>

  <div class="group">
    <div class="group-row"><span class="grow t-body">Created</span>
      <span class="t-callout secondary">{fmt(entry.createdAt)}</span></div>
    <div class="group-row"><span class="grow t-body">Modified</span>
      <span class="t-callout secondary">{fmt(entry.updatedAt)}</span></div>
    <div class="group-row"><span class="grow t-body">Last used</span>
      <span class="t-callout secondary">{fmt(entry.lastUsedAt)}</span></div>
    <div class="group-row"><span class="grow t-body">Identifier</span>
      <span class="mono t-footnote tertiary selectable">{entry.id}</span></div>
  </div>

  <div class="foot">
    <button class="destructive" onclick={doDelete} disabled={busy !== ''}>Delete Entry</button>
  </div>
</div>

<style>
  .detail { display: flex; flex-direction: column; gap: var(--s4); max-width: 560px; }
  header { display: flex; align-items: flex-start; gap: var(--s3); }
  .icon {
    flex: none;
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: var(--accent);
    color: #fff;
  }
  .grow { flex: 1; min-width: 0; }
  h2 { margin: 0 0 3px; word-break: break-word; }
  .tags { display: flex; flex-wrap: wrap; gap: var(--s1); }
  .tag {
    font-size: 10px;
    padding: 1px 7px;
    border-radius: var(--r-pill);
    background: var(--fill-quaternary);
    color: var(--label-secondary);
  }
  .tag.kind { color: var(--accent); }
  .secret { align-items: center; }
  .value { margin-top: 2px; word-break: break-all; white-space: pre-wrap; }
  .masked { color: var(--label-tertiary); letter-spacing: 2px; }
  .note { color: var(--label-secondary); }
  .foot { display: flex; }
</style>
