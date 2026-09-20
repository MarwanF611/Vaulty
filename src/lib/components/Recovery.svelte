<script lang="ts">
  import { listSnapshots, restoreSnapshot } from '$lib/api';
  import { errorMessage, type SnapshotInfo, type VaultStatus } from '$lib/types';

  let { status, onRestored }: { status: VaultStatus; onRestored: (s: VaultStatus) => void } =
    $props();

  let snapshots = $state<SnapshotInfo[]>([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');

  $effect(() => {
    void load();
  });

  async function load() {
    try {
      snapshots = await listSnapshots();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }

  async function restore(index: number) {
    if (
      !confirm(
        'Replace the current vault file with this snapshot?\n\n' +
          'The current file is kept alongside it as .prerestore, so this can be undone.'
      )
    )
      return;
    error = '';
    busy = true;
    try {
      onRestored(await restoreSnapshot(index));
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  const when = (s: SnapshotInfo) =>
    s.modifiedAt
      ? new Date(s.modifiedAt * 1000).toLocaleString(undefined, {
          dateStyle: 'medium',
          timeStyle: 'short'
        })
      : 'Unknown date';

  const size = (b: number) =>
    b > 1024 * 1024 ? `${(b / 1024 / 1024).toFixed(1)} MB` : `${Math.round(b / 1024)} KB`;
</script>

<div class="screen">
  <div class="panel">
    <div class="mark" aria-hidden="true">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none">
        <path d="M12 3.2 2.6 19.4h18.8L12 3.2Z" stroke="currentColor" stroke-width="1.8"
          stroke-linejoin="round" />
        <path d="M12 9.6v4.2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
        <circle cx="12" cy="16.6" r="1" fill="currentColor" />
      </svg>
    </div>

    <h1 class="t-title-2">This vault cannot be opened</h1>
    <p class="t-callout secondary lede">
      The file is there, but its header is unreadable — a truncated write, a bad sector, or an
      interrupted copy. Your master password cannot help with this.
    </p>

    {#if error}<div class="banner error">{error}</div>{/if}

    {#if loading}
      <p class="t-callout secondary">Looking for snapshots…</p>
    {:else if snapshots.length === 0}
      <div class="banner warn">
        No snapshots were found next to the vault. If you have an encrypted backup
        (<span class="mono">.vaultybak</span>), restore it by replacing the vault file.
      </div>
    {:else}
      <p class="t-subheadline secondary">
        Vaulty keeps the last three snapshots. Restoring replaces the damaged file and keeps it
        alongside as <span class="mono">.prerestore</span>.
      </p>
      <div class="group">
        {#each snapshots as s (s.index)}
          <div class="group-row">
            <div class="grow">
              <div class="t-body">{s.index === 1 ? 'Most recent' : `Snapshot ${s.index}`}</div>
              <div class="t-subheadline secondary">{when(s)} · {size(s.sizeBytes)}</div>
            </div>
            <button class={s.index === 1 ? 'primary' : ''} disabled={busy}
              onclick={() => restore(s.index)}>Restore</button>
          </div>
        {/each}
      </div>
    {/if}

    <p class="t-footnote tertiary path selectable">{status.path}</p>
  </div>
</div>

<style>
  .screen { display: grid; place-items: center; min-height: 100vh; padding: var(--s6); }
  .panel { width: 100%; max-width: 420px; display: flex; flex-direction: column; gap: var(--s3); }
  .mark { color: var(--orange); }
  h1 { margin: 0; }
  .lede { margin: 0; line-height: 1.5; }
  p { margin: 0; }
  .path { word-break: break-all; margin-top: var(--s2); }
</style>
