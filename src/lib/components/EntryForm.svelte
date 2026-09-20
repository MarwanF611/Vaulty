<script lang="ts">
  import { addEntry, updateEntry } from '$lib/api';
  import { ENTRY_KINDS, errorMessage, type EntryKind, type EntryMeta } from '$lib/types';

  let {
    existing = null,
    onSaved,
    onCancel
  }: {
    existing?: EntryMeta | null;
    onSaved: (m: EntryMeta) => void;
    onCancel: () => void;
  } = $props();

  const editing = $derived(existing !== null);

  // These intentionally seed from `existing` once and then belong to the form:
  // they are what the user is typing, not a view of the prop. The caller
  // remounts this component per entry (see the {#key} in +page.svelte), so a
  // stale instance cannot survive a selection change.
  // svelte-ignore state_referenced_locally
  let label = $state(existing?.label ?? '');
  // svelte-ignore state_referenced_locally
  let tagsText = $state(existing?.tags.join(', ') ?? '');
  // svelte-ignore state_referenced_locally
  let kind = $state<EntryKind>(existing?.kind ?? 'password');
  // On edit these start empty and are only sent if the user types something:
  // the form never loads the existing secret, so editing a label cannot leak it.
  let secret = $state('');
  let note = $state('');
  let busy = $state(false);
  let error = $state('');

  const tags = $derived(
    tagsText.split(',').map((t) => t.trim()).filter(Boolean)
  );

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';

    if (!label.trim()) {
      error = 'A label is required.';
      return;
    }
    if (!editing && !secret) {
      error = 'A secret is required.';
      return;
    }

    busy = true;
    try {
      let saved: EntryMeta;
      if (editing && existing) {
        saved = await updateEntry(existing.id, {
          label: label.trim(),
          tags,
          kind,
          // Only send what changed. An empty field means "leave it".
          ...(secret ? { secret } : {}),
          ...(note ? { note } : {})
        });
      } else {
        saved = await addEntry({
          label: label.trim(),
          tags,
          kind,
          secret,
          note: note || null
        });
      }
      // Clear plaintext out of the component as soon as it is stored.
      secret = '';
      note = '';
      onSaved(saved);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={submit}>
  <h2>{editing ? 'Edit entry' : 'New entry'}</h2>

  {#if error}<div class="error">{error}</div>{/if}

  <div class="field">
    <label for="label">Label</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input id="label" bind:value={label} autocomplete="off" autofocus disabled={busy} />
  </div>

  <div class="row">
    <div class="field">
      <label for="kind">Kind</label>
      <select id="kind" bind:value={kind} disabled={busy}>
        {#each ENTRY_KINDS as k (k)}<option value={k}>{k}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label for="tags">Tags (comma separated)</label>
      <input id="tags" bind:value={tagsText} autocomplete="off" disabled={busy} />
    </div>
  </div>

  <div class="field">
    <label for="secret">
      Secret {#if editing}<span class="muted">— leave blank to keep the current one</span>{/if}
    </label>
    <input id="secret" type="password" bind:value={secret} autocomplete="off" disabled={busy} />
  </div>

  <div class="field">
    <label for="note">
      Note {#if editing}<span class="muted">— leave blank to keep the current one</span>{/if}
    </label>
    <textarea id="note" bind:value={note} disabled={busy}></textarea>
  </div>

  <div class="actions">
    <button type="button" class="ghost" onclick={onCancel} disabled={busy}>Cancel</button>
    <button type="submit" class="primary" disabled={busy}>
      {busy ? 'Saving…' : editing ? 'Save changes' : 'Add entry'}
    </button>
  </div>
</form>

<style>
  h2 { margin: 0 0 16px; font-size: 15px; font-weight: 600; }
  .row { display: grid; grid-template-columns: 140px 1fr; gap: 12px; }
  .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }
</style>
