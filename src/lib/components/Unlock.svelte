<script lang="ts">
  import { createVault, unlockVault } from '$lib/api';
  import { errorMessage, isCmdError, type VaultStatus } from '$lib/types';

  let { status, onUnlocked }: { status: VaultStatus; onUnlocked: (s: VaultStatus) => void } =
    $props();

  // Held only for the duration of the form. Cleared the moment it is used.
  let password = $state('');
  let confirmPassword = $state('');
  let busy = $state(false);
  let error = $state('');

  const creating = $derived(!status.exists);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';

    if (creating && password !== confirmPassword) {
      error = 'The two passwords do not match.';
      return;
    }
    if (!password) {
      error = 'Enter your master password.';
      return;
    }

    busy = true;
    try {
      const next = creating ? await createVault(password) : await unlockVault(password);
      // Drop the password from the component before handing control onward.
      password = '';
      confirmPassword = '';
      onUnlocked(next);
    } catch (e) {
      // `auth` covers both a wrong password and a tampered file, and the
      // message stays identical on purpose (see vault-core/src/error.rs).
      error = isCmdError(e) && e.code === 'auth'
        ? 'Could not unlock the vault.'
        : errorMessage(e);
      password = '';
      confirmPassword = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit}>
    <h1>Vaulty</h1>

    {#if creating}
      <p class="lede">Create your vault.</p>
      <div class="warn">
        <strong>There is no password recovery.</strong>
        If you forget this password, every secret in the vault is gone permanently.
        Nobody can reset it — not us, not anyone.
      </div>
    {:else}
      <p class="lede">Unlock to continue.</p>
    {/if}

    {#if error}<div class="error">{error}</div>{/if}

    <div class="field">
      <label for="pw">{creating ? 'Choose a master password' : 'Master password'}</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        id="pw"
        type="password"
        bind:value={password}
        autocomplete="off"
        autofocus
        disabled={busy}
      />
    </div>

    {#if creating}
      <div class="field">
        <label for="pw2">Repeat it</label>
        <input id="pw2" type="password" bind:value={confirmPassword} autocomplete="off" disabled={busy} />
      </div>
    {/if}

    <button class="primary" type="submit" disabled={busy} style="width:100%">
      {busy ? 'Working…' : creating ? 'Create vault' : 'Unlock'}
    </button>

    <p class="path mono">{status.path}</p>
  </form>
</div>

<style>
  .wrap { display: grid; place-items: center; min-height: 100vh; padding: 24px; }
  .card {
    width: 100%; max-width: 380px; background: var(--panel);
    border: 1px solid var(--border); border-radius: 12px; padding: 24px;
  }
  h1 { margin: 0 0 2px; font-size: 20px; letter-spacing: -0.01em; }
  .lede { margin: 0 0 16px; color: var(--muted); font-size: 13px; }
  .warn {
    background: rgba(251, 191, 36, 0.08); border: 1px solid rgba(251, 191, 36, 0.3);
    color: #fcd34d; padding: 10px; border-radius: var(--radius);
    margin-bottom: 16px; font-size: 12.5px; line-height: 1.5;
  }
  .path { margin: 14px 0 0; font-size: 11px; color: var(--muted); word-break: break-all; }
</style>
