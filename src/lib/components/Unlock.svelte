<script lang="ts">
  import { biometricState, createVault, unlockVault, unlockWithBiometrics } from '$lib/api';
  import { errorMessage, isCmdError, type BiometricState, type VaultStatus } from '$lib/types';

  let { status, onUnlocked }: { status: VaultStatus; onUnlocked: (s: VaultStatus) => void } =
    $props();

  let password = $state('');
  let confirmPassword = $state('');
  let busy = $state(false);
  let error = $state('');
  let bio = $state<BiometricState | null>(null);
  let bioAttempted = $state(false);

  const creating = $derived(!status.exists);

  $effect(() => {
    if (creating) return;
    void loadBiometrics();
  });

  async function loadBiometrics() {
    try {
      bio = await biometricState();
      // Offer it, do not fire it. An unprompted Touch ID sheet on launch is
      // startling, and SECURITY.md is clear that biometrics is convenience
      // over the password rather than a replacement for deciding to unlock.
    } catch {
      bio = null;
    }
  }

  async function useBiometrics() {
    if (!bio?.canUnlock) return;
    error = '';
    busy = true;
    bioAttempted = true;
    try {
      const outcome = await unlockWithBiometrics();
      onUnlocked(outcome.status);
    } catch (e) {
      // Never a silent unlock, and never a retry loop: fall to the password
      // field with an explanation (SECURITY.md).
      if (isCmdError(e) && e.code === 'biometric_cancelled') {
        error = '';
      } else {
        error = errorMessage(e);
      }
      await loadBiometrics();
    } finally {
      busy = false;
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';

    if (creating && password !== confirmPassword) {
      error = 'Those two passwords do not match.';
      return;
    }
    if (!password) {
      error = 'Enter your master password.';
      return;
    }

    busy = true;
    try {
      const next = creating ? await createVault(password) : await unlockVault(password);
      password = '';
      confirmPassword = '';
      onUnlocked(next);
    } catch (e) {
      error =
        isCmdError(e) && e.code === 'auth' ? 'Could not unlock the vault.' : errorMessage(e);
      password = '';
      confirmPassword = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="screen">
  <form class="panel" onsubmit={submit}>
    <div class="mark" aria-hidden="true">
      <svg width="30" height="38" viewBox="0 0 30 38" fill="none">
        <path
          d="M15 1.5 3 6.2v11.4c0 8.2 5.1 15.4 12 18.9 6.9-3.5 12-10.7 12-18.9V6.2L15 1.5Z"
          stroke="currentColor" stroke-width="2.2" stroke-linejoin="round" />
        <circle cx="15" cy="16" r="3.4" fill="currentColor" />
        <path d="M15 19.4v5.2" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" />
      </svg>
    </div>

    <h1 class="t-title-1">{creating ? 'Create your vault' : 'Vaulty'}</h1>
    <p class="t-callout secondary lede">
      {creating ? 'One password protects everything inside.' : 'Enter your master password.'}
    </p>

    {#if creating}
      <div class="banner warn">
        <span>
          <strong>There is no password recovery.</strong> If you forget it, everything in the
          vault is gone permanently — not recoverable by us or by anyone.
        </span>
      </div>
    {/if}

    {#if error}<div class="banner error">{error}</div>{/if}

    {#if bio?.passwordDue && bio.enabled && !creating}
      <div class="banner info">
        Time for your master password — Vaulty asks every {bio.daysUntilPasswordDue === 0
          ? 'couple of weeks'
          : 'couple of weeks'} so it stays in memory.
      </div>
    {/if}

    <div class="field">
      <label for="pw">{creating ? 'Master password' : 'Password'}</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="pw" type="password" bind:value={password} autocomplete="off" autofocus
        disabled={busy} />
    </div>

    {#if creating}
      <div class="field">
        <label for="pw2">Verify</label>
        <input id="pw2" type="password" bind:value={confirmPassword} autocomplete="off"
          disabled={busy} />
      </div>
    {/if}

    <button class="primary wide" type="submit" disabled={busy}>
      {busy ? 'Unlocking…' : creating ? 'Create Vault' : 'Unlock'}
    </button>

    {#if !creating && bio?.canUnlock}
      <button type="button" class="plain wide bio" onclick={useBiometrics} disabled={busy}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3c-2 0-3.8.7-5.2 1.9M12 3c2 0 3.8.7 5.2 1.9M3.6 9.4A9 9 0 0 1 6 6.2
                   M20.4 9.4A9 9 0 0 0 18 6.2M4 14c0-1.3.2-2.5.6-3.6M20 14c0-1.3-.2-2.5-.6-3.6
                   M8 12a4 4 0 0 1 8 0c0 3-.5 5.7-1.4 8M12 12v4c0 2-.3 3.9-.8 5.6
                   M16 16.5c-.3 2-.8 3.8-1.5 5.4M7.2 19.5A16 16 0 0 0 8 15.5"
            stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
        </svg>
        Use {bio.displayName ?? 'biometrics'}
      </button>
    {:else if !creating && bio?.enabled && bio.availability === 'locked_out'}
      <p class="t-subheadline secondary note">
        {bio.displayName ?? 'Biometrics'} is locked. Unlock once with your password to re-enable it.
      </p>
    {:else if !creating && bio?.enabled && !bio.keyPresent}
      <p class="t-subheadline secondary note">
        The stored {bio.displayName ?? 'biometric'} key is gone. Unlock with your password and set
        it up again in Settings.
      </p>
    {/if}

    <p class="t-footnote tertiary path selectable">{status.path}</p>
  </form>
</div>

<style>
  .screen {
    display: grid;
    place-items: center;
    min-height: 100vh;
    padding: var(--s6);
    background: var(--window-bg);
  }
  .panel {
    width: 100%;
    max-width: 330px;
    display: flex;
    flex-direction: column;
    align-items: stretch;
    text-align: center;
  }
  .mark { color: var(--accent); margin: 0 auto var(--s3); }
  h1 { margin: 0 0 2px; }
  .lede { margin: 0 0 var(--s4); }
  .field { text-align: left; }
  label { text-align: left; }
  .wide { width: 100%; min-height: 28px; }
  .bio {
    margin-top: var(--s2);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  .note { margin: var(--s2) 0 0; }
  .path { margin: var(--s4) 0 0; word-break: break-all; }
  .banner { margin-bottom: var(--s3); text-align: left; }
</style>
