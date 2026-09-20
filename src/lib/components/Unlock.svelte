<script lang="ts">
  import { biometricState, unlockVault, unlockWithBiometrics } from '$lib/api';
  import { errorMessage, isCmdError, type BiometricState, type VaultStatus } from '$lib/types';

  /*
   * Unlocking only. Creating a vault is Onboarding's job, so this screen does
   * not carry a "verify password" field or the no-recovery warning — those
   * belong where the decision is made.
   */

  let {
    status,
    onUnlocked,
    lockNotice = ''
  }: {
    status: VaultStatus;
    onUnlocked: (s: VaultStatus) => void;
    /** Why the vault locked itself, if it did. */
    lockNotice?: string;
  } = $props();

  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let bio = $state<BiometricState | null>(null);

  $effect(() => {
    void loadBiometrics();
  });

  async function loadBiometrics() {
    try {
      bio = await biometricState();
    } catch {
      bio = null;
    }
  }

  async function useBiometrics() {
    if (!bio?.canUnlock) return;
    error = '';
    busy = true;
    try {
      onUnlocked((await unlockWithBiometrics()).status);
    } catch (e) {
      // Never a silent unlock and never a retry loop: fall to the password
      // field, with a reason unless the user simply cancelled (SECURITY.md).
      error = isCmdError(e) && e.code === 'biometric_cancelled' ? '' : errorMessage(e);
      await loadBiometrics();
    } finally {
      busy = false;
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (!password) {
      error = 'Enter your master password.';
      return;
    }

    busy = true;
    try {
      const next = await unlockVault(password);
      password = '';
      onUnlocked(next);
    } catch (e) {
      // `auth` covers a wrong password and a tampered file alike, and the
      // wording stays identical on purpose.
      error =
        isCmdError(e) && e.code === 'auth' ? 'Could not unlock the vault.' : errorMessage(e);
      password = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="screen">
  <form class="panel" onsubmit={submit}>
    <div class="mark" aria-hidden="true">
      <svg width="30" height="38" viewBox="0 0 30 38" fill="none">
        <path d="M15 1.5 3 6.2v11.4c0 8.2 5.1 15.4 12 18.9 6.9-3.5 12-10.7 12-18.9V6.2L15 1.5Z"
          stroke="currentColor" stroke-width="2.2" stroke-linejoin="round" />
        <circle cx="15" cy="16" r="3.4" fill="currentColor" />
        <path d="M15 19.4v5.2" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" />
      </svg>
    </div>

    <h1 class="t-title-1">Vaulty</h1>
    <p class="t-callout secondary lede">Enter your master password.</p>

    {#if lockNotice && !error}<div class="banner info">{lockNotice}</div>{/if}
    {#if error}<div class="banner error">{error}</div>{/if}

    {#if bio?.enabled && bio.passwordDue}
      <div class="banner info">
        Time for your master password — Vaulty asks every couple of weeks so it stays in
        memory.
      </div>
    {/if}

    <div class="field">
      <label for="pw">Password</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="pw" type="password" bind:value={password} autocomplete="off" autofocus
        disabled={busy} />
    </div>

    <button class="primary wide" type="submit" disabled={busy}>
      {busy ? 'Unlocking…' : 'Unlock'}
    </button>

    {#if bio?.canUnlock}
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
    {:else if bio?.enabled && bio.availability === 'locked_out'}
      <p class="t-subheadline secondary note">
        {bio.displayName ?? 'Biometrics'} is locked. Unlock once with your password to
        re-enable it.
      </p>
    {:else if bio?.enabled && !bio.keyPresent}
      <p class="t-subheadline secondary note">
        The stored {bio.displayName ?? 'biometric'} key is gone. Unlock with your password and
        set it up again in Settings.
      </p>
    {/if}

    <p class="t-footnote tertiary path selectable">{status.path}</p>
  </form>
</div>

<style>
  .screen { display: grid; place-items: center; min-height: 100vh; padding: var(--s6); }
  .panel {
    width: 100%;
    max-width: 330px;
    display: flex;
    flex-direction: column;
    text-align: center;
  }
  .mark { color: var(--accent); margin: 0 auto var(--s3); }
  h1 { margin: 0 0 2px; }
  .lede { margin: 0 0 var(--s4); }
  .field { text-align: left; }
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
