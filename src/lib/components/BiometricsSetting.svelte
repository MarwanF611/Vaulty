<script lang="ts">
  import { biometricState, disableBiometrics, enableBiometrics } from '$lib/api';
  import { errorMessage, isCmdError, type BiometricState } from '$lib/types';

  let { onChanged }: { onChanged?: () => void } = $props();

  let bio = $state<BiometricState | null>(null);
  let asking = $state(false);
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');

  $effect(() => {
    void load();
  });

  async function load() {
    try {
      bio = await biometricState();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  const name = $derived(bio?.displayName ?? 'Biometric unlock');

  /** Why the switch is unavailable, in a sentence, or null if it is usable. */
  const blocked = $derived.by(() => {
    if (!bio) return 'Checking…';
    switch (bio.availability) {
      case 'available':
        return null;
      case 'not_enrolled':
        return `No fingerprints are enrolled on this Mac. Add one in System Settings › Touch ID & Password.`;
      case 'locked_out':
        return `${name} is temporarily locked. Unlock your Mac with its password to re-enable it.`;
      case 'no_hardware':
        return 'This Mac has no biometric sensor.';
      default:
        return 'Biometric unlock is not supported on this platform.';
    }
  });

  async function toggle() {
    error = '';
    notice = '';
    if (!bio) return;

    if (bio.enabled) {
      busy = true;
      try {
        bio = await disableBiometrics();
        notice = `${name} turned off and the stored key removed.`;
        onChanged?.();
      } catch (e) {
        error = errorMessage(e);
      } finally {
        busy = false;
      }
    } else {
      // Enabling costs the master password — see enable_biometrics.
      asking = true;
    }
  }

  async function confirmEnable(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      bio = await enableBiometrics(password);
      password = '';
      asking = false;
      notice = `${name} is on. Your master password still works, and Vaulty will ask for it every couple of weeks.`;
      onChanged?.();
    } catch (err) {
      error =
        isCmdError(err) && err.code === 'auth'
          ? 'That is not your master password.'
          : errorMessage(err);
      password = '';
    } finally {
      busy = false;
    }
  }

  function cancel() {
    asking = false;
    password = '';
    error = '';
  }
</script>

<section>
  <h3 class="t-headline">Biometric unlock</h3>

  <div class="group">
    <div class="group-row">
      <div class="grow">
        <div class="t-body">{name}</div>
        <div class="t-subheadline secondary">
          {#if blocked}
            {blocked}
          {:else if bio?.enabled}
            On. Your master password always works as well.
          {:else}
            Unlock without typing your master password every time.
          {/if}
        </div>
      </div>

      <span class="switch">
        <input
          type="checkbox"
          checked={bio?.enabled ?? false}
          disabled={busy || !!blocked}
          onchange={toggle}
          aria-label="Enable {name}"
        />
        <span class="track"></span>
        <span class="thumb"></span>
      </span>
    </div>

    {#if bio?.enabled}
      <div class="group-row">
        <div class="grow">
          <div class="t-body">Master password reminder</div>
          <div class="t-subheadline secondary">
            {#if bio.passwordDue}
              Due at your next unlock.
            {:else}
              In {bio.daysUntilPasswordDue}
              {bio.daysUntilPasswordDue === 1 ? 'day' : 'days'}.
            {/if}
          </div>
        </div>
      </div>

      {#if !bio.keyPresent}
        <div class="group-row">
          <div class="banner warn grow">
            The stored key is missing from the keychain — {name} will not work until you turn it
            off and on again.
          </div>
        </div>
      {/if}
    {/if}
  </div>

  {#if asking}
    <form class="ask" onsubmit={confirmEnable}>
      <p class="t-callout secondary">
        Enter your master password to turn on {name}. Vaulty stores a key in the
        {' '}<span class="mono">keychain</span> that only {name} can read — never your password.
      </p>
      <div class="row">
        <!-- svelte-ignore a11y_autofocus -->
        <input type="password" bind:value={password} placeholder="Master password"
          autocomplete="off" autofocus disabled={busy} />
        <button class="primary" type="submit" disabled={busy || !password}>
          {busy ? 'Setting up…' : 'Turn On'}
        </button>
        <button type="button" onclick={cancel} disabled={busy}>Cancel</button>
      </div>
    </form>
  {/if}

  {#if error}<div class="banner error">{error}</div>{/if}
  {#if notice}<div class="banner ok">{notice}</div>{/if}

  <p class="t-footnote tertiary">
    A fingerprint is not a key. Touch ID gates a key held in the macOS keychain; adding a new
    fingerprint invalidates it and Vaulty falls back to your master password.
  </p>
</section>

<style>
  section { display: flex; flex-direction: column; gap: var(--s2); }
  h3 { margin: 0; }
  .ask { display: flex; flex-direction: column; gap: var(--s2); }
  .ask p { margin: 0; }
  .row { display: flex; gap: var(--s2); align-items: center; }
  .row input { flex: 1; }
  .row button { flex: none; }
  p { margin: 0; line-height: 1.45; }
</style>
