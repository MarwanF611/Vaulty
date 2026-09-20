<script lang="ts">
  import { createVault } from '$lib/api';
  import { errorMessage, type VaultStatus } from '$lib/types';

  /*
   * First run. PHASES.md: "First-run onboarding that states plainly there is no
   * password recovery."
   *
   * Plainly means two things here. The threat model is stated before the
   * password is chosen, in the same words as the README — overclaiming is how
   * vault products get taken apart publicly. And the no-recovery fact needs a
   * deliberate acknowledgement rather than a banner someone scrolls past,
   * because it is the one property of this app that cannot be undone later.
   */

  let { status, onCreated }: { status: VaultStatus; onCreated: (s: VaultStatus) => void } =
    $props();

  let step = $state<'intro' | 'password'>('intro');
  let password = $state('');
  let confirmPassword = $state('');
  let acknowledged = $state(false);
  let busy = $state(false);
  let error = $state('');

  const strength = $derived.by(() => {
    const p = password;
    if (!p) return null;
    if (p.length < 8) return { label: 'Too short', tone: 'bad' as const };
    if (p.length < 12) return { label: 'Weak', tone: 'bad' as const };
    if (p.length < 20) return { label: 'Reasonable', tone: 'ok' as const };
    return { label: 'Strong', tone: 'good' as const };
  });

  async function create(e: SubmitEvent) {
    e.preventDefault();
    error = '';

    if (password.length < 8) {
      error = 'Use at least 8 characters. A passphrase of a few words is easier to remember.';
      return;
    }
    if (password !== confirmPassword) {
      error = 'Those two passwords do not match.';
      return;
    }
    if (!acknowledged) {
      error = 'Please confirm you understand there is no password recovery.';
      return;
    }

    busy = true;
    try {
      const next = await createVault(password);
      password = '';
      confirmPassword = '';
      onCreated(next);
    } catch (err) {
      error = errorMessage(err);
      password = '';
      confirmPassword = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="screen">
  <div class="panel">
    {#if step === 'intro'}
      <div class="mark" aria-hidden="true">
        <svg width="34" height="42" viewBox="0 0 30 38" fill="none">
          <path d="M15 1.5 3 6.2v11.4c0 8.2 5.1 15.4 12 18.9 6.9-3.5 12-10.7 12-18.9V6.2L15 1.5Z"
            stroke="currentColor" stroke-width="2.2" stroke-linejoin="round" />
          <circle cx="15" cy="16" r="3.4" fill="currentColor" />
          <path d="M15 19.4v5.2" stroke="currentColor" stroke-width="2.2"
            stroke-linecap="round" />
        </svg>
      </div>

      <h1 class="t-title-1">Welcome to Vaulty</h1>
      <p class="t-body secondary lede">
        Select text anywhere, press the shortcut, give it a label. It is encrypted on disk
        before it touches anything else.
      </p>

      <div class="group">
        <div class="group-row col">
          <div class="t-headline">What this protects against</div>
          <div class="t-callout secondary">
            A stolen laptop, a stolen backup drive, someone copying your vault file, and the
            vault ending up in a cloud backup.
          </div>
        </div>
        <div class="group-row col">
          <div class="t-headline">What it does not</div>
          <div class="t-callout secondary">
            Malware already running as you, a keylogger, a kernel-level attacker, or someone
            reading your screen. No password manager does.
          </div>
        </div>
        <div class="group-row col">
          <div class="t-headline">Everything stays on this Mac</div>
          <div class="t-callout secondary">
            Vaulty makes no network connections. There is no account and nothing to sign in to.
          </div>
        </div>
      </div>

      <button class="primary wide" onclick={() => (step = 'password')}>Continue</button>
    {:else}
      <h1 class="t-title-2">Choose a master password</h1>
      <p class="t-callout secondary lede">
        This is the only thing standing between your secrets and anyone who has this file. A
        passphrase of four or five unrelated words beats a short complicated one.
      </p>

      <div class="banner warn">
        <span>
          <strong>There is no password recovery.</strong> Vaulty cannot reset it, and neither
          can anyone else — not by email, not by support request, not ever. If you forget this
          password, everything in the vault is gone permanently.
        </span>
      </div>

      {#if error}<div class="banner error">{error}</div>{/if}

      <form onsubmit={create}>
        <div class="field">
          <label for="pw">Master password</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input id="pw" type="password" bind:value={password} autocomplete="off" autofocus
            disabled={busy} />
          {#if strength}
            <div class="t-footnote strength {strength.tone}">{strength.label}</div>
          {/if}
        </div>

        <div class="field">
          <label for="pw2">Verify</label>
          <input id="pw2" type="password" bind:value={confirmPassword} autocomplete="off"
            disabled={busy} />
        </div>

        <label class="ack">
          <input type="checkbox" bind:checked={acknowledged} disabled={busy} />
          <span class="t-callout">
            I understand that if I forget this password, my secrets cannot be recovered.
          </span>
        </label>

        <div class="actions">
          <button type="button" onclick={() => (step = 'intro')} disabled={busy}>Back</button>
          <button type="submit" class="primary" disabled={busy}>
            {busy ? 'Creating…' : 'Create Vault'}
          </button>
        </div>
      </form>
    {/if}

    <p class="t-footnote tertiary path selectable">{status.path}</p>
  </div>
</div>

<style>
  .screen { display: grid; place-items: center; min-height: 100vh; padding: var(--s6); }
  .panel {
    width: 100%;
    max-width: 400px;
    display: flex;
    flex-direction: column;
    gap: var(--s3);
  }
  .mark { color: var(--accent); }
  h1 { margin: 0; }
  .lede { margin: 0; line-height: 1.5; }
  .group-row.col { flex-direction: column; align-items: flex-start; gap: 2px; }
  .wide { width: 100%; min-height: 28px; }
  form { display: flex; flex-direction: column; }
  .strength { margin-top: 3px; }
  .strength.bad { color: var(--red); }
  .strength.ok { color: var(--orange); }
  .strength.good { color: var(--green); }
  .ack {
    display: flex;
    gap: var(--s2);
    align-items: flex-start;
    margin: var(--s1) 0 var(--s3);
    font-size: 12px;
    color: var(--label);
  }
  .ack input { width: auto; min-height: 0; margin: 1px 0 0; flex: none; }
  .actions { display: flex; gap: var(--s2); justify-content: flex-end; }
  .path { word-break: break-all; margin: var(--s2) 0 0; }
</style>
