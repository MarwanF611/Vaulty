<script lang="ts">
  import type { EntryKind } from '$lib/types';

  /*
   * Drawn rather than taken from SF Symbols: those live in a private-use
   * Unicode range and render as tofu wherever SF Pro is not resolved, which
   * includes a webview on a non-Apple platform. These follow the same visual
   * grammar — 1.5px strokes, rounded caps, centred in a 16pt box.
   */
  let { kind, size = 14 }: { kind: EntryKind; size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
  {#if kind === 'password'}
    <rect x="3" y="7" width="10" height="7" rx="1.8" stroke="currentColor" stroke-width="1.4" />
    <path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" />
  {:else if kind === 'code'}
    <path d="M6 4.5 2.8 8 6 11.5M10 4.5 13.2 8 10 11.5" stroke="currentColor"
      stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  {:else if kind === 'note'}
    <path d="M4 2.6h8a1 1 0 0 1 1 1v8.8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V3.6a1 1 0 0 1 1-1Z"
      stroke="currentColor" stroke-width="1.4" />
    <path d="M5.6 6h4.8M5.6 8.6h4.8M5.6 11.2h2.8" stroke="currentColor" stroke-width="1.4"
      stroke-linecap="round" />
  {:else if kind === 'card'}
    <rect x="2.2" y="4" width="11.6" height="8" rx="1.6" stroke="currentColor"
      stroke-width="1.4" />
    <path d="M2.2 6.9h11.6" stroke="currentColor" stroke-width="1.4" />
    <path d="M4.6 9.6h2.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
  {:else}
    <path d="M1.8 6.2a9 9 0 0 1 12.4 0M4.2 8.7a5.6 5.6 0 0 1 7.6 0" stroke="currentColor"
      stroke-width="1.4" stroke-linecap="round" />
    <circle cx="8" cy="11.8" r="1.1" fill="currentColor" />
  {/if}
</svg>
