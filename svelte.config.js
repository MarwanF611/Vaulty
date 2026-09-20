import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
export default {
  preprocess: vitePreprocess(),
  kit: {
    // Tauri serves a static bundle from disk. No SSR, no Node adapter.
    adapter: adapter({ fallback: 'index.html' })
  }
};
