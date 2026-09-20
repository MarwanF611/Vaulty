import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // Tauri drives the dev server on a fixed port and needs a stable origin.
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**', '**/target/**'] }
  },
  build: {
    // Tauri v2 targets modern webviews; no legacy transpilation needed.
    target: 'esnext',
    // Never ship source maps: they make reading the app's internals trivial.
    sourcemap: false
  }
});
