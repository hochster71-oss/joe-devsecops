import { defineConfig } from 'vite';

// NOTE: The main process (main.js) is built using esbuild via forge.config.ts
// packageAfterCopy hook, NOT via this Vite config. This file exists for
// compatibility with electron-forge-plugin-vite but is not actively used
// for the main process build.
//
// The esbuild approach was necessary because plugin-vite has issues generating
// the main.js file correctly for this project's configuration.

export default defineConfig({
  build: {
    rollupOptions: {
      external: [
        'electron',
        'electron-squirrel-startup',
        'better-sqlite3',
        '@kubernetes/client-node',
        'electron-store'
      ]
    }
  }
});
