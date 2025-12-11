#!/usr/bin/env node
/**
 * J.O.E. Electron Launcher
 *
 * This script removes the ELECTRON_RUN_AS_NODE environment variable
 * before launching electron-forge to prevent VS Code extension conflicts.
 */

const { spawn } = require('child_process');
const path = require('path');

// Create a clean environment without ELECTRON_RUN_AS_NODE
// This is critical for VS Code which sets ELECTRON_RUN_AS_NODE=1
const cleanEnv = { ...process.env };

// Explicitly unset ELECTRON_RUN_AS_NODE - delete and set to empty
delete cleanEnv.ELECTRON_RUN_AS_NODE;
cleanEnv.ELECTRON_RUN_AS_NODE = '';  // Also set to empty string to override

// Also unset any other problematic Electron variables
delete cleanEnv.ELECTRON_NO_ATTACH_CONSOLE;
cleanEnv.ELECTRON_NO_ATTACH_CONSOLE = '';

console.log('[J.O.E. Launcher] Starting with clean environment...');
console.log('[J.O.E. Launcher] ELECTRON_RUN_AS_NODE:', process.env.ELECTRON_RUN_AS_NODE || '(not set)');

// Get the command to run (default to 'start')
const command = process.argv[2] || 'start';

// Determine the correct npx command based on platform
const isWin = process.platform === 'win32';
const npx = isWin ? 'npx.cmd' : 'npx';

// Spawn electron-forge with CLEAN environment (no ELECTRON_RUN_AS_NODE)
const child = spawn(npx, ['electron-forge', command], {
  cwd: path.join(__dirname, '..'),
  env: cleanEnv,  // Use clean environment WITHOUT ELECTRON_RUN_AS_NODE
  stdio: 'inherit',
  shell: true
});

child.on('exit', (code) => {
  process.exit(code || 0);
});
