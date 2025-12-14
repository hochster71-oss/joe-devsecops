#!/usr/bin/env node
/**
 * Add data-testid attributes to critical UI elements
 * Run this script when the dev server is not running
 *
 * Usage: node scripts/add-testids.js
 */

const fs = require('fs');
const path = require('path');

const TESTID_MAPPINGS = [
  // LoginView.tsx - Main login form
  {
    file: 'src/renderer/views/LoginView.tsx',
    replacements: [
      {
        find: 'id="username"',
        add: 'data-testid="login-username-input"',
        after: 'autoComplete="username"'
      },
      {
        find: 'id="password"',
        add: 'data-testid="login-password-input"',
        after: 'autoComplete="current-password"'
      },
      {
        find: 'onClick={() => setShowPassword(!showPassword)}',
        add: 'data-testid="toggle-password-visibility"',
        position: 'before-className'
      },
      {
        find: 'type="checkbox"',
        context: 'rememberMe',
        add: 'data-testid="remember-me-checkbox"',
        after: 'focus:ring-offset-0"'
      },
      {
        find: 'disabled={isLoading || !username || !password}',
        add: 'data-testid="login-submit-button"',
        position: 'after'
      }
    ]
  }
];

function addTestIds() {
  const projectRoot = path.resolve(__dirname, '..');

  for (const mapping of TESTID_MAPPINGS) {
    const filePath = path.join(projectRoot, mapping.file);

    if (!fs.existsSync(filePath)) {
      console.log(`⚠️  File not found: ${mapping.file}`);
      continue;
    }

    let content = fs.readFileSync(filePath, 'utf-8');
    let modified = false;

    for (const replacement of mapping.replacements) {
      if (content.includes(replacement.add)) {
        console.log(`✓ Already has: ${replacement.add}`);
        continue;
      }

      if (replacement.after && content.includes(replacement.after)) {
        const newContent = content.replace(
          replacement.after,
          `${replacement.after}\n                    ${replacement.add}`
        );
        if (newContent !== content) {
          content = newContent;
          modified = true;
          console.log(`✅ Added: ${replacement.add}`);
        }
      }
    }

    if (modified) {
      fs.writeFileSync(filePath, content);
      console.log(`\n📝 Updated: ${mapping.file}`);
    }
  }
}

console.log('🔧 Adding data-testid attributes to critical UI elements...\n');
addTestIds();
console.log('\n✅ Done!');
