import type { ForgeConfig } from '@electron-forge/shared-types';
import { MakerSquirrel } from '@electron-forge/maker-squirrel';
import { MakerZIP } from '@electron-forge/maker-zip';
import { MakerDeb } from '@electron-forge/maker-deb';
import { MakerRpm } from '@electron-forge/maker-rpm';
import { MakerDMG } from '@electron-forge/maker-dmg';
import { VitePlugin } from '@electron-forge/plugin-vite';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const config: ForgeConfig = {
  packagerConfig: {
    name: 'J.O.E. DevSecOps Arsenal',
    executableName: 'joe-devsecops',
    appBundleId: 'com.darkwolfsolutions.joe-devsecops',
    appCategoryType: 'public.app-category.developer-tools',
    icon: './resources/icons/joe-icon'
  },
  hooks: {
    // Build main.js with esbuild and copy to package after files are copied
    packageAfterCopy: async (_config, buildPath) => {
      console.log('[forge-hook] Building main.js with esbuild...');
      const projectRoot = process.cwd();

      // Build main.js with esbuild to .vite/build
      execSync(
        'npx esbuild electron/main.ts --bundle --platform=node --outfile=.vite/build/main.js --external:electron --external:electron-squirrel-startup --external:better-sqlite3 --external:@kubernetes/client-node --external:electron-store --format=esm --target=esnext',
        { cwd: projectRoot, stdio: 'inherit' }
      );

      // Copy main.js to the package's .vite/build directory
      const srcMainJs = path.join(projectRoot, '.vite', 'build', 'main.js');
      const destViteDir = path.join(buildPath, '.vite', 'build');
      const destMainJs = path.join(destViteDir, 'main.js');

      // Ensure destination directory exists
      if (!fs.existsSync(destViteDir)) {
        fs.mkdirSync(destViteDir, { recursive: true });
      }

      // Copy main.js
      fs.copyFileSync(srcMainJs, destMainJs);
      console.log(`[forge-hook] Copied main.js to ${destMainJs}`);
    }
  },
  makers: [
    // Windows
    new MakerZIP({}, ['win32']),
    new MakerSquirrel({
      name: 'JOEDevSecOps',
      setupIcon: './resources/icons/joe-icon.ico'
    }),
    // macOS
    new MakerZIP({}, ['darwin']),
    new MakerDMG({
      name: 'JOE-DevSecOps-Arsenal',
      format: 'ULFO'
    }),
    // Linux
    new MakerZIP({}, ['linux']),
    new MakerDeb({
      options: {
        name: 'joe-devsecops',
        productName: 'J.O.E. DevSecOps Arsenal',
        genericName: 'DevSecOps Security Tool',
        description: 'AI-driven DevSecOps security scanner with CMMC compliance',
        maintainer: 'Dark Wolf Solutions',
        homepage: 'https://github.com/darkwolfsolutions/joe-devsecops',
        categories: ['Development', 'Security', 'Utility'],
        icon: './resources/icons/joe-icon.png'
      }
    }),
    new MakerRpm({
      options: {
        name: 'joe-devsecops',
        productName: 'J.O.E. DevSecOps Arsenal',
        genericName: 'DevSecOps Security Tool',
        description: 'AI-driven DevSecOps security scanner with CMMC compliance',
        homepage: 'https://github.com/darkwolfsolutions/joe-devsecops',
        categories: ['Development', 'Security', 'Utility'],
        icon: './resources/icons/joe-icon.png'
      }
    })
  ],
  plugins: [
    new VitePlugin({
      build: [
        // Only build preload with Vite; main is built by esbuild in packageAfterCopy hook
        {
          entry: 'electron/preload.ts',
          config: 'vite.preload.config.ts'
        }
      ],
      renderer: [
        {
          name: 'main_window',
          config: 'vite.renderer.config.ts'
        }
      ]
    })
  ]
};

export default config;
