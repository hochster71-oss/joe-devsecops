import type { ForgeConfig } from '@electron-forge/shared-types';
import { MakerSquirrel } from '@electron-forge/maker-squirrel';
import { MakerZIP } from '@electron-forge/maker-zip';
import { MakerDeb } from '@electron-forge/maker-deb';
import { MakerRpm } from '@electron-forge/maker-rpm';
import { MakerDMG } from '@electron-forge/maker-dmg';
import { VitePlugin } from '@electron-forge/plugin-vite';

const config: ForgeConfig = {
  packagerConfig: {
    name: 'J.O.E. DevSecOps Arsenal',
    executableName: 'joe-devsecops',
    appBundleId: 'com.darkwolfsolutions.joe-devsecops',
    appCategoryType: 'public.app-category.developer-tools'
    // icon: './resources/icons/joe-icon' // Requires .ico/.icns file
  },
  makers: [
    // Windows
    new MakerZIP({}, ['win32']),
    new MakerSquirrel({
      name: 'JOEDevSecOps'
      // setupIcon: './resources/icons/joe-icon.ico'
    }),
    // macOS
    new MakerZIP({}, ['darwin']),
    new MakerDMG({
      name: 'JOE-DevSecOps-Arsenal',
      format: 'ULFO'
      // icon: './resources/icons/joe-icon.icns'
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
        categories: ['Development', 'Security', 'Utility']
        // icon: './resources/icons/joe-icon.png'
      }
    }),
    new MakerRpm({
      options: {
        name: 'joe-devsecops',
        productName: 'J.O.E. DevSecOps Arsenal',
        genericName: 'DevSecOps Security Tool',
        description: 'AI-driven DevSecOps security scanner with CMMC compliance',
        homepage: 'https://github.com/darkwolfsolutions/joe-devsecops',
        categories: ['Development', 'Security', 'Utility']
        // icon: './resources/icons/joe-icon.png'
      }
    })
  ],
  plugins: [
    new VitePlugin({
      build: [
        {
          entry: 'electron/main.ts',
          config: 'vite.main.config.ts'
        },
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
