import type { ForgeConfig } from '@electron-forge/shared-types';
import { MakerSquirrel } from '@electron-forge/maker-squirrel';
import { MakerZIP } from '@electron-forge/maker-zip';
import { VitePlugin } from '@electron-forge/plugin-vite';

const config: ForgeConfig = {
  packagerConfig: {
    name: 'J.O.E. DevSecOps Arsenal',
    executableName: 'joe-devsecops'
    // icon: './resources/icons/joe-icon' // Requires .ico file for Windows
  },
  makers: [
    new MakerZIP({}, ['win32']),
    new MakerSquirrel({
      name: 'JOEDevSecOps'
      // setupIcon: './resources/icons/joe-icon.ico', // Requires .ico file
      // iconUrl: 'https://raw.githubusercontent.com/darkwolfsolutions/joe/main/resources/icons/joe-icon.ico'
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
