import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// Use process.cwd() which works in both CJS and ESM
const root = process.cwd();

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.join(root, 'src'),
      '@renderer': path.join(root, 'src/renderer'),
      '@components': path.join(root, 'src/renderer/components'),
      '@views': path.join(root, 'src/renderer/views'),
      '@services': path.join(root, 'src/services'),
      '@hooks': path.join(root, 'src/renderer/hooks'),
      '@store': path.join(root, 'src/renderer/store'),
      '@assets': path.join(root, 'src/renderer/assets'),
      '@types': path.join(root, 'src/types')
    }
  }
});
