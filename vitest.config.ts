import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules', 'dist', 'dist-electron', '.vite', 'test/e2e/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'node_modules',
        'test',
        '**/*.d.ts',
        'src/renderer/main.tsx',
        'src/extension.ts'
      ],
      thresholds: {
        lines: 60,
        branches: 50,
        functions: 60,
        statements: 60
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@renderer': resolve(__dirname, './src/renderer'),
      '@components': resolve(__dirname, './src/renderer/components'),
      '@views': resolve(__dirname, './src/renderer/views'),
      '@services': resolve(__dirname, './src/services'),
      '@hooks': resolve(__dirname, './src/renderer/hooks'),
      '@store': resolve(__dirname, './src/renderer/store'),
      '@types': resolve(__dirname, './src/types')
    }
  }
});
