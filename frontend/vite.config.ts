import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    modulePreload: {
      resolveDependencies: (_filename, dependencies, { hostType }) => {
        if (hostType === 'html') {
          return dependencies.filter(
            (dependency) =>
              !/(?:^|\/)(three-core|react-three)-[^/]+\.js$/.test(dependency),
          );
        }

        return dependencies;
      },
    },
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: 'three-core',
              test: /node_modules\/three\//,
            },
            {
              name: 'react-three',
              test: /node_modules\/(@react-three\/fiber|@react-three\/drei)\//,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  envPrefix: ['VITE'],
  resolve: {
    alias: {
      '@': resolve(dirname(fileURLToPath(import.meta.url)), 'src'),
    },
  },
  envDir: './',
});