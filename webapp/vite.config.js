import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [
    react(),
  ],
  define: {
    'process.env': {},
    'global': 'globalThis',
  },
  resolve: {
    alias: {
      buffer: path.resolve(__dirname, 'node_modules/buffer'),
      process: path.resolve(__dirname, 'node_modules/process'),
      stream: path.resolve(__dirname, 'node_modules/stream-browserify'),
      util: path.resolve(__dirname, 'node_modules/util'),
      assert: path.resolve(__dirname, 'node_modules/assert'),
      events: path.resolve(__dirname, 'node_modules/events'),
      'snarkjs': path.resolve(__dirname, 'node_modules/snarkjs/build/main.cjs'),
      'circomlibjs': path.resolve(__dirname, 'node_modules/circomlibjs/main.js'),
      'ffjavascript': path.resolve(__dirname, 'node_modules/ffjavascript/build/browser.esm.js'),
    },
  },
  worker: {
    format: 'es',
    resolve: {
      alias: {
        buffer: path.resolve(__dirname, 'node_modules/buffer'),
        process: path.resolve(__dirname, 'node_modules/process'),
        stream: path.resolve(__dirname, 'node_modules/stream-browserify'),
        util: path.resolve(__dirname, 'node_modules/util'),
        assert: path.resolve(__dirname, 'node_modules/assert'),
        events: path.resolve(__dirname, 'node_modules/events'),
        'snarkjs': path.resolve(__dirname, 'node_modules/snarkjs/build/main.cjs'),
        'circomlibjs': path.resolve(__dirname, 'node_modules/circomlibjs/main.js'),
        'ffjavascript': path.resolve(__dirname, 'node_modules/ffjavascript/build/browser.esm.js'),
      }
    }
  },
  server: {
    fs: {
      allow: ['..'],
    },
  },
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
    },
  },
})