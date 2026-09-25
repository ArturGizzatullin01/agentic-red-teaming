/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// memnotsafe Mission Control is a purely static, offline SPA. It never talks
// to a server: every artifact it shows is read either from the bundled
// fixtures or from files the operator picks locally in the browser. `base`
// is relative so the built `dist/` can be opened from any path (or file://).
export default defineConfig({
  base: './',
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
