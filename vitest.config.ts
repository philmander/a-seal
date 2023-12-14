import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    chaiConfig: {
      truncateThreshold: 100000,
    },
    typecheck: {
      tsconfig: './tsconfig.json',
    },
    include: ['./src/**/*.test.ts', './src/**/*.test.js'],
  },
})
