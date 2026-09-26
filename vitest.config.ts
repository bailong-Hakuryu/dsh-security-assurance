import { typertPlugin } from '@deepseek-ai/dsh-typert-generator/tsdown'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

const decorators = typertPlugin({ faces: ['host'] })

export default defineConfig({
  plugins: [{ ...decorators, enforce: 'pre', writeBundle: undefined }],
  resolve: {
    alias: {
      // The Harness page supplies this module; tests use icon stand-ins.
      '@deepseek-ai/dsh-client-ui-primitives': fileURLToPath(
        new URL('./tests/support/ui-primitives.ts', import.meta.url),
      ),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.{ts,tsx}'],
    exclude: [
      'tests/workbench-ui.client.spec.tsx',
    ],
    restoreMocks: true,
    testTimeout: 15_000,
  },
})
