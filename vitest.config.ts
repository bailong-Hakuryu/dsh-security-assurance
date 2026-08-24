import { typertPlugin } from '@deepseek-ai/dsh-typert-generator/tsdown'
import { defineConfig } from 'vitest/config'

const decorators = typertPlugin({ faces: ['host'] })

export default defineConfig({
  plugins: [{ ...decorators, enforce: 'pre', writeBundle: undefined }],
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.ts'],
    restoreMocks: true,
  },
})
