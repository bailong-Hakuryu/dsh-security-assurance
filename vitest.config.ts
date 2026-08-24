import { typertPlugin } from '@deepseek-ai/dsh-typert-generator/tsdown'
import { defineConfig } from 'vitest/config'

const decorators = typertPlugin({ faces: ['host'] })

export default defineConfig({
  plugins: [{ ...decorators, enforce: 'pre', writeBundle: undefined }],
  resolve: {
    dedupe: ['react', 'react-dom'],
    alias: {
      '@deepseek-ai/dsh-client-runtime/client':
        'D:/Deepseek/deepseek-harness-master/packages/client/runtime/lib/types/client/index.js',
      '@deepseek-ai/dsh-client-locale/client':
        'D:/Deepseek/deepseek-harness-master/packages/client/locale/src/client/index.ts',
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.{ts,tsx}'],
    restoreMocks: true,
  },
})
