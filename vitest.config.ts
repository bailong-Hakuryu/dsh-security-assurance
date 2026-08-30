import { typertPlugin } from '@deepseek-ai/dsh-typert-generator/tsdown'
import { defineConfig } from 'vitest/config'

const decorators = typertPlugin({ faces: ['host'] })

export default defineConfig({
  plugins: [{ ...decorators, enforce: 'pre', writeBundle: undefined }],
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.{ts,tsx}'],
    exclude: [
      'tests/adr-0275-workbench-service-client.spec.ts',
      'tests/adr-0276-workbench-additive-mount.spec.ts',
      'tests/adr-0277-workbench-information-architecture.spec.ts',
      'tests/adr-0278-workbench-low-sensitivity-route.spec.ts',
      'tests/adr-0281-assessment-progress-view.spec.ts',
      'tests/adr-0285-service-projected-available-actions.spec.ts',
      'tests/adr-0287-finding-triage-dimensions.spec.ts',
      'tests/adr-0293-browser-sensitive-persistence.spec.ts',
      'tests/adr-0294-host-web-security-accessibility.spec.ts',
      'tests/workbench-client.spec.ts',
      'tests/workbench-ui.client.spec.tsx',
    ],
    restoreMocks: true,
  },
})
