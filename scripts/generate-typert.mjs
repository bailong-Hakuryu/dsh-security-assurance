import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WorkspaceTypertGenerator } from '@deepseek-ai/dsh-typert-generator'

const packageRoot = process.cwd()
const scratchParent = join(packageRoot, '.scratch')
await mkdir(scratchParent, { recursive: true })
const workspaceRoot = await mkdtemp(join(scratchParent, 'typert-workspace-'))
const syntheticPackageRoot = join(workspaceRoot, 'packages', 'security-assurance')
const syntheticProtocolRoot = join(workspaceRoot, 'packages', 'typert-protocol')
const protocolRoot = dirname(fileURLToPath(import.meta.resolve(
  '@deepseek-ai/dsh-typert-protocol/package.json',
)))

try {
  await mkdir(syntheticPackageRoot, { recursive: true })
  await cp(join(packageRoot, 'src'), join(syntheticPackageRoot, 'src'), { recursive: true })
  await cp(join(packageRoot, 'package.json'), join(syntheticPackageRoot, 'package.json'))
  await mkdir(syntheticProtocolRoot, { recursive: true })
  await cp(join(protocolRoot, 'src'), join(syntheticProtocolRoot, 'src'), { recursive: true })
  await cp(join(protocolRoot, 'package.json'), join(syntheticProtocolRoot, 'package.json'))
  const packageTsconfig = JSON.parse(await readFile(join(packageRoot, 'tsconfig.json'), 'utf8'))
  packageTsconfig.compilerOptions = {
    ...packageTsconfig.compilerOptions,
    composite: true,
    baseUrl: '../..',
    paths: {
      '@deepseek-ai/dsh-typert-protocol': ['packages/typert-protocol/src/index.ts'],
    },
  }
  packageTsconfig.exclude = ['src/client']
  await writeFile(
    join(syntheticPackageRoot, 'tsconfig.json'),
    `${JSON.stringify(packageTsconfig, null, 2)}\n`,
    'utf8',
  )
  await writeFile(
    join(syntheticProtocolRoot, 'tsconfig.json'),
    `${JSON.stringify({
      compilerOptions: {
        target: 'es2024',
        module: 'esnext',
        moduleResolution: 'bundler',
        composite: true,
        declaration: true,
        strict: true,
        skipLibCheck: true,
        rootDir: 'src',
        outDir: 'lib/types',
      },
      include: ['src'],
    }, null, 2)}\n`,
    'utf8',
  )
  await writeFile(
    join(workspaceRoot, 'tsconfig.host.json'),
    `${JSON.stringify({
      compilerOptions: {
        target: 'es2024',
        module: 'esnext',
        moduleResolution: 'bundler',
        strict: true,
        skipLibCheck: true,
        baseUrl: '.',
        paths: {
          '@deepseek-ai/dsh-typert-protocol': ['packages/typert-protocol/src/index.ts'],
        },
      },
      files: [],
      references: [
        { path: './packages/typert-protocol' },
        { path: './packages/security-assurance' },
      ],
    }, null, 2)}\n`,
    'utf8',
  )

  const artifacts = new WorkspaceTypertGenerator(workspaceRoot).generate(
    ['dsh-security-assurance'],
    ['host'],
  )
  const host = artifacts.find(artifact =>
    artifact.package === 'dsh-security-assurance' && artifact.face === 'host')
  if (host === undefined || host.remote === undefined) {
    throw new Error('Typert generation did not produce the Security Assurance Host and Remote artifacts')
  }
  await Promise.all([
    writeFile(join(packageRoot, 'lib', 'typert.host.js'), host.js, 'utf8'),
    writeFile(join(packageRoot, 'lib', 'typert.host.d.ts'), host.dts, 'utf8'),
    writeFile(join(packageRoot, 'lib', 'typert.remote-client.js'), host.remote.js, 'utf8'),
    writeFile(join(packageRoot, 'lib', 'typert.remote-client.d.ts'), host.remote.dts, 'utf8'),
    writeFile(join(packageRoot, 'lib', 'typert.remote-client.d.ts.map'), host.remote.dtsMap, 'utf8'),
  ])
} finally {
  await rm(workspaceRoot, { recursive: true, force: true })
}
