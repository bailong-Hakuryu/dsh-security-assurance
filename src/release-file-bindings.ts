import { z } from 'zod'

import { digestEnvelopeV1Schema } from './digest-envelope.ts'

export const RELEASE_FILE_BINDINGS_ENGINE_ID = 'security/release-file-bindings/v1' as const

export const releaseLockKindV1Schema = z.enum([
  'NPM_PACKAGE_LOCK',
  'NPM_SHRINKWRAP',
  'PNPM_LOCK',
  'YARN_LOCK',
  'OTHER_CANONICAL_LOCK',
])

const boundedPathSchema = z.string().min(1).max(4_096)
const mediaTypeSchema = z.string()
  .regex(/^application\/[a-z0-9.+-]+$|^text\/[a-z0-9.+-]+$/u)
  .max(128)
const sourceRevisionSchema = z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u)
const rawFileDigestSchema = digestEnvelopeV1Schema.refine(
  value => value.canonicalization === 'raw-bytes',
  'Release file digests must cover raw bytes.',
)

const candidateFileSchema = z.strictObject({
  path: boundedPathSchema,
  mediaType: mediaTypeSchema,
})

const dependencyLockFileSchema = z.strictObject({
  lockKind: releaseLockKindV1Schema,
  path: boundedPathSchema,
  mediaType: mediaTypeSchema,
})

function rejectDuplicateLocks(
  value: { readonly dependencyLockFiles: readonly { readonly lockKind: string; readonly path: string }[] },
  context: z.RefinementCtx,
): void {
  const lockKinds = value.dependencyLockFiles.map(item => item.lockKind)
  const lockPaths = value.dependencyLockFiles.map(item => item.path)
  if (new Set(lockKinds).size !== lockKinds.length || new Set(lockPaths).size !== lockPaths.length) {
    context.addIssue({ code: 'custom', message: 'Duplicate dependency lock binding.' })
  }
}

export const releaseFileBindingInputV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  sourceRepositoryPath: boundedPathSchema,
  candidateArtifact: candidateFileSchema,
  dependencyLockFiles: z.array(dependencyLockFileSchema).min(1).max(5),
}).superRefine(rejectDuplicateLocks)

export type ReleaseFileBindingInputV1 = z.infer<typeof releaseFileBindingInputV1Schema>

export const releaseFileBindingsV1Schema = z.strictObject({
  schemaVersion: z.literal(1),
  engineId: z.literal(RELEASE_FILE_BINDINGS_ENGINE_ID),
  sourceRepositoryPath: boundedPathSchema,
  sourceRevision: sourceRevisionSchema,
  candidateArtifact: candidateFileSchema.extend({ digest: rawFileDigestSchema }),
  dependencyLockFiles: z.array(
    dependencyLockFileSchema.extend({ digest: rawFileDigestSchema }),
  ).min(1).max(5),
}).superRefine((value, context) => {
  rejectDuplicateLocks(value, context)
  if (value.candidateArtifact.digest.mediaType !== value.candidateArtifact.mediaType) {
    context.addIssue({ code: 'custom', message: 'Candidate media type does not match its digest.' })
  }
  value.dependencyLockFiles.forEach((lock, index) => {
    if (lock.digest.mediaType !== lock.mediaType) {
      context.addIssue({
        code: 'custom',
        path: ['dependencyLockFiles', index, 'digest', 'mediaType'],
        message: 'Dependency lock media type does not match its digest.',
      })
    }
  })
})

export type ReleaseFileBindingsV1 = z.infer<typeof releaseFileBindingsV1Schema>
