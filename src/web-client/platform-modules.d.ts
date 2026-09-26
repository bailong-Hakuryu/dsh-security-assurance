/**
 * The Harness Web page supplies this module through its client module table
 * in every supported Harness version, so the bundle keeps it external. This
 * declares only the icons the Workbench renders; it is not a type package.
 */
declare module '@deepseek-ai/dsh-client-ui-primitives' {
  import type { ReactElement } from 'react'

  export function IconCloseOutline16(): ReactElement
  export function IconDataOutline16(): ReactElement
}
