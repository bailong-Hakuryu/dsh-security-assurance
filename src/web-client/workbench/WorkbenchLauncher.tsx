import type { MouseEvent } from 'react'
import { WorkbenchIcon } from './icons.tsx'
import type { PropsWorkbenchLocale, SidebarFooterActionOwnerProps } from './slot-types.ts'

export interface WorkbenchLauncherInjected {
  /** Show the overlay; a closed Workbench then opens under the Host's local authority. */
  readonly showWorkbench: (returnFocus: HTMLElement) => Promise<void>
}

export type WorkbenchLauncherProps =
  & SidebarFooterActionOwnerProps
  & PropsWorkbenchLocale
  & WorkbenchLauncherInjected

/** Additive sidebar action; it opens the overlay but acquires no authority. */
export function WorkbenchLauncher({ wide, t, showWorkbench }: WorkbenchLauncherProps) {
  const onClick = (event: MouseEvent<HTMLButtonElement>): void => {
    void showWorkbench(event.currentTarget)
  }
  return (
    <button
      type="button"
      className="dsh-security-launcher"
      data-wide={String(wide)}
      aria-label={t('launcher.open')}
      title={wide ? undefined : t('launcher.open')}
      onClick={onClick}
    >
      <span className="dsh-security-launcher__icon" aria-hidden="true">
        <WorkbenchIcon />
      </span>
      {wide && <span>{t('launcher.label')}</span>}
    </button>
  )
}
