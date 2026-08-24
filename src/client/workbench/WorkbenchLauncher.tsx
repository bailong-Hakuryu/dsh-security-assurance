import { IconDataOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { MouseEvent } from 'react'
import type { WORKBENCH_LOCALE_NAMESPACE } from './locales.ts'

export interface WorkbenchLauncherInjected {
  readonly showWorkbench: (returnFocus: HTMLElement) => void
}

export type WorkbenchLauncherProps =
  & PropsRuntime<'sidebar.footer.action'>
  & PropsLocale<typeof WORKBENCH_LOCALE_NAMESPACE>
  & WorkbenchLauncherInjected

/** Additive sidebar action; it opens the overlay but acquires no authority. */
export function WorkbenchLauncher({ wide, t, showWorkbench }: WorkbenchLauncherProps) {
  const onClick = (event: MouseEvent<HTMLButtonElement>): void => {
    showWorkbench(event.currentTarget)
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
        <IconDataOutline16 />
      </span>
      {wide && <span>{t('launcher.label')}</span>}
    </button>
  )
}
