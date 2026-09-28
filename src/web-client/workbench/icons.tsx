/**
 * Icons the Workbench draws itself. Harness renames its primitives icons
 * between releases (0.1.7 replaced `IconDataOutline16` with
 * `IconDataOutlineRegular`), and a missing export crashes the whole slot
 * entry, so the Workbench depends on no host icon.
 */

interface IconProps {
  readonly size?: number
}

/** Shield with a check: opens and titles the Security Assurance Workbench. */
export function WorkbenchIcon({ size = 16 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false">
      <path
        d="M8 1.75 2.75 3.5v4.1c0 3.1 2.2 5.6 5.25 6.65 3.05-1.05 5.25-3.55 5.25-6.65V3.5L8 1.75Z"
        stroke="currentColor"
        strokeWidth="1.25"
        strokeLinejoin="round"
      />
      <path d="m5.75 8 1.6 1.6 2.9-3.2" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Cross that closes the Workbench dialog. */
export function CloseIcon({ size = 16 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true" focusable="false">
      <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  )
}
