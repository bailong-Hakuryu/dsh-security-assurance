const STYLE_ATTRIBUTE = 'dsh-security-assurance/workbench'

const WORKBENCH_CSS = `
.dsh-security-launcher{align-items:center;background:transparent;border:0;border-radius:8px;color:var(--dsw-alias-text-primary,#262626);cursor:pointer;display:flex;font:inherit;gap:10px;min-height:36px;padding:8px 10px;text-align:left;width:100%}
.dsh-security-launcher:hover,.dsh-security-launcher:focus-visible{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.055));outline:none}
.dsh-security-launcher[data-wide=false]{justify-content:center;padding-inline:0}
.dsh-security-launcher__icon{align-items:center;display:inline-flex;flex:0 0 auto;justify-content:center}
.dsh-security-backdrop{align-items:center;background:rgba(9,14,25,.46);display:flex;inset:0;justify-content:center;padding:clamp(12px,3vw,32px);pointer-events:auto;position:absolute}
.dsh-security-dialog{background:var(--dsw-alias-bg-primary,#fff);border:1px solid var(--dsw-alias-border-subtle,rgba(0,0,0,.12));border-radius:18px;box-shadow:0 24px 70px rgba(0,0,0,.24);color:var(--dsw-alias-text-primary,#202124);display:flex;flex-direction:column;max-height:min(760px,calc(100vh - 24px));max-width:920px;min-height:360px;overflow:hidden;width:100%}
.dsh-security-dialog__header{align-items:center;border-bottom:1px solid var(--dsw-alias-border-subtle,rgba(0,0,0,.1));display:flex;justify-content:space-between;padding:18px 20px}
.dsh-security-dialog__title{font-size:18px;font-weight:650;letter-spacing:-.01em;margin:0}
.dsh-security-dialog__close{align-items:center;background:transparent;border:0;border-radius:8px;color:inherit;cursor:pointer;display:inline-flex;height:34px;justify-content:center;width:34px}
.dsh-security-dialog__close:hover,.dsh-security-dialog__close:focus-visible{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.055));outline:none}
.dsh-security-dialog__body{display:flex;flex:1;min-height:0;overflow:auto;padding:20px}
.dsh-security-empty{align-items:center;border:1px dashed var(--dsw-alias-border-subtle,rgba(0,0,0,.18));border-radius:14px;display:flex;flex:1;flex-direction:column;justify-content:center;min-height:280px;padding:40px;text-align:center}
.dsh-security-empty__icon{align-items:center;background:var(--dsw-alias-bg-hover,rgba(0,0,0,.055));border-radius:50%;display:flex;height:48px;justify-content:center;margin-bottom:16px;width:48px}
.dsh-security-empty h2{font-size:16px;margin:0 0 8px}
.dsh-security-empty p{color:var(--dsw-alias-text-secondary,#666);line-height:1.55;margin:0;max-width:480px}
.dsh-security-message__detail{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.055));border-radius:7px;margin-top:16px;max-width:100%;overflow-wrap:anywhere;padding:7px 9px}
.dsh-security-selection{display:flex;flex:1;flex-direction:column;gap:16px;min-width:0}.dsh-security-selection h2{font-size:16px;margin:0 0 6px}.dsh-security-selection>div>p{color:var(--dsw-alias-text-secondary,#666);font-size:12px;margin:0}.dsh-security-selection__list{display:flex;flex-direction:column;gap:8px;list-style:none;margin:0;padding:0}.dsh-security-selection__list button{align-items:center;background:var(--dsw-alias-bg-hover,rgba(0,0,0,.035));border:1px solid var(--dsw-alias-border-subtle,rgba(0,0,0,.1));border-radius:11px;color:inherit;cursor:pointer;display:flex;font:inherit;gap:16px;justify-content:space-between;padding:12px;text-align:left;width:100%}.dsh-security-selection__list button:hover,.dsh-security-selection__list button:focus-visible{border-color:var(--dsw-alias-text-secondary,#666);outline:none}.dsh-security-selection__identity{display:flex;flex-direction:column;gap:5px;min-width:0}.dsh-security-selection__identity code{font-size:12px;overflow-wrap:anywhere}.dsh-security-selection__identity small{color:var(--dsw-alias-text-secondary,#666);font-size:11px;overflow-wrap:anywhere}
.dsh-security-assessment{display:flex;flex:1;flex-direction:column;gap:16px;min-width:0}
.dsh-security-assessment__heading{align-items:flex-start;display:flex;gap:16px;justify-content:space-between}
.dsh-security-eyebrow{color:var(--dsw-alias-text-secondary,#666);display:block;font-size:12px;font-weight:650;letter-spacing:.06em;margin-bottom:5px;text-transform:uppercase}
.dsh-security-assessment__id{display:block;font-size:14px;overflow-wrap:anywhere}
.dsh-security-badges{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}
.dsh-security-badge{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.06));border:1px solid var(--dsw-alias-border-subtle,rgba(0,0,0,.1));border-radius:999px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;font-weight:700;padding:4px 8px}
.dsh-security-badge[data-value=GAP],.dsh-security-badge[data-value=FAILED],.dsh-security-badge[data-value=BLOCKED]{background:rgba(196,61,39,.1);border-color:rgba(196,61,39,.25)}
.dsh-security-badge[data-value=SATISFIED],.dsh-security-badge[data-value=COMPLETE],.dsh-security-badge[data-value=SEALED]{background:rgba(31,135,84,.1);border-color:rgba(31,135,84,.25)}
.dsh-security-facts{display:grid;gap:1px;grid-template-columns:repeat(2,minmax(0,1fr));margin:0;overflow:hidden}
.dsh-security-facts>div{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.035));min-width:0;padding:11px 12px}
.dsh-security-facts dt{color:var(--dsw-alias-text-secondary,#666);font-size:11px;margin-bottom:4px}
.dsh-security-facts dd{font-size:13px;margin:0;overflow-wrap:anywhere}
.dsh-security-facts code{white-space:normal}
.dsh-security-section{border:1px solid var(--dsw-alias-border-subtle,rgba(0,0,0,.1));border-radius:12px;padding:14px}
.dsh-security-section__header{align-items:center;display:flex;gap:12px;justify-content:space-between}
.dsh-security-section h2{font-size:14px;margin:0}
.dsh-security-metrics{display:grid;gap:10px;grid-template-columns:repeat(2,minmax(0,1fr));margin-top:12px}
.dsh-security-metric{background:var(--dsw-alias-bg-hover,rgba(0,0,0,.035));border-radius:9px;display:flex;flex-direction:column;gap:4px;padding:10px 12px}
.dsh-security-metric span{color:var(--dsw-alias-text-secondary,#666);font-size:11px}.dsh-security-metric strong{font-size:17px}
.dsh-security-readonly-note,.dsh-security-muted{color:var(--dsw-alias-text-secondary,#666);font-size:12px;line-height:1.5;margin:8px 0 0}
.dsh-security-actions{display:flex;flex-direction:column;gap:8px;list-style:none;margin:12px 0 0;padding:0}
.dsh-security-actions li{align-items:baseline;background:var(--dsw-alias-bg-hover,rgba(0,0,0,.035));border-radius:9px;display:grid;gap:4px 12px;grid-template-columns:minmax(150px,auto) 1fr auto;padding:10px 12px}
.dsh-security-actions code{font-size:11px;font-weight:700}.dsh-security-actions span{font-size:12px}.dsh-security-actions small{color:var(--dsw-alias-text-secondary,#666);font-size:11px}
@media(max-width:640px){.dsh-security-backdrop{align-items:stretch;padding:0}.dsh-security-dialog{border-radius:0;max-height:none;min-height:100%;width:100%}.dsh-security-dialog__body{padding:14px}.dsh-security-empty{padding:24px}.dsh-security-selection__list button{align-items:flex-start;flex-direction:column}.dsh-security-assessment__heading{flex-direction:column}.dsh-security-badges{justify-content:flex-start}.dsh-security-facts{grid-template-columns:1fr}.dsh-security-actions li{grid-template-columns:1fr}.dsh-security-metrics{grid-template-columns:1fr}}
@media(prefers-reduced-motion:no-preference){.dsh-security-backdrop{animation:dsh-security-fade-in .14s ease-out}.dsh-security-dialog{animation:dsh-security-rise-in .18s ease-out}@keyframes dsh-security-fade-in{from{opacity:0}to{opacity:1}}@keyframes dsh-security-rise-in{from{opacity:.7;transform:translateY(8px) scale(.992)}to{opacity:1;transform:none}}}
`

/** Install package-owned CSS for exactly the Client plugin lifetime. */
export function installWorkbenchStyles(): () => void {
  if (typeof document === 'undefined') return () => {}
  const style = document.createElement('style')
  style.dataset.pluginCss = STYLE_ATTRIBUTE
  style.textContent = WORKBENCH_CSS
  document.head.appendChild(style)
  return () => { style.remove() }
}
