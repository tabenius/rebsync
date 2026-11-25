// @ts-check
/**
 * Framework-neutral widget behaviour for plain HTML/JS surfaces. React widgets
 * and static UIs share these rules so focus, clipboard, tone and chrome auto-hide
 * cannot drift between Dash, Pieces, rebsync and the single-file consoles.
 *
 * @typedef {Pick<Clipboard, 'writeText'>} ClipboardWriter
 * @typedef {{ ok: true } | { ok: false, reason: 'unavailable' | 'denied' }} CopyTextResult
 * @typedef {'neutral' | 'active' | 'warning' | 'danger' | 'success'} StateTone
 */

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const DANGER = ['blocked', 'failed', 'denied', 'not_ready', 'changes_requested'];
const WARNING = ['stale', 'unavailable', 'degraded', 'pending', 'waiting', 'expired', 'unreviewed', 'review_required'];
const SUCCESS = ['passed', 'ready', 'merged', 'done', 'released', 'approved', 'applied'];
const ACTIVE = ['running', 'starting', 'active', 'in-progress', 'in_progress', 'review', 'evidence', 'queued', 'sent'];

/**
 * Copy an exact string. The value is never executed, parsed or logged.
 * @param {string} value
 * @param {ClipboardWriter | null | undefined} [clipboard]
 * @returns {Promise<CopyTextResult>}
 */
export async function copyText(value, clipboard) {
  const target = clipboard === undefined ? globalThis.navigator?.clipboard : clipboard;
  if (!target || typeof target.writeText !== 'function') return { ok: false, reason: 'unavailable' };
  try {
    await target.writeText(value);
    return { ok: true };
  } catch {
    return { ok: false, reason: 'denied' };
  }
}

/**
 * Map a recorded state to a semantic tone. Unknown states stay neutral; a
 * missing count or value must never become a confident status.
 * @param {string} state
 * @returns {StateTone}
 */
export function stateTone(state) {
  if (DANGER.includes(state)) return 'danger';
  if (WARNING.includes(state)) return 'warning';
  if (SUCCESS.includes(state)) return 'success';
  if (ACTIVE.includes(state)) return 'active';
  return 'neutral';
}

/**
 * Focus an element, a ref-like object or a fallback. Returns false when focus
 * cannot be restored, so hosts can decide whether to show a manual affordance.
 * @param {HTMLElement | { current: HTMLElement | null } | null | undefined} target
 * @param {HTMLElement | null} [fallback]
 * @returns {boolean}
 */
export function restoreFocus(target, fallback = null) {
  const node = target && 'current' in target ? target.current : target;
  const element = node ?? fallback;
  if (!element || typeof element.focus !== 'function') return false;
  element.focus();
  return true;
}

/**
 * Scroll a record into view and focus it. The selector is host-supplied; URL
 * parsing and record validation stay in the host.
 * @param {string} selector
 * @param {ParentNode | Document} [root]
 * @returns {boolean}
 */
export function focusAndReveal(selector, root = globalThis.document) {
  if (!root || typeof root.querySelector !== 'function') return false;
  const node = /** @type {HTMLElement | null} */ (root.querySelector(selector));
  if (!node || typeof node.focus !== 'function') return false;
  if (typeof node.scrollIntoView === 'function') node.scrollIntoView({ block: 'nearest' });
  try { node.focus({ preventScroll: true }); } catch { node.focus(); }
  return true;
}

/**
 * Shared scroll decision for app bars and in-content navigation bars.
 * `undefined` means "keep the previous scroll position" — a small jitter while
 * already past the grace zone must not become a hide/show flip.
 * @param {{ current: number, previous: number, threshold?: number, grace?: number, minScroll?: number, pointerInside?: boolean, focusInside?: boolean, menusOpen?: number }} args
 * @returns {boolean | undefined}
 */
export function shouldAutoHideChrome({ current, previous, threshold = 8, grace = 60, minScroll = 100, pointerInside = false, focusInside = false, menusOpen = 0 }) {
  if (Math.abs(current - previous) < threshold && current > grace) return undefined;
  return current > previous && current > minScroll && !pointerInside && !focusInside && menusOpen === 0;
}

/**
 * Attach the same disclosure contract as PopoverMenu to plain HTML: distinct
 * trigger/panel ids, aria-haspopup/controls/expanded, first-item focus, Escape,
 * outside pointerdown, Tab-out, close-on-select and configurable focus return.
 *
 * @param {{ trigger: HTMLElement, panel: HTMLElement, label?: string, closeOnSelect?: boolean | ((el: HTMLElement) => boolean), restoreFocus?: boolean | HTMLElement | { current: HTMLElement | null }, onOpenChange?: (open: boolean) => void }} options
 */
export function createPopoverController({ trigger, panel, label, closeOnSelect = true, restoreFocus = true, onOpenChange }) {
  const doc = trigger.ownerDocument ?? globalThis.document;
  const triggerId = trigger.id || `${panel.id || 'ragbaz-popover'}-trigger`;
  const panelId = panel.id || `${triggerId}-panel`;
  trigger.id = triggerId;
  panel.id = panelId;
  trigger.setAttribute('aria-haspopup', 'dialog');
  trigger.setAttribute('aria-controls', panelId);
  trigger.setAttribute('aria-expanded', 'false');
  if (label) {
    trigger.setAttribute('aria-label', label);
    panel.setAttribute('aria-label', label);
  }
  let open = false;

  function focusTarget() {
    if (restoreFocus === false) return null;
    if (restoreFocus && typeof restoreFocus === 'object') return 'current' in restoreFocus ? restoreFocus.current : restoreFocus;
    return trigger;
  }

  /** @param {boolean} next @param {boolean} [restore] */
  function setOpen(next, restore = true) {
    const wasOpen = open;
    open = next;
    trigger.setAttribute('aria-expanded', String(open));
    panel.hidden = !open;
    onOpenChange?.(open);
    if (!wasOpen && open) {
      const first = /** @type {HTMLElement | null} */ (panel.querySelector(FOCUSABLE)) ?? panel;
      if (typeof first.focus === 'function') first.focus();
    } else if (wasOpen && !open && restore) {
      restoreFocusNode(focusTarget());
    }
  }

  function toggle() { setOpen(!open, false); }
  /** @param {KeyboardEvent} event */
  function onKeyDown(event) {
    if (event.key === 'Escape' && open) { event.preventDefault(); event.stopPropagation(); setOpen(false); }
  }
  /** @param {PointerEvent} event */
  function onPointerDown(event) {
    const target = event.target;
    if (target && !trigger.contains(/** @type {Node} */ (target)) && !panel.contains(/** @type {Node} */ (target))) setOpen(false, false);
  }
  /** @param {FocusEvent} event */
  function onBlur(event) {
    if (!panel.contains(/** @type {Node} */ (event.relatedTarget))) setOpen(false, false);
  }
  /** @param {MouseEvent} event */
  function onClick(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.closest('[data-menu-keep-open],[data-appbar-keep-open]')) return;
    if (closeOnSelect === false) return;
    if (typeof closeOnSelect === 'function') { if (closeOnSelect(target)) setOpen(false); return; }
    if (target.closest('a,button,[data-menu-close],[data-appbar-close]')) setOpen(false);
  }

  trigger.addEventListener('click', toggle);
  trigger.addEventListener('keydown', onKeyDown);
  panel.addEventListener('keydown', onKeyDown);
  panel.addEventListener('blur', onBlur);
  panel.addEventListener('click', onClick);
  doc.addEventListener('pointerdown', onPointerDown, true);

  return {
    get isOpen() { return open; },
    open: () => setOpen(true, false),
    close: () => setOpen(false),
    toggle,
    destroy() {
      trigger.removeEventListener('click', toggle);
      trigger.removeEventListener('keydown', onKeyDown);
      panel.removeEventListener('keydown', onKeyDown);
      panel.removeEventListener('blur', onBlur);
      panel.removeEventListener('click', onClick);
      doc.removeEventListener('pointerdown', onPointerDown, true);
    },
  };
}

/** @param {HTMLElement | { focus: () => void } | null | undefined} element */
function restoreFocusNode(element) {
  if (element && typeof element.focus === 'function') element.focus();
}
