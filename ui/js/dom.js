// Safe DOM building. Untrusted text only ever reaches the page as text nodes (textContent);
// attributes are set one by one and event-handler or style attributes are refused.

// on* handlers, inline style (CSP), and anything that loads or navigates (src, srcset, href, action).
const REFUSED = /^(on|style$|src|href$|action$|formaction$|xlink:href$)/i;

function applyProps(el, props) {
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.setAttribute('class', Array.isArray(v) ? v.filter(Boolean).join(' ') : String(v));
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = String(dv);
    else if (k === 'value') el.value = String(v);
    else if (k === 'checked' || k === 'disabled' || k === 'readOnly' || k === 'hidden' || k === 'selected') el[k] = !!v;
    else if (REFUSED.test(k)) throw new Error(`dom: refusing attribute ${k}`);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** h('div', {class, text, on: {click}}, ...children): an element; strings become text nodes. */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) applyProps(el, props);
  return append(el, children);
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/** A small SVG icon from path data (trusted constants only). */
export function icon(paths, { size = 16, cls = 'icon' } = {}) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('class', cls);
  svg.setAttribute('aria-hidden', 'true');
  for (const d of [].concat(paths)) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}

export const ICONS = {
  close: 'M6 6l12 12M18 6L6 18',
  check: 'M5 12.5l4.5 4.5L19 7',
  x: 'M7 7l10 10M17 7L7 17',
  chevron: 'M9 6l6 6-6 6',
  plus: 'M12 5v14M5 12h14',
  trash: ['M5 7h14', 'M10 11v6M14 11v6', 'M7 7l1 12h8l1-12', 'M9 7V4h6v3'],
  refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 5v6h-6'],
  warn: ['M12 3l10 18H2z', 'M12 10v5', 'M12 18v.5'],
};

export function clear(el) {
  el.replaceChildren();
  return el;
}

export function $(sel, root = document) {
  return root.querySelector(sel);
}

// ---- toasts -----------------------------------------------------------------------------------

export function toast(message, { kind = 'info', details = [], timeout = 5000 } = {}) {
  const host = document.getElementById('toasts');
  if (!host) return;
  const close = h('button', { class: 'toast-close', type: 'button', 'aria-label': 'Dismiss' }, icon(ICONS.close, { size: 14 }));
  const el = h(
    'div',
    { class: ['toast', `toast-${kind}`], role: kind === 'error' ? 'alert' : 'status' },
    h('div', { class: 'toast-body' }, h('div', { class: 'toast-msg', text: message }), details.length ? h('ul', { class: 'toast-details' }, details.slice(0, 6).map((d) => h('li', { text: d }))) : null),
    close,
  );
  const remove = () => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 180);
  };
  close.addEventListener('click', remove);
  host.append(el);
  while (host.children.length > 5) host.firstElementChild.remove();
  if (timeout) setTimeout(remove, timeout);
}

/** A toast for a failed API call: its code and details. */
export function toastError(prefix, e) {
  const details = e && Array.isArray(e.details) ? e.details : [];
  const code = (e && e.code) || (e && e.message) || 'error';
  toast(`${prefix}: ${code}`, { kind: 'error', details, timeout: 9000 });
}

// ---- tooltip ------------------------------------------------------------------------------------

export function showTooltip(content, x, y) {
  const tip = document.getElementById('tooltip');
  if (!tip) return;
  clear(tip).append(content);
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  const left = Math.min(x + 14, window.innerWidth - r.width - 8);
  const top = y + 16 + r.height > window.innerHeight ? y - r.height - 12 : y + 16;
  tip.style.left = `${Math.max(8, left)}px`;
  tip.style.top = `${Math.max(8, top)}px`;
}

export function hideTooltip() {
  const tip = document.getElementById('tooltip');
  if (tip) tip.hidden = true;
}

/** A labelled key/value list (dl) from [[label, value-or-node], ...]; empty values are skipped. */
export function kv(rows, cls = 'kv') {
  return h(
    'dl',
    { class: cls },
    rows
      .filter((r) => r && r[1] !== undefined && r[1] !== null && r[1] !== '')
      .map(([k, v]) => [h('dt', { text: k }), h('dd', null, v instanceof Node ? v : String(v))]),
  );
}

export function pill(text, cls = '', title) {
  return h('span', { class: ['pill', cls], text, title });
}
