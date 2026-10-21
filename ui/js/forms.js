// Form controls bound to a draft object by key path. Each control writes its parsed value into
// the draft on input and reports validation errors to its Form.

import { h } from './dom.js';
import { getIn, setIn, pathString } from './util.js';

let uid = 0;
export const nextId = (prefix = 'f') => `${prefix}-${++uid}`;

export class Form {
  constructor({ disabled = false, onChange = () => {} } = {}) {
    this.disabled = disabled;
    this.onChange = onChange;
    this.errors = new Map();
  }

  setError(key, msg, errEl, control) {
    if (msg) this.errors.set(key, msg);
    else this.errors.delete(key);
    if (errEl) {
      errEl.textContent = msg || '';
      errEl.hidden = !msg;
    }
    if (control) {
      control.classList.toggle('invalid', !!msg);
      control.setAttribute('aria-invalid', msg ? 'true' : 'false');
    }
  }

  clearErrors(prefix = '') {
    for (const k of [...this.errors.keys()]) if (k.startsWith(prefix)) this.errors.delete(k);
  }

  hasErrors() {
    return this.errors.size > 0;
  }

  /** A labelled field wrapper; returns {el, err}. */
  field(label, control, { hint, wide = false, id } = {}) {
    const err = h('span', { class: 'field-error', hidden: true, role: 'alert' });
    if (id) control.id = id;
    const el = h(
      'div',
      { class: ['field', wide ? 'wide' : ''] },
      h('label', { class: 'field-label', for: control.id || undefined, text: label }),
      control,
      hint ? h('span', { class: 'field-hint', text: hint }) : null,
      err,
    );
    return { el, err };
  }

  bind(control, draft, keys, parse, validate, err) {
    const key = pathString(keys);
    const update = () => {
      const raw = control.type === 'checkbox' ? control.checked : control.value;
      const parsed = parse(raw);
      if (parsed.error) {
        this.setError(key, parsed.error, err, control);
        this.onChange(keys);
        return;
      }
      const msg = validate ? validate(parsed.value) : null;
      this.setError(key, msg, err, control);
      setIn(draft, keys, parsed.value);
      this.onChange(keys);
    };
    control.addEventListener(control.type === 'checkbox' || control.tagName === 'SELECT' ? 'change' : 'input', update);
    if (this.disabled) control.disabled = true;
    return control;
  }

  text(label, draft, keys, { placeholder, hint, mono, wide, required, validate, emptyUnset = true, list } = {}) {
    const v = getIn(draft, keys);
    const input = h('input', { type: 'text', class: ['input', mono ? 'mono' : ''], value: v == null ? '' : String(v), placeholder, spellcheck: 'false', autocomplete: 'off', list });
    const f = this.field(label, input, { hint, wide, id: nextId() });
    this.bind(
      input,
      draft,
      keys,
      (raw) => {
        const s = raw.trim();
        if (!s && required) return { error: `${label} is required` };
        return { value: s === '' && emptyUnset ? undefined : s };
      },
      validate,
      f.err,
    );
    return f.el;
  }

  textarea(label, draft, keys, { placeholder, hint, rows = 4, mono, wide = true, validate, emptyUnset = true } = {}) {
    const v = getIn(draft, keys);
    const ta = h('textarea', { class: ['input', mono ? 'mono' : ''], rows: String(rows), placeholder, spellcheck: 'false', value: v == null ? '' : String(v) });
    const f = this.field(label, ta, { hint, wide, id: nextId() });
    this.bind(ta, draft, keys, (raw) => ({ value: raw === '' && emptyUnset ? undefined : raw }), validate, f.err);
    return f.el;
  }

  number(label, draft, keys, { min, max, int = true, placeholder = 'default', hint } = {}) {
    const v = getIn(draft, keys);
    const input = h('input', {
      type: 'number',
      class: 'input num',
      value: v == null ? '' : String(v),
      placeholder,
      min: min === undefined ? undefined : String(min),
      max: max === undefined || max === Infinity ? undefined : String(max),
      step: int ? '1' : 'any',
      inputmode: int ? 'numeric' : 'decimal',
    });
    const f = this.field(label, input, { hint, id: nextId() });
    this.bind(
      input,
      draft,
      keys,
      (raw) => {
        const s = String(raw).trim();
        if (s === '') return { value: undefined };
        const n = Number(s);
        if (!Number.isFinite(n)) return { error: 'a number' };
        if (int && !Number.isInteger(n)) return { error: 'a whole number' };
        if (min !== undefined && n < min) return { error: `at least ${min}` };
        if (max !== undefined && n > max) return { error: `at most ${max}` };
        return { value: n };
      },
      null,
      f.err,
    );
    return f.el;
  }

  select(label, draft, keys, options, { hint, emptyUnset = false, disabledOptions = [] } = {}) {
    const v = getIn(draft, keys);
    const sel = h(
      'select',
      { class: 'input' },
      options.map(([value, text]) => h('option', { value, text, selected: String(v ?? '') === value, disabled: disabledOptions.includes(value) && String(v ?? '') !== value })),
    );
    const f = this.field(label, sel, { hint, id: nextId() });
    this.bind(sel, draft, keys, (raw) => ({ value: raw === '' && emptyUnset ? undefined : raw }), null, f.err);
    return f.el;
  }

  checkbox(label, draft, keys, { hint, onToggle } = {}) {
    const v = getIn(draft, keys);
    const box = h('input', { type: 'checkbox', checked: !!v });
    const id = nextId();
    box.id = id;
    // An explicit `false` stays explicit; an absent key stays absent when unchecked.
    const had = v !== undefined;
    this.bind(box, draft, keys, (raw) => ({ value: raw ? true : had ? false : undefined }), null, null);
    if (onToggle) box.addEventListener('change', () => onToggle(box.checked));
    return h('div', { class: 'field check' }, h('label', { class: 'check-label', for: id }, box, h('span', { text: label })), hint ? h('span', { class: 'field-hint', text: hint }) : null);
  }
}

export function section(title, ...children) {
  return h('section', { class: 'form-section' }, h('h3', { class: 'section-title', text: title }), ...children);
}

export function grid(...children) {
  return h('div', { class: 'form-grid' }, ...children);
}

export function button(text, { kind = 'secondary', onClick, disabled, title, type = 'button', iconNode, small } = {}) {
  const b = h('button', { type, class: ['btn', `btn-${kind}`, small ? 'btn-sm' : ''], disabled, title, on: onClick ? { click: onClick } : undefined }, iconNode || null, text ? h('span', { text }) : null);
  return b;
}

/** A short display of any JSON value for diffs and summaries. */
export function shortValue(v, max = 90) {
  if (v === undefined) return '(unset)';
  let s;
  try {
    s = typeof v === 'string' ? JSON.stringify(v) : JSON.stringify(v);
  } catch {
    s = String(v);
  }
  if (s === undefined) s = String(v);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** An error box listing an API error's code and details. */
export function errorBox(e, title = 'The request failed') {
  const details = (e && e.details) || [];
  return h(
    'div',
    { class: 'notice notice-error', role: 'alert' },
    h('div', { class: 'notice-title', text: `${title}: ${(e && e.code) || (e && e.message) || 'error'}` }),
    details.length ? h('ul', { class: 'notice-list' }, details.map((d) => h('li', { text: d }))) : null,
  );
}
