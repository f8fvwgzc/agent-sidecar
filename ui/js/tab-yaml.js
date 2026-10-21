// Inspector → YAML: the service charter as stored. Validate runs POST .../charter/validate and
// shows the role the change needs and what it weakens; Save is PUT with If-Match.

import { h, clear, append, toast, pill } from './dom.js';
import { button, errorBox } from './forms.js';
import { roleAtLeast, diffLines, diffHunks, relTime, shortId } from './util.js';

export class YamlTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body yaml-tab' });
    this.loaded = false;
    this.result = null;
    this.error = null;
    this.conflict = null;
    this.confirmWeakened = false;
  }

  get canEdit() {
    return this.ctx.app.canEdit();
  }

  activate() {
    if (!this.loaded && !this.loading) this.load();
  }

  isDirty() {
    return this.loaded && this.text !== undefined && this.text !== this.base;
  }

  async load() {
    const { ns, svc } = this.ctx.target;
    this.loading = true;
    if (!this.loaded) clear(this.el).append(h('div', { class: 'loading', text: 'Loading charter…' }));
    try {
      const [res, hist] = await Promise.all([this.ctx.api.charter(ns, svc), this.ctx.api.history(ns, svc).catch(() => null)]);
      this.version = res.version || (res.data && res.data.version);
      this.epoch = res.data && res.data.epoch;
      this.base = (res.data && res.data.yaml) || '';
      this.text = this.base;
      this.history = hist && Array.isArray(hist.data) ? hist.data : [];
      this.loaded = true;
      this.result = null;
      this.error = null;
      this.conflict = null;
      this.external = null;
      this.confirmWeakened = false;
      this.render();
    } catch (e) {
      const none = e.status === 404;
      clear(this.el).append(
        errorBox(e, none ? 'This service has no stored charter' : 'Could not load the charter'),
        none ? h('p', { class: 'muted', text: 'A sidecar start-up charter can be adopted from the banner, or an admin can create one.' }) : button('Retry', { onClick: () => this.load() }),
      );
    } finally {
      this.loading = false;
    }
  }

  onEvent(type, data) {
    const { ns, svc } = this.ctx.target;
    if (type === 'config' && data && data.namespace === ns && data.service === svc && this.loaded && data.version !== this.version && !this.saving) {
      if (!this.isDirty()) {
        this.load();
        toast(`Charter v${data.version} of ${svc} loaded (stored by ${data.actor}).`, { kind: 'info' });
      } else {
        this.external = data;
        this.renderStatus();
      }
    }
  }

  render() {
    const ro = !this.canEdit;
    this.textarea = h('textarea', { class: 'yaml-editor mono', spellcheck: 'false', wrap: 'off', readOnly: ro, 'aria-label': 'Charter YAML', value: this.text });
    this.textarea.addEventListener('input', () => {
      this.text = this.textarea.value;
      this.result = null;
      this.confirmWeakened = false;
      this.updateFooter();
      this.renderStatus();
    });
    this.textarea.addEventListener('keydown', (ev) => {
      if (ro) return;
      if (ev.key === 'Tab' && !ev.shiftKey && !ev.altKey && !ev.ctrlKey && !ev.metaKey) {
        ev.preventDefault();
        const ta = this.textarea;
        ta.setRangeText('  ', ta.selectionStart, ta.selectionEnd, 'end');
        ta.dispatchEvent(new Event('input'));
      } else if (ev.key === 'Escape') {
        this.textarea.blur();
      }
    });
    this.statusHost = h('div', { class: 'notices' });
    this.footer = h('div', { class: 'tab-footer' });
    const now = this.ctx.api.now();
    const hist = this.history.length
      ? h(
          'details',
          { class: 'history' },
          h('summary', { class: 'section-title', text: `History (${this.history.length})` }),
          h(
            'ol',
            { class: 'history-list' },
            this.history.map((e) =>
              h(
                'li',
                null,
                h('span', { class: 'mono', text: `v${e.version}` }),
                h('span', { text: e.actor }),
                h('span', { class: 'muted', text: relTime(e.ts, now), title: e.ts }),
                h('code', { class: 'muted', text: shortId(e.sha256, 10), title: `sha256 ${e.sha256}` }),
              ),
            ),
          ),
        )
      : null;
    append(clear(this.el), [
      h(
        'div',
        { class: 'tab-toolbar' },
        h('span', { class: 'mono', text: `v${this.version}` }),
        h('span', { class: 'muted', text: this.epoch ? `epoch ${shortId(this.epoch, 8)}` : '' }),
        h('span', { class: 'spacer' }),
        ro ? pill('read-only', 'pill-muted') : h('span', { class: 'muted small', text: 'Tab indents · Esc leaves the editor' }),
      ),
      this.statusHost,
      this.textarea,
      this.footer,
      hist,
    ]);
    this.renderStatus();
    this.updateFooter();
  }

  renderStatus() {
    if (!this.statusHost) return;
    clear(this.statusHost);
    if (this.external) {
      this.statusHost.append(h('div', { class: 'notice notice-warn' }, h('div', { class: 'notice-title', text: `v${this.external.version} was stored by ${this.external.actor} while you edit v${this.version}.` }), h('div', { text: 'Saving will meet a version conflict.' })));
    }
    if (this.conflict) this.statusHost.append(this.conflictPanel());
    if (this.error) this.statusHost.append(errorBox(this.error, this.error.status === 403 ? 'Not allowed' : this.error.code === 'invalid' ? 'Invalid charter' : 'Failed'));
    const r = this.result;
    if (r) {
      const me = this.ctx.app.me();
      const enough = roleAtLeast(me.role, r.needs_role);
      const cls = !enough ? 'notice-error' : r.weakened.length ? 'notice-warn' : 'notice-ok';
      this.statusHost.append(
        h(
          'div',
          { class: ['notice', cls] },
          h('div', { class: 'notice-title' }, h('span', { text: 'Valid. ' }), h('span', { text: 'Saving needs the ' }), pill(r.needs_role, `pill-role-${r.needs_role}`), h('span', { text: ' role' }), h('span', { text: enough ? '.' : ` (you are ${me.role}).` })),
          r.weakened.length
            ? h('div', null, h('div', { text: 'This change weakens protection:' }), h('ul', { class: 'notice-list' }, r.weakened.map((w) => h('li', null, h('code', { text: w })))))
            : h('div', { class: 'muted', text: 'Nothing that weakens protection.' }),
        ),
      );
    }
  }

  conflictPanel() {
    const c = this.conflict;
    const hunks = diffHunks(diffLines(c.mineBase, c.latest), 2);
    const view = hunks
      ? h(
          'pre',
          { class: 'diff' },
          hunks.slice(0, 400).map((o) => h('span', { class: `dl dl-${o.op === '+' ? 'add' : o.op === '-' ? 'del' : o.op === '…' ? 'gap' : 'ctx'}`, text: `${o.op === '…' ? '⋯' : o.op} ${o.text}\n` })),
        )
      : h('p', { class: 'muted', text: 'Too large to diff here.' });
    return h(
      'div',
      { class: 'notice notice-warn conflict' },
      h('div', { class: 'notice-title', text: `Version conflict: the stored charter moved from v${c.from} to v${c.to}.` }),
      h('div', { class: 'diff-head', text: `What changed between v${c.from} and v${c.to}:` }),
      view,
      h(
        'div',
        { class: 'notice-actions' },
        button(`Load v${c.to} (drop my edits)`, {
          small: true,
          onClick: () => {
            this.text = c.latest;
            this.base = c.latest;
            this.conflict = null;
            this.render();
          },
        }),
        button(`Keep my text, based on v${c.to}`, {
          kind: 'primary',
          small: true,
          title: 'Your text stays; the next Save replaces the new version',
          onClick: () => {
            this.base = c.latest;
            this.conflict = null;
            this.render();
          },
        }),
      ),
    );
  }

  updateFooter() {
    if (!this.footer) return;
    clear(this.footer);
    const dirty = this.isDirty();
    const lines = (this.text || '').split('\n').length;
    const meta = h('span', { class: ['footer-meta', dirty ? 'dirty' : ''], text: `${lines} lines${dirty ? ' · unsaved changes' : ''}` });
    if (!this.canEdit) {
      this.footer.append(meta);
      return;
    }
    const weakenedPending = this.confirmWeakened && this.result && this.result.weakened.length;
    this.footer.append(
      meta,
      h('span', { class: 'spacer' }),
      button('Revert', {
        disabled: !dirty || this.busy,
        onClick: () => {
          this.text = this.base;
          this.result = null;
          this.error = null;
          this.render();
        },
      }),
      button(this.busy === 'validate' ? 'Validating…' : 'Validate', { disabled: !!this.busy, onClick: () => this.validate() }),
      button(this.busy === 'save' ? 'Saving…' : weakenedPending ? 'Save anyway' : 'Save', {
        kind: weakenedPending ? 'danger' : 'primary',
        disabled: !dirty || !!this.busy,
        title: `Validates, then PUT with If-Match "${this.version}"`,
        onClick: () => this.save(),
      }),
    );
  }

  async validate() {
    const { ns, svc } = this.ctx.target;
    this.busy = 'validate';
    this.error = null;
    this.updateFooter();
    try {
      const res = await this.ctx.api.validateCharter(ns, svc, this.text);
      this.result = { needs_role: res.data.needs_role, weakened: res.data.weakened || [] };
      return this.result;
    } catch (e) {
      this.result = null;
      this.error = e;
      return null;
    } finally {
      this.busy = null;
      this.renderStatus();
      this.updateFooter();
    }
  }

  async save() {
    const { ns, svc } = this.ctx.target;
    const me = this.ctx.app.me();
    const confirmed = this.confirmWeakened;
    const v = await this.validate();
    if (!v) return;
    if (!roleAtLeast(me.role, v.needs_role)) return;
    if (v.weakened.length && !confirmed) {
      this.confirmWeakened = true;
      this.updateFooter();
      return;
    }
    this.busy = 'save';
    this.saving = true;
    this.updateFooter();
    try {
      const res = await this.ctx.api.putCharter(ns, svc, this.text, this.version);
      this.version = (res.data && res.data.version) || res.version;
      this.base = this.text;
      this.result = null;
      this.external = null;
      this.confirmWeakened = false;
      toast(`Saved the ${svc} charter as v${this.version}.`, { kind: 'success' });
      this.ctx.app.refresh();
      this.busy = null;
      this.saving = false;
      await this.load();
    } catch (e) {
      this.busy = null;
      this.saving = false;
      if (e.status === 409) {
        await this.onConflict();
      } else {
        this.error = e;
        this.renderStatus();
        this.updateFooter();
      }
    }
  }

  async onConflict() {
    const { ns, svc } = this.ctx.target;
    try {
      const res = await this.ctx.api.charter(ns, svc);
      const latest = (res.data && res.data.yaml) || '';
      this.conflict = { from: this.version, to: res.version || res.data.version, mineBase: this.base, latest };
      this.version = this.conflict.to;
      this.external = null;
      this.confirmWeakened = false;
      this.renderStatus();
      this.updateFooter();
      this.el.scrollTop = 0;
    } catch (e) {
      this.error = e;
      this.renderStatus();
    }
  }
}

