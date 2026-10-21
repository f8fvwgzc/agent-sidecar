// Inspector → Config: a form over the AgentView (GET/PUT .../agents/{agent}). Save sends
// If-Match with the charter version it loaded; on 409 it reloads, shows what changed, and can
// re-apply the viewer's own edits on top of the new version.

import { h, clear, toast, icon, ICONS } from './dom.js';
import { Form, section, grid, button, shortValue, errorBox, nextId } from './forms.js';
import { clone, diffPaths, applyPaths, overlappingPaths, stringChange, isModelName, DNS_LABEL, TOOL_NAME, utf8Length, roleAtLeast } from './util.js';

const TOOL_FIELDS = { agent: ['agent', 'service'], service: ['service', 'method', 'path'], http: ['method', 'url'] };
const ALL_TOOL_FIELDS = ['service', 'method', 'path', 'agent', 'url'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export function normalizeView(v) {
  const view = clone(v || {});
  view.agent = view.agent || {};
  if (!('allowed_tools' in view)) view.allowed_tools = null;
  if (!('allowed_services' in view)) view.allowed_services = null;
  if (!Array.isArray(view.callers)) view.callers = [];
  return view;
}

/** The PUT body: empty optional sections the original did not have are dropped. */
export function viewPayload(draft, original) {
  const a = clone(draft.agent);
  const o = (original && original.agent) || {};
  for (const k of ['budgets', 'harness', 'learning']) {
    if (a[k] && typeof a[k] === 'object' && !Object.keys(a[k]).length && !(k in o)) delete a[k];
  }
  for (const k of ['skills', 'tools']) if (Array.isArray(a[k]) && !a[k].length && !(k in o)) delete a[k];
  if (Array.isArray(a.tools)) {
    a.tools = a.tools.map((t) => {
      const keep = TOOL_FIELDS[t.type] || [];
      const out = { ...t };
      for (const f of ALL_TOOL_FIELDS) if (!keep.includes(f) || out[f] === '' || out[f] == null) delete out[f];
      return out;
    });
  }
  return { agent: a, allowed_tools: draft.allowed_tools ?? null, allowed_services: draft.allowed_services ?? null, callers: draft.callers || [] };
}

export class ConfigTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body config-tab' });
    this.loaded = false;
    this.conflict = null;
    this.serverError = null;
    this.saving = false;
  }

  get canEdit() {
    return this.ctx.app.canEdit();
  }

  activate() {
    if (!this.loaded && !this.loading) this.load();
  }

  isDirty() {
    if (!this.loaded) return false;
    return JSON.stringify(viewPayload(this.draft, this.base)) !== JSON.stringify(viewPayload(this.base, this.base));
  }

  async load() {
    const { ns, svc, agent } = this.ctx.target;
    this.loading = true;
    clear(this.el).append(h('div', { class: 'loading', text: 'Loading agent…' }));
    try {
      const [view, charter] = await Promise.all([this.ctx.api.agent(ns, svc, agent), this.ctx.api.charter(ns, svc).catch(() => null)]);
      this.version = view.version;
      this.base = normalizeView(view.data);
      this.draft = clone(this.base);
      this.skills = (charter && charter.data && charter.data.charter && charter.data.charter.skills) || [];
      this.loaded = true;
      this.render();
    } catch (e) {
      clear(this.el).append(errorBox(e, e.status === 404 ? 'This agent does not exist (any more)' : 'Could not load the agent'), button('Retry', { onClick: () => this.load() }));
    } finally {
      this.loading = false;
    }
  }

  onEvent(type, data) {
    const { ns, svc } = this.ctx.target;
    if (type === 'config' && data && data.namespace === ns && data.service === svc && this.loaded && data.version !== this.version) {
      if (!this.isDirty() && !this.saving) this.load();
      else {
        this.external = data;
        this.renderNotice();
      }
    }
  }

  render() {
    const form = new Form({ disabled: !this.canEdit, onChange: () => this.updateFooter() });
    this.form = form;
    const d = this.draft;
    const a = d.agent;
    this.noticeHost = h('div', { class: 'notices' });
    const body = h('div', { class: 'form' });
    const models = this.ctx.app.knownModels();
    const listId = nextId('models');
    body.append(
      h('datalist', { id: listId }, models.map((m) => h('option', { value: m }))),
      section(
        'Agent',
        grid(
          form.field('Name', h('input', { class: 'input mono', value: a.name || '', disabled: true })).el,
          form.select('Type', d, ['agent', 'type'], [
            ['agent', 'agent'],
            ['orchestrator', 'orchestrator'],
          ]),
        ),
        form.text('Model', d, ['agent', 'model'], {
          mono: true,
          wide: true,
          required: true,
          list: listId,
          validate: (v) => (isModelName(v) ? null : 'non-empty, at most 128 bytes, no spaces'),
        }),
        form.textarea('System prompt', d, ['agent', 'system'], {
          rows: 7,
          placeholder: 'Instructions for the agent',
          validate: (v) => (v && utf8Length(v) > 32768 ? 'at most 32768 bytes' : null),
        }),
      ),
      this.skillsSection(form),
      (this.toolsHost = h('div', { class: 'tools-host' })),
      this.servicesSection(form),
      section(
        'Budgets',
        grid(
          form.number('Max tokens per call', d, ['agent', 'budgets', 'max_tokens_per_call'], { min: 1, max: 128000 }),
          form.number('Max calls per minute', d, ['agent', 'budgets', 'max_calls_per_minute'], { min: 1 }),
          form.number('Max cost per day (USD)', d, ['agent', 'budgets', 'max_cost_usd_per_day'], { min: 0.0001, int: false }),
          form.number('Max steps', d, ['agent', 'budgets', 'max_steps'], { min: 1 }),
        ),
      ),
      section(
        'Harness',
        grid(
          form.number('Max retries', d, ['agent', 'harness', 'max_retries'], { min: 0, max: 10, placeholder: '2' }),
          form.number('Request timeout (s)', d, ['agent', 'harness', 'request_timeout_seconds'], { min: 1, max: 600, placeholder: '120' }),
          form.text('Fallback model', d, ['agent', 'harness', 'fallback_model'], {
            mono: true,
            list: listId,
            validate: (v) => (v === undefined ? null : !isModelName(v) ? 'not a valid model name' : v === d.agent.model ? 'must differ from the model' : null),
          }),
          form.number('Tool result max chars', d, ['agent', 'harness', 'tool_result_max_chars'], { min: 100, max: 200000, placeholder: '20000' }),
        ),
      ),
      this.learningSection(form),
      this.callersSection(),
    );
    this.footer = h('div', { class: 'tab-footer' });
    clear(this.el).append(this.noticeHost, body, this.footer);
    this.renderTools();
    this.renderNotice();
    this.updateFooter();
  }

  skillsSection(form) {
    const d = this.draft;
    const current = new Set(d.agent.skills || []);
    const known = this.skills.map((s) => s.name);
    const names = [...new Set([...known, ...current])];
    if (!names.length) {
      return section('Skills', h('p', { class: 'muted', text: 'The charter defines no skills. Add them under skills: in the YAML tab.' }));
    }
    const rows = names.map((name) => {
      const meta = this.skills.find((s) => s.name === name);
      const id = nextId('skill');
      const box = h('input', { type: 'checkbox', id, checked: current.has(name), disabled: !this.canEdit });
      box.addEventListener('change', () => {
        const set = new Set(d.agent.skills || []);
        if (box.checked) set.add(name);
        else set.delete(name);
        d.agent.skills = names.filter((n) => set.has(n));
        this.updateFooter();
      });
      return h(
        'label',
        { class: 'skill-row', for: id },
        box,
        h('span', { class: 'skill-name mono', text: name }),
        h('span', { class: 'skill-desc', text: meta ? meta.description : 'not defined in the charter' }),
      );
    });
    return section('Skills', h('div', { class: 'skill-list' }, rows), form.disabled ? null : h('p', { class: 'field-hint', text: 'Skill tools must be allowed for this agent.' }));
  }

  toolAllowed(name) {
    const list = this.draft.allowed_tools;
    return !Array.isArray(list) || list.includes(name);
  }

  setToolAllowed(name, on) {
    const d = this.draft;
    const names = (d.agent.tools || []).map((t) => t.name);
    let list = Array.isArray(d.allowed_tools) ? [...d.allowed_tools] : [...names];
    if (on && !list.includes(name)) list.push(name);
    if (!on) list = list.filter((n) => n !== name);
    if (this.base.allowed_tools == null && names.every((n) => list.includes(n))) list = null;
    d.allowed_tools = list;
    this.updateFooter();
  }

  renderTools() {
    const form = this.form;
    form.clearErrors('agent.tools');
    const d = this.draft;
    const tools = d.agent.tools || [];
    const cards = tools.map((t, i) => this.toolCard(form, t, i));
    const add = this.canEdit
      ? button('Add tool', {
          iconNode: icon(ICONS.plus, { size: 14 }),
          small: true,
          onClick: () => {
            d.agent.tools = [...(d.agent.tools || []), { name: '', description: '', type: 'service', service: this.ctx.target.svc, method: 'GET', path: '/' }];
            this.renderTools();
            this.updateFooter();
          },
        })
      : null;
    const restricted = Array.isArray(d.allowed_tools);
    clear(this.toolsHost).append(
      section(
        `Tools (${tools.length})`,
        h('p', {
          class: 'field-hint',
          text: restricted ? 'Only checked tools are offered to the model (guardrails.allowed_tools).' : 'Every declared tool is offered to the model (no guardrails.allowed_tools entry).',
        }),
        tools.length ? h('div', { class: 'tool-list' }, cards) : h('p', { class: 'muted', text: 'No tools.' }),
        add,
      ),
    );
  }

  toolCard(form, t, i) {
    const d = this.draft;
    let lastName = t.name;
    const keys = (k) => ['agent', 'tools', i, k];
    const nameField = form.text('Name', d, keys('name'), {
      mono: true,
      required: true,
      emptyUnset: false,
      validate: (v) => {
        if (!TOOL_NAME.test(v || '')) return 'letters, digits, _ and -, at most 64';
        if (v === 'load_skill') return 'load_skill is reserved';
        if ((d.agent.tools || []).some((x, j) => j !== i && x.name === v)) return 'another tool has this name';
        return null;
      },
    });
    const nameInput = nameField.querySelector('input');
    nameInput.addEventListener('input', () => {
      const now = d.agent.tools[i] && d.agent.tools[i].name;
      if (Array.isArray(d.allowed_tools) && lastName && now !== undefined) {
        d.allowed_tools = d.allowed_tools.map((n) => (n === lastName ? now : n));
      }
      lastName = now;
      header.querySelector('.tool-title').textContent = now || 'new tool';
    });
    const typeField = form.select('Type', d, keys('type'), [
      ['service', 'service'],
      ['agent', 'agent'],
      ['http', 'http'],
    ]);
    typeField.querySelector('select').addEventListener('change', () => {
      this.renderTools();
      this.updateFooter();
    });
    const fields = [];
    if (t.type === 'agent') {
      fields.push(
        form.text('Agent', d, keys('agent'), { mono: true, required: true, emptyUnset: false, validate: (v) => (DNS_LABEL.test(v || '') ? null : 'a DNS label') }),
        form.text('Service', d, keys('service'), { mono: true, hint: 'empty = this service', validate: (v) => (v === undefined || DNS_LABEL.test(v) ? null : 'a DNS label') }),
      );
    } else if (t.type === 'service') {
      fields.push(
        form.text('Service', d, keys('service'), { mono: true, required: true, emptyUnset: false, validate: (v) => (DNS_LABEL.test(v || '') ? null : 'a DNS label') }),
        form.select('Method', d, keys('method'), METHODS.map((m) => [m, m])),
        form.text('Path', d, keys('path'), { mono: true, required: true, emptyUnset: false, wide: true, validate: (v) => (v && v.startsWith('/') ? null : 'starts with /') }),
      );
    } else if (t.type === 'http') {
      fields.push(
        form.select('Method', d, keys('method'), METHODS.map((m) => [m, m])),
        form.text('URL', d, keys('url'), { mono: true, required: true, emptyUnset: false, wide: true, validate: (v) => (/^https?:\/\/[^/?#]+/.test(v || '') ? null : 'an http(s) URL') }),
      );
    }
    const desc = form.textarea('Description', d, keys('description'), { rows: 2, emptyUnset: false, validate: (v) => (v ? null : 'required') });
    const paramsText = t.parameters === undefined ? '' : JSON.stringify(t.parameters, null, 2);
    const params = h('textarea', { class: 'input mono', rows: '3', spellcheck: 'false', value: paramsText, placeholder: '{"type": "object", "properties": {}}' });
    const pf = form.field('Parameters (JSON Schema)', params, { wide: true, id: nextId() });
    if (form.disabled) params.disabled = true;
    params.addEventListener('input', () => {
      const s = params.value.trim();
      if (!s) {
        delete d.agent.tools[i].parameters;
        form.setError(`agent.tools[${i}].parameters`, null, pf.err, params);
      } else {
        try {
          const v = JSON.parse(s);
          if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
          d.agent.tools[i].parameters = v;
          form.setError(`agent.tools[${i}].parameters`, null, pf.err, params);
        } catch {
          form.setError(`agent.tools[${i}].parameters`, 'a JSON object', pf.err, params);
        }
      }
      this.updateFooter();
    });
    const allowedId = nextId('allowed');
    const allowed = h('input', { type: 'checkbox', id: allowedId, checked: this.toolAllowed(t.name), disabled: !this.canEdit });
    allowed.addEventListener('change', () => this.setToolAllowed(d.agent.tools[i].name, allowed.checked));
    const remove = this.canEdit
      ? button('', {
          kind: 'ghost',
          small: true,
          title: 'Remove this tool',
          iconNode: icon(ICONS.trash, { size: 14 }),
          onClick: () => {
            const name = d.agent.tools[i].name;
            d.agent.tools = d.agent.tools.filter((_, j) => j !== i);
            if (Array.isArray(d.allowed_tools)) d.allowed_tools = d.allowed_tools.filter((n) => n !== name);
            this.renderTools();
            this.updateFooter();
          },
        })
      : null;
    const header = h(
      'div',
      { class: 'tool-head' },
      h('span', { class: `type-dot td-${t.type}` }),
      h('span', { class: 'tool-title mono', text: t.name || 'new tool' }),
      h('label', { class: 'tool-allowed', for: allowedId, title: 'guardrails.allowed_tools' }, allowed, h('span', { text: 'offered' })),
      remove,
    );
    const det = h('details', { class: 'tool-card', open: !t.name }, h('summary', null, header), h('div', { class: 'form-grid' }, nameField, typeField, ...fields, desc, pf.el));
    if (!t.name) det.open = true;
    return det;
  }

  servicesSection(form) {
    const d = this.draft;
    const restricted = Array.isArray(d.allowed_services);
    const id = nextId('svcs');
    const input = h('input', { class: 'input mono', id, value: restricted ? d.allowed_services.join(', ') : '', placeholder: 'orders, inventory', disabled: !this.canEdit || !restricted });
    const err = h('span', { class: 'field-error', hidden: true });
    const parse = () => {
      const list = input.value
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const bad = list.filter((s) => !DNS_LABEL.test(s));
      form.setError('allowed_services', bad.length ? `not DNS labels: ${bad.join(', ')}` : null, err, input);
      if (!bad.length) d.allowed_services = [...new Set(list)];
      this.updateFooter();
    };
    input.addEventListener('input', parse);
    const box = h('input', { type: 'checkbox', id: nextId(), checked: restricted, disabled: !this.canEdit });
    box.addEventListener('change', () => {
      input.disabled = !box.checked;
      if (box.checked) parse();
      else {
        d.allowed_services = null;
        form.setError('allowed_services', null, err, input);
        this.updateFooter();
      }
    });
    return section(
      'Services',
      h('div', { class: 'field check' }, h('label', { class: 'check-label', for: box.id }, box, h('span', { text: 'Restrict the services this agent may call (guardrails.allowed_services)' }))),
      h('div', { class: 'field wide' }, h('label', { class: 'field-label', for: id, text: 'Allowed services' }), input, err),
    );
  }

  learningSection(form) {
    const d = this.draft;
    const admin = roleAtLeast(this.ctx.app.me().role, 'admin');
    const baseAuto = ((this.base.agent.learning || {}).mode || '') === 'auto';
    return section(
      'Learning',
      form.checkbox('Enabled: the agent proposes lessons from its runs', d, ['agent', 'learning', 'enabled']),
      grid(
        form.select(
          'Mode',
          d,
          ['agent', 'learning', 'mode'],
          [
            ['', 'default (review)'],
            ['review', 'review'],
            ['auto', 'auto'],
          ],
          { emptyUnset: true, disabledOptions: admin || baseAuto ? [] : ['auto'], hint: admin ? 'auto stores notes at once' : 'auto needs admin' },
        ),
        form.number('Max notes', d, ['agent', 'learning', 'max_notes'], { min: 1, max: 200, placeholder: '20' }),
        form.number('Max note chars', d, ['agent', 'learning', 'max_note_chars'], { min: 50, max: 4000, placeholder: '500' }),
        form.number('Note TTL (days, auto)', d, ['agent', 'learning', 'note_ttl_days'], { min: 1, max: 365, placeholder: '7' }),
        form.number('Max proposals per hour', d, ['agent', 'learning', 'max_proposals_per_hour'], { min: 1, max: 100, placeholder: '10' }),
      ),
      form.checkbox('Also reflect on runs a peer service started', d, ['agent', 'learning', 'from_peers']),
    );
  }

  callersSection() {
    const callers = this.draft.callers || [];
    return section(
      'Callers',
      callers.length
        ? h(
            'ul',
            { class: 'caller-list' },
            callers.map((c) =>
              h(
                'li',
                null,
                h('span', { class: 'mono', text: c.identity }),
                h('span', { class: 'muted', text: c.caller_agents ? ` · caller agents: ${c.caller_agents.join(', ')}` : ' · any caller agent' }),
              ),
            ),
          )
        : h('p', { class: 'muted', text: 'No authz.callers rule admits this agent: nothing can invoke it.' }),
      h('p', { class: 'field-hint', text: 'Caller rules are edited in the YAML tab (non-local identities need admin).' }),
    );
  }

  renderNotice() {
    if (!this.noticeHost) return;
    clear(this.noticeHost);
    if (!this.canEdit) this.noticeHost.append(h('div', { class: 'notice notice-info', text: 'Read-only: your role is viewer.' }));
    if (this.external) {
      this.noticeHost.append(
        h('div', { class: 'notice notice-warn' }, h('div', { class: 'notice-title', text: `Charter v${this.external.version} was stored by ${this.external.actor} while you edit.` }), h('div', { text: 'Saving will meet a version conflict; you can then review both changes.' })),
      );
    }
    if (this.conflict) this.noticeHost.append(this.conflictPanel());
    if (this.serverError) this.noticeHost.append(errorBox(this.serverError, this.serverError.status === 403 ? 'Not allowed' : 'Not saved'));
  }

  conflictPanel() {
    const c = this.conflict;
    const list = (items) =>
      h(
        'ul',
        { class: 'diff-list' },
        items.slice(0, 30).map((x) => {
          const text = typeof x.before === 'string' && typeof x.after === 'string' ? stringChange(x.before, x.after) : null;
          return h(
            'li',
            { class: c.overlap.includes(x.path) ? 'overlap' : '' },
            h('code', { text: x.path || '(whole agent)' }),
            h('span', { class: 'diff-before', text: text ? shortValue(text.before, 160) : shortValue(x.before) }),
            h('span', { class: 'diff-arrow', text: '→' }),
            h('span', { class: 'diff-after', text: text ? shortValue(text.after, 160) : shortValue(x.after) }),
          );
        }),
      );
    return h(
      'div',
      { class: 'notice notice-warn conflict' },
      h('div', { class: 'notice-title', text: `Version conflict: the charter moved from v${c.from} to v${c.to} while you were editing.` }),
      h('div', { class: 'diff-head', text: c.theirs.length ? 'What changed in this agent:' : 'This agent did not change (another part of the charter did).' }),
      c.theirs.length ? list(c.theirs) : null,
      c.mine.length
        ? h(
            'div',
            null,
            h('div', { class: 'diff-head', text: c.reapplied ? `Your ${c.mine.length} change(s) are re-applied on top of v${c.to}. Review, then Save.` : `Your ${c.mine.length} unsaved change(s) were set aside; the form shows v${c.to}.` }),
            c.overlap.length ? h('div', { class: 'diff-warn', text: `Both sides changed: ${c.overlap.join(', ')}` }) : null,
            c.reapplied ? null : list(c.mine),
          )
        : null,
      h(
        'div',
        { class: 'notice-actions' },
        c.mine.length && !c.reapplied ? button('Re-apply my changes', { kind: 'primary', small: true, onClick: () => this.reapply() }) : null,
        button(c.reapplied ? 'Dismiss' : 'Keep the new version', {
          small: true,
          onClick: () => {
            if (!c.reapplied) this.draft = clone(this.base);
            this.conflict = null;
            this.render();
          },
        }),
      ),
    );
  }

  reapply() {
    this.draft = applyPaths(clone(this.base), this.conflict.mine);
    this.conflict.reapplied = true;
    this.render();
  }

  updateFooter() {
    if (!this.footer) return;
    clear(this.footer);
    const dirty = this.isDirty();
    const ver = h('span', { class: 'footer-meta', text: `Charter v${this.version ?? '?'}${dirty ? ' · unsaved changes' : ''}` });
    if (dirty) ver.classList.add('dirty');
    if (!this.canEdit) {
      this.footer.append(ver);
      return;
    }
    const errors = this.form && this.form.hasErrors();
    this.footer.append(
      ver,
      h('span', { class: 'spacer' }),
      button('Revert', {
        disabled: !dirty || this.saving,
        onClick: () => {
          this.draft = clone(this.base);
          this.serverError = null;
          this.render();
        },
      }),
      button(this.saving ? 'Saving…' : 'Save', { kind: 'primary', disabled: !dirty || errors || this.saving, title: errors ? 'Fix the highlighted fields first' : `PUT with If-Match "${this.version}"`, onClick: () => this.save() }),
    );
    if (this.ctx.onDirty) this.ctx.onDirty(this, dirty);
  }

  async save() {
    if (this.form.hasErrors()) return;
    const { ns, svc, agent } = this.ctx.target;
    const body = viewPayload(this.draft, this.base);
    this.saving = true;
    this.serverError = null;
    this.updateFooter();
    try {
      const res = await this.ctx.api.putAgent(ns, svc, agent, body, this.version);
      this.version = (res.data && res.data.version) || res.version || this.version;
      this.base = normalizeView(body);
      this.draft = clone(this.base);
      this.conflict = null;
      this.external = null;
      toast(`Saved ${agent} as charter v${this.version}`, { kind: 'success' });
      this.ctx.app.refresh();
      this.saving = false;
      this.render();
    } catch (e) {
      this.saving = false;
      if (e.status === 409) await this.onConflict();
      else {
        this.serverError = e;
        this.renderNotice();
        this.updateFooter();
      }
    }
  }

  async onConflict() {
    const { ns, svc, agent } = this.ctx.target;
    const before = viewPayload(this.base, this.base);
    const mine = diffPaths(before, viewPayload(this.draft, this.base));
    try {
      const res = await this.ctx.api.agent(ns, svc, agent);
      const latest = normalizeView(res.data);
      const theirs = diffPaths(before, viewPayload(latest, latest));
      this.conflict = { from: this.version, to: res.version, mine, theirs, overlap: overlappingPaths(mine, theirs), reapplied: false };
      this.version = res.version;
      this.base = latest;
      this.draft = clone(latest);
      this.external = null;
      this.render();
      this.el.scrollTop = 0;
    } catch (e) {
      this.serverError = e;
      this.renderNotice();
    }
  }
}
