// Modal dialogs: + Agent, drag-to-link, and adopting a pending charter. One native <dialog>
// element is reused; its content is rebuilt each time with safe DOM calls.

import { h, clear, icon, ICONS, toast, pill } from './dom.js';
import { Form, grid, button, errorBox, nextId } from './forms.js';
import { DNS_LABEL, TOOL_NAME, isModelName, parseNodeId, roleAtLeast, suggestToolName, linkRequirement, agentNodeId, shortId } from './util.js';

/** Opens the shared dialog; returns {close, body, footer, setError}. */
export function openDialog({ title, subtitle, body, actions = [], wide = false, onClose } = {}) {
  const dlg = document.getElementById('dialog');
  const close = () => {
    if (dlg.open) dlg.close();
  };
  const errHost = h('div', { class: 'dialog-errors' });
  const footer = h('footer', { class: 'dialog-foot' }, actions);
  const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Close', on: { click: close } }, icon(ICONS.close));
  clear(dlg).append(
    h(
      'div',
      { class: ['dialog-inner', wide ? 'wide' : ''] },
      h('header', { class: 'dialog-head' }, h('div', null, h('h2', { class: 'dialog-title', text: title }), subtitle ? h('div', { class: 'dialog-sub', text: subtitle }) : null), closeBtn),
      h('div', { class: 'dialog-body' }, body, errHost),
      footer,
    ),
  );
  const onClick = (ev) => {
    if (ev.target === dlg) close();
  };
  const onClosed = () => {
    dlg.removeEventListener('click', onClick);
    dlg.removeEventListener('close', onClosed);
    if (onClose) onClose();
  };
  dlg.addEventListener('click', onClick);
  dlg.addEventListener('close', onClosed);
  if (!dlg.open) dlg.showModal();
  const first = dlg.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled])');
  if (first) first.focus();
  return {
    close,
    footer,
    setError(e, heading) {
      clear(errHost);
      if (e) errHost.append(errorBox(e, heading));
    },
    setNotice(node) {
      clear(errHost);
      if (node) errHost.append(node);
    },
  };
}

// ---- + Agent ------------------------------------------------------------------------------------

export function openAddAgent(app, preset = {}) {
  const services = app.services().filter((s) => s.charter_version && !app.isFiltered(s));
  if (!services.length) {
    toast('No service with a stored charter is visible. Adopt or create a charter first.', { kind: 'warn' });
    return;
  }
  // The model starts as the one most agents of this graph use, as reported by the control plane.
  const draft = { svc: '', agent: { name: '', type: 'agent', model: app.knownModels()[0] || '' } };
  const key = (s) => `${s.namespace}/${s.service}`;
  draft.svc = preset.svc && services.some((s) => key(s) === preset.svc) ? preset.svc : key(services[0]);
  const form = new Form({ onChange: () => sync() });
  const listId = nextId('models');
  const existing = () => {
    const s = services.find((x) => key(x) === draft.svc);
    return s ? app.agentsOf(s.namespace, s.service).map((n) => n.label) : [];
  };
  const body = h(
    'div',
    { class: 'form' },
    h('datalist', { id: listId }, app.knownModels().map((m) => h('option', { value: m }))),
    grid(
      form.select('Service', draft, ['svc'], services.map((s) => [key(s), `${s.service} (${s.namespace}) · v${s.charter_version}`])),
      form.select('Type', draft, ['agent', 'type'], [
        ['agent', 'agent'],
        ['orchestrator', 'orchestrator'],
      ]),
      form.text('Name', draft, ['agent', 'name'], {
        mono: true,
        required: true,
        emptyUnset: false,
        placeholder: 'agent-name',
        validate: (v) => (!DNS_LABEL.test(v || '') ? 'lowercase letters, digits and -, at most 63' : existing().includes(v) ? 'this service already has that agent' : null),
      }),
      form.text('Model', draft, ['agent', 'model'], { mono: true, required: true, emptyUnset: false, list: listId, placeholder: 'model-id', validate: (v) => (isModelName(v) ? null : 'non-empty, at most 128 bytes, no spaces') }),
    ),
    form.textarea('System prompt', draft, ['agent', 'system'], { rows: 5, placeholder: 'What this agent does and how it answers' }),
    grid(
      form.number('Max tokens per call', draft, ['agent', 'budgets', 'max_tokens_per_call'], { min: 1, max: 128000 }),
      form.number('Max steps', draft, ['agent', 'budgets', 'max_steps'], { min: 1 }),
    ),
    h('p', { class: 'field-hint', text: 'The new agent joins the identity: local caller rule, so the app can invoke it. Tools, skills and learning are set afterwards in Config.' }),
  );
  const create = button('Create agent', { kind: 'primary', onClick: () => submit() });
  const cancel = button('Cancel', { onClick: () => d.close() });
  const d = openDialog({ title: 'Add an agent', subtitle: 'POST /services/{ns}/{svc}/agents', body, actions: [cancel, create] });
  const sync = () => {
    create.disabled = form.hasErrors() || !draft.agent.name || !draft.agent.model;
  };
  sync();
  let version = null;
  const submit = async () => {
    if (create.disabled) return;
    const s = services.find((x) => key(x) === draft.svc);
    const agent = { ...draft.agent };
    if (agent.budgets && !Object.keys(agent.budgets).length) delete agent.budgets;
    const v = version || s.charter_version;
    create.disabled = true;
    try {
      const res = await app.api.createAgent(s.namespace, s.service, { agent }, v);
      d.close();
      toast(`Created ${agent.name} in ${s.service} (charter v${(res.data && res.data.version) || res.version}).`, { kind: 'success' });
      await app.refresh();
      const node = app.node(agentNodeId(s.namespace, s.service, agent.name));
      if (node) app.openNode(node, 'config');
    } catch (e) {
      if (e.status === 409 && e.currentVersion) {
        version = e.currentVersion;
        d.setError(e, `The ${s.service} charter is now v${e.currentVersion}; press Create again to add the agent to it`);
        app.refresh();
      } else {
        d.setError(e, e.status === 403 ? 'Not allowed' : 'Not created');
      }
      sync();
    }
  };
}

// ---- drag to link -------------------------------------------------------------------------------

export function openLinkDialog(app, from, to) {
  const req = linkRequirement(from.id, to.id);
  if (req.level === 'refused') {
    toast(`Cannot link ${from.label} to ${to.label}: ${req.reason}`, { kind: 'warn' });
    return;
  }
  const me = app.me();
  const a = parseNodeId(from.id);
  const b = parseNodeId(to.id);
  const allowed = roleAtLeast(me.role, req.level);
  const existingTools = (from.tools || []).map((t) => t.name).concat((from.ports && from.ports.out) || []);
  // Agent tools of the caller that already reach this agent (the graph resolves their targets).
  const linked = (from.tools || []).filter((t) => t.type === 'agent' && t.target === to.id);
  const draft = { name: suggestToolName(b.agent, existingTools), description: a.svc === b.svc ? `Ask the local ${b.agent} agent.` : `Ask the ${b.svc} service's ${b.agent} agent.`, again: false };
  const form = new Form({ onChange: () => sync() });
  const already = linked.length
    ? h(
        'div',
        { class: 'notice notice-warn link-exists' },
        h('div', { class: 'notice-title', text: `${from.label} already calls ${to.label}.` }),
        h(
          'div',
          null,
          h('span', { text: linked.length === 1 ? 'Through its tool ' : 'Through its tools ' }),
          linked.flatMap((t, i) => [i ? h('span', { text: ', ' }) : null, h('code', { text: t.name }), t.allowed === false ? h('span', { class: 'muted', text: ' (not offered to the model)' }) : null]),
          h('span', { text: '. A link adds one more agent tool next to it; to change the existing one, edit it in Config.' }),
        ),
        h(
          'div',
          { class: 'notice-actions' },
          button(`Open ${from.label} Config`, {
            small: true,
            onClick: () => {
              d.close();
              app.openNode(from, 'config');
            },
          }),
        ),
        form.checkbox('Add another tool to the same agent anyway', draft, ['again']),
      )
    : null;
  const body = h(
    'div',
    { class: 'form' },
    h(
      'div',
      { class: 'link-route' },
      h('div', { class: 'link-end' }, h('span', { class: 'muted small', text: 'caller' }), h('span', { class: 'mono', text: from.label }), h('span', { class: 'muted small', text: `${a.ns}/${a.svc}` })),
      h('div', { class: 'link-arrow' }, icon(ICONS.chevron, { size: 18 })),
      h('div', { class: 'link-end' }, h('span', { class: 'muted small', text: 'callee' }), h('span', { class: 'mono', text: to.label }), h('span', { class: 'muted small', text: `${b.ns}/${b.svc}` })),
    ),
    already,
    form.text('Tool name', draft, ['name'], {
      mono: true,
      required: true,
      emptyUnset: false,
      validate: (v) => (!TOOL_NAME.test(v || '') ? 'letters, digits, _ and -, at most 64' : v === 'load_skill' ? 'reserved' : existingTools.includes(v) ? `${from.label} already has this tool` : null),
    }),
    form.textarea('Description', draft, ['description'], { rows: 3, emptyUnset: false, validate: (v) => (v ? null : 'required'), hint: 'The model reads this to decide when to call the agent.' }),
    h(
      'div',
      { class: ['notice', req.level === 'admin' ? 'notice-warn' : 'notice-info'] },
      h('div', { class: 'notice-title' }, h('span', { text: 'Needs the ' }), pill(req.level, `pill-role-${req.level}`), h('span', { text: ' role.' })),
      h('div', { text: req.level === 'admin' ? `${req.reason} Then ${a.svc} gets the agent tool.` : `Adds an agent tool to ${from.label} and allows it in its guardrails.` }),
      allowed ? null : h('div', { class: 'neg', text: `You are ${me.role}: the control plane will refuse this link.` }),
    ),
  );
  const create = button(linked.length ? 'Add another link' : 'Create link', { kind: 'primary', disabled: !allowed, onClick: () => submit() });
  const d = openDialog({ title: linked.length ? 'Already linked' : 'Link agents', subtitle: 'POST /links', body, actions: [button('Cancel', { onClick: () => d.close() }), create] });
  const sync = () => {
    create.disabled = !allowed || form.hasErrors() || !draft.name || !draft.description || (linked.length > 0 && !draft.again);
  };
  sync();
  const submit = async () => {
    if (create.disabled) return;
    const ifMatch = {};
    for (const p of [a, b]) {
      const s = app.serviceSummary(p.ns, p.svc);
      if (s && s.charter_version) ifMatch[`${p.ns}/${p.svc}`] = s.charter_version;
    }
    create.disabled = true;
    try {
      const res = await app.api.link({ from: from.id, to: to.id, tool: { name: draft.name, description: draft.description }, if_match: ifMatch });
      const r = res.data || { applied: [], failed: {} };
      const failed = Object.entries(r.failed || {});
      await app.refresh();
      if (!failed.length) {
        d.close();
        toast(`Linked ${from.label} → ${to.label} as tool ${draft.name}.`, { kind: 'success', details: (r.applied || []).map((x) => `${x.service} is now v${x.version}`) });
        return;
      }
      d.setNotice(
        h(
          'div',
          { class: 'notice notice-error' },
          h('div', { class: 'notice-title', text: (r.applied || []).length ? 'Partly applied' : 'Not applied' }),
          h(
            'ul',
            { class: 'notice-list' },
            (r.applied || []).map((x) => h('li', { text: `applied: ${x.service} → v${x.version}` })),
            failed.map(([svc, e]) => h('li', { text: `failed: ${svc}: ${e.error}${e.details && e.details.length ? ` (${e.details.join('; ')})` : ''}` })),
          ),
          h('div', { class: 'muted', text: 'Versions were refreshed; press Create link to retry the rest.' }),
        ),
      );
      sync();
    } catch (e) {
      d.setError(e, e.status === 403 ? 'Not allowed' : 'Not linked');
      sync();
    }
  };
}

// ---- adoption -----------------------------------------------------------------------------------

export function openAdopt(app, s) {
  const p = s.pending_adoption;
  if (!p) return;
  const go = button('Adopt charter', { kind: 'primary', onClick: () => submit() });
  const d = openDialog({
    title: `Adopt the ${s.service} charter`,
    subtitle: 'POST /services/{ns}/{svc}/adopt',
    body: h(
      'div',
      { class: 'form' },
      h('p', { text: `The sidecar in pod ${p.pod} started with its own charter. Adopting stores it as the first charter of ${s.namespace}/${s.service}; from then on the control plane owns it.` }),
      h('div', { class: 'kv-inline' }, h('span', { class: 'muted', text: 'sha256 ' }), h('code', { text: p.sha256 })),
      h('p', { class: 'field-hint', text: `Fingerprint ${shortId(p.sha256, 12)}. The charter still passes the validator and policy.` }),
    ),
    actions: [button('Cancel', { onClick: () => d.close() }), go],
  });
  const submit = async () => {
    go.disabled = true;
    try {
      const res = await app.api.adopt(s.namespace, s.service, p.sha256);
      d.close();
      toast(`Adopted: ${s.service} charter v${(res.data && res.data.version) || res.version}.`, { kind: 'success' });
      await app.refresh();
    } catch (e) {
      d.setError(e, e.status === 409 ? 'The service already has a charter' : 'Not adopted');
      go.disabled = false;
      app.refresh();
    }
  };
}
