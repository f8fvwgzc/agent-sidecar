// Inspector → Traffic: recent audit records of an agent or a service (GET /events/recent),
// grouped by request_id, newest request first, with live records added as they arrive. Payloads
// are shown with JSON.stringify into <pre> via textContent.

import { h, clear, icon, ICONS, kv, pill } from './dom.js';
import { button, errorBox } from './forms.js';
import { groupByRequest, fmtClock, fmtMs, fmtCost, fmtInt, shortId, inputSummary, payloadState, payloadText, outcomeOf, parseTs } from './util.js';

const KIND_LABEL = {
  agent_invocation: 'invocation',
  model_call: 'model',
  tool_call: 'tool',
  agent_call: 'agent call',
  service_call: 'service',
  http_call: 'http',
  guardrail: 'guardrail',
  budget: 'budget',
  authz: 'authz',
  config: 'config',
  learning: 'learning',
};

function recordKey(r) {
  return [r.span_id, r.kind, r.ts, r.rule, r.direction, r.service].join('|');
}

export function payloadBlock(label, value, sha, canSee) {
  const st = payloadState(value, sha, canSee);
  const head = h(
    'div',
    { class: 'payload-head' },
    h('span', { class: 'payload-label', text: label }),
    sha ? h('code', { class: 'sha', title: `sha256 ${sha}`, text: `sha256 ${sha.slice(0, 12)}…` }) : null,
  );
  let body;
  if (st === 'hidden') {
    body = h('div', { class: 'payload-missing' }, pill('hidden', 'pill-muted'), h('span', { text: 'Your token may not see payloads.' }));
  } else if (st === 'absent') {
    body = h('div', { class: 'payload-missing' }, pill('not sent', 'pill-muted'), h('span', { text: 'Only the hash reached the control plane (or the value was withheld).' }));
  } else if (st === 'null') {
    body = h('div', { class: 'payload-missing' }, h('span', { class: 'mono muted', text: 'null' }));
  } else {
    const text = payloadText(value);
    const pre = h('pre', { class: 'json' });
    pre.textContent = text;
    const copy = button('', {
      kind: 'ghost',
      small: true,
      title: 'Copy',
      iconNode: icon(['M8 8h11v11H8z', 'M5 16V5h11'], { size: 13 }),
      onClick: (ev) => {
        ev.preventDefault();
        if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
      },
    });
    copy.classList.add('copy-btn');
    body = h('div', { class: 'payload-body' }, pre, copy);
  }
  return h('div', { class: 'payload' }, head, body);
}

export class TrafficTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body traffic-tab' });
    this.records = [];
    this.keys = new Set();
    this.openGroups = new Set();
    this.openRecords = new Set();
    this.onlyIssues = false;
    this.loaded = false;
    this.renderTimer = null;
  }

  activate() {
    if (!this.loaded && !this.loading) this.load();
  }

  isDirty() {
    return false;
  }

  query() {
    const { ns, svc, agent } = this.ctx.target;
    return { namespace: ns, service: svc, agent: agent || undefined, limit: 300 };
  }

  matches(r) {
    const { ns, svc, agent } = this.ctx.target;
    return r && r.namespace === ns && r.service === svc && (!agent || r.agent === agent || r.caller_agent === agent);
  }

  async load() {
    this.loading = true;
    if (!this.loaded) clear(this.el).append(h('div', { class: 'loading', text: 'Loading traffic…' }));
    try {
      const res = await this.ctx.api.recent(this.query());
      this.records = Array.isArray(res.data) ? res.data : [];
      this.keys = new Set(this.records.map(recordKey));
      this.loaded = true;
      if (!this.openGroups.size) {
        const first = groupByRequest(this.records)[0];
        if (first) this.openGroups.add(first.request_id);
      }
      this.render();
    } catch (e) {
      clear(this.el).append(errorBox(e, 'Could not load traffic'), button('Retry', { onClick: () => this.load() }));
    } finally {
      this.loading = false;
    }
  }

  onEvent(type, data) {
    if (type === 'audit' && data && data.record && this.loaded && this.matches(data.record)) {
      const k = recordKey(data.record);
      if (this.keys.has(k)) return;
      this.keys.add(k);
      this.records.unshift(data.record);
      if (this.records.length > 1500) this.records.length = 1500;
      this.fresh = data.record.request_id;
      this.scheduleRender();
    }
    if ((type === 'reset' || type === 'lagged') && this.loaded) this.load();
  }

  scheduleRender() {
    if (this.renderTimer) return;
    this.renderTimer = setTimeout(() => {
      this.renderTimer = null;
      this.render();
    }, 120);
  }

  render() {
    const scroll = this.el.scrollTop;
    const groups = groupByRequest(this.records).filter((g) => !this.onlyIssues || g.denied || g.errors);
    const box = h('input', { type: 'checkbox', id: `issues-${this.ctx.target.id}`, checked: this.onlyIssues });
    box.addEventListener('change', () => {
      this.onlyIssues = box.checked;
      this.render();
    });
    const bar = h(
      'div',
      { class: 'tab-toolbar' },
      h('span', { class: 'muted', text: `${fmtInt(this.records.length)} records · ${fmtInt(groupByRequest(this.records).length)} requests` }),
      h('span', { class: 'spacer' }),
      h('label', { class: 'check-label small', for: box.id }, box, h('span', { text: 'denied or errors only' })),
      button('', { kind: 'ghost', small: true, title: 'Reload', iconNode: icon(ICONS.refresh, { size: 14 }), onClick: () => this.load() }),
    );
    const list = h('div', { class: 'groups' });
    if (!groups.length) {
      list.append(
        h('div', { class: 'empty-state small' }, h('div', { class: 'empty-title', text: this.records.length ? 'No denied or failed requests.' : 'No traffic yet.' }), h('div', { class: 'muted', text: 'Records appear here live while the stream is on.' })),
      );
    }
    for (const g of groups.slice(0, 80)) list.append(this.groupEl(g));
    clear(this.el).append(bar, list);
    this.el.scrollTop = scroll;
    this.fresh = null;
  }

  groupEl(g) {
    const root = g.root;
    const summary = inputSummary(root || g.records.find((r) => inputSummary(r)) || {});
    const outcome = g.outcome;
    const details = h('details', { class: ['group', `o-${outcome}`, this.fresh === g.request_id ? 'fresh' : ''], open: this.openGroups.has(g.request_id) });
    details.addEventListener('toggle', () => {
      if (details.open) this.openGroups.add(g.request_id);
      else this.openGroups.delete(g.request_id);
    });
    const agentLabel = root ? root.agent : g.records[0].agent;
    const caller = root && root.caller !== 'local' ? `from ${root.caller_agent || root.caller.replace(/^spiffe:\/\/agentsc\/ns\//, '')}` : null;
    details.append(
      h(
        'summary',
        { class: 'group-head' },
        h('span', { class: `odot od-${outcome}` }),
        h('span', { class: 'group-time mono', text: fmtClock(g.first) }),
        h('span', { class: 'group-summary', text: summary || (root ? root.callee : g.records[0].kind) }),
        h(
          'span',
          { class: 'group-meta' },
          g.denied ? pill(`${g.denied} denied`, 'pill-deny') : null,
          g.errors ? pill(`${g.errors} error${g.errors === 1 ? '' : 's'}`, 'pill-error') : null,
          h('span', { class: 'muted', text: root ? fmtMs(root.latency_ms) : `${g.records.length} rec` }),
        ),
      ),
      h(
        'div',
        { class: 'group-body' },
        h(
          'div',
          { class: 'group-ids' },
          h('span', { class: 'muted', text: 'request ' }),
          h('code', { text: shortId(g.request_id, 13), title: g.request_id }),
          agentLabel ? h('span', { class: 'muted', text: ` · ${agentLabel}` }) : null,
          caller ? h('span', { class: 'muted', text: ` · ${caller}` }) : null,
          root && root.cost_usd ? h('span', { class: 'muted', text: ` · ${fmtCost(root.cost_usd)}` }) : null,
        ),
        h('ol', { class: 'records' }, g.records.map((r) => this.recordEl(r, g))),
      ),
    );
    return details;
  }

  recordEl(r, g) {
    const key = recordKey(r);
    const outcome = outcomeOf(r);
    const t0 = parseTs(g.first);
    const t = parseTs(r.ts);
    const offset = Number.isFinite(t0) && Number.isFinite(t) ? `+${fmtMs(t - t0)}` : '';
    const det = h('details', { class: ['record', `o-${outcome}`], open: this.openRecords.has(key) });
    det.addEventListener('toggle', () => {
      if (det.open) {
        this.openRecords.add(key);
        if (!det.dataset.filled) {
          det.dataset.filled = '1';
          det.append(this.recordDetail(r));
        }
      } else this.openRecords.delete(key);
    });
    det.append(
      h(
        'summary',
        { class: 'record-head' },
        h('span', { class: 'rec-offset mono', text: offset }),
        h('span', { class: `kind k-${r.kind}`, text: KIND_LABEL[r.kind] || r.kind }),
        h('span', { class: 'rec-callee mono', text: r.callee || '' }),
        h('span', { class: `decision d-${outcome}`, text: outcome === 'error' ? 'error' : r.decision }),
        h('span', { class: 'rec-latency muted', text: fmtMs(r.latency_ms) }),
      ),
    );
    if (det.open) {
      det.dataset.filled = '1';
      det.append(this.recordDetail(r));
    }
    return h('li', null, det);
  }

  recordDetail(r) {
    const canSee = this.ctx.app.me().payloads;
    const tokens = r.tokens ? `${fmtInt(r.tokens.input)} in / ${fmtInt(r.tokens.output)} out` : null;
    return h(
      'div',
      { class: 'record-body' },
      kv([
        ['decision', r.decision],
        ['rule', r.rule],
        ['reason', r.reason],
        ['error', r.error],
        ['latency', fmtMs(r.latency_ms)],
        ['tokens', tokens],
        ['cost', r.cost_usd == null ? null : fmtCost(r.cost_usd)],
        ['service', `${r.namespace}/${r.service}`],
        ['agent', r.agent],
        ['caller', r.caller],
        ['caller agent', r.caller_agent],
        ['direction', r.direction],
        ['time', r.ts],
        ['trace', r.trace_id],
        ['span', r.parent_span_id ? `${r.span_id} ← ${r.parent_span_id}` : r.span_id],
      ]),
      payloadBlock('Input', r.input, r.input_sha256, canSee),
      payloadBlock('Output', r.output, r.output_sha256, canSee),
    );
  }
}
