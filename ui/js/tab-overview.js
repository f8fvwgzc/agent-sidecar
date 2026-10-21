// Inspector → Overview: what a service frame, app, model provider, external origin or
// placeholder node is, and the edges around it with their 15-minute stats.

import { h, clear, kv, pill } from './dom.js';
import { fmtInt, fmtMs, relTime, parseNodeId } from './util.js';

const DESCRIPTION = {
  service: 'A service with its app and agents. Each pod runs the attached sidecar.',
  app: 'The application container of the service. It invokes agents; service tools call its HTTP API.',
  model_provider: 'The model provider the sidecars call for agents of this model family.',
  external: 'An external origin that http tools call through the sidecar.',
  placeholder: 'An unknown peer: a declared tool targets it, but the control plane has no charter and no instance for it.',
};

export class OverviewTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body overview-tab' });
  }

  activate() {
    this.render();
  }

  isDirty() {
    return false;
  }

  onEvent(type) {
    if (type === 'graph-updated' || type === 'services') this.render();
  }

  render() {
    const app = this.ctx.app;
    const n = app.node(this.ctx.target.id);
    if (!n) {
      clear(this.el).append(h('div', { class: 'empty-state small' }, h('div', { class: 'empty-title', text: 'No longer in the graph' }), h('div', { class: 'muted', text: 'It was removed, or the filter hides it.' })));
      return;
    }
    const type = n.placeholder ? 'placeholder' : n.type;
    const parts = [h('p', { class: 'lead', text: DESCRIPTION[type] || '' })];
    const id = parseNodeId(n.id) || {};
    if (type === 'service') {
      parts.push(
        kv([
          ['namespace', id.ns],
          ['status', pill(String(n.status).replace('_', ' '), `pill-st-${n.status}`)],
          ['instances', fmtInt(n.instances)],
          ['charter', n.charter_version ? `v${n.charter_version}` : 'none stored'],
        ]),
      );
      const kids = app.childrenOf(n.id);
      parts.push(h('h3', { class: 'section-title', text: `Agents (${kids.filter((k) => k.type === 'agent').length})` }));
      const rows = kids
        .filter((k) => k.type === 'agent')
        .map((k) =>
          h(
            'button',
            { type: 'button', class: 'row-link', on: { click: () => app.openNode(k) } },
            h('span', { class: `sdot sd-${k.placeholder ? 'disconnected' : k.status}` }),
            h('span', { class: 'mono', text: k.label }),
            h('span', { class: 'muted', text: k.placeholder ? 'unknown' : k.agent_type }),
            h('span', { class: 'spacer' }),
            h('span', { class: 'muted mono', text: k.model || '' }),
          ),
        );
      parts.push(rows.length ? h('div', { class: 'row-links' }, rows) : h('p', { class: 'muted', text: 'No agents.' }));
    } else if (type === 'app') {
      parts.push(kv([['service', `${id.ns}/${id.svc}`], ['app port', n.port == null ? 'unknown' : String(n.port)], ['peer calls (15 min)', fmtInt((n.stats || {}).calls)], ['denied', fmtInt((n.stats || {}).denied)]]));
    } else if (type === 'external') {
      parts.push(kv([['origin', h('code', { text: id.origin || n.id })]]));
    } else if (type === 'model_provider') {
      parts.push(kv([['provider', h('code', { text: n.id })]]));
    } else {
      parts.push(kv([['id', h('code', { text: n.id })], ['status', 'disconnected']]));
    }
    const members = type === 'service' ? new Set([n.id, ...app.childrenOf(n.id).map((k) => k.id)]) : new Set([n.id]);
    const edges = app.edges().filter((e) => members.has(e.source) || members.has(e.target));
    const inbound = edges.filter((e) => members.has(e.target) && !members.has(e.source));
    const outbound = edges.filter((e) => members.has(e.source) && !members.has(e.target));
    const internal = edges.filter((e) => members.has(e.source) && members.has(e.target));
    if (inbound.length) parts.push(this.edgeTable('Inbound', inbound, 'source'));
    if (outbound.length) parts.push(this.edgeTable('Outbound', outbound, 'target'));
    if (internal.length && type === 'service') parts.push(this.edgeTable('Inside the service', internal, 'both'));
    if (!edges.length) parts.push(h('p', { class: 'muted', text: 'No edges.' }));
    clear(this.el).append(...parts);
  }

  edgeTable(title, edges, end) {
    const app = this.ctx.app;
    const now = this.ctx.api.now();
    const label = (id) => {
      const x = app.node(id);
      return (x && x.label) || id;
    };
    return h(
      'div',
      { class: 'edge-table' },
      h('h3', { class: 'section-title', text: `${title} (${edges.length})` }),
      h(
        'ul',
        { class: 'edge-rows' },
        edges.map((e) => {
          const s = e.stats || {};
          const other = end === 'source' ? e.source : end === 'target' ? e.target : null;
          const name = end === 'both' ? `${label(e.source)} → ${label(e.target)}` : label(other);
          const target = other && app.node(other);
          return h(
            'li',
            { class: s.calls && s.denied === s.calls ? 'denied-only' : '' },
            target
              ? h('button', { type: 'button', class: 'link', text: name, on: { click: () => app.openNode(target) } })
              : h('span', { text: name }),
            h('span', { class: 'muted', text: e.kind === 'tool' ? ` · ${e.source_port}` : ` · ${e.kind}` }),
            e.declared ? null : pill('undeclared', 'pill-warn'),
            h('span', { class: 'spacer' }),
            h('span', { class: 'mono small', text: `${fmtInt(s.calls)} calls` }),
            s.denied ? h('span', { class: 'mono small neg', text: ` · ${fmtInt(s.denied)} denied` }) : null,
            s.calls ? h('span', { class: 'mono small muted', text: ` · ${fmtMs(s.avg_ms)}` }) : null,
            s.last_ts ? h('span', { class: 'small muted', text: ` · ${relTime(s.last_ts, now)}` }) : null,
          );
        }),
      ),
    );
  }
}
