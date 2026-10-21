// Inspector → Learning: pending lesson proposals (approve / reject with the memory version as
// If-Match) and the active notes in memory (remove = PUT memory without that note).

import { h, clear, toast, toastError, icon, ICONS, pill } from './dom.js';
import { button, errorBox } from './forms.js';
import { relTime, shortId, clone } from './util.js';

export class LearningTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body learning-tab' });
    this.loaded = false;
    this.busy = new Set();
    this.armed = null;
  }

  activate() {
    if (!this.loaded && !this.loading) this.load();
  }

  isDirty() {
    return false;
  }

  get canEdit() {
    return this.ctx.app.canEdit();
  }

  async load() {
    const { ns, svc } = this.ctx.target;
    this.loading = true;
    if (!this.loaded) clear(this.el).append(h('div', { class: 'loading', text: 'Loading memory and proposals…' }));
    try {
      const [mem, props] = await Promise.all([this.ctx.api.memory(ns, svc), this.ctx.api.proposals({ namespace: ns, service: svc })]);
      this.memory = mem.data || { version: mem.version, agents: {} };
      this.memVersion = mem.version || (mem.data && mem.data.version);
      this.proposals = Array.isArray(props.data) ? props.data : [];
      this.loaded = true;
      this.render();
    } catch (e) {
      clear(this.el).append(errorBox(e, e.status === 404 ? 'This service has no stored charter' : 'Could not load learning data'), button('Retry', { onClick: () => this.load() }));
    } finally {
      this.loading = false;
    }
  }

  onEvent(type, data) {
    const { ns, svc } = this.ctx.target;
    if (!this.loaded) return;
    if (type === 'proposal' && data && data.namespace === ns && data.service === svc) {
      const i = this.proposals.findIndex((p) => p.id === data.id);
      if (i >= 0) this.proposals[i] = data;
      else this.proposals.unshift(data);
      if (data.status === 'approved') this.load();
      else this.render();
    }
    if (type === 'reset' || type === 'lagged') this.load();
  }

  agentsInScope() {
    const { agent } = this.ctx.target;
    if (agent) return [agent];
    const fromMemory = Object.keys((this.memory && this.memory.agents) || {});
    const fromProps = this.proposals.map((p) => p.agent);
    const fromGraph = this.ctx.app.agentsOf(this.ctx.target.ns, this.ctx.target.svc).map((n) => n.label);
    return [...new Set([...fromGraph, ...fromMemory, ...fromProps])];
  }

  render() {
    const { agent } = this.ctx.target;
    const agents = this.agentsInScope();
    const props = this.proposals.filter((p) => agents.includes(p.agent));
    const pending = props.filter((p) => p.status === 'pending');
    const decided = props.filter((p) => p.status !== 'pending');
    const notes = agents.flatMap((a) => ((this.memory.agents || {})[a] || []).map((n) => ({ agent: a, note: n })));
    const body = [];
    if (agent) {
      const node = this.ctx.app.node(this.ctx.target.id);
      const l = (node && node.learning) || {};
      body.push(
        h(
          'div',
          { class: ['notice', l.enabled ? 'notice-info' : 'notice-muted'] },
          h('div', { class: 'notice-title', text: l.enabled ? `Learning is on (${l.mode || 'review'} mode).` : 'Learning is off for this agent.' }),
          h('div', {
            text: l.enabled
              ? l.mode === 'auto'
                ? 'Lessons are stored at once and expire after note_ttl_days.'
                : 'Lessons wait here for review before they become context.'
              : 'Existing notes and proposals stay listed; the control plane refuses new memory for agents without learning.',
          }),
        ),
      );
    }
    body.push(
      h('h3', { class: 'section-title', text: `Pending proposals (${pending.length})` }),
      pending.length ? h('div', { class: 'cards' }, pending.map((p) => this.proposalCard(p, true))) : h('p', { class: 'muted', text: 'Nothing to review.' }),
      h('h3', { class: 'section-title', text: `Active notes (${notes.length})` }),
      notes.length ? h('div', { class: 'cards' }, notes.map((n) => this.noteCard(n.agent, n.note))) : h('p', { class: 'muted', text: 'No notes in memory.' }),
    );
    if (decided.length) {
      body.push(h('details', { class: 'history' }, h('summary', { class: 'section-title', text: `Decided proposals (${decided.length})` }), h('div', { class: 'cards' }, decided.map((p) => this.proposalCard(p, false)))));
    }
    body.push(h('p', { class: 'field-hint', text: `Memory v${this.memVersion ?? '?'} · notes are data in the first user turn, never instructions.` }));
    clear(this.el).append(...body);
  }

  proposalCard(p, actionable) {
    const now = this.ctx.api.now();
    const busy = this.busy.has(p.id);
    const actions =
      actionable && this.canEdit
        ? h(
            'div',
            { class: 'card-actions' },
            button(busy ? 'Working…' : 'Approve', { kind: 'primary', small: true, disabled: busy, iconNode: icon(ICONS.check, { size: 14 }), onClick: () => this.decide(p, 'approve') }),
            button('Reject', { kind: 'danger-ghost', small: true, disabled: busy, iconNode: icon(ICONS.x, { size: 14 }), onClick: () => this.decide(p, 'reject') }),
          )
        : null;
    return h(
      'article',
      { class: ['card', 'proposal', `ps-${p.status}`] },
      h(
        'div',
        { class: 'card-meta' },
        this.ctx.target.agent ? null : h('span', { class: 'mono', text: p.agent }),
        pill(p.status, `pill-${p.status}`),
        p.auto ? pill('auto', 'pill-muted') : null,
        h('span', { class: 'muted', text: relTime(p.ts, now), title: p.ts }),
      ),
      h('blockquote', { class: 'note-text', text: p.note }),
      p.rationale ? h('p', { class: 'rationale', text: p.rationale }) : null,
      h('div', { class: 'card-ids muted' }, h('span', { text: 'request ' }), h('code', { text: shortId(p.request_id, 13), title: p.request_id }), h('span', { text: ' · trace ' }), h('code', { text: shortId(p.trace_id, 12), title: p.trace_id })),
      actions,
    );
  }

  noteCard(agent, n) {
    const now = this.ctx.api.now();
    const key = n.id;
    const busy = this.busy.has(key);
    const armed = this.armed === key;
    const remove = this.canEdit
      ? button(armed ? 'Confirm remove' : 'Remove', {
          kind: armed ? 'danger' : 'danger-ghost',
          small: true,
          disabled: busy,
          iconNode: icon(ICONS.trash, { size: 14 }),
          onClick: () => {
            if (!armed) {
              this.armed = key;
              this.render();
              setTimeout(() => {
                if (this.armed === key) {
                  this.armed = null;
                  this.render();
                }
              }, 4000);
              return;
            }
            this.armed = null;
            this.removeNote(agent, n);
          },
        })
      : null;
    return h(
      'article',
      { class: 'card note' },
      h(
        'div',
        { class: 'card-meta' },
        this.ctx.target.agent ? null : h('span', { class: 'mono', text: agent }),
        pill(n.source, `pill-src-${n.source}`),
        n.approved_by ? h('span', { class: 'muted', text: `approved by ${n.approved_by}` }) : null,
        h('span', { class: 'muted', text: relTime(n.ts, now), title: n.ts }),
        n.expires_at ? h('span', { class: 'muted', text: `expires ${relTime(n.expires_at, now)}`, title: n.expires_at }) : null,
      ),
      h('blockquote', { class: 'note-text', text: n.text }),
      h('div', { class: 'card-actions' }, n.request_id ? h('code', { class: 'muted', text: shortId(n.request_id, 13), title: `from request ${n.request_id}` }) : null, h('span', { class: 'spacer' }), remove),
    );
  }

  async decide(p, action) {
    this.busy.add(p.id);
    this.render();
    try {
      const res = await this.ctx.api.decide(p.id, action, this.memVersion);
      const d = res.data || {};
      if (d.proposal) {
        const i = this.proposals.findIndex((x) => x.id === p.id);
        if (i >= 0) this.proposals[i] = d.proposal;
      }
      if (d.memory_version) this.memVersion = d.memory_version;
      toast(action === 'approve' ? 'Approved: the note joins the agent’s memory.' : 'Rejected the proposal.', { kind: 'success' });
      this.busy.delete(p.id);
      if (action === 'approve') await this.load();
      else this.render();
      this.ctx.app.refresh();
    } catch (e) {
      this.busy.delete(p.id);
      if (e.status === 409) {
        toast('Memory or the proposal changed meanwhile; reloaded.', { kind: 'warn', details: e.details });
        await this.load();
      } else {
        toastError(`Could not ${action}`, e);
        this.render();
      }
    }
  }

  async removeNote(agent, n) {
    const { ns, svc } = this.ctx.target;
    const agents = clone((this.memory && this.memory.agents) || {});
    agents[agent] = (agents[agent] || []).filter((x) => x.id !== n.id);
    if (!agents[agent].length) delete agents[agent];
    this.busy.add(n.id);
    this.render();
    try {
      const res = await this.ctx.api.putMemory(ns, svc, agents, this.memVersion);
      toast(`Removed the note (memory v${(res.data && res.data.version) || res.version}).`, { kind: 'success' });
      this.busy.delete(n.id);
      await this.load();
      this.ctx.app.refresh();
    } catch (e) {
      this.busy.delete(n.id);
      if (e.status === 409) {
        toast('Memory changed meanwhile; reloaded. Try again.', { kind: 'warn' });
        await this.load();
      } else {
        toastError('Could not remove the note', e);
        this.render();
      }
    }
  }
}
