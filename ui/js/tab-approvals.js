// Inspector → Approvals: tool calls that wait for a person (CONTRACT.md §5.4), pending first, with
// approve and deny (a deny needs a reason), and the quarantine state of the service's agents
// (§5.3). Live through the `approval` SSE event.

import { h, clear, toast, toastError, icon, ICONS, pill } from './dom.js';
import { button, errorBox } from './forms.js';
import { relTime, shortId } from './util.js';

/** Pending approvals first, then the newest; each list keeps the server's order. */
export function sortApprovals(list) {
  const pending = list.filter((a) => a.status === 'pending');
  const rest = list.filter((a) => a.status !== 'pending');
  return [...pending, ...rest];
}

/** Seconds left before an approval expires (negative when past), from ISO times. */
export function secondsLeft(a, nowMs) {
  return Math.round((Date.parse(a.expires_at) - nowMs) / 1000);
}

export class ApprovalsTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body approvals-tab' });
    this.loaded = false;
    this.busy = new Set();
    this.reasons = new Map();
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

  /** The agent this tab is about, if the target is one. */
  get agent() {
    return this.ctx.target.agent || null;
  }

  async load() {
    const { ns, svc } = this.ctx.target;
    this.loading = true;
    if (!this.loaded) clear(this.el).append(h('div', { class: 'loading', text: 'Loading approvals…' }));
    try {
      const [ap, ag] = await Promise.all([
        this.ctx.api.approvals({ namespace: ns, service: svc, limit: '100' }),
        this.ctx.api.registryAgents({ namespace: ns, service: svc }),
      ]);
      this.approvals = Array.isArray(ap.data) ? ap.data : [];
      this.agents = Array.isArray(ag.data) ? ag.data : [];
      this.loaded = true;
      this.render();
    } catch (e) {
      clear(this.el).append(
        errorBox(e, e.status === 503 ? 'This control plane keeps no approvals (no AgentSecOps store)' : 'Could not load approvals'),
        button('Retry', { onClick: () => this.load() }),
      );
    } finally {
      this.loading = false;
    }
  }

  onEvent(type, data) {
    const { ns, svc } = this.ctx.target;
    if (!this.loaded) return;
    if (type === 'approval' && data && data.namespace === ns && data.service === svc) {
      const i = this.approvals.findIndex((a) => a.id === data.id);
      if (i >= 0) this.approvals[i] = data;
      else this.approvals.unshift(data);
      this.render();
    }
    if (type === 'reset' || type === 'lagged') this.load();
  }

  quarantineBanner() {
    const shown = this.agents.filter((a) => a.quarantine && (!this.agent || a.name === this.agent));
    if (!shown.length) return null;
    return h(
      'div',
      { class: 'callout callout-danger' },
      ...shown.map((a) =>
        h('p', {}, h('strong', { text: `${a.name} is quarantined` }), h('span', { text: `: ${a.quarantine.reason} (by ${a.quarantine.by}, ${relTime(a.quarantine.at, this.ctx.api.now())})` })),
      ),
    );
  }

  card(a) {
    const now = this.ctx.api.now();
    const busy = this.busy.has(a.id);
    const pending = a.status === 'pending';
    const left = secondsLeft(a, Date.parse(now) || Date.now());
    const reason = this.reasons.get(a.id) || '';
    const input = h('input', {
      type: 'text',
      class: 'input small',
      placeholder: 'Reason (required to deny)',
      value: reason,
      maxlength: '2000',
      'aria-label': `Reason for ${a.tool}`,
    });
    input.addEventListener('input', () => this.reasons.set(a.id, input.value));
    const actions =
      pending && this.canEdit
        ? h(
            'div',
            { class: 'card-actions' },
            input,
            button(busy ? 'Working…' : 'Approve', { kind: 'primary', small: true, disabled: busy, iconNode: icon(ICONS.check, { size: 14 }), onClick: () => this.decide(a, 'approve') }),
            button('Deny', { kind: 'danger-ghost', small: true, disabled: busy, iconNode: icon(ICONS.x, { size: 14 }), onClick: () => this.decide(a, 'deny') }),
          )
        : null;
    return h(
      'article',
      { class: ['card', 'approval', `ap-${a.status}`] },
      h(
        'div',
        { class: 'card-meta' },
        this.agent ? null : h('span', { class: 'mono', text: a.agent }),
        h('span', { class: 'mono', text: a.tool }),
        pill(a.status, `pill-${a.status}`),
        pending
          ? h('span', { class: left > 0 ? 'muted' : 'danger', text: left > 0 ? `expires in ${left}s` : 'expiring', title: a.expires_at })
          : h('span', { class: 'muted', text: a.decided_by ? `${a.status} by ${a.decided_by}` : a.status }),
        h('span', { class: 'muted', text: relTime(a.requested_at, now), title: a.requested_at }),
      ),
      a.reason ? h('p', { class: 'rationale', text: a.reason }) : null,
      h('div', { class: 'card-ids muted' }, h('span', { text: 'run ' }), h('code', { text: shortId(a.request_id, 13), title: a.request_id }), h('span', { text: ' · args sha256 ' }), h('code', { text: shortId(a.args_sha256, 12), title: a.args_sha256 })),
      actions,
    );
  }

  render() {
    const list = sortApprovals(this.approvals.filter((a) => !this.agent || a.agent === this.agent));
    const pending = list.filter((a) => a.status === 'pending').length;
    clear(this.el).append(
      this.quarantineBanner() || '',
      h('h3', { class: 'section-title', text: pending ? `${pending} pending` : 'No pending approvals' }),
      list.length ? h('div', { class: 'cards' }, ...list.map((a) => this.card(a))) : h('p', { class: 'muted', text: 'Tools with an approval in the charter wait here for a decision on each call.' }),
    );
  }

  async decide(a, action) {
    const reason = (this.reasons.get(a.id) || '').trim();
    if (action === 'deny' && !reason) {
      toast('A deny needs a reason: the model sees it.', { kind: 'warn' });
      return;
    }
    this.busy.add(a.id);
    this.render();
    try {
      const res = await this.ctx.api.decideApproval(a.id, action, reason);
      const i = this.approvals.findIndex((x) => x.id === a.id);
      if (i >= 0 && res.data) this.approvals[i] = res.data;
      toast(action === 'approve' ? `Approved: ${a.tool} runs now.` : `Denied: the agent is told why.`, { kind: 'success' });
    } catch (e) {
      if (e.status === 409) {
        toast('The approval was decided or expired meanwhile; reloaded.', { kind: 'warn', details: e.details });
        await this.load();
      } else {
        toastError(`Could not ${action}`, e);
      }
    } finally {
      this.busy.delete(a.id);
      this.reasons.delete(a.id);
      this.render();
    }
  }
}
