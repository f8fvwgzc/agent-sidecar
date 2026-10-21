// Inspector → Instances: the connected sidecars of a service (GET /services) with their ack
// chips (pending, ✓ vN, ✗ with the error), kept live by registry and ack events.

import { h, clear, kv, pill } from './dom.js';
import { button } from './forms.js';
import { instanceChip, relTime, fmtSeconds, fmtInt, shortId, parseTs } from './util.js';

function certText(sec) {
  if (typeof sec !== 'number') return '–';
  return sec < 0 ? fmtSeconds(sec) : `expires in ${fmtSeconds(sec)}`;
}

export class InstancesTab {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = h('div', { class: 'tab-body instances-tab' });
  }

  activate() {
    this.render();
  }

  isDirty() {
    return false;
  }

  onEvent(type) {
    if (['registry', 'ack', 'config', 'services', 'reset', 'lagged'].includes(type)) this.render();
  }

  render() {
    const { ns, svc } = this.ctx.target;
    const s = this.ctx.app.serviceSummary(ns, svc);
    const now = this.ctx.api.now();
    if (!s) {
      clear(this.el).append(h('div', { class: 'empty-state small' }, h('div', { class: 'empty-title', text: 'Unknown to the control plane' }), h('div', { class: 'muted', text: 'No stored charter and no connected instance.' })));
      return;
    }
    const parts = [
      kv([
        ['status', pill(String(s.status).replace('_', ' '), `pill-st-${s.status}`)],
        ['charter', s.charter_version ? `v${s.charter_version}` : 'none stored'],
        ['memory', s.memory_version ? `v${s.memory_version}` : null],
        ['epoch', s.epoch ? h('code', { text: shortId(s.epoch, 13), title: s.epoch }) : null],
      ]),
    ];
    if (s.pending_adoption) {
      const p = s.pending_adoption;
      parts.push(
        h(
          'div',
          { class: 'notice notice-info' },
          h('div', { class: 'notice-title', text: `Pod ${p.pod} offers its start-up charter for adoption.` }),
          h('div', { class: 'muted' }, h('span', { text: 'sha256 ' }), h('code', { text: shortId(p.sha256, 16), title: p.sha256 }), h('span', { text: ` · ${relTime(p.ts, now)}` })),
          this.ctx.app.canEdit()
            ? h('div', { class: 'notice-actions' }, button('Adopt', { kind: 'primary', small: true, onClick: () => this.ctx.app.adopt(s) }))
            : null,
        ),
      );
    }
    parts.push(h('h3', { class: 'section-title', text: `Instances (${s.instances.length})` }));
    if (!s.instances.length) {
      parts.push(h('p', { class: 'muted', text: 'No sidecar is connected. The pods are not running, or cannot reach the control plane; they keep their last charter.' }));
    }
    for (const inst of s.instances) parts.push(this.card(inst, s, now));
    clear(this.el).append(...parts);
  }

  card(inst, s, now) {
    const chip = instanceChip(inst, s.charter_version);
    const mem = this.ctx.app.ackOf(inst.instance_id, 'memory');
    const hb = parseTs(inst.last_heartbeat);
    const stale = Number.isFinite(hb) && now - hb > 30000;
    const certLow = typeof inst.cert_expires_in_s === 'number' && inst.cert_expires_in_s < 3600;
    return h(
      'article',
      { class: ['card', 'instance', `is-${chip.state}`] },
      h(
        'div',
        { class: 'instance-head' },
        h('span', { class: 'mono instance-pod', text: inst.pod }),
        h('span', { class: 'spacer' }),
        h('span', { class: `ack-chip ac-${chip.state}`, title: chip.title, text: chip.label }),
        mem
          ? h('span', {
              class: `ack-chip ac-${mem.applied ? 'ok' : 'error'} memory`,
              title: mem.error || `memory v${mem.version} applied`,
              text: `${mem.applied ? '✓' : '✗'} mem v${mem.version}`,
            })
          : null,
      ),
      chip.state === 'error' ? h('div', { class: 'ack-error mono', text: inst.ack_error }) : null,
      kv([
        ['instance', h('code', { text: shortId(inst.instance_id, 13), title: inst.instance_id })],
        ['sidecar', inst.sidecar_version],
        ['connected', relTime(inst.connected_at, now)],
        ['heartbeat', h('span', { class: stale ? 'warn' : '', text: inst.last_heartbeat ? relTime(inst.last_heartbeat, now) : 'none yet' })],
        ['runtime', h('span', { class: inst.runtime_ready ? 'ok' : 'warn', text: inst.runtime_ready ? 'ready' : 'not ready' })],
        ['certificate', h('span', { class: certLow ? 'warn' : '', text: certText(inst.cert_expires_in_s) })],
        ['audit dropped', h('span', { class: inst.audit_dropped ? 'warn' : '', text: fmtInt(inst.audit_dropped) })],
      ]),
    );
  }
}
