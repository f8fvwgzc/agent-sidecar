// The inspector: a right-hand drawer that opens on a node click, with tabs per node kind.
// Tab panels are created on first use and kept while the drawer shows the same node, so
// unsaved edits survive switching tabs.

import { h, clear, icon, ICONS, pill } from './dom.js';
import { parseNodeId } from './util.js';
import { ConfigTab } from './tab-config.js';
import { TrafficTab } from './tab-traffic.js';
import { LearningTab } from './tab-learning.js';
import { YamlTab } from './tab-yaml.js';
import { InstancesTab } from './tab-instances.js';
import { OverviewTab } from './tab-overview.js';
import { ApprovalsTab } from './tab-approvals.js';

const TAB_CLASSES = {
  config: ['Config', ConfigTab],
  traffic: ['Traffic', TrafficTab],
  learning: ['Learning', LearningTab],
  approvals: ['Approvals', ApprovalsTab],
  yaml: ['YAML', YamlTab],
  instances: ['Instances', InstancesTab],
  overview: ['Overview', OverviewTab],
};

/** The inspector target for a graph node. */
export function targetFor(node) {
  const p = parseNodeId(node && node.id) || {};
  const base = { id: node.id, ns: p.ns, svc: p.svc };
  if (node.placeholder) return { kind: 'node', ...base };
  if (node.type === 'agent') return { kind: 'agent', ...base, agent: p.agent };
  if (node.type === 'service') return { kind: 'service', ...base };
  if (node.type === 'app') return { kind: 'app', ...base };
  return { kind: 'node', ...base };
}

/** Which tabs a target gets; services without a stored charter only have overview and instances. */
export function tabsFor(target, hasCharter) {
  if (target.kind === 'agent') return ['config', 'traffic', 'learning', 'approvals', 'yaml', 'instances'];
  if (target.kind === 'service') return hasCharter ? ['overview', 'traffic', 'learning', 'approvals', 'yaml', 'instances'] : ['overview', 'instances'];
  if (target.kind === 'app') return hasCharter ? ['overview', 'traffic', 'yaml', 'instances'] : ['overview', 'instances'];
  return ['overview'];
}

const MIN_W = 380;
const MAX_W = 960;

export class Inspector {
  constructor(el, { api, app, onClose, onResize, onTab }) {
    this.el = el;
    this.api = api;
    this.app = app;
    this.onClose = onClose;
    this.onResize = onResize;
    this.onTab = onTab;
    this.target = null;
    this.tabs = new Map();
    this.lastTab = {};
    this.head = h('header', { class: 'insp-head' });
    this.nav = h('nav', { class: 'insp-tabs', role: 'tablist', 'aria-label': 'Inspector tabs' });
    this.body = h('div', { class: 'insp-body' });
    this.handle = h('div', { class: 'insp-resize', role: 'separator', 'aria-orientation': 'vertical', title: 'Drag to resize' });
    clear(el).append(this.handle, this.head, this.nav, this.body);
    this.initResize();
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && !ev.defaultPrevented && !(ev.target instanceof HTMLTextAreaElement)) this.close();
    });
  }

  initResize() {
    let startX = 0;
    let startW = 0;
    const move = (ev) => {
      const w = Math.max(MIN_W, Math.min(MAX_W, startW + (startX - ev.clientX)));
      this.el.style.width = `${w}px`;
    };
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      this.el.classList.remove('resizing');
      if (this.onResize) this.onResize();
    };
    this.handle.addEventListener('pointerdown', (ev) => {
      if (ev.button) return;
      ev.preventDefault();
      startX = ev.clientX;
      startW = this.el.getBoundingClientRect().width;
      this.el.classList.add('resizing');
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  }

  get isOpen() {
    return !this.el.hidden && !!this.target;
  }

  width() {
    return this.isOpen ? this.el.getBoundingClientRect().width : 0;
  }

  open(target, tabName) {
    const same = this.target && this.target.id === target.id && this.target.kind === target.kind;
    if (!same) {
      this.destroyTabs();
      this.target = target;
      this.tabNames = tabsFor(target, this.hasCharter(target));
      clear(this.nav);
      for (const name of this.tabNames) {
        const b = h('button', { type: 'button', class: 'insp-tab', role: 'tab', 'aria-selected': 'false', dataset: { tab: name }, text: TAB_CLASSES[name][0] });
        b.addEventListener('click', () => this.selectTab(name));
        b.addEventListener('keydown', (ev) => this.tabKey(ev, name));
        this.nav.append(b);
      }
    }
    this.el.hidden = false;
    this.renderHead();
    const remembered = this.lastTab[target.kind];
    const name = tabName && this.tabNames.includes(tabName) ? tabName : same ? this.current : this.tabNames.includes(remembered) ? remembered : this.tabNames[0];
    this.selectTab(name);
  }

  hasCharter(target) {
    if (!target.ns) return false;
    const s = this.app.serviceSummary(target.ns, target.svc);
    if (s) return !!s.charter_version;
    const n = this.app.node(`svc:${target.ns}/${target.svc}`);
    return !!(n && n.charter_version);
  }

  tabKey(ev, name) {
    const i = this.tabNames.indexOf(name);
    let j = null;
    if (ev.key === 'ArrowRight') j = (i + 1) % this.tabNames.length;
    if (ev.key === 'ArrowLeft') j = (i - 1 + this.tabNames.length) % this.tabNames.length;
    if (j === null) return;
    ev.preventDefault();
    this.selectTab(this.tabNames[j]);
    const b = this.nav.querySelector(`[data-tab="${this.tabNames[j]}"]`);
    if (b) b.focus();
  }

  selectTab(name) {
    if (!this.target) return;
    this.current = name;
    this.lastTab[this.target.kind] = name;
    let tab = this.tabs.get(name);
    if (!tab) {
      const Cls = TAB_CLASSES[name][1];
      tab = new Cls({ api: this.api, app: this.app, target: this.target, onDirty: (t, dirty) => this.markDirty(name, dirty) });
      tab.el.setAttribute('role', 'tabpanel');
      this.tabs.set(name, tab);
      this.body.append(tab.el);
    }
    for (const [n, t] of this.tabs) t.el.hidden = n !== name;
    if (this.onTab) this.onTab(this.target, name);
    for (const b of this.nav.children) {
      const on = b.dataset.tab === name;
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
    }
    tab.activate();
  }

  markDirty(name, dirty) {
    const b = [...this.nav.children].find((x) => x.dataset.tab === name);
    if (b) b.classList.toggle('dirty', dirty);
  }

  renderHead() {
    const t = this.target;
    if (!t) return;
    const n = this.app.node(t.id);
    const app = this.app;
    const title = (n && n.label) || t.agent || t.svc || t.id;
    const badges = [];
    if (n) {
      if (n.placeholder) badges.push(pill('unknown peer', 'pill-muted'));
      else if (n.type === 'agent') {
        badges.push(pill(n.agent_type || 'agent', n.agent_type === 'orchestrator' ? 'pill-orch' : 'pill-agent'));
        badges.push(pill(n.status, `pill-as-${n.status}`));
      } else if (n.type === 'service') badges.push(pill(String(n.status).replace('_', ' '), `pill-st-${n.status}`));
      else badges.push(pill(n.type.replace('_', ' '), 'pill-muted'));
    } else badges.push(pill('removed', 'pill-error'));
    const sub = [];
    if (t.ns) sub.push(`${t.ns}/${t.svc}`);
    if (n && n.model) sub.push(n.model);
    if (t.kind === 'node' && n && !t.ns) sub.push(n.id);
    const svcNode = t.ns ? app.node(`svc:${t.ns}/${t.svc}`) : null;
    const close = h('button', { type: 'button', class: 'icon-btn', title: 'Close (Esc)', 'aria-label': 'Close inspector', on: { click: () => this.close() } }, icon(ICONS.close));
    clear(this.head).append(
      h(
        'div',
        { class: 'insp-title-row' },
        h('h2', { class: 'insp-title', text: title }),
        h('div', { class: 'insp-badges' }, badges),
        h('span', { class: 'spacer' }),
        close,
      ),
      h(
        'div',
        { class: 'insp-sub' },
        h('span', { class: 'mono', text: sub.join(' · ') }),
        t.kind !== 'service' && svcNode && !svcNode.placeholder
          ? h('button', { type: 'button', class: 'link small', text: 'service →', on: { click: () => app.openNode(svcNode) } })
          : null,
      ),
    );
  }

  /** Forwards a live event (or an app notification like `services`) to every open tab. */
  onEvent(type, data) {
    if (!this.target) return;
    if (type === 'graph-updated' || type === 'services') {
      const fresh = tabsFor(this.target, this.hasCharter(this.target));
      if (fresh.join() !== (this.tabNames || []).join()) {
        const keep = this.current;
        const target = this.target;
        this.target = null;
        this.open(target, fresh.includes(keep) ? keep : undefined);
        return;
      }
      this.renderHead();
    }
    for (const tab of this.tabs.values()) if (tab.onEvent) tab.onEvent(type, data);
  }

  destroyTabs() {
    for (const tab of this.tabs.values()) {
      if (tab.destroy) tab.destroy();
      tab.el.remove();
    }
    this.tabs.clear();
    this.current = null;
  }

  close() {
    if (!this.target) return;
    this.destroyTabs();
    this.target = null;
    this.el.hidden = true;
    if (this.onClose) this.onClose();
  }
}
