// The attache console: boots the API client, the sign-in screen, the canvas, the inspector and
// the live stream, and wires the toolbar. Design: docs/design/agent-platform.md §11.

import { ApiError, createApi, isUnreachable } from './api.js';
import { GraphView } from './graph.js';
import { Inspector, targetFor } from './inspector.js';
import { openAddAgent, openLinkDialog, openAdopt } from './dialogs.js';
import { showSignin, hideSignin } from './signin.js';
import { h, clear, append, toast, toastError, icon, ICONS, $ } from './dom.js';
import { roleAtLeast, parseNodeId, throttle, outcomeOf, shortId, svcNodeId } from './util.js';
import { loadFilters, saveFilters } from './store.js';

const state = {
  api: null,
  me: null,
  graph: { version: '0', nodes: [], edges: [] },
  nodeIndex: new Map(),
  services: [],
  filters: loadFilters(),
  live: true,
  stream: null,
  acks: new Map(),
  graphSeq: 0,
  servicesSeq: 0,
};
let view = null;
let inspector = null;

/** What the inspector tabs and dialogs may use. */
const app = {
  get api() {
    return state.api;
  },
  me: () => state.me,
  canEdit: () => !!state.me && roleAtLeast(state.me.role, 'editor'),
  node: (id) => state.nodeIndex.get(id) || null,
  edges: () => state.graph.edges || [],
  childrenOf: (svcId) => state.graph.nodes.filter((n) => n.parent === svcId),
  agentsOf: (ns, svc) => state.graph.nodes.filter((n) => n.type === 'agent' && !n.placeholder && n.parent === svcNodeId(ns, svc)),
  services: () => state.services,
  serviceSummary: (ns, svc) => state.services.find((s) => s.namespace === ns && s.service === svc) || null,
  // The models the control plane reports for this graph's agents, most used first.
  knownModels: () => {
    const count = new Map();
    for (const n of state.graph.nodes) if (n.type === 'agent' && !n.placeholder && n.model) count.set(n.model, (count.get(n.model) || 0) + 1);
    return [...count.entries()].sort((a, b) => b[1] - a[1]).map(([m]) => m);
  },
  refresh: () => Promise.all([refreshGraph(), refreshServices()]),
  openNode: (node, tab) => openNode(node, tab),
  adopt: (s) => openAdopt(app, s),
  ackOf: (instanceId, kind) => {
    const a = state.acks.get(instanceId);
    return (a && a[kind]) || null;
  },
  isFiltered: (s) => !!state.filters.ns && s.namespace !== state.filters.ns,
};

// ---- boot ----------------------------------------------------------------------------------------

function fatal(title, message, { detail, retry } = {}) {
  const boot = $('#boot');
  boot.hidden = false;
  clear(boot).append(
    h(
      'div',
      { class: 'boot-card', role: 'alert' },
      h('div', { class: 'boot-title', text: title }),
      h('div', { text: message }),
      detail ? h('div', { class: 'muted small mono', text: detail }) : null,
      retry ? h('button', { type: 'button', class: 'btn btn-primary', text: 'Retry', on: { click: () => location.reload() } }) : null,
    ),
  );
}

/** Why GET /whoami did not give a session, for the boot screen. */
function whoamiDetail(e) {
  if (!e) return '';
  if (e.code === 'not_the_api') return 'GET /whoami did not answer with the control-plane API';
  if (!e.status) return `GET /whoami failed: ${(e.details && e.details[0]) || e.message || 'network error'}`;
  return `GET /whoami answered HTTP ${e.status}${e.code && e.code !== `http_${e.status}` ? ` (${e.code})` : ''}`;
}

async function boot() {
  if (!globalThis.d3) {
    fatal('The console could not start', 'd3 did not load (vendor/d3.v7.9.0.min.js).');
    return;
  }
  state.api = createApi();
  state.api.onUnauthenticated = () => signedOut('Your session ended. Sign in again.');
  wireToolbar();
  let me;
  try {
    const res = await state.api.whoami();
    me = res.data;
    if (!me || typeof me !== 'object' || typeof me.name !== 'string' || typeof me.role !== 'string') throw new ApiError(200, { error: 'not_the_api' });
  } catch (e) {
    if (e && e.status === 401) {
      $('#boot').hidden = true;
      signedOut();
    } else if (isUnreachable(e)) {
      fatal('Not connected', `Cannot reach the control plane at ${state.api.baseUrl} — start embassy serve.`, { detail: whoamiDetail(e), retry: true });
    } else {
      fatal('The control plane refused the console', `${state.api.baseUrl} answered GET /whoami with an error.`, { detail: whoamiDetail(e), retry: true });
    }
    return;
  }
  $('#boot').hidden = true;
  await enter(me);
}

async function enter(me) {
  state.me = me;
  hideSignin();
  $('#app').hidden = false;
  const editor = roleAtLeast(me.role, 'editor');
  document.body.classList.toggle('read-only', !editor);
  $('#user-name').textContent = me.name;
  const role = $('#user-role');
  role.textContent = editor ? me.role : `${me.role} · read-only`;
  role.className = `pill pill-role-${me.role}`;
  const scope = (me.namespaces || []).includes('*') ? 'all namespaces' : (me.namespaces || []).join(', ');
  $('#user').title = `${me.name} (${me.role}) · ${scope} · payloads ${me.payloads ? 'visible' : 'hidden'}`;
  $('#btn-add').hidden = !editor;
  if (!view) {
    view = new GraphView($('#canvas-host'), {
      onSelect: (n) => openNode(n),
      onSelectService: (n) => openNode(n),
      onBackground: () => {
        if (inspector) inspector.close();
        view.select(null);
      },
      onLink: (from, to) => openLinkDialog(app, from, to),
      now: () => state.api.now(),
      rightInset: () => (inspector && inspector.isOpen && window.innerWidth >= 900 ? inspector.width() : 0),
    });
    inspector = new Inspector($('#inspector'), {
      api: state.api,
      app,
      onClose: () => {
        if (view) view.select(null);
        writeHash(null);
      },
      onTab: (target, tab) => writeHash(target.id, tab),
    });
    window.addEventListener('hashchange', () => openFromHash());
  }
  view.setCanLink(editor);
  view.setFilters(state.filters);
  await app.refresh();
  setLive(state.live);
  openFromHash();
}

// ---- deep links: #node=<node id>&tab=<tab> ------------------------------------------------------

function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  return { node: p.get('node'), tab: p.get('tab') };
}

function writeHash(id, tab) {
  const want = id ? `#${new URLSearchParams(tab ? { node: id, tab } : { node: id })}` : '';
  if (location.hash === want || (!want && !location.hash)) return;
  history.replaceState(null, '', want || `${location.pathname}${location.search}`);
}

function openFromHash() {
  const { node, tab } = readHash();
  if (!node || !state.me) return;
  const n = app.node(node);
  if (n && !(inspector.target && inspector.target.id === n.id && inspector.current === tab)) openNode(n, tab || undefined);
}

function signedOut(message) {
  if (state.stream) {
    state.stream.close();
    state.stream = null;
  }
  if (inspector) inspector.close();
  state.me = null;
  const dlg = $('#dialog');
  if (dlg.open) dlg.close();
  showSignin({ api: state.api, message, onSignedIn: (me) => enter(me) });
}

// ---- data --------------------------------------------------------------------------------------

async function refreshGraph() {
  if (!state.me) return;
  const seq = ++state.graphSeq;
  try {
    const res = await state.api.graph();
    if (seq !== state.graphSeq) return;
    const g = res.data && Array.isArray(res.data.nodes) ? res.data : { nodes: [], edges: [] };
    g.edges = Array.isArray(g.edges) ? g.edges : [];
    state.graph = g;
    state.nodeIndex = new Map(g.nodes.map((n) => [n.id, n]));
    view.setGraph(g);
    updateFilterOptions();
    updateEmpty();
    inspector.onEvent('graph-updated');
  } catch (e) {
    if (e.status !== 401) toastError('Could not load the graph', e);
  }
}

async function refreshServices() {
  if (!state.me) return;
  const seq = ++state.servicesSeq;
  try {
    const res = await state.api.services();
    if (seq !== state.servicesSeq) return;
    state.services = Array.isArray(res.data) ? res.data : [];
    renderBanner();
    inspector.onEvent('services');
  } catch (e) {
    if (e.status !== 401) toastError('Could not load the services', e);
  }
}

const graphSoon = throttle(() => refreshGraph(), 1000);
const servicesSoon = throttle(() => refreshServices(), 700);

// ---- live events -------------------------------------------------------------------------------

function recordAck(d) {
  if (!d || !d.instance_id) return;
  const prev = state.acks.get(d.instance_id) || {};
  state.acks.set(d.instance_id, { ...prev, [d.kind]: { version: d.version, applied: d.applied, error: d.error } });
  if (d.kind === 'charter') {
    const s = app.serviceSummary(d.namespace, d.service);
    const inst = s && s.instances.find((i) => i.instance_id === d.instance_id);
    if (inst) {
      inst.acked_version = d.version;
      inst.ack_error = d.applied ? null : d.error || 'not applied';
    }
  }
}

function onEvent(type, data) {
  switch (type) {
    case 'audit':
      if (data && data.record && data.animate && data.edge_id) view.animate(data.edge_id, outcomeOf(data.record));
      break;
    case 'graph':
    case 'proposal':
      graphSoon();
      break;
    case 'registry':
      servicesSoon();
      break;
    case 'config':
      graphSoon();
      servicesSoon();
      break;
    case 'ack':
      recordAck(data);
      servicesSoon();
      break;
    case 'cp_audit':
      if (data && state.me && data.actor !== state.me.name) {
        const where = [data.namespace, data.service].filter(Boolean).join('/') + (data.agent ? `/${data.agent}` : '');
        toast(`${data.actor}: ${String(data.action).replace(/_/g, ' ')} ${where} (${data.result})`, { kind: data.result === 'ok' ? 'info' : 'warn', timeout: 4500 });
      }
      break;
    case 'lagged':
    case 'reset':
      graphSoon();
      servicesSoon();
      break;
    default:
      break;
  }
  if (inspector) inspector.onEvent(type, data);
}

const CONN_TEXT = { connecting: 'connecting', live: 'live', reconnecting: 'reconnecting', offline: 'offline', paused: 'paused' };

function setConn(status) {
  const el = $('#conn');
  el.dataset.state = status;
  $('#conn-text').textContent = CONN_TEXT[status] || status;
  el.title = status === 'live' ? 'Receiving live events' : status === 'paused' ? 'Live updates are off' : `Event stream: ${status}`;
  if (status === 'offline' && state.me) state.api.whoami().catch(() => {});
}

function setLive(on) {
  state.live = on;
  const btn = $('#btn-live');
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  btn.title = on ? 'Live updates on: click to pause' : 'Live updates paused: click to resume';
  if (on && !state.stream && state.me) {
    state.stream = state.api.subscribe({ onEvent, onStatus: setConn });
    // Events were missed while paused: catch up like after a `reset`.
    if (state.paused) onEvent('reset', {});
    state.paused = false;
  } else if (!on && state.stream) {
    state.stream.close();
    state.stream = null;
    state.paused = true;
    setConn('paused');
  }
}

// ---- toolbar, filters, banner -------------------------------------------------------------------

function wireToolbar() {
  $('#btn-fit').addEventListener('click', () => view && view.fit());
  $('#btn-layout').addEventListener('click', () => view && view.autoLayout());
  $('#btn-add').addEventListener('click', () => {
    const f = state.filters;
    openAddAgent(app, { svc: f.ns && f.svc ? `${f.ns}/${f.svc}` : inspector && inspector.target && inspector.target.ns ? `${inspector.target.ns}/${inspector.target.svc}` : '' });
  });
  $('#btn-live').addEventListener('click', () => setLive(!state.live));
  $('#btn-signout').addEventListener('click', async () => {
    try {
      await state.api.logout();
    } catch {
      /* the session may already be gone */
    }
    signedOut('Signed out.');
  });
  $('#f-ns').addEventListener('change', (ev) => setFilters({ ns: ev.target.value, svc: '' }));
  $('#f-svc').addEventListener('change', (ev) => {
    const v = ev.target.value;
    if (!v) setFilters({ ns: state.filters.ns, svc: '' });
    else {
      const [ns, svc] = v.split('/');
      setFilters({ ns, svc });
    }
  });
  document.addEventListener('keydown', (ev) => {
    const t = ev.target;
    const typing = t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || (t && t.isContentEditable);
    if (typing || ev.metaKey || ev.ctrlKey || ev.altKey || !state.me || $('#dialog').open) return;
    if (ev.key === 'f' || ev.key === 'F') view && view.fit();
    if (ev.key === 'Escape' && inspector && inspector.isOpen) inspector.close();
  });
  // GraphView watches its own size (ResizeObserver); this covers browsers without it.
  window.addEventListener('resize', throttle(() => view && view.resized(), 150));
}

function setFilters(f) {
  state.filters = { ns: f.ns || '', svc: f.svc || '' };
  saveFilters(state.filters);
  view.setFilters(state.filters);
  updateFilterOptions();
  updateEmpty();
  view.fit();
}

function option(value, text, selected) {
  return h('option', { value, text, selected });
}

function updateFilterOptions() {
  const svcs = state.graph.nodes
    .filter((n) => n.type === 'service')
    .map((n) => parseNodeId(n.id))
    .filter(Boolean);
  const namespaces = [...new Set(svcs.map((s) => s.ns))].sort();
  const f = state.filters;
  const nsSel = $('#f-ns');
  append(clear(nsSel), [option('', 'All namespaces', !f.ns), namespaces.map((ns) => option(ns, ns, ns === f.ns))]);
  if (f.ns && !namespaces.includes(f.ns)) nsSel.append(option(f.ns, `${f.ns} (empty)`, true));
  const list = svcs.filter((s) => !f.ns || s.ns === f.ns).sort((a, b) => (a.svc < b.svc ? -1 : 1));
  const svcSel = $('#f-svc');
  append(clear(svcSel), [
    option('', 'All services', !f.svc),
    list.map((s) => option(`${s.ns}/${s.svc}`, f.ns ? s.svc : `${s.svc} · ${s.ns}`, s.ns === f.ns && s.svc === f.svc)),
  ]);
  $('#filters').classList.toggle('active', !!(f.ns || f.svc));
}

function updateEmpty() {
  const empty = $('#empty');
  const total = state.graph.nodes.length;
  const shown = view && view.view ? view.view.nodes.length : 0;
  if (total && shown) {
    empty.hidden = true;
    return;
  }
  empty.hidden = false;
  clear(empty).append(
    total
      ? h('div', { class: 'empty-card' }, h('div', { class: 'empty-title', text: 'Nothing matches the filter' }), h('button', { type: 'button', class: 'btn btn-secondary', text: 'Show everything', on: { click: () => setFilters({ ns: '', svc: '' }) } }))
      : h(
          'div',
          { class: 'empty-card' },
          h('div', { class: 'empty-title', text: 'No services connected yet' }),
          h('div', { class: 'muted', text: 'Services appear here when their sidecars connect to the control plane, or when a charter is stored.' }),
        ),
  );
}

function renderBanner() {
  const banner = $('#banner');
  const pending = state.services.filter((s) => s.pending_adoption);
  clear(banner);
  banner.hidden = !pending.length;
  for (const s of pending) {
    const p = s.pending_adoption;
    banner.append(
      h(
        'div',
        { class: 'banner-item' },
        icon(ICONS.warn, { size: 16, cls: 'icon warn' }),
        h(
          'span',
          { class: 'banner-text' },
          h('strong', { text: `${s.service}` }),
          h('span', { class: 'muted', text: ` (${s.namespace})` }),
          h('span', { text: ` has no stored charter. Pod ${p.pod} offers its start-up charter ` }),
          h('code', { text: shortId(p.sha256, 12), title: `sha256 ${p.sha256}` }),
          h('span', { text: ' for adoption.' }),
        ),
        h('span', { class: 'spacer' }),
        h('button', {
          type: 'button',
          class: 'btn btn-ghost btn-sm',
          text: 'Show',
          on: {
            click: () => {
              const n = app.node(svcNodeId(s.namespace, s.service));
              if (n) openNode(n, 'instances');
            },
          },
        }),
        app.canEdit()
          ? h('button', { type: 'button', class: 'btn btn-primary btn-sm', text: 'Adopt', on: { click: () => openAdopt(app, s) } })
          : h('span', { class: 'muted small', text: 'An editor can adopt it.' }),
      ),
    );
  }
}

function openNode(node, tab) {
  if (!node) return;
  view.select(node.id);
  inspector.open(targetFor(node), tab);
  requestAnimationFrame(() => view.reveal(node.id));
}

boot();
