// The node canvas (design §11): a dotted grid with d3-zoom pan/zoom, ComfyUI-style node cards
// with ports, service frames, Bézier edges, live dots, and drag-to-link from orchestrators.
// d3 comes from the pinned classic script (globalThis.d3). All text goes through .text().

import { G, nodeBox, portPoint, bezier, edgePath, frameRect, emptyFrameRect, rectContains } from './geometry.js';
import { resolvePositions } from './layout.js';
import { visibleGraph, fmtInt, fmtMs, fmtCost, fmtCompact, relTime, parseNodeId, linkRequirement } from './util.js';
import { h, kv, showTooltip, hideTooltip } from './dom.js';
import { loadPositions, savePositions, clearPositions } from './store.js';

const d3 = globalThis.d3;

const IN_PORT_TYPE = { invoke: 'agent', service: 'service', model: 'model', http: 'http' };
const BADGE = { agent: 'agent', orchestrator: 'orchestrator', app: 'app', model_provider: 'model', external: 'external', placeholder: 'unknown' };

function outPortType(node, name) {
  if (name === 'model') return 'model';
  if (node.type === 'app' && name === 'invoke') return 'invoke';
  const t = (node.tools || []).find((x) => x.name === name);
  return t ? t.type : 'unknown';
}

function edgeType(e, byId) {
  if (e.kind === 'invoke') return 'invoke';
  if (e.kind === 'model') return 'model';
  const src = byId.get(e.source);
  const t = src && (src.tools || []).find((x) => x.name === e.source_port);
  if (t) return t.type;
  const target = byId.get(e.target);
  if (!target) return 'unknown';
  if (target.type === 'agent') return 'agent';
  if (target.type === 'app') return 'service';
  if (target.type === 'external') return 'http';
  return 'unknown';
}

/** Shortens an SVG text element with an ellipsis until it fits `max` px. */
function fitText(sel, text, max) {
  sel.text(text);
  const node = sel.node();
  if (!node || typeof node.getComputedTextLength !== 'function' || max <= 0) return;
  if (node.getComputedTextLength() <= max) return;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    node.textContent = `${text.slice(0, mid)}…`;
    if (node.getComputedTextLength() <= max) lo = mid;
    else hi = mid - 1;
  }
  node.textContent = `${text.slice(0, lo)}…`;
  sel.append('title').text(text);
}

function textWidth(sel) {
  const n = sel.node();
  return n && typeof n.getComputedTextLength === 'function' ? n.getComputedTextLength() : 0;
}

export class GraphView {
  constructor(host, opts) {
    this.host = host;
    this.opts = opts;
    this.graph = { nodes: [], edges: [] };
    this.filters = { ns: '', svc: '' };
    this.canLink = false;
    this.selected = null;
    this.placed = loadPositions();
    this.pos = new Map();
    this.boxes = new Map();
    this.nodeById = new Map();
    this.edgeEls = new Map();
    this.nodeEls = new Map();
    this.signatures = new Map();
    this.fitted = false;
    this.build();
  }

  build() {
    const svg = d3.select(this.host).append('svg').attr('class', 'canvas').attr('role', 'img').attr('aria-label', 'Agent graph');
    const defs = svg.append('defs');
    this.grid = defs.append('pattern').attr('id', 'grid-dots').attr('width', 24).attr('height', 24).attr('patternUnits', 'userSpaceOnUse');
    this.grid.append('circle').attr('class', 'grid-dot').attr('cx', 1).attr('cy', 1).attr('r', 1);
    this.gridMajor = defs.append('pattern').attr('id', 'grid-major').attr('width', 120).attr('height', 120).attr('patternUnits', 'userSpaceOnUse');
    this.gridMajor.append('circle').attr('class', 'grid-dot-major').attr('cx', 1).attr('cy', 1).attr('r', 1.4);
    svg.append('rect').attr('class', 'grid-bg').attr('width', '100%').attr('height', '100%');
    svg.append('rect').attr('class', 'grid').attr('width', '100%').attr('height', '100%').attr('fill', 'url(#grid-dots)');
    svg.append('rect').attr('class', 'grid').attr('width', '100%').attr('height', '100%').attr('fill', 'url(#grid-major)');
    this.svg = svg;
    this.viewport = svg.append('g').attr('class', 'viewport');
    this.layers = {
      frames: this.viewport.append('g').attr('class', 'layer-frames'),
      edges: this.viewport.append('g').attr('class', 'layer-edges'),
      nodes: this.viewport.append('g').attr('class', 'layer-nodes'),
      dots: this.viewport.append('g').attr('class', 'layer-dots'),
      ghost: this.viewport.append('g').attr('class', 'layer-ghost'),
    };
    this.ghost = this.layers.ghost.append('path').attr('class', 'ghost-edge').attr('visibility', 'hidden');

    this.zoom = d3
      .zoom()
      .scaleExtent([0.15, 2.5])
      .on('zoom', (event) => {
        const t = event.transform;
        this.viewport.attr('transform', t);
        const pt = `translate(${t.x},${t.y}) scale(${t.k})`;
        this.grid.attr('patternTransform', pt);
        this.gridMajor.attr('patternTransform', pt);
        svg.classed('zoomed-out', t.k < 0.45);
        hideTooltip();
      });
    svg.call(this.zoom).on('dblclick.zoom', null);
    svg.on('click', (event) => {
      if (event.target === svg.node() || event.target.classList.contains('grid') || event.target.classList.contains('grid-bg')) {
        this.opts.onBackground && this.opts.onBackground();
      }
    });

    const self = this;
    this.nodeDrag = d3
      .drag()
      .filter((event) => !event.button && !(event.target.closest && event.target.closest('.port-link')))
      .clickDistance(4)
      .on('start', function onStart(event) {
        this.__moved = false;
        this.__start = [event.x, event.y];
        hideTooltip();
      })
      .on('drag', function onDrag(event, d) {
        // Raise only once the pointer really moves: re-inserting the element during a click
        // would cancel the click that opens the inspector.
        if (!this.__moved && Math.hypot(event.x - this.__start[0], event.y - this.__start[1]) > 3) {
          this.__moved = true;
          d3.select(this).raise().classed('dragging', true);
        }
        self.dragNode(event, d);
      })
      .on('end', function onEnd() {
        d3.select(this).classed('dragging', false);
        if (this.__moved) self.persist();
      });
    this.dragNode = (event, d) => {
      const p = this.pos.get(d.id);
      if (!p) return;
      p.x += event.dx;
      p.y += event.dy;
      this.placeNode(d.id);
      this.updateFramesAndEdges();
    };

    this.frameDrag = d3
      .drag()
      .filter((event) => !event.button)
      .clickDistance(4)
      .on('drag', (event, d) => {
        const ids = d.children.length ? d.children : [d.id];
        for (const id of ids) {
          const p = this.pos.get(id);
          if (!p) continue;
          p.x += event.dx;
          p.y += event.dy;
          if (id !== d.id) this.placeNode(id);
        }
        this.updateFramesAndEdges();
      })
      .on('end', () => this.persist());

    this.linkDrag = d3
      .drag()
      .container(() => this.viewport.node())
      .filter((event) => !event.button)
      .on('start', (event, d) => this.linkStart(d))
      .on('drag', (event) => this.linkMove({ x: event.x, y: event.y }))
      .on('end', (event) => this.linkEnd({ x: event.x, y: event.y }));
  }

  // ---- data ------------------------------------------------------------------------------------

  boxOf(node) {
    return nodeBox(node, { linkPort: this.canLink });
  }

  setGraph(graph) {
    this.graph = graph && Array.isArray(graph.nodes) ? graph : { nodes: [], edges: [] };
    this.layoutPositions();
    this.render();
    if (!this.fitted && this.view.nodes.length) {
      this.fitted = true;
      this.fit(0);
    }
  }

  setFilters(filters) {
    this.filters = { ns: filters.ns || '', svc: filters.svc || '' };
    this.render();
  }

  setCanLink(on) {
    if (this.canLink === !!on) return;
    this.canLink = !!on;
    this.signatures.clear();
    this.render();
  }

  layoutPositions() {
    // Current positions (a drag may be in progress) win over the last persisted ones.
    const known = new Map([...this.placed, ...this.pos]);
    const next = resolvePositions(this.graph, known, (n) => this.boxOf(n));
    for (const [id, p] of next) {
      const cur = this.pos.get(id);
      if (cur) {
        cur.x = p.x;
        cur.y = p.y;
        next.set(id, cur);
      }
    }
    this.pos = next;
    this.placed = new Map([...next].map(([id, p]) => [id, { ...p }]));
  }

  persist() {
    this.placed = new Map([...this.pos].map(([id, p]) => [id, { x: p.x, y: p.y }]));
    savePositions(this.placed);
  }

  // ---- rendering -------------------------------------------------------------------------------

  render() {
    const view = visibleGraph(this.graph, this.filters);
    this.view = view;
    this.nodeById = new Map(this.graph.nodes.map((n) => [n.id, n]));
    this.boxes = new Map(view.nodes.map((n) => [n.id, this.boxOf(n)]));
    this.renderFrames();
    this.renderEdges();
    this.renderNodes();
    this.applySelection();
  }

  rectOf(id) {
    const p = this.pos.get(id);
    const b = this.boxes.get(id);
    return p && b ? { x: p.x, y: p.y, w: b.w, h: b.h } : null;
  }

  frameData() {
    const services = this.view.nodes.filter((n) => n.type === 'service');
    const kids = new Map(services.map((s) => [s.id, []]));
    for (const n of this.view.nodes) if (n.parent && kids.has(n.parent)) kids.get(n.parent).push(n.id);
    return services.map((s) => {
      const children = kids.get(s.id);
      const rects = children.map((id) => this.rectOf(id)).filter(Boolean);
      const rect = rects.length ? frameRect(rects) : emptyFrameRect(this.pos.get(s.id) || { x: 0, y: 0 });
      return { id: s.id, node: s, children, rect };
    });
  }

  renderFrames() {
    const data = this.frameData();
    const sel = this.layers.frames.selectAll('g.frame').data(data, (d) => d.id);
    sel.exit().remove();
    const enter = sel.enter().append('g').call(this.frameDrag);
    enter.append('rect').attr('class', 'frame-rect').attr('rx', 16);
    enter.append('path').attr('class', 'frame-band');
    enter.append('text').attr('class', 'frame-title');
    enter.append('text').attr('class', 'frame-ns');
    enter.append('g').attr('class', 'frame-meta');
    enter.on('click', (event, d) => {
      event.stopPropagation();
      this.opts.onSelectService && this.opts.onSelectService(d.node);
    });
    enter.on('mouseenter', (event, d) => this.showFrameTip(event, d)).on('mousemove', (event, d) => this.showFrameTip(event, d)).on('mouseleave', hideTooltip);
    const all = enter.merge(sel);
    all.attr('class', (d) => `frame fs-${d.node.status || 'unknown'}${d.node.placeholder ? ' placeholder' : ''}${d.children.length ? '' : ' empty'}`);
    all.each((d, i, els) => this.drawFrame(d3.select(els[i]), d));
  }

  drawFrame(g, d) {
    const r = d.rect;
    g.select('.frame-rect').attr('x', r.x).attr('y', r.y).attr('width', r.w).attr('height', r.h);
    const band = G.frameTitle + 10;
    g.select('.frame-band').attr('d', `M${r.x},${r.y + 16} a16,16 0 0 1 16,-16 h${r.w - 32} a16,16 0 0 1 16,16 v${band - 16} h-${r.w} z`);
    const n = d.node;
    const id = parseNodeId(n.id) || {};
    const title = g.select('.frame-title').attr('x', r.x + 16).attr('y', r.y + 22);
    fitText(title, n.label || id.svc || n.id, r.w - 32);
    const tw = textWidth(title);
    const meta = g.select('.frame-meta');
    meta.selectAll('*').remove();
    const statusText = n.placeholder ? 'unknown peer' : (n.status || 'unknown').replace('_', ' ');
    const bits = [statusText];
    if (!n.placeholder) {
      if (typeof n.instances === 'number') bits.push(`${n.instances} pod${n.instances === 1 ? '' : 's'}`);
      bits.push(n.charter_version ? `v${n.charter_version}` : 'no charter');
    }
    const mt = meta.append('text').attr('class', 'frame-meta-text').attr('text-anchor', 'end').attr('x', r.x + r.w - 16).attr('y', r.y + 22).text(bits.join(' · '));
    const mw = textWidth(mt);
    meta.append('circle').attr('class', 'frame-status-dot').attr('cx', r.x + r.w - 24 - mw).attr('cy', r.y + 18).attr('r', 4);
    const nsText = g.select('.frame-ns').attr('x', r.x + 22 + tw).attr('y', r.y + 22);
    const room = r.w - 16 - tw - 22 - mw - 34;
    nsText.text('');
    if (id.ns && room > 40) fitText(nsText, id.ns, room);
  }

  showFrameTip(event, d) {
    if (event.target.closest && !event.target.closest('.frame-band, .frame-title, .frame-meta, .frame-ns')) {
      hideTooltip();
      return;
    }
    const n = d.node;
    const id = parseNodeId(n.id) || {};
    showTooltip(
      h(
        'div',
        { class: 'tip' },
        h('div', { class: 'tip-title', text: `${id.ns}/${id.svc}` }),
        kv([
          ['status', n.placeholder ? 'unknown peer (no charter, no instance)' : String(n.status || '').replace('_', ' ')],
          ['instances', n.placeholder ? null : fmtInt(n.instances)],
          ['charter', n.placeholder ? null : n.charter_version ? `v${n.charter_version}` : 'none'],
        ]),
        h('div', { class: 'tip-foot', text: 'Click for the charter and instances; drag to move the frame.' }),
      ),
      event.clientX,
      event.clientY,
    );
  }

  edgePoints(e) {
    const sp = this.pos.get(e.source);
    const tp = this.pos.get(e.target);
    const sb = this.boxes.get(e.source);
    const tb = this.boxes.get(e.target);
    if (!sp || !tp || !sb || !tb) return null;
    return {
      s: portPoint(sb, sp, 'out', e.source_port),
      t: portPoint(tb, tp, 'in', e.target_port),
      sr: { x: sp.x, y: sp.y, w: sb.w, h: sb.h },
      tr: { x: tp.x, y: tp.y, w: tb.w, h: tb.h },
    };
  }

  renderEdges() {
    const byId = this.nodeById;
    const data = this.view.edges.filter((e) => this.boxes.has(e.source) && this.boxes.has(e.target));
    const sel = this.layers.edges.selectAll('g.edge').data(data, (d) => d.id);
    sel.exit().each((d) => this.edgeEls.delete(d.id)).remove();
    const enter = sel.enter().append('g');
    enter.append('path').attr('class', 'edge-hit');
    enter.append('path').attr('class', 'edge-line');
    enter
      .on('mouseenter', (event, d) => {
        d3.select(event.currentTarget).classed('hover', true);
        this.showEdgeTip(event, d);
      })
      .on('mousemove', (event, d) => this.showEdgeTip(event, d))
      .on('mouseleave', (event) => {
        d3.select(event.currentTarget).classed('hover', false);
        hideTooltip();
      });
    const all = enter.merge(sel);
    all.attr('class', (d) => {
      const s = d.stats || {};
      const deniedOnly = s.calls > 0 && s.denied === s.calls;
      return [
        'edge',
        `k-${d.kind}`,
        `t-${edgeType(d, byId)}`,
        d.declared ? 'declared' : 'undeclared',
        deniedOnly ? 'denied-only' : '',
        s.calls > 0 ? 'has-traffic' : 'no-traffic',
      ]
        .filter(Boolean)
        .join(' ');
    });
    all.select('.edge-line').attr('stroke-width', (d) => {
      const calls = (d.stats && d.stats.calls) || 0;
      return Math.min(6, 1.6 + Math.log2(1 + calls) * 0.9).toFixed(2);
    });
    all.each((d, i, els) => this.edgeEls.set(d.id, d3.select(els[i]).select('.edge-line').node()));
    this.updateEdgePaths();
  }

  updateEdgePaths() {
    this.layers.edges.selectAll('g.edge').each((d, i, els) => {
      const pts = this.edgePoints(d);
      const g = d3.select(els[i]);
      if (!pts) {
        g.attr('visibility', 'hidden');
        return;
      }
      g.attr('visibility', null);
      const path = edgePath(pts.s, pts.t, pts.sr, pts.tr);
      g.select('.edge-hit').attr('d', path);
      g.select('.edge-line').attr('d', path);
    });
  }

  showEdgeTip(event, e) {
    const s = this.nodeById.get(e.source);
    const t = this.nodeById.get(e.target);
    const st = e.stats || {};
    const now = this.opts.now ? this.opts.now() : Date.now();
    const what = e.kind === 'tool' ? `tool ${e.source_port}` : e.kind === 'invoke' ? 'app invokes agent' : 'model calls';
    showTooltip(
      h(
        'div',
        { class: 'tip' },
        h('div', { class: 'tip-title', text: `${(s && s.label) || e.source} → ${(t && t.label) || e.target}` }),
        h('div', { class: 'tip-sub' }, h('span', { text: what }), e.declared ? null : h('span', { class: 'pill pill-warn', text: 'undeclared' })),
        kv([
          ['calls', fmtInt(st.calls)],
          ['denied', fmtInt(st.denied)],
          ['errors', fmtInt(st.errors)],
          ['avg', st.calls ? fmtMs(st.avg_ms) : '–'],
          ['last', st.last_ts ? relTime(st.last_ts, now) : 'never'],
        ]),
        h('div', { class: 'tip-foot', text: e.declared ? 'Last 15 minutes.' : 'Seen in traffic but not declared by the current charter. Last 15 minutes.' }),
      ),
      event.clientX,
      event.clientY,
    );
  }

  renderNodes() {
    const data = this.view.nodes.filter((n) => n.type !== 'service');
    const sel = this.layers.nodes.selectAll('g.node').data(data, (d) => d.id);
    sel.exit().each((d) => {
      this.nodeEls.delete(d.id);
      this.signatures.delete(d.id);
    }).remove();
    const enter = sel
      .enter()
      .append('g')
      .attr('tabindex', 0)
      .attr('role', 'button')
      .call(this.nodeDrag)
      .on('click', (event, d) => {
        if (event.defaultPrevented) return;
        event.stopPropagation();
        this.opts.onSelect && this.opts.onSelect(d);
      })
      .on('keydown', (event, d) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        this.opts.onSelect && this.opts.onSelect(d);
      })
      .on('mouseenter', (event, d) => this.hoverNode(d.id, true))
      .on('mouseleave', (event, d) => this.hoverNode(d.id, false));
    const all = enter.merge(sel);
    all.each((d, i, els) => {
      const g = d3.select(els[i]);
      this.nodeEls.set(d.id, els[i]);
      const box = this.boxes.get(d.id);
      const sig = JSON.stringify([d, box.h, this.canLink]);
      if (this.signatures.get(d.id) !== sig) {
        this.signatures.set(d.id, sig);
        this.drawNode(g, d, box);
      }
      const cls = ['node', `c-${box.type}`];
      if (d.type === 'agent' && !d.placeholder) cls.push(`s-${d.status || 'idle'}`, d.agent_type === 'orchestrator' ? 'orchestrator' : 'plain');
      if (d.placeholder) cls.push('placeholder');
      g.attr('class', cls.join(' '));
      g.attr('aria-label', `${d.label || d.id}, ${d.placeholder ? 'unknown peer' : d.type === 'agent' ? `${d.agent_type || 'agent'}, ${d.status || 'idle'}` : d.type.replace('_', ' ')}`);
      this.placeNode(d.id);
    });
  }

  placeNode(id) {
    const el = this.nodeEls.get(id);
    const p = this.pos.get(id);
    if (el && p) el.setAttribute('transform', `translate(${p.x},${p.y})`);
  }

  updateFramesAndEdges() {
    const data = this.frameData();
    const byId = new Map(data.map((d) => [d.id, d]));
    this.layers.frames.selectAll('g.frame').each((d, i, els) => {
      const fresh = byId.get(d.id);
      if (!fresh) return;
      d.rect = fresh.rect;
      this.drawFrame(d3.select(els[i]), d);
    });
    this.updateEdgePaths();
  }

  drawNode(g, n, box) {
    g.selectAll('*').remove();
    const w = box.w;
    const r = 10;
    g.append('rect').attr('class', 'card').attr('width', w).attr('height', box.h).attr('rx', r);
    g.append('path')
      .attr('class', 'card-header')
      .attr('d', `M0,${r} a${r},${r} 0 0 1 ${r},-${r} h${w - 2 * r} a${r},${r} 0 0 1 ${r},${r} v${G.header - r} h-${w} z`);
    g.append('line').attr('class', 'card-sep').attr('x1', 0).attr('x2', w).attr('y1', G.header).attr('y2', G.header);
    g.append('rect').attr('class', 'card-outline').attr('width', w).attr('height', box.h).attr('rx', r);

    // header: title, badge, status dot
    const badgeText = n.placeholder ? 'unknown' : n.type === 'agent' ? (n.agent_type === 'orchestrator' ? 'orchestrator' : 'agent') : BADGE[n.type] || n.type;
    const badge = g.append('g').attr('class', `badge b-${n.type === 'agent' ? n.agent_type || 'agent' : box.type}`);
    const bt = badge.append('text').attr('y', 20).text(badgeText);
    const bw = textWidth(bt) + 14;
    const hasDot = n.type === 'agent' || n.placeholder;
    const bx = w - bw - (hasDot ? 26 : 10);
    badge.insert('rect', 'text').attr('x', bx).attr('y', 8).attr('width', bw).attr('height', 17).attr('rx', 8.5);
    bt.attr('x', bx + bw / 2).attr('text-anchor', 'middle');
    if (hasDot) {
      const st = n.placeholder ? 'disconnected' : n.status || 'idle';
      g.append('circle').attr('class', `status-dot sd-${st}`).attr('cx', w - 14).attr('cy', 16).attr('r', 4.5).append('title').text(`status: ${st}`);
    }
    fitText(g.append('text').attr('class', 'card-title').attr('x', 12).attr('y', 21), n.label || n.id, bx - 20);

    // ports
    for (const p of box.inPorts) {
      const t = IN_PORT_TYPE[p.name] || 'unknown';
      const pg = g.append('g').attr('class', `port in pt-${t}`).attr('data-port', p.name);
      pg.append('circle').attr('cx', 0).attr('cy', p.y).attr('r', G.portR);
      fitText(pg.append('text').attr('class', 'port-label').attr('x', 12).attr('y', p.y + 4), p.name, w / 2 - 20);
      pg.append('title').text(`input: ${p.name}`);
    }
    for (const p of box.outPorts) {
      const type = outPortType(n, p.name);
      const tool = (n.tools || []).find((x) => x.name === p.name);
      const dim = tool && tool.allowed === false;
      const pg = g.append('g').attr('class', `port out pt-${type}${dim ? ' dimmed' : ''}`).attr('data-port', p.name);
      pg.append('circle').attr('cx', w).attr('cy', p.y).attr('r', G.portR);
      fitText(pg.append('text').attr('class', 'port-label').attr('text-anchor', 'end').attr('x', w - 12).attr('y', p.y + 4), p.name, w / 2 - 16);
      const target = tool ? ` → ${tool.target}` : '';
      pg.append('title').text(`${type} ${p.name}${target}${dim ? ' (not in guardrails.allowed_tools: the model never sees it)' : ''}`);
    }
    if (box.linkPort) {
      const lp = g.append('g').attr('class', 'port-link');
      lp.append('text').attr('class', 'port-label link-label').attr('text-anchor', 'end').attr('x', w - 14).attr('y', box.linkPort.y + 4).text('drag to link an agent');
      lp.append('circle').attr('cx', w).attr('cy', box.linkPort.y).attr('r', 7);
      lp.append('path').attr('class', 'plus').attr('d', `M${w - 3.5},${box.linkPort.y} h7 M${w},${box.linkPort.y - 3.5} v7`);
      lp.append('title').text('Drag onto another agent to let this orchestrator call it');
      lp.call(this.linkDrag);
    }

    // widgets
    const top = box.widgetsTop;
    g.append('line').attr('class', 'card-sep soft').attr('x1', 10).attr('x2', w - 10).attr('y1', top - 4).attr('y2', top - 4);
    const rowY = (i) => top + i * G.row + G.row / 2 + 4;
    const keyVal = (i, key, val, cls = '') => {
      g.append('text').attr('class', 'w-key').attr('x', 12).attr('y', rowY(i)).text(key);
      const v = g.append('text').attr('class', `w-val ${cls}`).attr('text-anchor', 'end').attr('x', w - 12).attr('y', rowY(i));
      fitText(v, val, w - 90);
    };
    if (n.placeholder) {
      g.append('text').attr('class', 'w-note').attr('x', 12).attr('y', rowY(0)).text('no charter or instance known');
      return;
    }
    if (n.type === 'agent') {
      keyVal(0, 'model', n.model || '–', 'mono');
      this.drawChips(g, rowY(1), w, n.skills || []);
      this.drawLearning(g, rowY(2), w, n.learning || {});
      this.drawAgentStats(g, rowY(3), w, n.stats || {});
    } else if (n.type === 'app') {
      keyVal(0, 'app port', n.port == null ? 'unknown' : String(n.port), 'mono');
      const s = n.stats || {};
      const t = g.append('text').attr('class', 'w-stats').attr('x', 12).attr('y', rowY(1));
      if (!s.calls) t.text('no peer calls in 15 min');
      else {
        t.append('tspan').text(`${fmtInt(s.calls)} peer call${s.calls === 1 ? '' : 's'}`);
        if (s.denied) t.append('tspan').attr('class', 'neg').text(` · ${fmtInt(s.denied)} denied`);
        if (s.errors) t.append('tspan').attr('class', 'warn').text(` · ${fmtInt(s.errors)} errors`);
        t.append('tspan').text(` · avg ${fmtMs(s.avg_ms)}`);
      }
    } else if (n.type === 'model_provider') {
      g.append('text').attr('class', 'w-note mono').attr('x', 12).attr('y', rowY(0)).text(n.id);
    } else if (n.type === 'external') {
      fitText(g.append('text').attr('class', 'w-note mono').attr('x', 12).attr('y', rowY(0)), (parseNodeId(n.id) || {}).origin || n.id, w - 24);
    }
  }

  drawChips(g, y, w, skills) {
    if (!skills.length) {
      g.append('text').attr('class', 'w-key').attr('x', 12).attr('y', y).text('no skills');
      return;
    }
    let x = 12;
    const max = w - 12;
    for (let i = 0; i < skills.length; i++) {
      const chip = g.append('g').attr('class', 'chip');
      const t = chip.append('text').attr('x', x + 7).attr('y', y).text(skills[i]);
      const tw = textWidth(t) + 14;
      const restLabel = `+${skills.length - i}`;
      if (x + tw > max - (i < skills.length - 1 ? 30 : 0)) {
        chip.remove();
        const more = g.append('g').attr('class', 'chip more');
        const mt = more.append('text').attr('x', x + 7).attr('y', y).text(restLabel);
        more.insert('rect', 'text').attr('x', x).attr('y', y - 12).attr('width', textWidth(mt) + 14).attr('height', 17).attr('rx', 8.5);
        more.append('title').text(skills.slice(i).join(', '));
        break;
      }
      chip.insert('rect', 'text').attr('x', x).attr('y', y - 12).attr('width', tw).attr('height', 17).attr('rx', 8.5);
      x += tw + 5;
    }
  }

  drawLearning(g, y, w, l) {
    const t = g.append('text').attr('class', 'w-learning').attr('x', 12).attr('y', y);
    t.append('tspan').attr('class', l.enabled ? 'on' : 'off').text(l.enabled ? `learning · ${l.mode || 'review'}` : 'learning off');
    const right = g.append('text').attr('class', 'w-learning').attr('text-anchor', 'end').attr('x', w - 12).attr('y', y);
    right.append('tspan').text(`${fmtInt(l.notes || 0)} note${l.notes === 1 ? '' : 's'}`);
    if (l.pending) right.append('tspan').attr('class', 'pending').text(` · ${fmtInt(l.pending)} pending`);
  }

  drawAgentStats(g, y, w, s) {
    const t = g.append('text').attr('class', 'w-stats').attr('x', 12).attr('y', y);
    if (!s.invocations && !s.denied && !s.errors) {
      t.text('no invocations in 15 min');
      return;
    }
    t.append('tspan').text(`${fmtInt(s.invocations)} run${s.invocations === 1 ? '' : 's'}`);
    if (s.denied) t.append('tspan').attr('class', 'neg').text(` · ${fmtInt(s.denied)} denied`);
    if (s.errors) t.append('tspan').attr('class', 'warn').text(` · ${fmtInt(s.errors)} err`);
    t.append('tspan').text(` · p95 ${fmtMs(s.p95_ms)}`);
    // The right side shows tokens and cost when there is room, else only the cost.
    const r = g.append('text').attr('class', 'w-stats').attr('text-anchor', 'end').attr('x', w - 12).attr('y', y);
    const room = w - 24 - textWidth(t) - 10;
    r.text(`${fmtCompact((s.tokens_in || 0) + (s.tokens_out || 0))} tok · ${fmtCost(s.cost_usd)}`);
    if (textWidth(r) > room) r.text(fmtCost(s.cost_usd));
    if (textWidth(r) > room) r.remove();
    t.append('title').text(`invocations ${fmtInt(s.invocations)}, denied ${fmtInt(s.denied)}, errors ${fmtInt(s.errors)}, p50 ${fmtMs(s.p50_ms)}, p95 ${fmtMs(s.p95_ms)}, tokens in ${fmtInt(s.tokens_in)} / out ${fmtInt(s.tokens_out)}, cost ${fmtCost(s.cost_usd)} (15 min)`);
  }

  hoverNode(id, on) {
    this.svg.classed('hovering', on);
    this.layers.edges.selectAll('g.edge').classed('hl', (d) => on && (d.source === id || d.target === id));
    const el = this.nodeEls.get(id);
    if (el) d3.select(el).classed('hl', on);
  }

  // ---- selection, fit, layout ------------------------------------------------------------------

  select(id) {
    this.selected = id;
    this.applySelection();
  }

  applySelection() {
    const id = this.selected;
    this.layers.nodes.selectAll('g.node').classed('selected', (d) => d.id === id);
    this.layers.frames.selectAll('g.frame').classed('selected', (d) => d.id === id);
  }

  contentBounds() {
    const rects = [];
    for (const n of this.view ? this.view.nodes : []) {
      if (n.type === 'service') continue;
      const r = this.rectOf(n.id);
      if (r) rects.push(r);
    }
    for (const f of this.frameData()) rects.push(f.rect);
    if (!rects.length) return null;
    const x0 = Math.min(...rects.map((r) => r.x));
    const y0 = Math.min(...rects.map((r) => r.y));
    const x1 = Math.max(...rects.map((r) => r.x + r.w));
    const y1 = Math.max(...rects.map((r) => r.y + r.h));
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  }

  fit(duration = 450) {
    const b = this.contentBounds();
    if (!b) return;
    const inset = this.opts.rightInset ? this.opts.rightInset() : 0;
    const W = Math.max(120, this.host.clientWidth - inset);
    const H = Math.max(120, this.host.clientHeight);
    const k = Math.max(0.15, Math.min(1.15, 0.9 * Math.min(W / b.w, H / b.h)));
    const tx = (W - b.w * k) / 2 - b.x * k;
    const ty = (H - b.h * k) / 2 - b.y * k;
    const t = d3.zoomIdentity.translate(tx, ty).scale(k);
    if (duration) this.svg.transition().duration(duration).ease(d3.easeCubicOut).call(this.zoom.transform, t);
    else this.svg.call(this.zoom.transform, t);
  }

  /** Centers a node in view if it is off screen (used when the inspector opens). */
  reveal(id) {
    const r = this.rectOf(id);
    if (!r) return;
    const t = d3.zoomTransform(this.svg.node());
    const inset = this.opts.rightInset ? this.opts.rightInset() : 0;
    const W = this.host.clientWidth - inset;
    const H = this.host.clientHeight;
    const x0 = t.applyX(r.x);
    const y0 = t.applyY(r.y);
    const x1 = t.applyX(r.x + r.w);
    const y1 = t.applyY(r.y + r.h);
    if (x0 >= 0 && y0 >= 0 && x1 <= W && y1 <= H) return;
    const cx = r.x + r.w / 2;
    const cy = r.y + r.h / 2;
    this.svg.transition().duration(400).call(this.zoom.transform, d3.zoomIdentity.translate(W / 2 - cx * t.k, H / 2 - cy * t.k).scale(t.k));
  }

  autoLayout() {
    clearPositions();
    const from = new Map([...this.pos].map(([id, p]) => [id, { ...p }]));
    const to = resolvePositions(this.graph, new Map(), (n) => this.boxOf(n));
    this.placed = new Map([...to].map(([id, p]) => [id, { ...p }]));
    this.svg
      .transition('layout')
      .duration(550)
      .ease(d3.easeCubicInOut)
      .tween('layout', () => (k) => {
        for (const [id, p] of to) {
          const f = from.get(id) || p;
          this.pos.set(id, { x: f.x + (p.x - f.x) * k, y: f.y + (p.y - f.y) * k });
          this.placeNode(id);
        }
        this.updateFramesAndEdges();
      })
      .on('end', () => {
        this.pos = new Map([...to].map(([id, p]) => [id, { ...p }]));
        this.fit();
      });
  }

  // ---- live traffic ----------------------------------------------------------------------------

  animate(edgeId, outcome) {
    if (typeof document !== 'undefined' && document.hidden) return;
    const path = this.edgeEls.get(edgeId);
    if (!path || !path.isConnected || this.layers.dots.node().childElementCount > 80) return;
    const L = path.getTotalLength();
    if (!L) return;
    const edgeG = d3.select(path.parentNode);
    edgeG.classed('active', true);
    clearTimeout(path.__activeTimer);
    path.__activeTimer = setTimeout(() => edgeG.classed('active', false), 1400);
    const datum = edgeG.datum();
    const dot = this.layers.dots.append('circle').attr('class', `dot dot-${outcome}`).attr('r', 4.5);
    dot
      .transition()
      .duration(Math.max(550, Math.min(1700, L * 1.7)))
      .ease(d3.easeCubicInOut)
      .attrTween('transform', () => (t) => {
        const p = path.getPointAtLength(t * L);
        return `translate(${p.x},${p.y})`;
      })
      .on('end', () => datum && this.pulse(datum.target, outcome))
      .transition()
      .duration(260)
      .attr('r', 10)
      .style('opacity', 0)
      .remove();
  }

  pulse(id, outcome) {
    const el = this.nodeEls.get(id);
    if (!el) return;
    const g = d3.select(el);
    g.classed(`pulse-${outcome}`, false);
    void el.getBoundingClientRect();
    g.classed(`pulse-${outcome}`, true);
    clearTimeout(el.__pulseTimer);
    el.__pulseTimer = setTimeout(() => g.classed(`pulse-${outcome}`, false), 700);
  }

  // ---- drag to link ----------------------------------------------------------------------------

  linkCandidates(from) {
    return this.view.nodes.filter((n) => n.type === 'agent' && !n.placeholder && n.id !== from.id);
  }

  linkStart(from) {
    hideTooltip();
    const box = this.boxes.get(from.id);
    const p = this.pos.get(from.id);
    if (!box || !box.linkPort || !p) return;
    this.linking = { from, start: { x: p.x + box.linkPort.x, y: p.y + box.linkPort.y }, target: null };
    this.svg.classed('linking', true);
    const cands = new Set(this.linkCandidates(from).map((n) => n.id));
    this.layers.nodes.selectAll('g.node').classed('link-candidate', (d) => cands.has(d.id) && linkRequirement(from.id, d.id).level !== 'refused');
    this.layers.nodes.selectAll('g.node').classed('link-refused', (d) => cands.has(d.id) && linkRequirement(from.id, d.id).level === 'refused');
    this.ghost.attr('visibility', 'visible').attr('d', bezier(this.linking.start, this.linking.start));
  }

  linkHit(p) {
    if (!this.linking) return null;
    for (const n of this.linkCandidates(this.linking.from)) {
      const r = this.rectOf(n.id);
      if (r && rectContains(r, p, 10)) return n;
    }
    return null;
  }

  linkMove(p) {
    if (!this.linking) return;
    const target = this.linkHit(p);
    this.linking.target = target;
    let end = p;
    if (target) {
      const box = this.boxes.get(target.id);
      end = portPoint(box, this.pos.get(target.id), 'in', 'invoke');
    }
    this.ghost.attr('d', bezier(this.linking.start, end)).classed('snapped', !!target);
    this.layers.nodes.selectAll('g.node').classed('drop-target', (d) => !!target && d.id === target.id);
  }

  linkEnd(p) {
    if (!this.linking) return;
    const target = this.linkHit(p);
    const from = this.linking.from;
    this.linking = null;
    this.svg.classed('linking', false);
    this.ghost.attr('visibility', 'hidden').classed('snapped', false);
    this.layers.nodes.selectAll('g.node').classed('link-candidate', false).classed('link-refused', false).classed('drop-target', false);
    if (target && this.opts.onLink) this.opts.onLink(from, target);
  }
}
