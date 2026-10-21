// Per-viewer conveniences kept in localStorage: node positions (design §11 key
// `agentsc.positions.v1`) and the namespace/service filter. Storage can be missing or throw
// (private windows, blocked site data); the console works the same without it.

export const POSITIONS_KEY = 'agentsc.positions.v1';
const FILTERS_KEY = 'agentsc.filters.v1';

function storage() {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

function readJson(key) {
  const s = storage();
  if (!s) return null;
  try {
    const raw = s.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeJson(key, value) {
  const s = storage();
  if (!s) return;
  try {
    if (value === null) s.removeItem(key);
    else s.setItem(key, JSON.stringify(value));
  } catch {
    /* quota or blocked: positions are a convenience */
  }
}

const finite = (n) => typeof n === 'number' && Number.isFinite(n) && Math.abs(n) < 1e6;

/** Saved positions as Map(node id → {x, y}); malformed entries are dropped. */
export function loadPositions() {
  const raw = readJson(POSITIONS_KEY);
  const out = new Map();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [id, p] of Object.entries(raw)) {
    if (typeof id === 'string' && id.length < 600 && Array.isArray(p) && finite(p[0]) && finite(p[1])) out.set(id, { x: p[0], y: p[1] });
  }
  return out;
}

export function savePositions(map) {
  const obj = {};
  for (const [id, p] of map) obj[id] = [Math.round(p.x), Math.round(p.y)];
  writeJson(POSITIONS_KEY, obj);
}

export function clearPositions() {
  writeJson(POSITIONS_KEY, null);
}

export function loadFilters() {
  const raw = readJson(FILTERS_KEY);
  const ns = raw && typeof raw.ns === 'string' ? raw.ns : '';
  const svc = raw && typeof raw.svc === 'string' ? raw.svc : '';
  return { ns, svc };
}

export function saveFilters(f) {
  writeJson(FILTERS_KEY, { ns: f.ns || '', svc: f.svc || '' });
}
