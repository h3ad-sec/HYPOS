import { getIndex, getData } from './data-loader.js';

// Returns: { type, query, actor?, items }
// type: 'technique' | 'group' | 'malware' | 'tool' | 'campaign' | 'not-found'
// items: array of technique objects

export function detectQueryType(q) {
  const t = q.trim();
  if (/^T\d{4}(\.\d{3})?$/i.test(t))  return 'technique-id';
  if (/^G\d{4}$/i.test(t))             return 'group-id';
  if (/^S\d{4}$/i.test(t))             return 'software-id';
  if (/^C\d{4}$/i.test(t))             return 'campaign-id';
  return 'name';
}

export function lookup(query) {
  const index = getIndex();
  const data  = getData();
  if (!index || !data) return { type: 'not-found', query };

  const q    = query.trim();
  const qup  = q.toUpperCase();
  const ql   = q.toLowerCase();
  const qtype = detectQueryType(q);

  if (qtype === 'technique-id') {
    const t = index.techById[qup];
    if (!t) return { type: 'not-found', query: q };
    if (t.sub) {
      return { type: 'technique', items: [t], query: q };
    }
    const subs = (t.subs || []).map(sid => index.techById[sid]).filter(Boolean);
    subs.sort((a, b) => a.id.localeCompare(b.id));
    return { type: 'technique', items: [t, ...subs], query: q };
  }

  if (qtype === 'group-id' || qtype === 'software-id' || qtype === 'campaign-id') {
    const actor = findActorById(data, qup);
    if (!actor) return { type: 'not-found', query: q };
    return buildActorResult(actor, index, query);
  }

  // Name search — score and rank
  const scored = [];
  const seen   = new Set();

  for (const e of index.entries) {
    if (!e.key.includes(ql)) continue;
    const dedup = `${e.type}:${e.id}`;
    if (seen.has(dedup)) continue;
    seen.add(dedup);
    const score = e.key === ql ? 100 : e.key.startsWith(ql) ? 80 : 50;
    scored.push({ score, e });
  }

  scored.sort((a, b) => b.score - a.score || a.e.id.localeCompare(b.e.id));

  if (!scored.length) return { type: 'not-found', query: q };

  const best = scored[0].e;

  // If best is an actor, return actor result
  if (best.type !== 'technique') {
    return buildActorResult(best.obj, index, q);
  }

  // All techniques - return them
  const techs = scored
    .filter(s => s.e.type === 'technique')
    .slice(0, 50)
    .map(s => s.e.obj);

  return { type: 'technique', items: techs, query: q };
}

function buildActorResult(actor, index, query) {
  const techs = actor.techs
    .map(id => index.techById[id])
    .filter(Boolean);
  return { type: actor.type, actor, items: techs, query };
}

function findActorById(data, id) {
  for (const list of [data.groups, data.malware, data.tools, data.campaigns]) {
    const found = list.find(a => a.id === id);
    if (found) return found;
  }
  return null;
}

export function lookupAll() {
  const data = getData();
  if (!data) return null;
  const parents = data.techniques.filter(t => !t.sub);
  return { type: 'all', items: parents, query: '' };
}

// Returns up to `limit` suggestions for autocomplete
export function suggest(query, limit = 12) {
  const index = getIndex();
  if (!index || query.length < 2) return [];

  const ql   = query.toLowerCase();
  const seen = new Set();
  const out  = [];

  // Exact ID prefix first (T1003, G00, S00, C00)
  for (const e of index.entries) {
    if (!e.id.toLowerCase().startsWith(ql)) continue;
    const key = `${e.type}:${e.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ id: e.id, name: e.obj.name, type: e.type });
    if (out.length >= limit) return out;
  }

  // Name prefix
  for (const e of index.entries) {
    if (!e.key.startsWith(ql)) continue;
    const key = `${e.type}:${e.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ id: e.id, name: e.obj.name, type: e.type });
    if (out.length >= limit) return out;
  }

  // Name contains
  for (const e of index.entries) {
    if (!e.key.includes(ql) || e.key.startsWith(ql)) continue;
    const key = `${e.type}:${e.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ id: e.id, name: e.obj.name, type: e.type });
    if (out.length >= limit) return out;
  }

  return out;
}
