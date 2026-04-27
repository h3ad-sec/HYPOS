let _db         = null;
let _tagIndex   = null;
let _relatedMap = null;

export async function loadHypDB() {
  try {
    const r = await fetch('./data/hyp-db.json');
    if (r.ok) {
      _db = await r.json();
      _buildTagIndex();
    }
  } catch (_) {}
}

function _buildTagIndex() {
  _tagIndex   = { tools: {}, actors: {} };
  _relatedMap = {};

  for (const [techId, entry] of Object.entries(_db.techniques || {})) {
    const tools  = [...new Set((entry.hypotheses || []).flatMap(h => h.tools  || []))];
    const actors = [...new Set((entry.hypotheses || []).flatMap(h => h.actors || []))];
    for (const t of tools) {
      const k = t.toLowerCase();
      if (!_tagIndex.tools[k]) _tagIndex.tools[k] = { name: t, techs: [] };
      _tagIndex.tools[k].techs.push(techId);
    }
    for (const a of actors) {
      const k = a.toLowerCase();
      if (!_tagIndex.actors[k]) _tagIndex.actors[k] = { name: a, techs: [] };
      _tagIndex.actors[k].techs.push(techId);
    }
  }

  for (const [techId, entry] of Object.entries(_db.techniques || {})) {
    const tools  = [...new Set((entry.hypotheses || []).flatMap(h => h.tools  || []))];
    const actors = [...new Set((entry.hypotheses || []).flatMap(h => h.actors || []))];
    const rel    = new Set();
    for (const t of tools)  (_tagIndex.tools[t.toLowerCase()]?.techs   || []).forEach(id => id !== techId && rel.add(id));
    for (const a of actors) (_tagIndex.actors[a.toLowerCase()]?.techs  || []).forEach(id => id !== techId && rel.add(id));
    _relatedMap[techId] = [...rel];
  }
}

export function getCurated(techniqueId) {
  return _db?.techniques?.[techniqueId]?.hypotheses || null;
}

export function getRelated(techniqueId) {
  return _relatedMap?.[techniqueId] || [];
}

export function lookupByTag(query) {
  if (!_tagIndex) return null;
  const ql = query.toLowerCase();
  for (const pass of [0, 1, 2]) {
    for (const [k, v] of Object.entries(_tagIndex.tools)) {
      if ((pass === 0 && k === ql) || (pass === 1 && k.startsWith(ql)) || (pass === 2 && k.includes(ql)))
        return { tagType: 'tool', tagName: v.name, techIds: v.techs };
    }
    for (const [k, v] of Object.entries(_tagIndex.actors)) {
      if ((pass === 0 && k === ql) || (pass === 1 && k.startsWith(ql)) || (pass === 2 && k.includes(ql)))
        return { tagType: 'actor', tagName: v.name, techIds: v.techs };
    }
  }
  return null;
}

export function suggestTags(query, limit = 4) {
  if (!_tagIndex || query.length < 2) return [];
  const ql  = query.toLowerCase();
  const out = [];
  for (const [k, v] of Object.entries(_tagIndex.tools)) {
    if (!k.includes(ql)) continue;
    out.push({ id: v.name, name: `${v.techs.length} technique${v.techs.length !== 1 ? 's' : ''}`, type: 'tool' });
    if (out.length >= limit) return out;
  }
  for (const [k, v] of Object.entries(_tagIndex.actors)) {
    if (!k.includes(ql) || out.length >= limit) continue;
    out.push({ id: v.name, name: `${v.techs.length} technique${v.techs.length !== 1 ? 's' : ''}`, type: 'actor' });
  }
  return out;
}
