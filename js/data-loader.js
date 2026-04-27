const STIX_URL  = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const LOCAL_URL = './data/attack.json';
const CACHE_KEY = 'hypos_v5';
const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

let _data  = null;
let _index = null;

export async function loadData(onProgress) {
  if (_data) return _data;

  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (raw) {
      const { ts, data } = JSON.parse(raw);
      if (Date.now() - ts < CACHE_TTL) {
        onProgress?.('ready', `Loaded from cache — ${data.techniques.length} techniques`);
        _data  = data;
        _index = buildIndex(data);
        return _data;
      }
    }
  } catch (_) {}

  try {
    onProgress?.('loading', 'Loading ATT&CK dataset…');
    const r = await fetch(LOCAL_URL);
    if (r.ok) {
      const d = await r.json();
      if (d.techniques) {
        onProgress?.('ready', `${d.techniques.length} techniques · ${d.groups.length} groups · ${d.malware.length} malware · ${d.tools.length} tools`);
        _data  = d;
        _index = buildIndex(d);
        cacheData(d);
        return _data;
      }
    }
  } catch (_) {}

  onProgress?.('loading', 'Connecting to MITRE ATT&CK…');
  const r = await fetch(STIX_URL);
  if (!r.ok) throw new Error(`STIX fetch failed: ${r.status}`);

  onProgress?.('loading', 'Downloading dataset (may take a moment)…');
  const text = await r.text();

  onProgress?.('loading', 'Processing techniques…');
  const bundle = JSON.parse(text);

  onProgress?.('loading', 'Building index…');
  _data  = processBundle(bundle);
  _index = buildIndex(_data);
  cacheData(_data);

  onProgress?.('ready', `${_data.techniques.length} techniques · ${_data.groups.length} groups · ${_data.malware.length} malware · ${_data.tools.length} tools`);
  return _data;
}

export function getData()    { return _data;  }
export function getIndex()   { return _index; }
export function getUsedBy(techId) {
  return _index?.techUsedBy?.[techId] || { groups: [], malware: [], tools: [] };
}

function getMitreId(obj) {
  const r = (obj.external_references || []).find(x => x.source_name === 'mitre-attack');
  return r ? r.external_id : null;
}

function getUrl(obj) {
  const r = (obj.external_references || []).find(x => x.source_name === 'mitre-attack');
  return r ? r.url : null;
}

function stripMd(t) {
  return (t || '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\*{1,2}([^*]+)\*{1,2}/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/#{1,6}\s*/g, '')
    .trim();
}

function trunc(t, n) {
  const s = stripMd(t || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function firstSentence(t) {
  const s = stripMd(t || '');
  const m = s.match(/^[^.!?\n]+[.!?]/);
  return m ? m[0].trim() : trunc(s, 200);
}

function processBundle(bundle) {
  const dsNameByStix  = {};
  const compInfoByStix = {};

  for (const obj of bundle.objects) {
    if (obj.type === 'x-mitre-data-source') dsNameByStix[obj.id] = obj.name;
  }
  for (const obj of bundle.objects) {
    if (obj.type !== 'x-mitre-data-component') continue;
    const src = dsNameByStix[obj.x_mitre_data_source_ref] || '';
    compInfoByStix[obj.id] = {
      str:       src ? `${src}: ${obj.name}` : obj.name,
      source:    src,
      component: obj.name,
    };
  }

  const techDsMap       = {};
  const techAnalyticMap = {};

  for (const obj of bundle.objects) {
    if (obj.type !== 'relationship' || obj.relationship_type !== 'detects') continue;
    const info = compInfoByStix[obj.source_ref];
    if (!info) continue;
    const tid = obj.target_ref;
    if (!techDsMap[tid])       techDsMap[tid]       = [];
    if (!techAnalyticMap[tid]) techAnalyticMap[tid] = {};
    if (!techDsMap[tid].includes(info.str)) techDsMap[tid].push(info.str);
    const analytic = trunc(obj.description, 500);
    if (analytic) techAnalyticMap[tid][info.str] = analytic;
  }

  const mitInfoByStix = {};
  for (const obj of bundle.objects) {
    if (obj.type !== 'course-of-action') continue;
    const id = getMitreId(obj);
    if (id) mitInfoByStix[obj.id] = { id, name: obj.name };
  }

  const techMitMap = {};
  for (const obj of bundle.objects) {
    if (obj.type !== 'relationship' || obj.relationship_type !== 'mitigates') continue;
    const mit = mitInfoByStix[obj.source_ref];
    if (!mit) continue;
    const tid = obj.target_ref;
    if (!techMitMap[tid]) techMitMap[tid] = [];
    if (!techMitMap[tid].find(m => m.id === mit.id)) techMitMap[tid].push(mit);
  }

  const techByStix  = {};
  const actorByStix = {};
  const techniques  = [];
  const groups      = [];
  const malware     = [];
  const tools       = [];
  const campaigns   = [];

  for (const obj of bundle.objects) {
    if (obj.revoked || obj.x_mitre_deprecated) continue;
    const id = getMitreId(obj);
    if (!id) continue;

    if (obj.type === 'attack-pattern') {
      const ds = (obj.x_mitre_data_sources && obj.x_mitre_data_sources.length)
        ? obj.x_mitre_data_sources.slice(0, 12)
        : (techDsMap[obj.id] || []).slice(0, 12);

      const t = {
        id,
        name: obj.name,
        desc: trunc(obj.description, 400),
        sentence: firstSentence(obj.description),
        tactics: (obj.kill_chain_phases || [])
          .filter(p => p.kill_chain_name === 'mitre-attack')
          .map(p => p.phase_name),
        platforms: (obj.x_mitre_platforms || []).slice(0, 8),
        ds,
        detect:    trunc(obj.x_mitre_detection, 400),
        analytics: techAnalyticMap[obj.id] || {},
        mits: (techMitMap[obj.id] || []).slice(0, 10),
        sub: !!(obj.x_mitre_is_subtechnique),
        pid: null,
        subs: [],
        url: getUrl(obj),
        _s: obj.id,
      };
      techniques.push(t);
      techByStix[obj.id] = t;

    } else {
      let list, type;
      if      (obj.type === 'intrusion-set') { list = groups;    type = 'group';    }
      else if (obj.type === 'malware')        { list = malware;   type = 'malware';  }
      else if (obj.type === 'tool')           { list = tools;     type = 'tool';     }
      else if (obj.type === 'campaign')       { list = campaigns; type = 'campaign'; }
      else continue;

      const a = {
        type,
        id,
        name: obj.name,
        aliases: ((type === 'group' ? obj.aliases : obj.x_mitre_aliases) || []).slice(0, 10).filter(Boolean),
        desc: trunc(obj.description, 220),
        url: getUrl(obj),
        techs: [],
        _s: obj.id,
      };
      list.push(a);
      actorByStix[obj.id] = a;
    }
  }

  for (const obj of bundle.objects) {
    if (obj.type !== 'relationship') continue;

    if (obj.relationship_type === 'subtechnique-of') {
      const sub = techByStix[obj.source_ref];
      const par = techByStix[obj.target_ref];
      if (sub && par) { sub.pid = par.id; if (!par.subs.includes(sub.id)) par.subs.push(sub.id); }

    } else if (obj.relationship_type === 'uses') {
      const tech  = techByStix[obj.target_ref];
      if (!tech) continue;
      const actor = actorByStix[obj.source_ref];
      if (!actor) continue;
      if (!actor.techs.includes(tech.id)) actor.techs.push(tech.id);
    }
  }

  const clean = arr => arr.map(o => { const r = { ...o }; delete r._s; return r; });

  return {
    meta: { generated: new Date().toISOString().split('T')[0] },
    techniques: clean(techniques),
    groups:     clean(groups),
    malware:    clean(malware),
    tools:      clean(tools),
    campaigns:  clean(campaigns),
  };
}

function buildIndex(data) {
  const techById = {};
  for (const t of data.techniques) techById[t.id] = t;

  const techUsedBy = {};
  const addUsedBy = (list, field) => {
    for (const a of list) {
      for (const tid of a.techs) {
        if (!techUsedBy[tid]) techUsedBy[tid] = { groups: [], malware: [], tools: [] };
        techUsedBy[tid][field].push({ id: a.id, name: a.name });
      }
    }
  };
  addUsedBy(data.groups,  'groups');
  addUsedBy(data.malware, 'malware');
  addUsedBy(data.tools,   'tools');

  const entries = [];

  for (const t of data.techniques) {
    entries.push({ key: t.id.toLowerCase(), id: t.id, name: t.name, type: 'technique', obj: t });
    entries.push({ key: t.name.toLowerCase(), id: t.id, name: t.name, type: 'technique', obj: t });
  }

  const addActors = (list) => {
    for (const a of list) {
      entries.push({ key: a.name.toLowerCase(), id: a.id, name: a.name, type: a.type, obj: a });
      entries.push({ key: a.id.toLowerCase(), id: a.id, name: a.name, type: a.type, obj: a });
      for (const alias of a.aliases) {
        if (alias) entries.push({ key: alias.toLowerCase(), id: a.id, name: a.name, type: a.type, obj: a });
      }
    }
  };

  addActors(data.groups);
  addActors(data.malware);
  addActors(data.tools);
  addActors(data.campaigns);

  return { techById, entries, techUsedBy };
}

function cacheData(data) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), data }));
  } catch (_) {}
}

export function clearCache() {
  localStorage.removeItem(CACHE_KEY);
}
