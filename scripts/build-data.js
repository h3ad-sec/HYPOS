#!/usr/bin/env node
// Run: node scripts/build-data.js
// Fetches MITRE ATT&CK STIX bundle and writes compact data/attack.json.
// Only needed to refresh data — the browser fetches live if this file is absent.

const https = require('https');
const fs = require('fs');
const path = require('path');

const STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const OUT = path.resolve(__dirname, '../data/attack.json');

function get(url) {
  return new Promise((res, rej) => {
    https.get(url, { headers: { 'User-Agent': 'hypos-build/1.0' } }, r => {
      if (r.statusCode === 301 || r.statusCode === 302) return res(get(r.headers.location));
      const chunks = [];
      r.on('data', c => { chunks.push(c); process.stdout.write('.'); });
      r.on('end', () => res(Buffer.concat(chunks).toString()));
      r.on('error', rej);
    }).on('error', rej);
  });
}

function getMitreId(obj) {
  const ref = (obj.external_references || []).find(r => r.source_name === 'mitre-attack');
  return ref ? ref.external_id : null;
}

function getUrl(obj) {
  const ref = (obj.external_references || []).find(r => r.source_name === 'mitre-attack');
  return ref ? ref.url : null;
}

function stripMd(t) {
  return (t || '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\*{1,2}([^*]+)\*{1,2}/g, '$1').replace(/`([^`]+)`/g, '$1').trim();
}

function trunc(t, n) {
  if (!t) return '';
  const s = stripMd(t);
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

async function main() {
  console.log('Fetching MITRE ATT&CK STIX bundle');
  process.stdout.write('Downloading ');
  const raw = await get(STIX_URL);
  console.log(`\nDownloaded ${(raw.length / 1024 / 1024).toFixed(1)} MB`);

  const bundle = JSON.parse(raw);
  console.log(`Loaded ${bundle.objects.length} STIX objects`);

  const techByStix = {};
  const actorByStix = {};
  const techniques = [];
  const groups = [];
  const malware = [];
  const tools = [];
  const campaigns = [];

  for (const obj of bundle.objects) {
    if (obj.revoked || obj.x_mitre_deprecated) continue;
    const id = getMitreId(obj);
    if (!id) continue;

    if (obj.type === 'attack-pattern') {
      const t = {
        id,
        name: obj.name,
        desc: trunc(obj.description, 400),
        tactics: (obj.kill_chain_phases || []).filter(p => p.kill_chain_name === 'mitre-attack').map(p => p.phase_name),
        platforms: (obj.x_mitre_platforms || []).slice(0, 8),
        ds: (obj.x_mitre_data_sources || []).slice(0, 12),
        detect: trunc(obj.x_mitre_detection, 400),
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
      if (obj.type === 'intrusion-set') { list = groups; type = 'group'; }
      else if (obj.type === 'malware') { list = malware; type = 'malware'; }
      else if (obj.type === 'tool') { list = tools; type = 'tool'; }
      else if (obj.type === 'campaign') { list = campaigns; type = 'campaign'; }
      else continue;

      const a = {
        type,
        id,
        name: obj.name,
        aliases: ((type === 'group' ? obj.aliases : obj.x_mitre_aliases) || []).slice(0, 8),
        desc: trunc(obj.description, 200),
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
      const tech = techByStix[obj.target_ref];
      if (!tech) continue;
      const actor = actorByStix[obj.source_ref];
      if (!actor) continue;
      if (!actor.techs.includes(tech.id)) actor.techs.push(tech.id);
    }
  }

  const clean = arr => arr.map(o => { const r = { ...o }; delete r._s; return r; });

  const out = {
    meta: { generated: new Date().toISOString().split('T')[0] },
    techniques: clean(techniques),
    groups: clean(groups),
    malware: clean(malware),
    tools: clean(tools),
    campaigns: clean(campaigns),
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out));

  console.log(`Written → ${OUT}`);
  console.log(`  Techniques : ${techniques.length}`);
  console.log(`  Groups     : ${groups.length}`);
  console.log(`  Malware    : ${malware.length}`);
  console.log(`  Tools      : ${tools.length}`);
  console.log(`  Campaigns  : ${campaigns.length}`);
}

main().catch(e => { console.error(e); process.exit(1); });
