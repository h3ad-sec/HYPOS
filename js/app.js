import { loadData, getData } from './data-loader.js';
import { loadHypDB, getCurated } from './hyp-db.js';
import { lookup, lookupAll, suggest, detectQueryType } from './lookup.js';
import { TACTIC_META, generateHypothesis, groupByTactic } from './hypothesis.js';
import {
  setDataStatus, showLoading, appendTerminalLine, finalizeTerminal,
  showEmpty, showError, renderResults, renderSuggestions, hideAutocomplete,
  moveAcSelection, updateDetectBadge,
} from './ui.js';

window.__hyposLookup = { detectQueryType };
window.__hypSearch   = (q) => { runSearch(q); };

let _dataReady    = false;
let _pendingQuery = null;
let _lastResult   = null;

const _activePlatforms  = new Set();
const _activeSources    = new Set();
const _activeActors     = new Set();
const _activeMits       = new Set();
const _activeComponents = new Set();
const _mySources        = new Set();
window.__coverageSources = _mySources;

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

window.__exportNavigator = function() {
  if (!_lastResult?.items?.length) return;
  const date  = new Date().toISOString().split('T')[0];
  const actor = _lastResult.actor;
  const techniques = _lastResult.items.map(t => {
    const tactic    = t.tactics?.[0] || '';
    const meta      = TACTIC_META[tactic] || { color: '#3b82f6' };
    const isCurated = !!getCurated(t.id);
    return {
      techniqueID:       t.id,
      tactic:            tactic || undefined,
      color:             isCurated ? '#00ff9f' : meta.color,
      score:             100,
      comment:           isCurated ? 'Curated hypothesis in HYPOS' : 'Hunt hypothesis in HYPOS',
      enabled:           true,
      metadata:          [],
      links:             [{ label: 'HYPOS', url: `https://h3ad-sec.github.io/HYPOS/?q=${t.id}` }],
      showSubtechniques: (t.subs || []).length > 0,
    };
  });
  const layer = {
    name:        actor ? `${actor.name} — HYPOS` : 'HYPOS Hunt Layer',
    versions:    { attack: '14', navigator: '4.9', layer: '4.5' },
    domain:      'enterprise-attack',
    description: `Exported from HYPOS by H3AD-SEC · ${date}${actor ? ` · ${actor.name} (${actor.id})` : ''} · ${_lastResult.items.length} techniques`,
    filters:     { platforms: [] },
    sorting:     3,
    layout:      { layout: 'side', aggregateFunction: 'average', showID: true, showName: true, showAggregateScores: false, countUnscored: false },
    hideDisabled: false,
    techniques,
    gradient:    { colors: ['#ff6666', '#ffe766', '#8ec843'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'Curated Hypothesis', color: '#00ff9f' },
      { label: 'Hunt Technique',     color: '#3b82f6' },
    ],
    metadata: [], links: [],
    showTacticRowBackground: false, tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: false, selectSubtechniquesWithParent: false,
  };
  download(
    actor ? `hypos-${actor.id}-navigator-${date}.json` : `hypos-navigator-${date}.json`,
    JSON.stringify(layer, null, 2),
    'application/json'
  );
};

window.__exportBulk = function(format) {
  if (!_lastResult?.items?.length) return;
  const items = _lastResult.items;
  const actor = _lastResult.actor;
  const date  = new Date().toISOString().split('T')[0];
  const slug  = actor ? actor.id : 'export';

  if (format === 'json') {
    const out = {
      exported: date,
      source:   'HYPOS by H3AD-SEC · https://h3ad-sec.github.io/HYPOS/',
      actor:    actor ? { id: actor.id, name: actor.name, type: actor.type } : null,
      techniques: items.map(t => {
        const h = generateHypothesis(t);
        return {
          id: t.id, name: t.name, tactic: h.tactic, tacticLabel: h.tacticLabel,
          platforms: h.platforms, hypothesis: h.hypothesis, dataSources: h.dataSources,
          detection: h.detection, mits: h.mits, url: h.url,
          curated: getCurated(t.id) || null,
        };
      }),
    };
    download(`hypos-${slug}-${date}.json`, JSON.stringify(out, null, 2), 'application/json');
    return;
  }

  const title = actor ? `${actor.name} (${actor.id}) — Hunt Package` : 'Hunt Hypothesis Package';
  const lines = [
    `# ${title}`,
    `> [HYPOS](https://h3ad-sec.github.io/HYPOS/) by H3AD-SEC · ${date} · ${items.length} techniques`,
    '',
  ];
  for (const { tactic, items: hyps } of groupByTactic(items.map(t => generateHypothesis(t)))) {
    const meta = TACTIC_META[tactic] || { label: tactic };
    lines.push(`## ${meta.label.toUpperCase()}`, '');
    for (const h of hyps) {
      lines.push(`### ${h.id} · ${h.name}`);
      lines.push(`**Platforms:** ${h.platforms.join(', ') || '—'} · **ATT&CK:** ${h.url || '—'}`, '');
      lines.push('**Hypothesis:**', h.hypothesis, '');
      if (h.dataSources.length) {
        lines.push('**Data Sources:**');
        h.dataSources.forEach(ds => lines.push(`- ${ds}`));
        lines.push('');
      }
      lines.push('**Detection:**', h.detection || '—', '');
      if (h.mits?.length) {
        lines.push('**Mitigations:**');
        h.mits.forEach(m => lines.push(`- [${m.id}](https://attack.mitre.org/mitigations/${m.id}/) — ${m.name}`));
        lines.push('');
      }
      const curated = getCurated(h.id);
      if (curated?.length) {
        lines.push('**Curated Hypotheses:**');
        for (const c of curated) {
          lines.push(`\n#### ${c.id} · ${c.title} *(${(c.severity || 'high').toUpperCase()})*`);
          lines.push(c.statement, '');
          if (c.pivots?.length) {
            c.pivots.forEach(p => lines.push(`- **${p.label}:** ${p.detail}`));
            lines.push('');
          }
          if (c.detection_logic?.query_hint) {
            lines.push('```', c.detection_logic.query_hint, '```', '');
            if (c.detection_logic.sigma_url) lines.push(`Sigma: ${c.detection_logic.sigma_url}`, '');
          }
        }
      }
      lines.push('---', '');
    }
  }
  download(`hypos-${slug}-${date}.md`, lines.join('\n'), 'text/markdown');
};

window.__toggleCovSource = function(src) {
  _mySources.has(src) ? _mySources.delete(src) : _mySources.add(src);
  document.querySelectorAll('.hyp-cov-src-chip').forEach(el =>
    el.classList.toggle('active', _mySources.has(el.dataset.src)));
  document.getElementById('hyp-cov-toggle')?.classList.toggle('active', _mySources.size > 0);
  if (_lastResult) renderResults(applyFilters(_lastResult));
};

window.__clearCoverage = function() {
  _mySources.clear();
  document.querySelectorAll('.hyp-cov-src-chip').forEach(el => el.classList.remove('active'));
  document.getElementById('hyp-cov-toggle')?.classList.remove('active');
  if (_lastResult) renderResults(applyFilters(_lastResult));
};

window.__toggleCoveragePanel = function() {
  document.getElementById('hyp-coverage-panel')?.classList.toggle('open');
};

function applyFilters(result) {
  if (!result || result.type === 'not-found') return result;
  if (!_activePlatforms.size && !_activeSources.size && !_activeActors.size &&
      !_activeMits.size && !_activeComponents.size) return result;

  let actorTechSet = null;
  if (_activeActors.size) {
    const d = getData();
    actorTechSet = new Set();
    for (const a of [...d.groups, ...d.malware, ...d.tools, ...d.campaigns]) {
      if (_activeActors.has(a.id)) for (const tid of a.techs) actorTechSet.add(tid);
    }
  }

  const items = result.items.filter(t => {
    if (_activePlatforms.size  && !t.platforms.some(p => _activePlatforms.has(p))) return false;
    if (_activeSources.size    && !t.ds.some(ds => _activeSources.has(ds.split(':')[0].trim()))) return false;
    if (actorTechSet           && !actorTechSet.has(t.id)) return false;
    if (_activeMits.size       && !(t.mits || []).some(m => _activeMits.has(m.id))) return false;
    if (_activeComponents.size && !t.ds.some(ds => {
      const c = ds.split(':')[1]?.trim();
      return c && _activeComponents.has(c);
    })) return false;
    return true;
  });
  return { ...result, items, _total: result.items.length };
}

function syncFilterUI() {
  document.querySelectorAll('.hyp-fchip[data-plat]').forEach(el =>
    el.classList.toggle('active', _activePlatforms.has(el.dataset.plat)));
  document.querySelectorAll('.hyp-fchip[data-src]').forEach(el =>
    el.classList.toggle('active', _activeSources.has(el.dataset.src)));
  document.querySelectorAll('.hyp-fchip[data-actor]').forEach(el =>
    el.classList.toggle('active', _activeActors.has(el.dataset.actor)));
  document.querySelectorAll('.hyp-fchip[data-mit]').forEach(el =>
    el.classList.toggle('active', _activeMits.has(el.dataset.mit)));
  document.querySelectorAll('.hyp-fchip[data-comp]').forEach(el =>
    el.classList.toggle('active', _activeComponents.has(el.dataset.comp)));
  document.querySelectorAll('.hyp-fdropdown-item[data-actor]').forEach(el => {
    const active = _activeActors.has(el.dataset.actor);
    el.classList.toggle('active', active);
    const check = el.querySelector('.hyp-fdropdown-check');
    if (check) check.textContent = active ? '✓' : '';
  });
  document.querySelectorAll('.hyp-fdropdown-item[data-src]').forEach(el => {
    const active = _activeSources.has(el.dataset.src);
    el.classList.toggle('active', active);
    const check = el.querySelector('.hyp-fdropdown-check');
    if (check) check.textContent = active ? '✓' : '';
  });
  document.querySelectorAll('.hyp-fdropdown-item[data-mit]').forEach(el => {
    const active = _activeMits.has(el.dataset.mit);
    el.classList.toggle('active', active);
    const check = el.querySelector('.hyp-fdropdown-check');
    if (check) check.textContent = active ? '✓' : '';
  });
  document.querySelectorAll('.hyp-fdropdown-item[data-comp]').forEach(el => {
    const active = _activeComponents.has(el.dataset.comp);
    el.classList.toggle('active', active);
    const check = el.querySelector('.hyp-fdropdown-check');
    if (check) check.textContent = active ? '✓' : '';
  });
  const anyActive = _activePlatforms.size > 0 || _activeSources.size > 0 || _activeActors.size > 0 ||
    _activeMits.size > 0 || _activeComponents.size > 0;
  document.getElementById('hyp-filter-clear')?.classList.toggle('visible', anyActive);
}

function rerender() {
  if (_lastResult) renderResults(applyFilters(_lastResult));
}

window.__togglePlatform = p => {
  _activePlatforms.has(p) ? _activePlatforms.delete(p) : _activePlatforms.add(p);
  syncFilterUI();
  rerender();
};

window.__toggleSource = s => {
  _activeSources.has(s) ? _activeSources.delete(s) : _activeSources.add(s);
  syncFilterUI();
  rerender();
};

window.__toggleActor = id => {
  _activeActors.has(id) ? _activeActors.delete(id) : _activeActors.add(id);
  syncFilterUI();
  rerender();
};

window.__toggleMit = id => {
  _activeMits.has(id) ? _activeMits.delete(id) : _activeMits.add(id);
  syncFilterUI();
  rerender();
};

window.__toggleComponent = c => {
  _activeComponents.has(c) ? _activeComponents.delete(c) : _activeComponents.add(c);
  syncFilterUI();
  rerender();
};

window.__clearFilters = () => {
  _activePlatforms.clear();
  _activeSources.clear();
  _activeActors.clear();
  _activeMits.clear();
  _activeComponents.clear();
  syncFilterUI();
  rerender();
};

function attachSourceDropdown(chipsEl, allSources) {
  const row = chipsEl.closest('.hyp-filter-row');
  if (!row) return;

  const wrap    = document.createElement('div');
  wrap.className = 'hyp-fdropdown-wrap';

  const trigger = document.createElement('span');
  trigger.className   = 'hyp-fdropdown-trigger';
  trigger.textContent = `▾ ALL (${allSources.length})`;

  const panel   = document.createElement('div');
  panel.className = 'hyp-fdropdown';

  const searchEl = document.createElement('input');
  searchEl.type        = 'text';
  searchEl.className   = 'hyp-fdropdown-search';
  searchEl.placeholder = 'Search sources…';

  const listEl = document.createElement('div');
  listEl.className = 'hyp-fdropdown-list';

  function renderItems(items) {
    listEl.innerHTML = '';
    for (const s of items) {
      const item  = document.createElement('div');
      item.className  = `hyp-fdropdown-item${_activeSources.has(s.name) ? ' active' : ''}`;
      item.dataset.src = s.name;

      const check = document.createElement('span');
      check.className   = 'hyp-fdropdown-check';
      check.textContent = _activeSources.has(s.name) ? '✓' : '';

      const name = document.createElement('span');
      name.textContent = s.name;

      const cnt = document.createElement('span');
      cnt.className   = 'hyp-fdropdown-count';
      cnt.textContent = s.count;

      item.append(check, name, cnt);
      item.addEventListener('click', () => {
        window.__toggleSource(s.name);
        const active = _activeSources.has(s.name);
        item.classList.toggle('active', active);
        check.textContent = active ? '✓' : '';
      });
      listEl.appendChild(item);
    }
  }

  searchEl.addEventListener('input', () => {
    const q = searchEl.value.toLowerCase();
    renderItems(q ? allSources.filter(s => s.name.toLowerCase().includes(q)) : allSources);
  });

  trigger.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = panel.classList.toggle('open');
    trigger.classList.toggle('open', isOpen);
    if (isOpen) { renderItems(allSources); searchEl.value = ''; setTimeout(() => searchEl.focus(), 0); }
  });

  document.addEventListener('click', e => {
    if (!wrap.contains(e.target)) {
      panel.classList.remove('open');
      trigger.classList.remove('open');
    }
  });

  panel.append(searchEl, listEl);
  wrap.append(trigger, panel);
  row.appendChild(wrap);
}

function attachDropdown(chipsEl, allItems) {
  const row = chipsEl.closest('.hyp-filter-row');
  if (!row) return;

  const wrap    = document.createElement('div');
  wrap.className = 'hyp-fdropdown-wrap';

  const trigger = document.createElement('span');
  trigger.className   = 'hyp-fdropdown-trigger';
  trigger.textContent = `▾ ALL (${allItems.length})`;

  const panel   = document.createElement('div');
  panel.className = 'hyp-fdropdown';

  const searchEl = document.createElement('input');
  searchEl.type        = 'text';
  searchEl.className   = 'hyp-fdropdown-search';
  searchEl.placeholder = 'Search…';

  const listEl = document.createElement('div');
  listEl.className = 'hyp-fdropdown-list';

  function renderItems(items) {
    listEl.innerHTML = '';
    for (const a of items) {
      const item  = document.createElement('div');
      item.className  = `hyp-fdropdown-item${_activeActors.has(a.id) ? ' active' : ''}`;
      item.dataset.actor = a.id;

      const check = document.createElement('span');
      check.className   = 'hyp-fdropdown-check';
      check.textContent = _activeActors.has(a.id) ? '✓' : '';

      const name = document.createElement('span');
      name.textContent = a.name;

      const cnt = document.createElement('span');
      cnt.className   = 'hyp-fdropdown-count';
      cnt.textContent = a.techs.length;

      item.append(check, name, cnt);
      item.addEventListener('click', () => {
        window.__toggleActor(a.id);
        const active = _activeActors.has(a.id);
        item.classList.toggle('active', active);
        check.textContent = active ? '✓' : '';
      });
      listEl.appendChild(item);
    }
  }

  searchEl.addEventListener('input', () => {
    const q = searchEl.value.toLowerCase();
    renderItems(q ? allItems.filter(a => a.name.toLowerCase().includes(q)) : allItems);
  });

  trigger.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = panel.classList.toggle('open');
    trigger.classList.toggle('open', isOpen);
    if (isOpen) { renderItems(allItems); searchEl.value = ''; setTimeout(() => searchEl.focus(), 0); }
  });

  document.addEventListener('click', e => {
    if (!wrap.contains(e.target)) {
      panel.classList.remove('open');
      trigger.classList.remove('open');
    }
  });

  panel.append(searchEl, listEl);
  wrap.append(trigger, panel);
  row.appendChild(wrap);
}

function attachMitDropdown(chipsEl, allMits) {
  const row = chipsEl.closest('.hyp-filter-row');
  if (!row) return;

  const wrap    = document.createElement('div');
  wrap.className = 'hyp-fdropdown-wrap';

  const trigger = document.createElement('span');
  trigger.className   = 'hyp-fdropdown-trigger';
  trigger.textContent = `▾ ALL (${allMits.length})`;

  const panel   = document.createElement('div');
  panel.className = 'hyp-fdropdown';

  const searchEl = document.createElement('input');
  searchEl.type        = 'text';
  searchEl.className   = 'hyp-fdropdown-search';
  searchEl.placeholder = 'Search mitigations…';

  const listEl = document.createElement('div');
  listEl.className = 'hyp-fdropdown-list';

  function renderItems(items) {
    listEl.innerHTML = '';
    for (const m of items) {
      const item  = document.createElement('div');
      item.className  = `hyp-fdropdown-item${_activeMits.has(m.id) ? ' active' : ''}`;
      item.dataset.mit = m.id;

      const check = document.createElement('span');
      check.className   = 'hyp-fdropdown-check';
      check.textContent = _activeMits.has(m.id) ? '✓' : '';

      const name = document.createElement('span');
      name.textContent = `${m.id} · ${m.name}`;

      const cnt = document.createElement('span');
      cnt.className   = 'hyp-fdropdown-count';
      cnt.textContent = m.count;

      item.append(check, name, cnt);
      item.addEventListener('click', () => {
        window.__toggleMit(m.id);
        const active = _activeMits.has(m.id);
        item.classList.toggle('active', active);
        check.textContent = active ? '✓' : '';
      });
      listEl.appendChild(item);
    }
  }

  searchEl.addEventListener('input', () => {
    const q = searchEl.value.toLowerCase();
    renderItems(q ? allMits.filter(m => m.id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q)) : allMits);
  });

  trigger.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = panel.classList.toggle('open');
    trigger.classList.toggle('open', isOpen);
    if (isOpen) { renderItems(allMits); searchEl.value = ''; setTimeout(() => searchEl.focus(), 0); }
  });

  document.addEventListener('click', e => {
    if (!wrap.contains(e.target)) {
      panel.classList.remove('open');
      trigger.classList.remove('open');
    }
  });

  panel.append(searchEl, listEl);
  wrap.append(trigger, panel);
  row.appendChild(wrap);
}

function attachCompDropdown(chipsEl, allComps) {
  const row = chipsEl.closest('.hyp-filter-row');
  if (!row) return;

  const wrap    = document.createElement('div');
  wrap.className = 'hyp-fdropdown-wrap';

  const trigger = document.createElement('span');
  trigger.className   = 'hyp-fdropdown-trigger';
  trigger.textContent = `▾ ALL (${allComps.length})`;

  const panel   = document.createElement('div');
  panel.className = 'hyp-fdropdown';

  const searchEl = document.createElement('input');
  searchEl.type        = 'text';
  searchEl.className   = 'hyp-fdropdown-search';
  searchEl.placeholder = 'Search components…';

  const listEl = document.createElement('div');
  listEl.className = 'hyp-fdropdown-list';

  function renderItems(items) {
    listEl.innerHTML = '';
    for (const c of items) {
      const item  = document.createElement('div');
      item.className  = `hyp-fdropdown-item${_activeComponents.has(c.name) ? ' active' : ''}`;
      item.dataset.comp = c.name;

      const check = document.createElement('span');
      check.className   = 'hyp-fdropdown-check';
      check.textContent = _activeComponents.has(c.name) ? '✓' : '';

      const name = document.createElement('span');
      name.textContent = c.name;

      const cnt = document.createElement('span');
      cnt.className   = 'hyp-fdropdown-count';
      cnt.textContent = c.count;

      item.append(check, name, cnt);
      item.addEventListener('click', () => {
        window.__toggleComponent(c.name);
        const active = _activeComponents.has(c.name);
        item.classList.toggle('active', active);
        check.textContent = active ? '✓' : '';
      });
      listEl.appendChild(item);
    }
  }

  searchEl.addEventListener('input', () => {
    const q = searchEl.value.toLowerCase();
    renderItems(q ? allComps.filter(c => c.name.toLowerCase().includes(q)) : allComps);
  });

  trigger.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = panel.classList.toggle('open');
    trigger.classList.toggle('open', isOpen);
    if (isOpen) { renderItems(allComps); searchEl.value = ''; setTimeout(() => searchEl.focus(), 0); }
  });

  document.addEventListener('click', e => {
    if (!wrap.contains(e.target)) {
      panel.classList.remove('open');
      trigger.classList.remove('open');
    }
  });

  panel.append(searchEl, listEl);
  wrap.append(trigger, panel);
  row.appendChild(wrap);
}

function initFilters(data) {
  const PLATFORM_ORDER = [
    'Windows', 'Linux', 'macOS', 'Network', 'Containers',
    'IaaS', 'Azure AD', 'Office 365', 'SaaS', 'Google Workspace', 'PRE',
  ];
  const platSet = new Set();
  for (const t of data.techniques) t.platforms.forEach(p => platSet.add(p));
  const platforms = PLATFORM_ORDER.filter(p => platSet.has(p));

  const platEl = document.getElementById('plat-chips');
  if (platEl) {
    platEl.innerHTML = platforms.map(p =>
      `<span class="hyp-fchip" data-plat="${p}" onclick="window.__togglePlatform('${p}')">${p}</span>`
    ).join('');
  }

  const srcCount = {};
  for (const t of data.techniques) {
    for (const ds of t.ds) {
      const src = ds.split(':')[0].trim();
      srcCount[src] = (srcCount[src] || 0) + 1;
    }
  }
  const allSources = Object.entries(srcCount)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  const srcEl = document.getElementById('src-chips');
  if (srcEl) {
    if (allSources.length) {
      srcEl.innerHTML = allSources.slice(0, 14).map(s =>
        `<span class="hyp-fchip" data-src="${s.name}" onclick="window.__toggleSource('${s.name}')">${s.name}</span>`
      ).join('');
      attachSourceDropdown(srcEl, allSources);
    } else {
      srcEl.closest('.hyp-filter-row')?.remove();
    }
  }

  const TOP = 14;
  const sortedGroups    = [...data.groups]   .sort((a, b) => b.techs.length - a.techs.length);
  const sortedMalware   = [...data.malware]  .sort((a, b) => b.techs.length - a.techs.length);
  const sortedTools     = [...data.tools]    .sort((a, b) => b.techs.length - a.techs.length);
  const sortedCampaigns = [...data.campaigns].sort((a, b) => b.techs.length - a.techs.length);

  const makeActorChip = a =>
    `<span class="hyp-fchip" data-actor="${a.id}" onclick="window.__toggleActor('${a.id}')">${a.name}</span>`;

  const initActorRow = (elId, sorted) => {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!sorted.length) { el.closest('.hyp-filter-row')?.remove(); return; }
    attachDropdown(el, sorted);
  };

  initActorRow('group-chips',    sortedGroups);
  initActorRow('malware-chips',  sortedMalware);
  initActorRow('tool-chips',     sortedTools);
  initActorRow('campaign-chips', sortedCampaigns);

  const mitCount = {};
  for (const t of data.techniques) {
    for (const m of (t.mits || [])) {
      if (!mitCount[m.id]) mitCount[m.id] = { id: m.id, name: m.name, count: 0 };
      mitCount[m.id].count++;
    }
  }
  const allMits = Object.values(mitCount).sort((a, b) => b.count - a.count);
  const mitEl   = document.getElementById('mit-chips');
  if (mitEl) {
    if (allMits.length) {
      attachMitDropdown(mitEl, allMits);
    } else {
      mitEl.closest('.hyp-filter-row')?.remove();
    }
  }

  const compCount = {};
  for (const t of data.techniques) {
    for (const ds of t.ds) {
      const c = ds.split(':')[1]?.trim();
      if (c) compCount[c] = (compCount[c] || 0) + 1;
    }
  }
  const allComps = Object.entries(compCount).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));
  const compEl   = document.getElementById('comp-chips');
  if (compEl) {
    if (allComps.length) {
      compEl.innerHTML = allComps.slice(0, TOP).map(c =>
        `<span class="hyp-fchip" data-comp="${c.name}" onclick="window.__toggleComponent('${c.name}')">${c.name}</span>`
      ).join('');
      attachCompDropdown(compEl, allComps);
    } else {
      compEl.closest('.hyp-filter-row')?.remove();
    }
  }

  const srcFreq = new Map();
  for (const t of data.techniques) {
    for (const ds of t.ds) {
      const src = ds.split(':')[0].trim();
      srcFreq.set(src, (srcFreq.get(src) || 0) + 1);
    }
  }
  const covSources = [...srcFreq.entries()].sort((a, b) => b[1] - a[1]).map(([s]) => s);
  const covEl = document.getElementById('coverage-sources');
  if (covEl) {
    covEl.innerHTML = covSources.map(s =>
      `<span class="hyp-cov-src-chip" data-src="${s}" onclick="window.__toggleCovSource('${s}')">${s}</span>`
    ).join('');
  }

  document.getElementById('hyp-filter-bar')?.classList.add('ready');
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNav();
  initSearch();
  loadHypDB();
  loadATTACK();
});

async function loadATTACK() {
  showLoading(['Initializing HYPOS…']);
  setDataStatus('loading', 'Loading ATT&CK…');

  try {
    await loadData((state, msg) => {
      if (state === 'loading') {
        appendTerminalLine(msg);
      } else {
        finalizeTerminal(msg);
        setDataStatus('ready', msg);
        _dataReady = true;
        initFilters(getData());
        if (_pendingQuery) {
          runSearch(_pendingQuery);
          _pendingQuery = null;
        } else {
          const all = lookupAll();
          if (all) {
            const d = getData();
            all._stats = {
              techniques:    d.techniques.filter(t => !t.sub).length,
              subTechniques: d.techniques.filter(t => t.sub).length,
              groups:        d.groups.length,
              campaigns:     d.campaigns.length,
              software:      (d.malware || []).length + (d.tools || []).length,
            };
            _lastResult = all;
            renderResults(applyFilters(all));
          } else showEmpty();
        }
      }
    });
  } catch (err) {
    const msg = err.message || 'Failed to load ATT&CK data';
    setDataStatus('error', 'Load failed');
    showError(`${msg}. Check your internet connection or try refreshing.`);
  }
}

function initSearch() {
  const form  = document.getElementById('hyp-form');
  const input = document.getElementById('hyp-input');
  const ac    = document.getElementById('hyp-ac');

  if (!form || !input) return;

  form.addEventListener('submit', e => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    hideAutocomplete();
    if (!_dataReady) { _pendingQuery = q; return; }
    runSearch(q);
  });

  input.addEventListener('input', () => {
    const q = input.value.trim();
    updateDetectBadge(q);
    if (!_dataReady || q.length < 2) { hideAutocomplete(); return; }
    const suggestions = suggest(q);
    renderSuggestions(suggestions);
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const val = moveAcSelection(1);
      if (val) input.value = val;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const val = moveAcSelection(-1);
      if (val) input.value = val;
    } else if (e.key === 'Escape') {
      hideAutocomplete();
    }
  });

  document.addEventListener('click', e => {
    if (!e.target.closest('#hyp-search-box')) hideAutocomplete();
  });

  document.addEventListener('keydown', e => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });

  ac?.addEventListener('click', e => {
    const item = e.target.closest('.hyp-ac-item');
    if (!item) return;
    input.value = item.dataset.val;
    hideAutocomplete();
    form.dispatchEvent(new Event('submit'));
  });

  const params = new URLSearchParams(window.location.search);
  const qParam = params.get('q');
  if (qParam) {
    input.value = qParam;
    if (_dataReady) runSearch(qParam);
    else _pendingQuery = qParam;
  }
}

function runSearch(query) {
  const q = query.trim();
  if (!q) return;
  const url = new URL(window.location);
  url.searchParams.set('q', q);
  window.history.replaceState(null, '', url);

  const result = lookup(q);
  _lastResult = result;
  renderResults(applyFilters(result));
  window.scrollTo({ top: document.getElementById('hyp-state')?.offsetTop - 160, behavior: 'smooth' });
}

function initTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  applyTheme(saved);
}

function applyTheme(theme) {
  document.body.classList.toggle('light', theme === 'light');
  document.body.classList.toggle('dark',  theme !== 'light');
  const logo = document.getElementById('navLogo');
  if (logo) logo.src = theme === 'light'
    ? 'https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-light.png'
    : 'https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-dark.png';
}

window.toggleTheme = function () {
  const isLight = document.body.classList.contains('light');
  const next = isLight ? 'dark' : 'light';
  localStorage.setItem('theme', next);
  applyTheme(next);
};

function initNav() {
  window.toggleDrawer = () => {
    document.getElementById('navDrawer')?.classList.toggle('open');
  };
  window.closeDrawer = () => {
    document.getElementById('navDrawer')?.classList.remove('open');
  };
}


