import { generateHypothesis, groupByTactic, TACTIC_META } from './hypothesis.js';

const $ = id => document.getElementById(id);

export function setDataStatus(state, text) {
  const el = $('dataStatus');
  if (!el) return;
  el.className = `data-status ${state}`;
  el.innerHTML = `<span class="dot"></span>${escapeHtml(text)}`;
}

export function showLoading(lines) {
  $('hyp-state').innerHTML = renderTerminal(lines);
}

export function appendTerminalLine(text, cls = '') {
  const wrap = document.querySelector('.hyp-terminal');
  if (!wrap) return;
  const div = document.createElement('div');
  div.className = `hyp-terminal-line${cls ? ' ' + cls : ''}`;
  div.innerHTML = `<span class="term-prompt">&gt;</span><span>${escapeHtml(text)}</span>`;
  const cursor = wrap.querySelector('.term-cursor');
  if (cursor) cursor.closest('.hyp-terminal-line')?.remove();
  wrap.appendChild(div);
  const cursorLine = document.createElement('div');
  cursorLine.className = 'hyp-terminal-line active';
  cursorLine.innerHTML = '<span class="term-prompt">&gt;</span><span class="term-cursor"></span>';
  wrap.appendChild(cursorLine);
}

export function finalizeTerminal(text) {
  const wrap = document.querySelector('.hyp-terminal');
  if (!wrap) return;
  const cursor = wrap.querySelector('.term-cursor');
  if (cursor) cursor.closest('.hyp-terminal-line')?.remove();
  const div = document.createElement('div');
  div.className = 'hyp-terminal-line done';
  div.innerHTML = `<span class="term-prompt">&gt;</span><span>${escapeHtml(text)}</span>`;
  wrap.appendChild(div);
}

export function showEmpty() {
  $('hyp-state').innerHTML = `
    <div class="hyp-empty">
      <div class="hyp-empty-title">ENTER A TECHNIQUE · GROUP · MALWARE · TOOL · CAMPAIGN</div>
      <div class="hyp-examples">
        ${['T1003','T1059','T1078','T1055','APT28','Lazarus Group','Mimikatz','Cobalt Strike','PowerShell Empire','Operation Wocao']
            .map(e => `<span class="hyp-example-chip" data-ex="${escapeAttr(e)}">${escapeHtml(e)}</span>`).join('')}
      </div>
    </div>`;

  document.querySelectorAll('.hyp-example-chip').forEach(el => {
    el.addEventListener('click', () => {
      const input = $('hyp-input');
      if (input) { input.value = el.dataset.ex; input.dispatchEvent(new Event('input')); }
      $('hyp-form')?.dispatchEvent(new Event('submit'));
    });
  });
}

export function showError(msg) {
  $('hyp-state').innerHTML = `
    <div class="hyp-error">
      <div class="hyp-error-box">&gt; ERROR: ${escapeHtml(msg)}</div>
    </div>`;
}

// ── Results rendering ──────────────────────────────────────────

export function renderResults(result) {
  if (!result || result.type === 'not-found') {
    $('hyp-state').innerHTML = `
      <div class="hyp-error">
        <div class="hyp-error-box">&gt; No results for "${escapeHtml(result?.query || '')}" — check spelling or try a different query.</div>
      </div>`;
    return;
  }

  if (result.items.length === 0 && result._total !== undefined) {
    $('hyp-state').innerHTML = `
      <div class="hyp-error">
        <div class="hyp-error-box">&gt; No techniques match the active filters — <a href="#" onclick="window.__clearFilters();return false;" style="color:var(--accent);text-decoration:none">clear filters</a> to restore all ${result._total} results.</div>
      </div>`;
    return;
  }

  const hypotheses = result.items.map(t => generateHypothesis(t));
  const total = result._total;

  if (result.type === 'technique') {
    renderTechniqueResults(hypotheses, result.query, total);
  } else {
    renderActorResults(result, hypotheses, total);
  }
}

function renderTechniqueResults(hypotheses, query, total) {
  const parent = hypotheses.find(h => !h.isSub);
  const subs   = hypotheses.filter(h => h.isSub);

  let html = `<div class="hyp-results">`;
  html += renderSummaryBar(hypotheses.length, `hypothesis${hypotheses.length !== 1 ? 'es' : ''} for "${escapeHtml(query)}"`, total);

  if (parent) html += renderCard(parent);
  if (subs.length) {
    html += `<div class="hyp-tactic-group">`;
    html += `<div class="hyp-tactic-header" onclick="this.closest('.hyp-tactic-group').classList.toggle('collapsed')">
      <div class="hyp-tactic-rule"></div>
      <span class="hyp-tactic-count">SUB-TECHNIQUES (${subs.length})</span>
      <span class="hyp-tactic-toggle">▾</span>
    </div>`;
    html += `<div class="hyp-tactic-cards">`;
    for (const h of subs) html += renderCard(h);
    html += `</div></div>`;
  }
  html += `</div>`;
  $('hyp-state').innerHTML = html;
}

function renderActorResults(result, hypotheses, total) {
  const groups  = groupByTactic(hypotheses);
  const tactics = groups.length;

  let html = `<div class="hyp-results">`;
  html += renderActorHeader(result.actor, hypotheses.length, tactics);
  html += renderSummaryBar(hypotheses.length, `technique${hypotheses.length !== 1 ? 's' : ''} · ${tactics} tactic${tactics !== 1 ? 's' : ''}`, total);

  for (const { tactic, items } of groups) {
    const meta = TACTIC_META[tactic] || { label: tactic, color: '#7d8fb3' };
    html += `<div class="hyp-tactic-group">`;
    html += `<div class="hyp-tactic-header" onclick="this.closest('.hyp-tactic-group').classList.toggle('collapsed')">
      <div class="hyp-tactic-rule"></div>
      <span class="hyp-tactic-badge" style="background:${escapeAttr(meta.color)}">${escapeHtml(meta.label)}</span>
      <span class="hyp-tactic-count">${items.length}</span>
      <span class="hyp-tactic-toggle">▾</span>
    </div>`;
    html += `<div class="hyp-tactic-cards">`;
    for (const h of items) html += renderCard(h);
    html += `</div></div>`;
  }

  html += `</div>`;
  $('hyp-state').innerHTML = html;
}

function renderSummaryBar(count, label, total) {
  const isFiltered = total !== undefined && total !== count;
  const countHtml  = isFiltered
    ? `<strong>${count}</strong> of ${total}`
    : `<strong>${count}</strong>`;
  return `<div class="hyp-summary">
    <div class="hyp-summary-left">${countHtml} ${escapeHtml(label)}</div>
  </div>`;
}

function renderActorHeader(actor, techCount, tacticCount) {
  const typeLabel = { group: 'GROUP', malware: 'MALWARE', tool: 'TOOL', campaign: 'CAMPAIGN' }[actor.type] || 'ACTOR';
  const aliases = actor.aliases.length
    ? actor.aliases.slice(0, 8).map(a => `<span class="actor-alias">${escapeHtml(a)}</span>`).join('')
    : '';

  return `<div class="hyp-actor-header">
    <span class="actor-icon ${escapeAttr(actor.type)}">${typeLabel}</span>
    <div class="actor-info">
      <div class="actor-name">${escapeHtml(actor.name)}</div>
      <div class="actor-id">${escapeHtml(actor.id)}${actor.url ? ` · <a href="${escapeAttr(actor.url)}" target="_blank" rel="noopener" style="color:var(--muted);text-decoration:none;">ATT&amp;CK ↗</a>` : ''}</div>
      ${aliases ? `<div class="actor-aliases">${aliases}</div>` : ''}
      ${actor.desc ? `<div class="actor-desc">${escapeHtml(actor.desc)}</div>` : ''}
    </div>
    <div class="actor-stats">
      <div class="actor-stat"><span class="actor-stat-val">${techCount}</span><span class="actor-stat-lbl">Techniques</span></div>
      <div class="actor-stat"><span class="actor-stat-val">${tacticCount}</span><span class="actor-stat-lbl">Tactics</span></div>
    </div>
  </div>`;
}

function renderCard(h) {
  const dsList = h.dataSources.length
    ? h.dataSources.slice(0, 8).map(ds => `<li>${escapeHtml(ds)}</li>`).join('')
    : '<li style="color:var(--muted)">No data sources listed</li>';

  const platformChips = h.platforms.length
    ? h.platforms.map(p => `<span class="hyp-platform-chip">${escapeHtml(p)}</span>`).join('')
    : '<span class="hyp-platform-chip" style="color:var(--muted)">—</span>';

  const footer = buildFooter(h);

  return `<div class="hyp-card">
    <div class="hyp-card-head">
      <span class="hyp-card-id">${escapeHtml(h.id)}</span>
      <span class="hyp-card-name">${escapeHtml(h.name)}</span>
      <span class="hyp-tactic-pill" style="background:${escapeAttr(h.tacticColor)}">${escapeHtml(h.tacticLabel)}</span>
    </div>
    <div class="hyp-card-body">
      <div>
        <div class="hyp-section-lbl">HYPOTHESIS</div>
        <div class="hyp-hypothesis-text">${escapeHtml(h.hypothesis)}</div>
      </div>
      <div class="hyp-meta-grid">
        <div>
          <div class="hyp-section-lbl">DATA SOURCES</div>
          <ul class="hyp-ds-list">${dsList}</ul>
        </div>
        <div>
          <div class="hyp-section-lbl">PLATFORMS</div>
          <div class="hyp-platform-chips">${platformChips}</div>
        </div>
      </div>
      <div>
        <div class="hyp-section-lbl">DETECTION FOCUS</div>
        <div class="hyp-detect-text">${escapeHtml(h.detection)}</div>
      </div>
    </div>
    ${footer}
  </div>`;
}

function buildFooter(h) {
  const parts = [];

  if (h.isSub && h.parentId) {
    parts.push(`<span class="hyp-parent-link">↑ Parent: <a href="#" onclick="window.__hypSearch('${escapeAttr(h.parentId)}');return false;">${escapeHtml(h.parentId)}</a></span>`);
  } else if (h.subs.length) {
    const chips = h.subs.slice(0, 12)
      .map(sid => `<span class="hyp-sub-chip" onclick="window.__hypSearch('${escapeAttr(sid)}')">${escapeHtml(sid)}</span>`)
      .join('');
    parts.push(`<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;"><span class="hyp-section-lbl" style="margin-bottom:0">SUBS</span><div class="hyp-subs-list">${chips}</div></div>`);
  }

  const link = h.url
    ? `<a href="${escapeAttr(h.url)}" target="_blank" rel="noopener" class="hyp-mitre-link">ATT&CK ↗</a>`
    : '';

  return `<div class="hyp-card-foot">
    <div style="flex:1;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">${parts.join('')}</div>
    ${link}
  </div>`;
}

// ── Autocomplete ───────────────────────────────────────────────

let _acSelected = -1;

export function renderSuggestions(suggestions) {
  const ac = $('hyp-ac');
  if (!ac) return;
  if (!suggestions.length) { ac.classList.remove('open'); return; }

  _acSelected = -1;
  const typeColors = { technique: 'var(--accent)', group: 'var(--accent2)', malware: 'var(--red)', tool: 'var(--t-exec)', campaign: 'var(--t-persist)' };

  ac.innerHTML = suggestions.map((s, i) =>
    `<div class="hyp-ac-item" data-idx="${i}" data-val="${escapeAttr(s.id)}">
      <span class="hyp-ac-id" style="color:${typeColors[s.type] || 'var(--muted)'}">${escapeHtml(s.id)}</span>
      <span class="hyp-ac-name">${escapeHtml(s.name)}</span>
      <span class="hyp-ac-type">${escapeHtml(s.type)}</span>
    </div>`
  ).join('');

  ac.classList.add('open');
}

export function hideAutocomplete() {
  const ac = $('hyp-ac');
  if (ac) { ac.classList.remove('open'); _acSelected = -1; }
}

export function moveAcSelection(dir) {
  const items = document.querySelectorAll('.hyp-ac-item');
  if (!items.length) return null;
  items.forEach(el => el.classList.remove('selected'));
  _acSelected = (_acSelected + dir + items.length) % items.length;
  const sel = items[_acSelected];
  sel.classList.add('selected');
  return sel.dataset.val;
}

export function updateDetectBadge(query) {
  const el = $('hyp-detect');
  if (!el) return;
  if (!query.trim()) { el.textContent = ''; el.classList.remove('active'); return; }

  const { detectQueryType } = window.__hyposLookup || {};
  if (!detectQueryType) return;

  const type = detectQueryType(query);
  const labels = {
    'technique-id': '⬡ Technique ID',
    'group-id':     '◈ Group ID',
    'software-id':  '◉ Software ID',
    'campaign-id':  '◆ Campaign ID',
    'name':         '◎ Name search',
  };
  el.textContent = labels[type] || '';
  el.classList.add('active');
}

// ── Helpers ────────────────────────────────────────────────────

function renderTerminal(lines) {
  const rows = lines.map(l =>
    `<div class="hyp-terminal-line"><span class="term-prompt">&gt;</span><span>${escapeHtml(l)}</span></div>`
  ).join('');
  return `<div class="hyp-loading"><div class="hyp-terminal">
    ${rows}
    <div class="hyp-terminal-line active"><span class="term-prompt">&gt;</span><span class="term-cursor"></span></div>
  </div></div>`;
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escapeAttr(s) {
  return String(s ?? '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
