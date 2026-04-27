import { generateHypothesis, groupByTactic, TACTIC_META } from './hypothesis.js';
import { getCurated, getRelated, getCuratedStats } from './hyp-db.js';
import { getData, getUsedBy } from './data-loader.js';

let _techNameCache = null;
function getTechName(id) {
  if (!_techNameCache) {
    const data = getData();
    if (data) _techNameCache = Object.fromEntries(data.techniques.map(t => [t.id, t.name]));
  }
  return _techNameCache?.[id] || id;
}

window.__exportHyp = function(techId, format, btn) {
  const curated = getCurated(techId);
  if (!curated) return;
  let text;
  if (format === 'json') {
    text = JSON.stringify({ technique: techId, hypotheses: curated }, null, 2);
  } else {
    const lines = [`# ${techId} — Curated Hunt Hypotheses`, `> Source: HYPOS by H3AD-SEC`, ''];
    for (const c of curated) {
      lines.push(`## ${c.id} · ${c.title}`, `**Severity:** ${(c.severity || 'high').toUpperCase()}`, '');
      lines.push(`**Statement:**\n${c.statement}`, '');
      if (c.pivots?.length) {
        lines.push('**Hunt Pivots:**');
        for (const p of c.pivots) lines.push(`- **${p.label}:** ${p.detail}`);
        lines.push('');
      }
      if (c.detection_logic?.query_hint) {
        lines.push('**Detection Logic:**', '```', c.detection_logic.query_hint, '```', '');
        if (c.detection_logic.sigma_url) lines.push(`Sigma: ${c.detection_logic.sigma_url}`, '');
      }
      if (c.mitigations?.length) {
        lines.push('**Mitigations:**');
        for (const m of c.mitigations) lines.push(`- ${m.id} ${m.name}: ${m.detail}`);
        lines.push('');
      }
      if (c.fpr) lines.push(`**FPR:** ${c.fpr}`, '');
      lines.push('---', '');
    }
    text = lines.join('\n');
  }
  navigator.clipboard.writeText(text).catch(() => {});
  const orig = btn.textContent;
  btn.textContent = '✓ Copied';
  setTimeout(() => { btn.textContent = orig; }, 1600);
};

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
    renderTechniqueResults(hypotheses, result.query, total, result._tag);
  } else if (result.type === 'all') {
    renderAllResults(result, hypotheses, total);
  } else {
    renderActorResults(result, hypotheses, total);
  }
}

function renderTechniqueResults(hypotheses, query, total, tag) {
  const parent = hypotheses.find(h => !h.isSub);
  const subs   = hypotheses.filter(h => h.isSub);

  let html = `<div class="hyp-results">`;
  if (tag) {
    const icon = tag.type === 'tool' ? '⬡' : '◈';
    html += `<div class="hyp-tag-banner">
      <span class="hyp-tag-banner-icon">${icon}</span>
      <span class="hyp-tag-banner-type">${escapeHtml(tag.type.toUpperCase())}</span>
      <span class="hyp-tag-banner-name">${escapeHtml(tag.name)}</span>
      <span class="hyp-tag-banner-count">${hypotheses.length} technique${hypotheses.length !== 1 ? 's' : ''} matched</span>
    </div>`;
  }
  html += renderSummaryBar(hypotheses.length, `hypothesis${hypotheses.length !== 1 ? 'es' : ''} for "${escapeHtml(query)}"`, total);

  if (parent) html += `<div class="hyp-tactic-cards">${renderCard(parent)}</div>`;
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

function renderAllResults(result, hypotheses, total) {
  const groups = groupByTactic(hypotheses);
  const curatedStats    = getCuratedStats();
  const curatedTechCount = curatedStats.techniques;
  const curatedHypCount  = curatedStats.hypotheses;
  const s = result._stats || {};

  let html = `<div class="hyp-matrix-wrap">`;

  html += `<div class="hyp-matrix-bar">
    <div class="hyp-matrix-stats">
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${s.techniques || hypotheses.length}</span><span class="hyp-matrix-stat-lbl">Techniques</span></span>
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${s.subTechniques || '—'}</span><span class="hyp-matrix-stat-lbl">Sub-techniques</span></span>
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${groups.length}</span><span class="hyp-matrix-stat-lbl">Tactics</span></span>
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${s.groups || '—'}</span><span class="hyp-matrix-stat-lbl">Groups</span></span>
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${s.campaigns || '—'}</span><span class="hyp-matrix-stat-lbl">Campaigns</span></span>
      <span class="hyp-matrix-stat-item"><span class="hyp-matrix-stat-val">${s.software || '—'}</span><span class="hyp-matrix-stat-lbl">Software</span></span>
      <span class="hyp-matrix-stat-item accent"><span class="hyp-matrix-stat-val">${curatedTechCount}</span><span class="hyp-matrix-stat-lbl">Curated Techniques</span></span>
      <span class="hyp-matrix-stat-item accent"><span class="hyp-matrix-stat-val">${curatedHypCount}</span><span class="hyp-matrix-stat-lbl">Curated Hypotheses</span></span>
    </div>
    <div class="hyp-matrix-legend">
      <span class="hyp-matrix-legend-item"><span class="hyp-matrix-legend-dot curated"></span>Curated hypothesis</span>
      <span class="hyp-matrix-legend-item">Click any technique to view hypotheses</span>
    </div>
  </div>`;

  html += `<div class="hyp-matrix-scroll"><div class="hyp-matrix-grid">`;

  for (const { tactic, items } of groups) {
    const meta = TACTIC_META[tactic] || { label: tactic, color: '#7d8fb3' };
    html += `<div class="hyp-matrix-col">`;
    html += `<div class="hyp-matrix-tactic-hdr" style="border-top:2px solid ${escapeAttr(meta.color)};background:${escapeAttr(meta.color)}18">
      <span class="hyp-matrix-tactic-name">${escapeHtml(meta.label)}</span>
      <span class="hyp-matrix-tactic-cnt">${items.length} techniques</span>
    </div>`;
    for (const h of items) {
      const hasCurated = !!getCurated(h.id);
      const subsCount  = h.subs.length;
      const primaryDs  = h.dataSources.length
        ? h.dataSources[0].split(':')[0].trim()
        : '';
      html += `<div class="hyp-matrix-cell${hasCurated ? ' curated' : ''}" onclick="window.__hypSearch('${escapeAttr(h.id)}')">
        <div class="hyp-matrix-cell-name">${escapeHtml(h.name)}</div>
        <div class="hyp-matrix-cell-meta">
          <span class="hyp-matrix-cell-id">${escapeHtml(h.id)}</span>
          ${subsCount ? `<span class="hyp-matrix-cell-subs">+${subsCount}</span>` : ''}
          ${primaryDs ? `<span class="hyp-matrix-cell-ds" title="${escapeAttr(h.dataSources.join(', '))}">${escapeHtml(primaryDs)}</span>` : ''}
          ${hasCurated ? `<span class="hyp-matrix-cell-star">★</span>` : ''}
        </div>
      </div>`;
    }
    html += `</div>`;
  }

  html += `</div></div></div>`;
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
  const curated = getCurated(h.id);
  if (curated) return renderCuratedCard(h, curated);

  const dsList = h.dataSources.length
    ? h.dataSources.slice(0, 8).map(ds => `<li>${escapeHtml(ds)}</li>`).join('')
    : '';

  const platformChips = h.platforms.length
    ? h.platforms.map(p => `<span class="hyp-platform-chip">${escapeHtml(p)}</span>`).join('')
    : '<span class="hyp-platform-chip" style="color:var(--muted)">—</span>';

  const footer           = buildFooter(h);
  const dsComponentChips = buildDsComponentChips(h.dataSources, h.analytics);
  const analyticsHtml    = buildAnalyticsSection(h.dataSources, h.analytics);

  const usedBy = getUsedBy(h.id);
  const CAP = 12;
  const groupChips = usedBy.groups.slice(0, CAP).map(a =>
    `<span class="hyp-actor-chip" onclick="window.__hypSearch('${escapeAttr(a.name)}')">${escapeHtml(a.name)}</span>`
  ).join('') + (usedBy.groups.length > CAP ? `<span class="hyp-actor-chip" style="opacity:.55">+${usedBy.groups.length - CAP} more</span>` : '');
  const malwareChips = usedBy.malware.slice(0, CAP).map(a =>
    `<span class="hyp-actor-chip" onclick="window.__hypSearch('${escapeAttr(a.name)}')">${escapeHtml(a.name)}</span>`
  ).join('') + (usedBy.malware.length > CAP ? `<span class="hyp-actor-chip" style="opacity:.55">+${usedBy.malware.length - CAP} more</span>` : '');
  const stixToolChips = usedBy.tools.slice(0, CAP).map(a =>
    `<span class="hyp-tool-chip" onclick="window.__hypSearch('${escapeAttr(a.name)}')">${escapeHtml(a.name)}</span>`
  ).join('') + (usedBy.tools.length > CAP ? `<span class="hyp-tool-chip" style="opacity:.55">+${usedBy.tools.length - CAP} more</span>` : '');

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
        ${dsComponentChips ? `<div><div class="hyp-section-lbl">DATA COMPONENTS</div><div class="hyp-ds-components">${dsComponentChips}</div></div>` : ''}
        <div>
          <div class="hyp-section-lbl">PLATFORMS</div>
          <div class="hyp-platform-chips">${platformChips}</div>
        </div>
      </div>
      ${groupChips   ? `<div><div class="hyp-section-lbl">KNOWN GROUPS</div><div class="hyp-actor-chips">${groupChips}</div></div>`   : ''}
      ${malwareChips ? `<div><div class="hyp-section-lbl">KNOWN MALWARE</div><div class="hyp-actor-chips">${malwareChips}</div></div>` : ''}
      ${stixToolChips ? `<div><div class="hyp-section-lbl">KNOWN TOOLS</div><div class="hyp-tool-chips">${stixToolChips}</div></div>` : ''}
      ${analyticsHtml ? `<div>${analyticsHtml}</div>` : ''}
      <div>
        <div class="hyp-section-lbl">DETECTION FOCUS</div>
        <div class="hyp-detect-text">${escapeHtml(h.detection)}</div>
      </div>
    </div>
    ${footer}
  </div>`;
}

function renderCuratedCard(h, curated) {
  const allTools  = [...new Set(curated.flatMap(c => c.tools  || []))];
  const allActors = [...new Set(curated.flatMap(c => c.actors || []))];
  const allRefs   = curated.flatMap(c => c.refs || [])
    .filter((r, i, a) => a.findIndex(x => x.label === r.label) === i);

  const hypSections = curated.map(c => {
    const sev = c.severity || 'high';
    const pivotRows = (c.pivots || []).map(p =>
      `<div class="hyp-pivot">
        <span class="hyp-pivot-label">${escapeHtml(p.label)}</span>
        <span class="hyp-pivot-detail">${escapeHtml(p.detail)}</span>
      </div>`
    ).join('');

    const dl = c.detection_logic;
    const detectionLogicHtml = dl
      ? `<div class="hyp-section-lbl" style="margin-top:8px">DETECTION LOGIC</div>
         <div class="hyp-detect-logic">
           ${dl.sigma_url
             ? `<a class="hyp-detect-sigma-link" href="${escapeAttr(dl.sigma_url)}" target="_blank" rel="noopener">⬡ Sigma: ${escapeHtml(dl.sigma_title || 'rule')}</a>`
             : ''}
           ${dl.query_hint ? `<code class="hyp-detect-query">${escapeHtml(dl.query_hint)}</code>` : ''}
         </div>`
      : '';

    const mitigationChips = (c.mitigations || []).map(m =>
      `<span class="hyp-mitigation-chip" title="${escapeAttr(m.detail)}">
        <span class="hyp-mitigation-id">${escapeHtml(m.id)}</span>${escapeHtml(m.name)}
      </span>`
    ).join('');

    const SEV_TIP = {
      critical: 'Very High Prevalence · Hard to Detect · Severe Impact',
      high:     'High Prevalence · Moderate Detection Difficulty · Significant Impact',
      medium:   'Medium Prevalence · Lower Detection Difficulty · Moderate Impact',
      low:      'Low Prevalence · Easier to Detect · Limited Impact',
    };

    return `<div class="hyp-chyp">
      <div class="hyp-chyp-head">
        <span class="hyp-chyp-id">${escapeHtml(c.id)}</span>
        <span class="hyp-chyp-title">${escapeHtml(c.title)}</span>
        <span class="hyp-chyp-sev ${escapeAttr(sev)}" data-tip="${escapeAttr(SEV_TIP[sev] || '')}">${sev.toUpperCase()}</span>
      </div>
      <div class="hyp-chyp-stmt">${escapeHtml(c.statement)}</div>
      ${pivotRows ? `<div class="hyp-section-lbl" style="margin-top:6px">HUNT PIVOTS</div><div class="hyp-pivot-list">${pivotRows}</div>` : ''}
      ${detectionLogicHtml}
      ${mitigationChips ? `<div class="hyp-section-lbl" style="margin-top:8px">MITIGATIONS</div><div class="hyp-mitigation-chips">${mitigationChips}</div>` : ''}
      ${c.fpr ? `<div class="hyp-chyp-fpr"><span class="hyp-section-lbl" style="display:inline;margin-right:6px">FPR</span>${escapeHtml(c.fpr)}</div>` : ''}
    </div>`;
  }).join('<hr class="hyp-chyp-divider">');

  const dsList = h.dataSources.length
    ? h.dataSources.slice(0, 8).map(ds => `<li>${escapeHtml(ds)}</li>`).join('')
    : '';

  const platformChips = h.platforms.length
    ? h.platforms.map(p => `<span class="hyp-platform-chip">${escapeHtml(p)}</span>`).join('')
    : '<span class="hyp-platform-chip" style="color:var(--muted)">—</span>';

  const toolChips  = allTools.map(t =>
    `<span class="hyp-tool-chip">${escapeHtml(t)}</span>`).join('');
  const actorChips = allActors.map(a =>
    `<span class="hyp-actor-chip" onclick="window.__hypSearch('${escapeAttr(a)}')">${escapeHtml(a)}</span>`).join('');

  const refItems = allRefs.map(r =>
    r.url
      ? `<a class="hyp-ref-item" href="${escapeAttr(r.url)}" target="_blank" rel="noopener"><span class="hyp-ref-type">${escapeHtml(r.type)}</span>${escapeHtml(r.label)}</a>`
      : `<span class="hyp-ref-item"><span class="hyp-ref-type">${escapeHtml(r.type)}</span>${escapeHtml(r.label)}</span>`
  ).join('');

  const footer = buildFooter(h);

  const dsComponentChips = buildDsComponentChips(h.dataSources, h.analytics);
  const analyticsHtml    = buildAnalyticsSection(h.dataSources, h.analytics);
  const related = getRelated(h.id).slice(0, 6);
  const relatedChips = related.map(id =>
    `<span class="hyp-related-chip" onclick="window.__hypSearch('${escapeAttr(id)}')" title="${escapeAttr(getTechName(id))}">${escapeHtml(id)}</span>`
  ).join('');

  return `<div class="hyp-card curated">
    <div class="hyp-card-head">
      <span class="hyp-card-id">${escapeHtml(h.id)}</span>
      <span class="hyp-card-name">${escapeHtml(h.name)}</span>
      <span class="hyp-curated-badge" style="margin-left:auto">★ CURATED</span>
      <span class="hyp-tactic-pill" style="background:${escapeAttr(h.tacticColor)};margin-left:0">${escapeHtml(h.tacticLabel)}</span>
      <div class="hyp-export-group">
        <button class="hyp-export-btn" onclick="window.__exportHyp('${escapeAttr(h.id)}','markdown',this)">MD</button>
        <button class="hyp-export-btn" onclick="window.__exportHyp('${escapeAttr(h.id)}','json',this)">JSON</button>
      </div>
    </div>
    <div class="hyp-card-body">
      <div class="hyp-curated-hyps">${hypSections}</div>
      <div class="hyp-meta-grid">
        ${dsComponentChips ? `<div><div class="hyp-section-lbl">DATA COMPONENTS</div><div class="hyp-ds-components">${dsComponentChips}</div></div>` : ''}
        <div>
          <div class="hyp-section-lbl">PLATFORMS</div>
          <div class="hyp-platform-chips">${platformChips}</div>
        </div>
      </div>
      ${toolChips  ? `<div><div class="hyp-section-lbl">KNOWN TOOLS</div><div class="hyp-tool-chips">${toolChips}</div></div>` : ''}
      ${actorChips ? `<div><div class="hyp-section-lbl">DOCUMENTED ACTORS</div><div class="hyp-actor-chips">${actorChips}</div></div>` : ''}
      ${analyticsHtml ? `<div>${analyticsHtml}</div>` : ''}
      ${h.detection ? `<div><div class="hyp-section-lbl">DETECTION FOCUS</div><div class="hyp-detect-text">${escapeHtml(h.detection)}</div></div>` : ''}
      ${refItems ? `<div><div class="hyp-section-lbl">REFERENCES</div><div class="hyp-refs">${refItems}</div></div>` : ''}
      ${relatedChips ? `<div><div class="hyp-section-lbl">RELATED TECHNIQUES</div><div class="hyp-related-chips">${relatedChips}</div></div>` : ''}
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

let _acSelected = -1;

export function renderSuggestions(suggestions) {
  const ac = $('hyp-ac');
  if (!ac) return;
  if (!suggestions.length) { ac.classList.remove('open'); return; }

  _acSelected = -1;
  const typeColors = { technique: 'var(--accent)', group: 'var(--accent2)', malware: 'var(--red)', tool: 'var(--t-exec)', campaign: 'var(--t-persist)', actor: 'var(--accent2)' };

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

function buildDsComponentChips(dataSources, analytics) {
  if (!dataSources || !dataSources.length) return '';
  return dataSources.slice(0, 10).map(ds => {
    const parts     = ds.split(':');
    const source    = parts[0].trim();
    const component = parts[1]?.trim() || source;
    const hasAnalytic = analytics && analytics[ds];
    return `<span class="hyp-ds-chip${hasAnalytic ? ' has-analytic' : ''}" onclick="window.__toggleSource('${escapeAttr(source)}')" title="Filter by: ${escapeAttr(source)}">${escapeHtml(component)}</span>`;
  }).join('');
}

function buildAnalyticsSection(dataSources, analytics) {
  if (!analytics || !dataSources || !dataSources.length) return '';
  const entries = dataSources
    .filter(ds => analytics[ds])
    .map(ds => {
      const parts     = ds.split(':');
      const source    = parts[0].trim();
      const component = parts[1]?.trim() || source;
      return `<div class="hyp-analytic-item">
        <div class="hyp-analytic-label">
          <span class="hyp-analytic-source">${escapeHtml(source)}</span>
          <span class="hyp-analytic-arrow">›</span>
          <span class="hyp-analytic-component">${escapeHtml(component)}</span>
        </div>
        <div class="hyp-analytic-text">${escapeHtml(analytics[ds])}</div>
      </div>`;
    });
  if (!entries.length) return '';
  return `<div class="hyp-section-lbl">DETECTION ANALYTICS <span class="hyp-section-src">MITRE ATT&amp;CK</span></div>
    <div class="hyp-analytics-list">${entries.join('')}</div>`;
}

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
