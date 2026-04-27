import { loadData, getData, getIndex, clearCache } from './data-loader.js';
import { loadHypDB } from './hyp-db.js';
import { lookup, lookupAll, suggest, detectQueryType } from './lookup.js';
import {
  setDataStatus, showLoading, appendTerminalLine, finalizeTerminal,
  showEmpty, showError, renderResults, renderSuggestions, hideAutocomplete,
  moveAcSelection, updateDetectBadge,
} from './ui.js';

// Expose for inline onclick handlers in rendered cards
window.__hyposLookup = { detectQueryType };
window.__hypSearch   = (q) => { runSearch(q); };

let _dataReady    = false;
let _pendingQuery = null;
let _lastResult   = null;

// ── Filters ────────────────────────────────────────────────────

const _activePlatforms = new Set();
const _activeSources   = new Set();

function applyFilters(result) {
  if (!result || result.type === 'not-found') return result;
  if (!_activePlatforms.size && !_activeSources.size) return result;

  const items = result.items.filter(t => {
    if (_activePlatforms.size && !t.platforms.some(p => _activePlatforms.has(p))) return false;
    if (_activeSources.size  && !t.ds.some(ds => _activeSources.has(ds.split(':')[0].trim()))) return false;
    return true;
  });
  return { ...result, items, _total: result.items.length };
}

function syncFilterUI() {
  document.querySelectorAll('.hyp-fchip[data-plat]').forEach(el =>
    el.classList.toggle('active', _activePlatforms.has(el.dataset.plat)));
  document.querySelectorAll('.hyp-fchip[data-src]').forEach(el =>
    el.classList.toggle('active', _activeSources.has(el.dataset.src)));
  const anyActive = _activePlatforms.size > 0 || _activeSources.size > 0;
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

window.__clearFilters = () => {
  _activePlatforms.clear();
  _activeSources.clear();
  syncFilterUI();
  rerender();
};

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
  const sources = Object.entries(srcCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 14)
    .map(([s]) => s);

  const srcEl = document.getElementById('src-chips');
  if (srcEl) {
    srcEl.innerHTML = sources.map(s =>
      `<span class="hyp-fchip" data-src="${s}" onclick="window.__toggleSource('${s}')">${s}</span>`
    ).join('');
  }

  document.getElementById('hyp-filter-bar')?.classList.add('ready');
}

// ── Init ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMatrix();
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

// ── Search ─────────────────────────────────────────────────────

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

  ac?.addEventListener('click', e => {
    const item = e.target.closest('.hyp-ac-item');
    if (!item) return;
    input.value = item.dataset.val;
    hideAutocomplete();
    form.dispatchEvent(new Event('submit'));
  });

  // URL query param support: ?q=T1003
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
  // Update URL without navigation
  const url = new URL(window.location);
  url.searchParams.set('q', q);
  window.history.replaceState(null, '', url);

  const result = lookup(q);
  _lastResult = result;
  renderResults(applyFilters(result));
  window.scrollTo({ top: document.getElementById('hyp-state')?.offsetTop - 160, behavior: 'smooth' });
}

// ── Theme ──────────────────────────────────────────────────────

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
  const matrix = document.getElementById('matrix');
  if (matrix) matrix.dataset.theme = theme;
  if (typeof window.__matrixSetColor === 'function') {
    window.__matrixSetColor(theme === 'light' ? '#0077ff' : '#00ff9f');
  }
}

window.toggleTheme = function () {
  const isLight = document.body.classList.contains('light');
  const next = isLight ? 'dark' : 'light';
  localStorage.setItem('theme', next);
  applyTheme(next);
};

// ── Nav drawer ─────────────────────────────────────────────────

function initNav() {
  window.toggleDrawer = () => {
    document.getElementById('navDrawer')?.classList.toggle('open');
  };
  window.closeDrawer = () => {
    document.getElementById('navDrawer')?.classList.remove('open');
  };
}

// ── Matrix ─────────────────────────────────────────────────────

function initMatrix() {
  const canvas = document.getElementById('matrix');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const CHARS = ['443','80','8443','3389','445','22','53','T1003','T1059','T1047','T1021','T1566','T1071','T1218','T1547','T1486','T1055','T1105','IOC','IOA','YARA','SIGMA','STIX2','TAXII','Enrichment','Correlation','Attribution','ThreatHunt','MD5','SHA1','SHA256','SHA512','Detection','Response','Containment','Triage','Indicator','Feed','Pulse','CVE','CVSS','Exploit','Payload','Analysis','Sandbox','Reputation','Blocklist','Allowlist','Firewall','EDR','XDR','SIEM','SOAR','4624','4625','4688','4672','4768','4769','IAM','AzureAD','OAuth','CloudTrail','BLOCK','INVESTIGATE','ALLOW','MONITOR','HYPOS','MALICIOUS','SUSPICIOUS','BENIGN','UNKNOWN','VT','ABUSEIPDB','OTX','SHODAN','URLHAUS','H3AD-SEC'];

  let cols, drops;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = document.body.classList.contains('light')
      ? 'rgba(245,247,251,0.08)'
      : 'rgba(0,0,0,0.12)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = document.body.classList.contains('light') ? '#0077ff' : '#00ff9f';
    ctx.font = '12px monospace';
    for (let i = 0; i < drops.length; i++) {
      const c = CHARS[Math.floor(Math.random() * CHARS.length)];
      ctx.fillText(c, i * 18, drops[i] * 18);
      if (drops[i] * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  window.__matrixSetColor = c => {};
  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 45);
}
