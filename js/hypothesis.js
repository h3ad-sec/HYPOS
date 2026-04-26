export const TACTIC_META = {
  'initial-access':        { label: 'Initial Access',        color: '#ff6b35', goal: 'gain an initial foothold in the target environment' },
  'execution':             { label: 'Execution',             color: '#f59e0b', goal: 'execute malicious code on the target system' },
  'persistence':           { label: 'Persistence',           color: '#a855f7', goal: 'maintain long-term access to the compromised environment' },
  'privilege-escalation':  { label: 'Privilege Escalation',  color: '#ec4899', goal: 'obtain elevated or administrative privileges' },
  'defense-evasion':       { label: 'Defense Evasion',       color: '#6366f1', goal: 'avoid detection or bypass security controls' },
  'credential-access':     { label: 'Credential Access',     color: '#00ff9f', goal: 'harvest valid credentials for lateral movement or further access' },
  'discovery':             { label: 'Discovery',             color: '#3b82f6', goal: 'gather intelligence about the environment, systems, or network topology' },
  'lateral-movement':      { label: 'Lateral Movement',      color: '#00c8ff', goal: 'move laterally and expand access across the network' },
  'collection':            { label: 'Collection',            color: '#10b981', goal: 'stage or gather sensitive data of interest' },
  'command-and-control':   { label: 'Command & Control',     color: '#ff3b5c', goal: 'establish covert communication with compromised systems' },
  'exfiltration':          { label: 'Exfiltration',          color: '#ffd60a', goal: 'transfer collected data outside the environment' },
  'impact':                { label: 'Impact',                color: '#ef4444', goal: 'disrupt, destroy, encrypt, or manipulate systems or data' },
  'reconnaissance':        { label: 'Reconnaissance',        color: '#8b5cf6', goal: 'gather information about the target prior to active intrusion' },
  'resource-development':  { label: 'Resource Development',  color: '#78716c', goal: 'establish infrastructure or resources for conducting operations' },
};

const FALLBACK_TACTIC = { label: 'Unknown', color: '#7d8fb3', goal: 'achieve their objective' };

export function generateHypothesis(technique) {
  const tactic   = technique.tactics[0] || '';
  const tacticMeta = TACTIC_META[tactic] || FALLBACK_TACTIC;

  const hypothesis = buildStatement(technique, tacticMeta);
  const detection  = buildDetection(technique);

  return {
    id:          technique.id,
    name:        technique.name,
    tactic,
    tacticLabel: tacticMeta.label,
    tacticColor: tacticMeta.color,
    hypothesis,
    dataSources: technique.ds || [],
    platforms:   technique.platforms || [],
    detection,
    isSub:       technique.sub,
    parentId:    technique.pid,
    subs:        technique.subs || [],
    url:         technique.url,
    desc:        technique.desc,
  };
}

function buildStatement(t, meta) {
  const platformStr = t.platforms.length
    ? t.platforms.slice(0, 3).join(', ') + (t.platforms.length > 3 ? ' and others' : '')
    : 'target systems';

  const dsStr = t.ds.length
    ? t.ds.slice(0, 2).map(d => d.split(':')[0]).join(' and ') + ' telemetry'
    : 'endpoint telemetry';

  const context = t.sentence || '';

  return `IF an adversary has obtained sufficient access to ${platformStr}, THEN they may leverage ${t.name} to ${meta.goal}. ${context ? context + ' ' : ''}Observable evidence should be present in ${dsStr}.`;
}

function buildDetection(t) {
  if (t.detect) {
    const first = t.detect.match(/^[^.!?\n]+[.!?]/);
    return first ? first[0].trim() : t.detect.slice(0, 250);
  }
  if (t.ds.length) {
    const sources = t.ds.slice(0, 5).join('; ');
    return `Monitor the following data sources for anomalous or unexpected activity: ${sources}.`;
  }
  return `Review process, file, and network telemetry on ${(t.platforms || []).join(', ') || 'target systems'} for indicators consistent with ${t.name}.`;
}

// Groups technique hypotheses by tactic, preserving tactic order
export function groupByTactic(hypotheses) {
  const TACTIC_ORDER = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
  ];

  const map = new Map();
  for (const h of hypotheses) {
    const t = h.tactic || 'unknown';
    if (!map.has(t)) map.set(t, []);
    map.get(t).push(h);
  }

  const ordered = [];
  for (const t of TACTIC_ORDER) {
    if (map.has(t)) { ordered.push({ tactic: t, items: map.get(t) }); map.delete(t); }
  }
  for (const [t, items] of map) {
    ordered.push({ tactic: t, items });
  }
  return ordered;
}
