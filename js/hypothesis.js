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

// Tactic-specific IF premises; {platforms} is substituted at render time
const TACTIC_PREMISE = {
  'reconnaissance':       'IF a threat actor is conducting pre-intrusion reconnaissance against the organization',
  'resource-development': 'IF a threat actor is establishing infrastructure or capabilities ahead of an intrusion',
  'initial-access':       'IF a threat actor is targeting external-facing systems, user endpoints, or identity providers',
  'execution':            'IF a threat actor has obtained a foothold and is attempting to execute code on {platforms}',
  'persistence':          'IF a threat actor has established initial access on {platforms} and is seeking to maintain it',
  'privilege-escalation': 'IF a threat actor holds low-privileged access on {platforms} and is attempting to escalate',
  'defense-evasion':      'IF a threat actor is actively operating on {platforms} and attempting to avoid detection',
  'credential-access':    'IF a threat actor has achieved code execution or elevated access on {platforms}',
  'discovery':            'IF a threat actor is enumerating the environment from a foothold on {platforms}',
  'lateral-movement':     'IF a threat actor has compromised at least one host and is moving within the network',
  'collection':           'IF a threat actor has established access on {platforms} and is staging or gathering data',
  'command-and-control':  'IF a threat actor has implanted a foothold on {platforms}',
  'exfiltration':         'IF a threat actor has collected data of interest on {platforms} and is preparing to exfiltrate',
  'impact':               'IF a threat actor has achieved sufficient access on {platforms} to cause disruption or damage',
};

export function generateHypothesis(technique) {
  const tactic     = technique.tactics[0] || '';
  const tacticMeta = TACTIC_META[tactic] || FALLBACK_TACTIC;

  const hypothesis = buildStatement(technique, tactic);
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

function buildStatement(t, tactic) {
  const platformStr = t.platforms.length
    ? t.platforms.slice(0, 3).join(', ') + (t.platforms.length > 3 ? ' and others' : '')
    : 'target systems';

  const template = TACTIC_PREMISE[tactic] || `IF a threat actor has obtained access to ${platformStr}`;
  const premise  = template.replace('{platforms}', platformStr);

  // Use the component name (after the colon) for specific event-type language
  const components = t.ds.length
    ? [...new Set(
        t.ds.slice(0, 6).map(d => {
          const parts = d.split(':');
          return parts.length > 1 ? parts[1].trim() : parts[0].trim();
        })
      )].slice(0, 4)
    : [];

  const eventsStr = components.length
    ? components.join(', ') + ' events'
    : 'anomalous activity';

  return `${premise}, THEN ${t.name} should produce ${eventsStr} inconsistent with established baseline behavior.`;
}

function buildDetection(t) {
  if (t.detect) {
    const sentences = t.detect.match(/[^.!?\n]+[.!?]/g) || [];
    if (sentences.length) return sentences.slice(0, 3).map(s => s.trim()).join(' ');
    return t.detect.slice(0, 350);
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
