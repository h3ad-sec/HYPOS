export const TACTIC_META = {
  'initial-access':        { label: 'Initial Access',        color: '#ff6b35', goal: 'gain an initial foothold in the target environment' },
  'execution':             { label: 'Execution',             color: '#f59e0b', goal: 'execute adversary-controlled code on the target system' },
  'persistence':           { label: 'Persistence',           color: '#a855f7', goal: 'maintain long-term access to the compromised environment' },
  'privilege-escalation':  { label: 'Privilege Escalation',  color: '#ec4899', goal: 'obtain elevated or administrative privileges' },
  'defense-evasion':       { label: 'Defense Evasion',       color: '#6366f1', goal: 'avoid detection or subvert security controls' },
  'credential-access':     { label: 'Credential Access',     color: '#00ff9f', goal: 'harvest valid authentication material for lateral movement or further access' },
  'discovery':             { label: 'Discovery',             color: '#3b82f6', goal: 'enumerate and map the environment, systems, or network topology' },
  'lateral-movement':      { label: 'Lateral Movement',      color: '#00c8ff', goal: 'expand access and move laterally across the network' },
  'collection':            { label: 'Collection',            color: '#10b981', goal: 'stage or aggregate sensitive data of interest' },
  'command-and-control':   { label: 'Command & Control',     color: '#ff3b5c', goal: 'maintain covert communication with compromised systems' },
  'exfiltration':          { label: 'Exfiltration',          color: '#ffd60a', goal: 'transfer collected data outside the environment' },
  'impact':                { label: 'Impact',                color: '#ef4444', goal: 'disrupt, destroy, encrypt, or manipulate systems or data' },
  'reconnaissance':        { label: 'Reconnaissance',        color: '#8b5cf6', goal: 'gather intelligence about the target prior to active intrusion' },
  'resource-development':  { label: 'Resource Development',  color: '#78716c', goal: 'establish adversary infrastructure or capabilities for conducting operations' },
};

const FALLBACK_TACTIC = { label: 'Unknown', color: '#7d8fb3', goal: 'achieve their objective' };

// Tactic-specific adversary assumption; {platforms} substituted at build time
const TACTIC_PREMISE = {
  'reconnaissance':       'A threat actor is suspected of conducting pre-intrusion reconnaissance',
  'resource-development': 'A threat actor is suspected of building adversary infrastructure ahead of intrusion',
  'initial-access':       'A threat actor is suspected of targeting external-facing systems or user endpoints',
  'execution':            'A threat actor with a foothold on {platforms} is suspected of executing adversary-controlled code',
  'persistence':          'A threat actor with initial access on {platforms} is suspected of establishing persistence',
  'privilege-escalation': 'A threat actor with low-privileged access on {platforms} is suspected of escalating privileges',
  'defense-evasion':      'A threat actor on {platforms} is suspected of evading detection or subverting security controls',
  'credential-access':    'A threat actor with elevated access on {platforms} is suspected of harvesting authentication material',
  'discovery':            'A threat actor with a foothold on {platforms} is suspected of enumerating the internal environment',
  'lateral-movement':     'A threat actor with a compromised host is suspected of moving laterally across the network',
  'collection':           'A threat actor on {platforms} is suspected of staging or aggregating sensitive data',
  'command-and-control':  'A threat actor with an implant on {platforms} is suspected of maintaining covert C2 communications',
  'exfiltration':         'A threat actor on {platforms} is suspected of transferring collected data outside the environment',
  'impact':               'A threat actor with sufficient access on {platforms} is suspected of executing destructive or disruptive operations',
};

// Maps ATT&CK data component names to concise hunt-pivot language
const COMPONENT_HUNT_HINTS = {
  'OS API Execution':                     'anomalous calls to credential, injection, or memory-manipulation APIs',
  'Process Access':                       'cross-process memory reads outside known software',
  'Process Creation':                     'unexpected process ancestry or binaries from anomalous paths',
  'Process Modification':                 'in-memory hollowing or modification of host processes',
  'Process Termination':                  'unexpected termination of security tooling or critical processes',
  'Command Execution':                    'suspicious command-line patterns or encoded payloads',
  'Script Execution':                     'obfuscated or non-standard-location script execution',
  'Module Load':                          'unsigned or reflectively loaded modules in sensitive processes',
  'File Creation':                        'artifact drops in temp or world-writable paths',
  'File Access':                          'reads targeting credential stores or sensitive data paths',
  'File Modification':                    'unauthorized changes to system binaries or startup configs',
  'File Deletion':                        'removal of logs, prefetch, or recently dropped tools',
  'File Metadata':                        'timestamp manipulation or anti-forensic attribute changes',
  'Network Connection Creation':          'outbound connections to uncategorized or low-reputation endpoints',
  'Network Traffic Content':              'protocol anomalies or encoded payloads in network flows',
  'Network Traffic Flow':                 'beaconing patterns or connections outside expected time windows',
  'DNS Resolution':                       'high-entropy domain queries or DNS tunneling indicators',
  'Windows Registry Key Access':          'reads targeting SAM, SECURITY, LSA, or SYSTEM hives',
  'Windows Registry Key Creation':        'new Run, Services, or scheduled task registry entries',
  'Windows Registry Key Modification':    'changes to ASEP or security-policy registry locations',
  'User Account Authentication':          'auth events from unusual sources, times, or credential types',
  'User Account Creation':                'accounts provisioned outside IT workflows',
  'User Account Modification':            'privilege changes not correlated with change management records',
  'Logon Session Creation':               'logon sessions with anomalous type, source, or timing',
  'Logon Session Metadata':               'session characteristics inconsistent with user baseline',
  'Active Directory Object Access':       'LDAP reads targeting sensitive AD objects or ACLs',
  'Active Directory Object Modification': 'changes to AD group memberships, SID history, or ACLs',
  'Active Directory Object Creation':     'new AD accounts, GPOs, or service accounts outside provisioning',
  'Service Creation':                     'new services with suspicious binary paths or accounts',
  'Service Modification':                 'changes to security tool or audit-logging service configs',
  'Scheduled Job Creation':               'new tasks outside known patching or admin workflows',
  'Scheduled Job Modification':           'task changes altering binary path or execution context',
  'WMI Creation':                         'WMI subscriptions registered by unexpected processes',
  'Named Pipe Creation':                  'named pipes associated with lateral movement or inter-process C2',
  'Volume Shadow Copy':                   'shadow copy deletion or access outside backup windows',
  'Driver Load':                          'unsigned or anomalous kernel driver loads',
  'Cloud Storage Access':                 'cloud object access outside normal application patterns',
  'Cloud Service Modification':           'changes to cloud IAM, security groups, or logging configs',
  'Application Log Content':             'log gaps, clearance events, or unexpected principals in audit logs',
  'Firmware Modification':                'changes to UEFI or bootloader components',
  'Pod Creation':                         'pods from unexpected images or with elevated privilege flags',
  'Container Creation':                   'containers outside CI/CD pipelines with anomalous capabilities',
};

export function generateHypothesis(technique) {
  const tactic     = technique.tactics[0] || '';
  const tacticMeta = TACTIC_META[tactic] || FALLBACK_TACTIC;

  const hypothesis = buildStatement(technique, tactic, tacticMeta);
  const detection  = buildDetection(technique);

  return {
    id:          technique.id,
    name:        technique.name,
    tactic,
    tacticLabel: tacticMeta.label,
    tacticColor: tacticMeta.color,
    hypothesis,
    dataSources: technique.ds || [],
    analytics:   technique.analytics || {},
    platforms:   technique.platforms || [],
    detection,
    isSub:       technique.sub,
    parentId:    technique.pid,
    subs:        technique.subs || [],
    url:         technique.url,
    desc:        technique.desc,
  };
}

function buildStatement(t, tactic, meta) {
  const platformStr = t.platforms.length
    ? t.platforms.slice(0, 3).join(', ') + (t.platforms.length > 3 ? ' and others' : '')
    : 'target systems';

  const template  = TACTIC_PREMISE[tactic] || `A threat actor with access to ${platformStr} is suspected of`;
  const premise   = template.replace('{platforms}', platformStr);
  const sentence1 = `${premise}, employing ${t.name} to ${meta.goal}.`;

  const hints = t.ds
    .slice(0, 5)
    .map(d => {
      const comp = d.includes(':') ? d.split(':')[1].trim() : d.trim();
      return COMPONENT_HUNT_HINTS[comp] || comp.toLowerCase();
    })
    .filter((v, i, a) => a.indexOf(v) === i)
    .slice(0, 3);

  const sentence2 = hints.length
    ? `Hunt for ${hints.join(', ')}.`
    : `Hunt for anomalous process, file, or network activity on ${platformStr} deviating from baseline.`;

  return `${sentence1} ${sentence2}`;
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

// Groups technique hypotheses by tactic, preserving canonical ATT&CK order
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
