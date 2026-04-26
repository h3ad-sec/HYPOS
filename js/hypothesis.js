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
  'reconnaissance':       'A threat actor is suspected of conducting pre-intrusion reconnaissance against the organization',
  'resource-development': 'A threat actor is suspected of establishing adversary infrastructure or capabilities ahead of an intrusion',
  'initial-access':       'A threat actor is suspected of targeting external-facing systems, user endpoints, or identity providers',
  'execution':            'A threat actor with a foothold on {platforms} is suspected of executing adversary-controlled code',
  'persistence':          'A threat actor with initial access on {platforms} is suspected of establishing persistence mechanisms to survive reboots or credential rotation',
  'privilege-escalation': 'A threat actor with low-privileged access on {platforms} is suspected of escalating to administrative or system-level authority',
  'defense-evasion':      'A threat actor actively operating on {platforms} is suspected of subverting security controls or evading defensive visibility',
  'credential-access':    'A threat actor with code execution or elevated access on {platforms} is suspected of harvesting authentication material from memory, disk, or the OS credential store',
  'discovery':            'A threat actor with a foothold on {platforms} is suspected of conducting internal reconnaissance to map accounts, systems, and network topology',
  'lateral-movement':     'A threat actor with at least one compromised host is suspected of moving laterally to expand access across the network',
  'collection':           'A threat actor with established access on {platforms} is suspected of aggregating or staging sensitive data in preparation for exfiltration',
  'command-and-control':  'A threat actor with an implant on {platforms} is suspected of maintaining covert command-and-control communications with attacker infrastructure',
  'exfiltration':         'A threat actor with collected data on {platforms} is suspected of transferring it outside the environment via covert or permitted channels',
  'impact':               'A threat actor with sufficient access on {platforms} is suspected of executing destructive, disruptive, or manipulative operations against systems or data',
};

// Maps ATT&CK data component names to analyst-readable hunt language
const COMPONENT_HUNT_HINTS = {
  'OS API Execution':                     'API calls to credential-access, injection, or memory-manipulation system functions',
  'Process Access':                       'cross-process handle or memory-read operations inconsistent with known software behavior',
  'Process Creation':                     'unexpected process ancestry, suspicious parent-child relationships, or binaries executing from anomalous paths',
  'Process Modification':                 'in-memory process modifications or hollowing of legitimate host processes',
  'Process Termination':                  'unexpected termination of security tooling, EDR agents, or critical system processes',
  'Command Execution':                    'command-line arguments matching known offensive tooling, encoded payloads, or unusual flag combinations',
  'Script Execution':                     'scripts executing from non-standard locations, with obfuscated content, or spawned by unexpected parent processes',
  'Module Load':                          'unsigned, anomalous, or reflectively loaded modules injected into sensitive or high-integrity processes',
  'File Creation':                        'artifact drops in world-writable, temp, or staging directories outside of normal software install paths',
  'File Access':                          'reads targeting credential stores, OS secrets, configuration files, or sensitive data paths',
  'File Modification':                    'unauthorized changes to system binaries, startup files, or security-sensitive configurations',
  'File Deletion':                        'removal of forensic artifacts, recently dropped tools, prefetch entries, or security logs',
  'File Metadata':                        'timestamp manipulation or attribute changes consistent with anti-forensic activity',
  'Network Connection Creation':          'outbound connections to uncategorized, newly registered, or low-reputation endpoints outside normal application baselines',
  'Network Traffic Content':              'protocol anomalies, unusual payload sizes, or encoded content embedded in otherwise legitimate network flows',
  'Network Traffic Flow':                 'anomalous bandwidth consumption, beaconing patterns, or connections outside expected time windows',
  'DNS Resolution':                       'high-entropy or DGA-like domain queries, lookups to newly registered infrastructure, or DNS tunneling indicators',
  'Windows Registry Key Access':          'reads targeting sensitive hives such as SAM, SECURITY, LSA Secrets, or SYSTEM outside of known admin tooling',
  'Windows Registry Key Creation':        'new registry entries under Run, Services, or scheduled task paths outside of approved software deployment',
  'Windows Registry Key Modification':    'changes to security policy, ASEP, or boot-relevant registry keys inconsistent with patch or admin activity',
  'User Account Authentication':          'authentication events from unusual source addresses, non-business hours, or using atypical credential types (e.g., pass-the-hash)',
  'User Account Creation':                'new local or domain accounts provisioned outside of documented IT workflows',
  'User Account Modification':            'privilege or group membership changes not correlated with HR, ticketing, or change management records',
  'Logon Session Creation':               'interactive or network logon sessions with anomalous type, source, or timing characteristics',
  'Logon Session Metadata':               'session attributes — duration, originating host, or token characteristics — inconsistent with the user\'s established baseline',
  'Active Directory Object Access':       'LDAP queries or AD attribute reads targeting sensitive objects (AdminSDHolder, ACLs, trusts) outside normal operational patterns',
  'Active Directory Object Modification': 'changes to AD objects, group memberships, SID history, or ACLs outside provisioning or approved change windows',
  'Active Directory Object Creation':     'creation of new AD objects such as computer accounts, GPOs, or service accounts outside known provisioning processes',
  'Service Creation':                     'new service registrations with suspicious binary paths, descriptions, or accounts not matching known software',
  'Service Modification':                 'changes to existing service configurations — especially security tools, antivirus, or audit-logging services',
  'Scheduled Job Creation':               'new scheduled tasks registered outside known patching, backup, or administrative workflows',
  'Scheduled Job Modification':           'modifications to existing tasks that alter execution context, binary path, or schedule',
  'WMI Creation':                         'WMI subscriptions or event consumers created by unexpected processes or accounts',
  'Named Pipe Creation':                  'named pipe activity associated with lateral tool transfer, inter-process C2, or exploitation of IPC channels',
  'Volume Shadow Copy':                   'shadow copy deletion, modification, or access inconsistent with backup operations',
  'Driver Load':                          'unsigned, anomalous, or known-malicious kernel driver loads outside approved update or security software activity',
  'Cloud Storage Access':                 'access to cloud storage objects — S3 buckets, Azure Blobs, GCS — outside normal application or user activity patterns',
  'Cloud Service Modification':           'changes to cloud IAM policies, security group rules, logging configurations, or compute resources',
  'Application Log Content':             'anomalous entries in authentication, application error, or audit logs — especially gaps, clearance events, or unexpected principals',
  'Firmware Modification':                'changes to UEFI, firmware images, or bootloader components outside vendor-authorized update processes',
  'Pod Creation':                         'container or pod instantiation from unexpected images, unusual namespaces, or with elevated privilege flags',
  'Container Creation':                   'new container creation outside CI/CD pipelines, with anomalous mounts, capabilities, or network modes',
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

  // Sentence 1: tactic-specific adversary assumption
  const template  = TACTIC_PREMISE[tactic] || `A threat actor with access to ${platformStr} is suspected of`;
  const premisePt = template.replace('{platforms}', platformStr);
  const sentence1 = `${premisePt}, employing ${t.name} to ${meta.goal}.`;

  // Sentence 2: MITRE behavioral context (first sentence of description, trimmed)
  const sentence2 = t.sentence || '';

  // Sentence 3: hunt pivot — map data components to analyst-specific hunt language
  const hints = t.ds
    .slice(0, 6)
    .map(d => {
      const comp = d.includes(':') ? d.split(':')[1].trim() : d.trim();
      return COMPONENT_HUNT_HINTS[comp] || comp.toLowerCase();
    })
    .filter((v, i, a) => a.indexOf(v) === i)
    .slice(0, 4);

  let sentence3;
  if (hints.length === 0) {
    sentence3 = `Hunt for anomalous process, file, or network activity on ${platformStr} that deviates from an established organizational baseline.`;
  } else if (hints.length === 1) {
    sentence3 = `Hunt for ${hints[0]}.`;
  } else {
    const last   = hints[hints.length - 1];
    const others = hints.slice(0, -1);
    sentence3 = `Hunt for ${others.join('; ')}, and ${last}.`;
  }

  const parts = [sentence1];
  if (sentence2) parts.push(sentence2);
  parts.push(sentence3);
  return parts.join(' ');
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
