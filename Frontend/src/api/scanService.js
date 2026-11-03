/**
 * PkgSentinel REST API Service
 * 
 * Designed for seamless integration with Spring Boot backend:
 * - POST /api/scan     -> submit a package for deep zero-day analysis
 * - GET  /api/scans    -> get recent scan audit history
 * - GET  /api/scans/:id -> get comprehensive scan report
 * 
 * Toggle USE_MOCK_DATA to false once the Spring Boot server is active on localhost:8080.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api';
const USE_MOCK_DATA = true; // Set to false when connecting to Spring Boot

// Seeded preset samples to demonstrate distinct security decisions
const KNOWN_SAMPLES = {
  'color-setup-v2': {
    ecosystem: 'npm',
    version: '1.2.0',
    riskScore: 96,
    classification: 'HIGH',
    decision: 'BLOCK',
    summary: 'Critical malicious payload discovered in preinstall hook. Attempts credential exfiltration via raw TCP socket.',
    findings: [
      {
        category: 'Suspicious Installation Scripts',
        severity: 'CRITICAL',
        title: 'Arbitrary Base64 execution in postinstall hook',
        detail: 'The package.json postinstall lifecycle hook invokes a node child_process executing encoded PowerShell commands.',
        recommendation: 'Do not install. Revoke any developer environment tokens if installed.'
      },
      {
        category: 'Code Obfuscation',
        severity: 'HIGH',
        title: 'Packed & XOR-encrypted entrypoint file',
        detail: 'index.js contains high Shannon entropy (> 7.6) and layered hex decoding loops bypassing static AST parsers.',
        recommendation: 'Block at company proxy / registry firewall.'
      },
      {
        category: 'Suspicious Package Metadata',
        severity: 'MEDIUM',
        title: 'Typosquatting candidate target',
        detail: 'Matches pattern for popular library "colors" with newly created disposable author account.',
        recommendation: 'Check spelling and verify official package namespace.'
      }
    ],
    metadata: {
      publisher: 'ghost-dev-291',
      publishedDate: '2 hours ago',
      installScriptDetected: true,
      obfuscationDetected: true,
      entropyScore: 7.82,
      networkActivity: 'Outbound HTTP to raw IP (185.220.101.4)'
    }
  },
  'discord-token-logger': {
    ecosystem: 'npm',
    version: '0.4.1',
    riskScore: 92,
    classification: 'HIGH',
    decision: 'BLOCK',
    summary: 'High-confidence info-stealer targeting browser caches, local discord tokens, and SSH keys.',
    findings: [
      {
        category: 'Suspicious Installation Scripts',
        severity: 'CRITICAL',
        title: 'Stealthy webhook dispatcher',
        detail: 'Harvests Discord LocalStorage LevelDB paths and sends multipart payload to unauthorized Discord webhook.',
        recommendation: 'Quarantine immediately.'
      },
      {
        category: 'Unexpected Publisher Changes',
        severity: 'HIGH',
        title: 'Account takeover indicator',
        detail: 'Publisher email domain changed to temp-mail.org right before publishing 0.4.1.',
        recommendation: 'Reject version 0.4.1.'
      }
    ],
    metadata: {
      publisher: 'discord-helper-bot',
      publishedDate: '1 day ago',
      installScriptDetected: true,
      obfuscationDetected: true,
      entropyScore: 7.15,
      networkActivity: 'Discord Webhook Exfiltration'
    }
  },
  'py-cryptoutil-plus': {
    ecosystem: 'pypi',
    version: '3.0.0',
    riskScore: 68,
    classification: 'MEDIUM',
    decision: 'WARN',
    summary: 'Elevated anomaly index: drastic maintainer transfer, unpinned setup.py download, and unusual major version jump.',
    findings: [
      {
        category: 'Unexpected Publisher Changes',
        severity: 'HIGH',
        title: 'Abrupt maintainer ownership reassignment',
        detail: 'Original PyPI maintainer with 7-year track record was replaced by a newly registered account without release notes.',
        recommendation: 'Manual code audit required prior to dependency upgrade.'
      },
      {
        category: 'Unusual Version Changes',
        severity: 'MEDIUM',
        title: 'Sudden major version skip',
        detail: 'Version stepped from 1.0.4 directly to 3.0.0 with empty changelog.',
        recommendation: 'Inspect diff against 1.0.4.'
      },
      {
        category: 'Suspicious Package Metadata',
        severity: 'LOW',
        title: 'Unlinked GitHub repository',
        detail: 'Project URL points to 404 repository page.',
        recommendation: 'Confirm source authenticity.'
      }
    ],
    metadata: {
      publisher: 'crypto-maintainer-new',
      publishedDate: '3 days ago',
      installScriptDetected: false,
      obfuscationDetected: false,
      entropyScore: 5.2,
      networkActivity: 'None detected during static analysis'
    }
  },
  'react': {
    ecosystem: 'npm',
    version: 'latest',
    riskScore: 4,
    classification: 'LOW',
    decision: 'ALLOW',
    summary: 'Clean verified package. Verified Meta provenance, signed release keys, and zero suspicious lifecycle hooks.',
    findings: [],
    metadata: {
      publisher: 'facebook (verified)',
      publishedDate: 'Official release',
      installScriptDetected: false,
      obfuscationDetected: false,
      entropyScore: 4.12,
      networkActivity: 'None'
    }
  },
  'requests': {
    ecosystem: 'pypi',
    version: 'latest',
    riskScore: 6,
    classification: 'LOW',
    decision: 'ALLOW',
    summary: 'Trustworthy package with millions of downloads, active community governance, and verified security posture.',
    findings: [],
    metadata: {
      publisher: 'psf / Kenneth Reitz (verified)',
      publishedDate: 'Official release',
      installScriptDetected: false,
      obfuscationDetected: false,
      entropyScore: 4.25,
      networkActivity: 'None'
    }
  },
  'express': {
    ecosystem: 'npm',
    version: 'latest',
    riskScore: 9,
    classification: 'LOW',
    decision: 'ALLOW',
    summary: 'Established web framework with OpenSSF Best Practices badge and full dependency chain auditing.',
    findings: [],
    metadata: {
      publisher: 'OpenJS Foundation (verified)',
      publishedDate: 'Stable release',
      installScriptDetected: false,
      obfuscationDetected: false,
      entropyScore: 4.08,
      networkActivity: 'None'
    }
  }
};

// Initial default scan history
const INITIAL_HISTORY = [
  {
    id: 'scan-1001',
    name: 'color-setup-v2',
    ecosystem: 'npm',
    version: '1.2.0',
    riskScore: 96,
    classification: 'HIGH',
    decision: 'BLOCK',
    summary: 'Critical malicious payload in postinstall hook executing encoded PowerShell.',
    timestamp: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
    findingsCount: 3
  },
  {
    id: 'scan-1002',
    name: 'py-cryptoutil-plus',
    ecosystem: 'pypi',
    version: '3.0.0',
    riskScore: 68,
    classification: 'MEDIUM',
    decision: 'WARN',
    summary: 'Drastic maintainer change and suspicious unpinned dependencies.',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    findingsCount: 3
  },
  {
    id: 'scan-1003',
    name: 'requests',
    ecosystem: 'pypi',
    version: '2.31.0',
    riskScore: 6,
    classification: 'LOW',
    decision: 'ALLOW',
    summary: 'Verified community release with clean metadata and signed distribution.',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    findingsCount: 0
  },
  {
    id: 'scan-1004',
    name: 'discord-token-logger',
    ecosystem: 'npm',
    version: '0.4.1',
    riskScore: 92,
    classification: 'HIGH',
    decision: 'BLOCK',
    summary: 'Credential harvesting and webhook exfiltration detected.',
    timestamp: new Date(Date.now() - 1000 * 60 * 310).toISOString(),
    findingsCount: 2
  },
  {
    id: 'scan-1005',
    name: 'express',
    ecosystem: 'npm',
    version: '4.19.2',
    riskScore: 9,
    classification: 'LOW',
    decision: 'ALLOW',
    summary: 'Passed all static and behavioral dependency checks.',
    timestamp: new Date(Date.now() - 1000 * 60 * 600).toISOString(),
    findingsCount: 0
  }
];

const STORAGE_KEY = 'pkgsentinel_scan_history';

/**
 * Get stored scan history from localStorage or fallback to defaults
 */
function getLocalHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_HISTORY));
      return INITIAL_HISTORY;
    }
    return JSON.parse(raw);
  } catch (e) {
    console.warn('LocalStorage error:', e);
    return INITIAL_HISTORY;
  }
}

/**
 * Save history to localStorage
 */
function saveLocalHistory(list) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch (e) {
    console.warn('Failed to save history to localStorage', e);
  }
}

/**
 * Generates synthetic risk assessment for custom packages typed by user
 */
function generateDynamicAnalysis(name, ecosystem, version) {
  const lowerName = name.toLowerCase().trim();

  // If matched predefined sample
  if (KNOWN_SAMPLES[lowerName]) {
    const sample = KNOWN_SAMPLES[lowerName];
    return {
      id: 'scan-' + Date.now().toString(36),
      name,
      ecosystem: sample.ecosystem || ecosystem,
      version: version === 'latest' ? sample.version : version,
      riskScore: sample.riskScore,
      classification: sample.classification,
      decision: sample.decision,
      summary: sample.summary,
      findings: sample.findings,
      metadata: sample.metadata,
      timestamp: new Date().toISOString()
    };
  }

  // Heuristic mock scoring based on package name keywords
  const suspiciousKeywords = ['hack', 'stealer', 'grabber', 'token', 'pass', 'free', 'bot', 'setup', 'inject', 'payload', 'crypto'];
  const isSuspicious = suspiciousKeywords.some(k => lowerName.includes(k));

  let score = 12;
  let classification = 'LOW';
  let decision = 'ALLOW';
  let findings = [];
  let summary = 'Clean package profile. No zero-day malicious behavior patterns identified.';

  if (isSuspicious) {
    score = 88;
    classification = 'HIGH';
    decision = 'BLOCK';
    summary = 'Zero-Day warning: Identified high risk of unauthorized credential collection and hidden lifecycle hooks.';
    findings = [
      {
        category: 'Suspicious Installation Scripts',
        severity: 'CRITICAL',
        title: 'Hidden execution in install script',
        detail: `The package contains pre/post install scripts triggering outbound calls during installation.`,
        recommendation: 'Do not install in development or production environments.'
      },
      {
        category: 'Code Obfuscation',
        severity: 'HIGH',
        title: 'High entropy data blocks detected',
        detail: 'Static analysis flagged payload chunks disguised as config arrays.',
        recommendation: 'Inspect raw package source before approving.'
      }
    ];
  } else if (lowerName.length < 4 || lowerName.includes('test') || lowerName.includes('temp')) {
    score = 45;
    classification = 'MEDIUM';
    decision = 'WARN';
    summary = 'Unusual metadata pattern. Low maintainer reputation and missing provenance signature.';
    findings = [
      {
        category: 'Suspicious Package Metadata',
        severity: 'MEDIUM',
        title: 'Missing source repository and documentation',
        detail: 'The package metadata does not link to an active public repository or verified developer identity.',
        recommendation: 'Verify package integrity with your security team.'
      }
    ];
  }

  return {
    id: 'scan-' + Date.now().toString(36),
    name,
    ecosystem,
    version: version || 'latest',
    riskScore: score,
    classification,
    decision,
    summary,
    findings,
    metadata: {
      publisher: `${lowerName}-publisher (simulated)`,
      publishedDate: 'Recent',
      installScriptDetected: isSuspicious,
      obfuscationDetected: isSuspicious,
      entropyScore: isSuspicious ? 7.4 : 3.8,
      networkActivity: isSuspicious ? 'Suspicious socket connection' : 'None detected'
    },
    timestamp: new Date().toISOString()
  };
}

/**
 * POST /api/scan
 * Submit a package for zero-day scanning
 */
export async function scanPackage({ name, ecosystem, version }) {
  if (!USE_MOCK_DATA) {
    try {
      const res = await fetch(`${BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, ecosystem, version })
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      return data;
    } catch (err) {
      console.warn('Backend unavailable, falling back to client simulation', err);
    }
  }

  // Simulated scan delay to represent deep inspection pipeline
  await new Promise(resolve => setTimeout(resolve, 1800));

  const result = generateDynamicAnalysis(name, ecosystem, version);

  // Prepend to history
  const history = getLocalHistory();
  const historyItem = {
    id: result.id,
    name: result.name,
    ecosystem: result.ecosystem,
    version: result.version,
    riskScore: result.riskScore,
    classification: result.classification,
    decision: result.decision,
    summary: result.summary,
    timestamp: result.timestamp,
    findingsCount: result.findings.length
  };

  const updatedHistory = [historyItem, ...history.filter(h => h.id !== result.id)].slice(0, 30);
  saveLocalHistory(updatedHistory);

  return result;
}

/**
 * GET /api/scans
 * Retrieve recent scan history
 */
export async function getScans() {
  if (!USE_MOCK_DATA) {
    try {
      const res = await fetch(`${BASE_URL}/scans`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('Backend unavailable, using local mock data', err);
    }
  }

  // Small delay for UI smoothness
  await new Promise(resolve => setTimeout(resolve, 300));
  return getLocalHistory();
}

/**
 * GET /api/scans/:id
 * Retrieve a specific scan details
 */
export async function getScanById(id) {
  if (!USE_MOCK_DATA) {
    try {
      const res = await fetch(`${BASE_URL}/scans/${id}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('Backend unavailable, using local mock data', err);
    }
  }

  const history = getLocalHistory();
  const match = history.find(item => item.id === id);
  if (match) {
    // Generate full scan report for this item
    return generateDynamicAnalysis(match.name, match.ecosystem, match.version);
  }
  return null;
}

/**
 * Helper to reset history to demo default
 */
export function resetDemoHistory() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_HISTORY));
  return INITIAL_HISTORY;
}
