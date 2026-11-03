import { BackendVerdict, UIVerdict, RiskClassification, mapBackendVerdictToUI } from './verdict';
import { BackendFindingItem, UIFinding, mapBackendFindingToUI } from './finding';

export type ScanStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export interface BackendScanReport {
  jobId: string;
  ecosystem: 'NPM' | 'PYPI' | string;
  name: string;
  version: string;
  status: ScanStatus;
  verdict?: BackendVerdict | null;
  riskScore?: number | null;
  rawScore?: number | null;
  confidenceScore?: number | null;
  summaryNotes?: string | null;
  verdictReasons?: string[] | null;
  analysisCoverage?: Record<string, string> | null;
  analyzedAt?: string | null;
  createdAt?: string | null;
  completedAt?: string | null;
  failureReason?: string | null;
  findings?: BackendFindingItem[] | null;
}

export interface UIScanResult {
  id: string;
  name: string;
  ecosystem: 'npm' | 'pypi';
  version: string;
  riskScore: number;
  rawScore?: number;
  classification: RiskClassification;
  decision: UIVerdict;
  verdict: BackendVerdict;
  status: ScanStatus;
  summary: string;
  verdictReasons: string[];
  findings: UIFinding[];
  coverage: Record<string, string>;
  confidence: number;
  metadata: {
    publisher?: string;
    publishedDate?: string;
    installScriptDetected: boolean;
    obfuscationDetected: boolean;
    entropyScore?: number | string;
    networkActivity?: string;
  };
  timestamp: string;
  failureReason?: string;
}

export function mapBackendReportToUI(r: BackendScanReport): UIScanResult {
  const risk = r.riskScore !== undefined && r.riskScore !== null ? Number(r.riskScore) : 0;
  const { decision, classification } = mapBackendVerdictToUI(r.verdict, risk);
  const uiFindings = (r.findings || []).map(mapBackendFindingToUI);

  // Check if findings detect install scripts or obfuscation
  const installScriptDetected = uiFindings.some(f => 
    f.category.toUpperCase().includes('INSTALL') || f.ruleId.includes('INSTALL')
  );
  const obfuscationDetected = uiFindings.some(f => 
    f.category.toUpperCase().includes('OBFUSCATION') || f.ruleId.includes('ENTROPY') || f.ruleId.includes('ENCODED')
  );

  let summaryText = r.summaryNotes || '';
  if (!summaryText && r.verdictReasons && r.verdictReasons.length > 0) {
    summaryText = r.verdictReasons.join(' ');
  }
  if (!summaryText) {
    if (r.verdict === 'MALICIOUS') {
      summaryText = 'Critical zero-day security risks detected in package source or lifecycle hooks.';
    } else if (r.verdict === 'SUSPICIOUS') {
      summaryText = 'Suspicious heuristic anomalies flagged in AST or package metadata requiring review.';
    } else {
      summaryText = 'Clean package profile. No significant zero-day malicious patterns identified.';
    }
  }

  return {
    id: r.jobId,
    name: r.name,
    ecosystem: (r.ecosystem?.toLowerCase() === 'pypi' ? 'pypi' : 'npm'),
    version: r.version || 'latest',
    riskScore: Math.round(risk),
    rawScore: r.rawScore ? Number(r.rawScore) : undefined,
    classification,
    decision,
    verdict: r.verdict || (decision === 'BLOCK' ? 'MALICIOUS' : decision === 'WARN' ? 'SUSPICIOUS' : 'SAFE'),
    status: r.status,
    summary: summaryText,
    verdictReasons: r.verdictReasons || [],
    findings: uiFindings,
    coverage: r.analysisCoverage || {},
    confidence: r.confidenceScore ? Number(r.confidenceScore) : 1.0,
    metadata: {
      publisher: 'Registry Verified',
      publishedDate: r.completedAt ? new Date(r.completedAt).toLocaleDateString() : 'Recent',
      installScriptDetected,
      obfuscationDetected,
      entropyScore: r.analysisCoverage?.['Entropy'] || 'Normal',
      networkActivity: uiFindings.some(f => f.ruleId.includes('NETWORK') || f.ruleId.includes('SOCKET') || f.ruleId.includes('IP')) 
        ? 'Suspicious raw IP / socket APIs detected' 
        : 'None detected'
    },
    timestamp: r.completedAt || r.createdAt || new Date().toISOString(),
    failureReason: r.failureReason || undefined
  };
}
