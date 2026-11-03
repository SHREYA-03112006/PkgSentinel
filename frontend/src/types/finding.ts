export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface BackendFindingItem {
  findingId: string;
  moduleName: string;
  ruleId: string;
  category: string;
  severity: SeverityLevel;
  confidence: number;
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  codeSnippet?: string;
  detectionMethod: string;
}

export interface UIFinding {
  findingId: string;
  category: string;
  severity: SeverityLevel;
  title: string;
  detail: string;
  recommendation?: string;
  filePath?: string;
  lineNumber?: number;
  codeSnippet?: string;
  detectionMethod: string;
  confidence: number;
  ruleId: string;
}

export function mapBackendFindingToUI(f: BackendFindingItem): UIFinding {
  let recommendation = 'Review package dependencies and source before approving.';
  if (f.severity === 'CRITICAL') {
    recommendation = 'Quarantine or remove dependency immediately. Do not execute or install.';
  } else if (f.severity === 'HIGH') {
    recommendation = 'Investigate flagged API usage, credential hooks, or network calls.';
  } else if (f.severity === 'MEDIUM') {
    recommendation = 'Audit package provenance, repository links, and maintainer changes.';
  } else {
    recommendation = 'Informational finding. Verify alignment with security policy.';
  }

  return {
    findingId: f.findingId,
    category: f.category || 'Static Analysis',
    severity: f.severity,
    title: f.title,
    detail: f.description,
    recommendation,
    filePath: f.filePath,
    lineNumber: f.lineNumber,
    codeSnippet: f.codeSnippet,
    detectionMethod: f.detectionMethod || 'HEURISTIC',
    confidence: f.confidence ?? 1.0,
    ruleId: f.ruleId
  };
}
