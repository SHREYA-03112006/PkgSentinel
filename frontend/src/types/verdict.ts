export type BackendVerdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
export type UIVerdict = 'ALLOW' | 'WARN' | 'BLOCK';
export type RiskClassification = 'LOW' | 'MEDIUM' | 'HIGH';

export function mapBackendVerdictToUI(verdict?: BackendVerdict | null, riskScore: number = 0): {
  decision: UIVerdict;
  classification: RiskClassification;
} {
  if (verdict === 'MALICIOUS' || riskScore >= 70) {
    return { decision: 'BLOCK', classification: 'HIGH' };
  }
  if (verdict === 'SUSPICIOUS' || riskScore >= 30) {
    return { decision: 'WARN', classification: 'MEDIUM' };
  }
  return { decision: 'ALLOW', classification: 'LOW' };
}

