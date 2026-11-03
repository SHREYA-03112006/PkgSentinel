import { request } from './apiClient';
import { BackendPage, UIHistoryItem } from '../types/scan';
import { BackendScanReport } from '../types/report';
import { mapBackendVerdictToUI } from '../types/verdict';

export interface HistoryResponse {
  items: UIHistoryItem[];
  total: number;
}

export async function getScanHistory(page: number = 0, size: number = 50): Promise<HistoryResponse> {
  try {
    const pageData = await request<BackendPage<BackendScanReport>>(`/scans?page=${page}&size=${size}`);
    const items: UIHistoryItem[] = (pageData.content || []).map((report) => {
      const risk = report.riskScore ? Number(report.riskScore) : 0;
      const { decision, classification } = mapBackendVerdictToUI(report.verdict, risk);
      const summary = report.summaryNotes || (report.verdictReasons && report.verdictReasons[0]) || (
        report.status === 'COMPLETED' ? 'Heuristic analysis complete' : `Job status: ${report.status}`
      );

      return {
        id: report.jobId,
        name: report.name,
        ecosystem: (report.ecosystem?.toLowerCase() === 'pypi' ? 'pypi' : 'npm'),
        version: report.version,
        riskScore: Math.round(risk),
        classification,
        decision,
        status: report.status,
        summary,
        timestamp: report.completedAt || report.createdAt || new Date().toISOString(),
        findingsCount: report.findings?.length || 0
      };
    });

    return {
      items,
      total: pageData.totalElements || 0
    };
  } catch (err) {
    console.warn('Failed to load scan history from backend:', err);
    return { items: [], total: 0 };
  }
}
