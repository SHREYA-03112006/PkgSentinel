import { request } from './apiClient';
import { BackendScanJobResponse } from '../types/scan';
import { BackendScanReport, UIScanResult, mapBackendReportToUI } from '../types/report';
import { getScanHistory } from './historyService';
import { getScanReport } from './reportService';

export interface ScanSubmissionParams {
  name: string;
  ecosystem: 'npm' | 'pypi' | string;
  version?: string;
  onProgress?: (progress: { stage: string; percent: number; status: string }) => void;
}

export interface SystemHealth {
  status: 'HEALTHY' | 'DEGRADED' | 'OFFLINE';
  service: string;
  version: string;
  components: Record<string, string>;
}

/**
 * Checks system health via Spring Boot /api/v1/health
 */
export async function checkSystemHealth(): Promise<SystemHealth> {
  try {
    const data = await request<SystemHealth>('/health');
    return data;
  } catch {
    return {
      status: 'OFFLINE',
      service: 'pkgsentinel-backend',
      version: '0.1.0',
      components: { backend: 'DOWN' }
    };
  }
}

/**
 * Submits an npm or PyPI package for real zero-day heuristic scanning,
 * and polls until the job reaches COMPLETED or FAILED.
 */
export async function scanPackage({
  name,
  ecosystem,
  version = 'latest',
  onProgress
}: ScanSubmissionParams): Promise<UIScanResult> {
  const normalizedEco = ecosystem.toUpperCase() === 'PYPI' ? 'PYPI' : 'NPM';
  const trimmedName = name.trim();
  const trimmedVersion = version.trim() || 'latest';

  onProgress?.({
    stage: 'Submitting scan request to orchestrator outbox...',
    percent: 15,
    status: 'QUEUED'
  });

  // 1. Submit scan job to Spring Boot
  const submission = await request<BackendScanJobResponse>('/scans', {
    method: 'POST',
    body: JSON.stringify({
      ecosystem: normalizedEco,
      name: trimmedName,
      version: trimmedVersion
    })
  });

  const jobId = submission.jobId;

  // 2. Poll scan status until terminal state
  const maxAttempts = 50; // ~60 seconds timeout
  const pollIntervalMs = 1200;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

    const report = await request<BackendScanReport>(`/scans/${jobId}`);

    if (report.status === 'PROCESSING') {
      onProgress?.({
        stage: 'Decompressing archive & traversing AST heuristics...',
        percent: 45 + Math.min(attempt * 4, 45),
        status: 'PROCESSING'
      });
    } else if (report.status === 'COMPLETED') {
      onProgress?.({
        stage: 'Verifying findings & calculating risk score...',
        percent: 100,
        status: 'COMPLETED'
      });
      return mapBackendReportToUI(report);
    } else if (report.status === 'FAILED') {
      throw new Error(report.failureReason || `Package inspection failed for ${trimmedName}@${trimmedVersion}`);
    }
  }

  throw new Error(`Scan timed out after 60s for job ${jobId}. The worker may be processing a large package.`);
}

/**
 * Get recent scan history items
 */
export async function getScans() {
  const result = await getScanHistory(0, 50);
  return result.items;
}

/**
 * Get full report by job ID
 */
export async function getScanById(id: string): Promise<UIScanResult | null> {
  try {
    return await getScanReport(id);
  } catch (err) {
    console.error(`Failed to fetch scan report ${id}:`, err);
    return null;
  }
}
