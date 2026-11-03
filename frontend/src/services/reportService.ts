import { request } from './apiClient';
import { BackendScanReport, UIScanResult, mapBackendReportToUI } from '../types/report';

export async function getBackendScanReport(jobId: string): Promise<BackendScanReport> {
  return request<BackendScanReport>(`/scans/${jobId}`);
}

export async function getScanReport(jobId: string): Promise<UIScanResult> {
  const backendReport = await getBackendScanReport(jobId);
  return mapBackendReportToUI(backendReport);
}

