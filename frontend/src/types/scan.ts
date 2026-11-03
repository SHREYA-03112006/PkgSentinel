import { ScanStatus } from './report';

export interface ScanRequestPayload {
  ecosystem: 'NPM' | 'PYPI' | 'npm' | 'pypi';
  name: string;
  version: string;
}

export interface BackendScanJobResponse {
  jobId: string;
  packageEcosystem: string;
  packageName: string;
  packageVersion: string;
  status: ScanStatus;
  createdAt: string;
  message?: string;
}

export interface BackendPage<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  size: number;
  number: number;
}

export interface UIHistoryItem {
  id: string;
  name: string;
  ecosystem: 'npm' | 'pypi';
  version: string;
  riskScore: number;
  classification: 'LOW' | 'MEDIUM' | 'HIGH';
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  status: ScanStatus;
  summary: string;
  timestamp: string;
  findingsCount: number;
}
