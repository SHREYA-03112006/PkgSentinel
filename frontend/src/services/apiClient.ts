/**
 * Centralized API Client for PkgSentinel
 */

const RAW_BASE = import.meta.env.VITE_API_BASE_URL || '';
// Clean trailing slashes
const CLEAN_BASE = RAW_BASE ? RAW_BASE.replace(/\/+$/, '') : '';

export const API_ROOT = CLEAN_BASE ? `${CLEAN_BASE}/api/v1` : '/api/v1';

export class ApiError extends Error {
  status: number;
  data: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_ROOT}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const config: RequestInit = {
    ...options,
    headers,
  };

  const response = await fetch(url, config);

  if (!response.ok) {
    let errorData: unknown;
    try {
      errorData = await response.json();
    } catch {
      errorData = await response.text();
    }
    const message = (errorData && typeof errorData === 'object' && 'message' in errorData)
      ? String((errorData as { message: unknown }).message)
      : `HTTP error ${response.status}: ${response.statusText}`;
    throw new ApiError(message, response.status, errorData);
  }

  return response.json() as Promise<T>;
}
