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

interface ParsedResponse {
  rawText: string;
  data: unknown;
}

/**
 * Safely consumes an HTTP Response body exactly once.
 * Handles JSON, empty responses (e.g. 204 No Content), plain-text errors, and HTML proxy pages.
 */
async function parseResponseBody(response: Response): Promise<ParsedResponse> {
  // 1. Empty body statuses or zero content-length
  if (response.status === 204 || response.headers.get('content-length') === '0') {
    return { rawText: '', data: null };
  }

  // 2. Consume the body stream ONCE as raw text
  let rawText = '';
  try {
    rawText = await response.text();
  } catch {
    return { rawText: '', data: null };
  }

  const trimmed = rawText.trim();
  if (!trimmed) {
    return { rawText: '', data: null };
  }

  // 3. Attempt JSON parse from the text string
  try {
    const json = JSON.parse(trimmed);
    return { rawText, data: json };
  } catch {
    // Non-JSON response (plain-text message or HTML error page)
    return { rawText, data: trimmed };
  }
}

/**
 * Extracts a human-readable, actionable error message from status and parsed data.
 * Prioritizes backend validation errors, message fields, plain text, and status code fallbacks.
 */
function extractErrorMessage(status: number, statusText: string, data: unknown): string {
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;

    // 1. Check for field validation maps (e.g. from GlobalExceptionHandler or Bean Validation)
    if (obj.validationErrors && typeof obj.validationErrors === 'object') {
      const errs = Object.values(obj.validationErrors as Record<string, string>).filter(Boolean);
      if (errs.length > 0) {
        return errs.join(', ');
      }
    }

    // 2. Check for Spring Boot default errors array
    if (Array.isArray(obj.errors) && obj.errors.length > 0) {
      const msgs = obj.errors
        .map((e) => (typeof e === 'object' && e !== null && 'defaultMessage' in e ? String((e as { defaultMessage: unknown }).defaultMessage) : String(e)))
        .filter(Boolean);
      if (msgs.length > 0) {
        return msgs.join(', ');
      }
    }

    // 3. Explicit message field
    if (typeof obj.message === 'string' && obj.message.trim().length > 0) {
      return obj.message.trim();
    }

    // 4. Explicit error field
    if (typeof obj.error === 'string' && obj.error.trim().length > 0) {
      return obj.error.trim();
    }
  }

  // 5. Plain text string (ensure it's not raw HTML)
  if (typeof data === 'string' && data.length > 0) {
    if (!data.startsWith('<') && !data.includes('<!DOCTYPE') && data.length < 300) {
      return data;
    }
  }

  // 6. Semantic status fallbacks
  switch (status) {
    case 400:
      return 'Invalid request format or missing required fields.';
    case 401:
      return 'Authentication required. Please verify your credentials.';
    case 403:
      return 'Access denied. You do not have permission to perform this action.';
    case 404:
      return 'The requested resource was not found.';
    case 409:
      return 'Conflict: An account with this username or email already exists.';
    case 500:
    case 502:
    case 503:
    case 504:
      return 'Backend service is currently unavailable. Please verify the security engine is running.';
    default:
      return `Request failed with HTTP status ${status}${statusText ? `: ${statusText}` : ''}.`;
  }
}

export async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_ROOT}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  // Identify SPA fetch requests to prevent basic auth challenges
  if (!headers.has('X-Requested-With')) {
    headers.set('X-Requested-With', 'XMLHttpRequest');
  }

  // Inject Bearer token if present and not explicitly provided
  if (!headers.has('Authorization')) {
    try {
      const token = localStorage.getItem('pkgsentinel_auth_token');
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
    } catch {
      // Storage access may be restricted
    }
  }

  const config: RequestInit = {
    ...options,
    headers,
  };

  const response = await fetch(url, config);
  const { data } = await parseResponseBody(response);

  if (!response.ok) {
    const message = extractErrorMessage(response.status, response.statusText, data);
    throw new ApiError(message, response.status, data);
  }

  return data as T;
}
