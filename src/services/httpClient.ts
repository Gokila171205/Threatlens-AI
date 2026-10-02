/**
 * ThreatLens AI Centralized HTTP Client & Service Layer
 * Supports seamless plug-and-play backend integration with automatic mock fallback.
 */

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string) || 'http://localhost:8000/api';
export const USE_MOCK_API = (import.meta.env.VITE_USE_MOCK_API as string) === 'true';

export class ApiError extends Error {
  public status: number;
  public errorCode: string;

  constructor(status: number, message: string, errorCode: string = 'ERR_API_UNKNOWN') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errorCode = errorCode;
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

/**
 * Sanitizes backend HTTP error status into clear, operational SOC messages.
 */
function sanitizeErrorMessage(status: number, rawMessage?: string): { message: string; errorCode: string } {
  switch (status) {
    case 401:
      return {
        message: 'Security Session Expired — Please re-authenticate your credentials.',
        errorCode: 'ERR_AUTH_UNAUTHORIZED_401',
      };
    case 403:
      return {
        message: 'Access Denied — Account lacks clearance for target security endpoint.',
        errorCode: 'ERR_AUTH_FORBIDDEN_403',
      };
    case 404:
      return {
        message: 'Threat Resource Not Found — Hash or sample identifier does not exist.',
        errorCode: 'ERR_RESOURCE_NOT_FOUND_404',
      };
    case 422:
      return {
        message: 'Unprocessable Payload — Invalid binary header structure or missing parameters.',
        errorCode: 'ERR_UNPROCESSABLE_ENTITY_422',
      };
    case 429:
      return {
        message: 'Rate Limit Exceeded — Telemetry query threshold exceeded. Retry in 60s.',
        errorCode: 'ERR_RATE_LIMIT_EXCEEDED_429',
      };
    case 500:
    case 502:
    case 503:
      return {
        message: 'Telemetry Ingestion Stream Error — Backend sensor cluster offline or degraded.',
        errorCode: `ERR_INTERNAL_SERVER_${status}`,
      };
    default:
      return {
        message: rawMessage || 'Network Communication Failure — Sensor endpoint unreachable.',
        errorCode: 'ERR_NETWORK_FAILURE',
      };
  }
}

export const httpClient = {
  getAuthToken: (): string | null => {
    return localStorage.getItem('threatlens_auth_token');
  },

  setAuthToken: (token: string): void => {
    localStorage.setItem('threatlens_auth_token', token);
  },

  removeAuthToken: (): void => {
    localStorage.removeItem('threatlens_auth_token');
  },

  async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { timeoutMs = 25000, headers = {}, ...customConfig } = options;

    const token = this.getAuthToken();

    const headersObj: Record<string, string> = {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(headers as Record<string, string>),
    };

    if (!(customConfig.body instanceof FormData)) {
      headersObj['Content-Type'] = headersObj['Content-Type'] || 'application/json';
    }

    const config: RequestInit = {
      ...customConfig,
      headers: headersObj,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    config.signal = controller.signal;

    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
      clearTimeout(timeoutId);

      if (!response.ok) {
        let rawErrorMsg = '';
        try {
          const errJson = await response.json();
          rawErrorMsg = errJson.message || errJson.detail || '';
        } catch {
          // ignore JSON parse failure on non-JSON error pages
        }

        const sanitized = sanitizeErrorMessage(response.status, rawErrorMsg);
        throw new ApiError(response.status, sanitized.message, sanitized.errorCode);
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      clearTimeout(timeoutId);

      if (err instanceof ApiError) {
        throw err;
      }

      if (err instanceof Error && err.name === 'AbortError') {
        throw new ApiError(408, 'Ingestion Sensor Timeout — Request exceeded 15,000ms limit.', 'ERR_TIMEOUT_408');
      }

      const sanitized = sanitizeErrorMessage(0, err instanceof Error ? err.message : undefined);
      throw new ApiError(0, sanitized.message, sanitized.errorCode);
    }
  },
};
