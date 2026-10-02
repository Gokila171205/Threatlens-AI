/**
 * ThreatLens AI - Centralized API Configuration
 * 
 * Safely resolves backend API URLs across local development and production.
 * Ensures production never silently falls back to localhost and validates configuration.
 */

// Read VITE_API_URL from Vite environment (also support VITE_API_BASE_URL as fallback if previously configured)
const rawEnvUrl = (
  (import.meta.env.VITE_API_URL as string | undefined) ||
  (import.meta.env.VITE_API_BASE_URL as string | undefined)
)?.trim();

// Normalize: remove trailing slashes and trailing '/api'
const cleanApiUrl = rawEnvUrl
  ? rawEnvUrl.replace(/\/+$/, '').replace(/\/api$/, '')
  : '';

/**
 * Base API URL (e.g. "https://threatlens-backend.onrender.com" or "http://localhost:8000" in DEV)
 * In production, strictly uses the configured environment variable with no silent localhost fallback.
 */
export const API_URL: string =
  cleanApiUrl || (import.meta.env.DEV ? 'http://localhost:8000' : '');

/**
 * Validates that API configuration is present.
 * Throws a descriptive error in production if VITE_API_URL is missing.
 */
export function validateApiConfig(): void {
  if (!API_URL && !import.meta.env.DEV) {
    const errorMsg = 'VITE_API_URL is not configured for this deployment.';
    console.error(`[ThreatLens Config Error] ${errorMsg}`);
    throw new Error(errorMsg);
  }
}

/**
 * Base API endpoint path including '/api' prefix (e.g. "https://threatlens-backend.onrender.com/api")
 */
export const API_BASE_URL: string = API_URL ? `${API_URL}/api` : '';
