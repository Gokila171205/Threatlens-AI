import type { UserRole } from '../types';
import type { LoginCredentials, UserSession } from '../types/auth';
import { API_URL, validateApiConfig } from '../config/api';
import { httpClient } from './httpClient';

const USER_SESSION_KEY = 'threatlens_user_session';

/**
 * Standard test credentials for development/evaluation quick-login.
 * Every persona calls the real backend POST /api/auth/login endpoint.
 */
const ROLE_TEST_CREDENTIALS: Record<UserRole, { email: string; pass: string }> = {
  'Security Analyst': {
    email: 'analyst@threatlens.ai',
    pass: 'analyst123',
  },
  'SOC Team Member': {
    email: 'soc@threatlens.ai',
    pass: 'soc123',
  },
  'Administrator': {
    email: 'admin@threatlens.ai',
    pass: 'admin123',
  },
  'Researcher': {
    email: 'researcher@threatlens.ai',
    pass: 'research123',
  },
};

export const AuthService = {
  /**
   * Register a new user against FastAPI backend POST /api/auth/register
   */
  register: async (name: string, email: string, password: string): Promise<any> => {
    validateApiConfig();

    let response: Response;
    try {
      response = await fetch(`${API_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ name, email, password }),
      });
    } catch (err: any) {
      if (err?.message && err.message.includes('VITE_API_URL')) {
        throw err;
      }
      throw new Error('Failed to connect to authentication server. Verify backend is running.');
    }

    if (!response.ok) {
      let errMsg = 'Registration failed.';
      try {
        const errJson = await response.json();
        errMsg = errJson.message || errJson.detail?.message || errJson.detail || errMsg;
      } catch {
        // use default
      }
      throw new Error(typeof errMsg === 'string' ? errMsg : 'Registration failed.');
    }

    return response.json();
  },

  /**
   * Authenticate user against FastAPI backend POST /api/auth/login
   * Validates credentials, receives genuine JWT, and loads /api/auth/me profile.
   */
  login: async (credentials: LoginCredentials): Promise<UserSession> => {
    const email = credentials.email.trim();
    const password = credentials.password;

    if (!email || !password) {
      throw new Error('Both email and password are required.');
    }

    validateApiConfig();

    let response: Response;
    try {
      response = await fetch(`${API_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });
    } catch (err: any) {
      if (err?.message && err.message.includes('VITE_API_URL')) {
        throw err;
      }
      throw new Error('Failed to connect to authentication server. Verify backend is running.');
    }

    if (!response.ok) {
      let errMsg = 'Invalid email or password.';
      try {
        const errJson = await response.json();
        errMsg = errJson.message || errJson.detail?.message || errJson.detail || errMsg;
      } catch {
        // use default
      }
      throw new Error(typeof errMsg === 'string' ? errMsg : 'Invalid email or password.');
    }

    const data = await response.json();
    const token: string = data.token;
    if (!token) {
      throw new Error('Authentication response did not provide an access token.');
    }

    // Securely persist server-signed JWT
    httpClient.setAuthToken(token);
    // Also set legacy key if any component reads it
    localStorage.setItem('threatlens_session_token', token);

    // Verify session with GET /api/auth/me
    let meData: any;
    try {
      meData = await httpClient.request<{ success: boolean; user: any }>('/auth/me');
    } catch {
      meData = { user: data.user };
    }

    const u = meData?.user || data.user;
    const role: UserRole = (u.role || 'Security Analyst') as UserRole;

    const initials = (u.name || 'User')
      .split(' ')
      .map((part: string) => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);

    const session: UserSession = {
      id: u.id,
      name: u.name,
      email: u.email,
      role,
      department: u.department || (role === 'Administrator' ? 'SecOps & Infrastructure' : 'Tier 3 Incident Response'),
      clearanceLevel: role === 'Administrator' ? 'DEFCON-1 / TOP SECRET' : 'DEFCON-2 / RESTRICTED',
      token,
      expiresAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      avatarInitials: initials || 'TL',
    };

    localStorage.setItem(USER_SESSION_KEY, JSON.stringify(session));
    return session;
  },

  /**
   * Development-only quick-login: Authenticates the selected role persona
   * through the real backend API using standard seeded credentials.
   */
  loginAsRole: async (role: UserRole): Promise<UserSession> => {
    const creds = ROLE_TEST_CREDENTIALS[role];
    if (!creds) {
      throw new Error(`Unrecognized persona role: ${role}`);
    }
    return AuthService.login({ email: creds.email, password: creds.pass });
  },

  /**
   * Retrieves active authenticated session from local storage.
   */
  getCurrentSession: (): UserSession | null => {
    try {
      const token = httpClient.getAuthToken() || localStorage.getItem('threatlens_session_token');
      const userStr = localStorage.getItem(USER_SESSION_KEY);
      if (!token || !userStr) return null;

      const user: UserSession = JSON.parse(userStr);
      if (new Date(user.expiresAt).getTime() < Date.now()) {
        AuthService.logout();
        return null;
      }
      return user;
    } catch {
      AuthService.logout();
      return null;
    }
  },

  /**
   * Destroys active user session and clears all security tokens.
   */
  logout: (): void => {
    httpClient.removeAuthToken();
    localStorage.removeItem('threatlens_session_token');
    localStorage.removeItem(USER_SESSION_KEY);
  },
};
