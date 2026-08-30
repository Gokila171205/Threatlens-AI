import type { UserRole } from '../types';
import type { LoginCredentials, UserSession } from '../types/auth';

const TOKEN_KEY = 'threatlens_session_token';
const USER_KEY = 'threatlens_user_session';

export const DEMO_USERS: Record<UserRole, UserSession> = {
  'Security Analyst': {
    id: 'usr_soc_9412',
    name: 'Alex Rivera',
    email: 'a.rivera@defense.threatlens.ai',
    role: 'Security Analyst',
    department: 'Tier 3 Incident Response',
    clearanceLevel: 'DEFCON-2 / RESTRICTED',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.analyst_token_9412',
    expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    avatarInitials: 'AR',
  },
  'SOC Team Member': {
    id: 'usr_soc_8820',
    name: 'Sarah Chen',
    email: 's.chen@soc.threatlens.ai',
    role: 'SOC Team Member',
    department: 'Global SOC Operations Center',
    clearanceLevel: 'DEFCON-3 / CONFIDENTIAL',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.soc_token_8820',
    expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    avatarInitials: 'SC',
  },
  'Administrator': {
    id: 'usr_admin_001',
    name: 'Marcus Vance',
    email: 'm.vance@admin.threatlens.ai',
    role: 'Administrator',
    department: 'Cyber Infrastructure & SecOps',
    clearanceLevel: 'DEFCON-1 / TOP SECRET',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token_001',
    expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    avatarInitials: 'MV',
  },
  'Researcher': {
    id: 'usr_res_3309',
    name: 'Dr. Elena Rostova',
    email: 'e.rostova@lab.threatlens.ai',
    role: 'Researcher',
    department: 'AI Neural Malware Lab',
    clearanceLevel: 'DEFCON-2 / SCI RESEARCH',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.researcher_token_3309',
    expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    avatarInitials: 'ER',
  },
};

export const AuthService = {
  /**
   * Authenticate user with credentials or role key.
   */
  login: async (credentials: LoginCredentials): Promise<UserSession> => {
    // Simulate API network latency
    await new Promise((res) => setTimeout(res, 450));

    const emailLower = credentials.email.toLowerCase().trim();

    // Check matching demo email or role keyword
    let matchedUser: UserSession | undefined;

    if (emailLower.includes('analyst') || emailLower === DEMO_USERS['Security Analyst'].email) {
      matchedUser = DEMO_USERS['Security Analyst'];
    } else if (emailLower.includes('soc') || emailLower === DEMO_USERS['SOC Team Member'].email) {
      matchedUser = DEMO_USERS['SOC Team Member'];
    } else if (emailLower.includes('admin') || emailLower === DEMO_USERS['Administrator'].email) {
      matchedUser = DEMO_USERS['Administrator'];
    } else if (emailLower.includes('research') || emailLower === DEMO_USERS['Researcher'].email) {
      matchedUser = DEMO_USERS['Researcher'];
    } else if (credentials.password && credentials.password.length >= 6) {
      // Default to Security Analyst for generic valid credentials
      matchedUser = {
        ...DEMO_USERS['Security Analyst'],
        email: credentials.email,
        name: credentials.email.split('@')[0].replace('.', ' '),
      };
    }

    if (!matchedUser) {
      throw new Error('Invalid security credentials or unrecognized analyst clearance.');
    }

    // Persist session securely
    const session = {
      ...matchedUser,
      expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
    };

    localStorage.setItem(TOKEN_KEY, session.token);
    localStorage.setItem(USER_KEY, JSON.stringify(session));

    return session;
  },

  /**
   * Directly login with a persona for seamless SOC testing
   */
  loginAsRole: async (role: UserRole): Promise<UserSession> => {
    await new Promise((res) => setTimeout(res, 250));
    const session = DEMO_USERS[role];
    localStorage.setItem(TOKEN_KEY, session.token);
    localStorage.setItem(USER_KEY, JSON.stringify(session));
    return session;
  },

  /**
   * Retrieve active session from storage
   */
  getCurrentSession: (): UserSession | null => {
    try {
      const token = localStorage.getItem(TOKEN_KEY);
      const userStr = localStorage.getItem(USER_KEY);
      if (!token || !userStr) return null;
      const user: UserSession = JSON.parse(userStr);
      // Check expiration
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
   * Destroy user session
   */
  logout: (): void => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
};
