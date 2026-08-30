import type { UserRole } from './index';

export type Permission =
  | 'upload_file'
  | 'run_static_analysis'
  | 'view_classification'
  | 'view_monitoring'
  | 'review_alerts'
  | 'generate_reports'
  | 'manage_users'
  | 'manage_settings'
  | 'manage_integrations'
  | 'access_datasets'
  | 'view_historical_analytics';

export interface UserSession {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  department: string;
  clearanceLevel: string;
  token: string;
  expiresAt: string;
  avatarInitials: string;
}

export interface LoginCredentials {
  email: string;
  password?: string;
  mfaCode?: string;
}

export interface AuthState {
  user: UserSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}
