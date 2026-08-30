import type { UserRole } from '../types';
import type { Permission } from '../types/auth';

/**
 * Centralized ThreatLens AI Role-Permission Matrix
 */
export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  'Security Analyst': [
    'upload_file',
    'run_static_analysis',
    'view_classification',
    'view_monitoring',
    'review_alerts',
    'generate_reports',
    'view_historical_analytics',
  ],
  'SOC Team Member': [
    'view_classification',
    'view_monitoring',
    'review_alerts',
    'generate_reports',
    'view_historical_analytics',
  ],
  'Administrator': [
    'upload_file',
    'run_static_analysis',
    'view_classification',
    'view_monitoring',
    'review_alerts',
    'generate_reports',
    'manage_users',
    'manage_settings',
    'manage_integrations',
    'access_datasets',
    'view_historical_analytics',
  ],
  'Researcher': [
    'upload_file',
    'run_static_analysis',
    'view_classification',
    'view_monitoring',
    'generate_reports',
    'access_datasets',
    'view_historical_analytics',
  ],
};

/**
 * Check if a role possesses a specific permission.
 */
export function hasPermission(role: UserRole | undefined | null, permission: Permission): boolean {
  if (!role) return false;
  const permissions = ROLE_PERMISSIONS[role];
  if (!permissions) return false;
  return permissions.includes(permission);
}

/**
 * Check if a role possesses ANY of the given permissions.
 */
export function hasAnyPermission(role: UserRole | undefined | null, permissions: Permission[]): boolean {
  if (!role || !permissions.length) return false;
  return permissions.some((p) => hasPermission(role, p));
}

/**
 * Check if a role possesses ALL of the given permissions.
 */
export function hasAllPermissions(role: UserRole | undefined | null, permissions: Permission[]): boolean {
  if (!role || !permissions.length) return false;
  return permissions.every((p) => hasPermission(role, p));
}
