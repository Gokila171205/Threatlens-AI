import { NAVIGATION_ITEMS } from '../data/mockData';
import type { NavigationItem, UserRole } from '../types';
import type { Permission } from '../types/auth';
import { hasPermission } from '../utils/permissions';

export const ROUTES = {
  LOGIN: '/login',
  OVERVIEW: '/overview',
  FILE_ANALYSIS: '/file-analysis',
  MALWARE_CLASSIFICATION: '/malware-classification',
  THREAT_MONITORING: '/threat-monitoring',
  ALERTS: '/alerts',
  ANALYTICS: '/analytics',
  REPORTS: '/reports',
  RESEARCH: '/research',
  ADMIN: '/admin',
  PROFILE: '/profile',
};

export const ROUTE_PERMISSIONS: Record<string, Permission> = {
  [ROUTES.OVERVIEW]: 'view_classification',
  [ROUTES.FILE_ANALYSIS]: 'run_static_analysis',
  [ROUTES.MALWARE_CLASSIFICATION]: 'view_classification',
  [ROUTES.THREAT_MONITORING]: 'view_monitoring',
  [ROUTES.ALERTS]: 'review_alerts',
  [ROUTES.ANALYTICS]: 'view_historical_analytics',
  [ROUTES.REPORTS]: 'generate_reports',
  [ROUTES.RESEARCH]: 'access_datasets',
  [ROUTES.ADMIN]: 'manage_users',
};

export function getFilteredNavigation(role: UserRole | undefined): NavigationItem[] {
  if (!role) return [];
  return NAVIGATION_ITEMS.filter((item) => {
    const requiredPermission = ROUTE_PERMISSIONS[item.path];
    if (!requiredPermission) return true;
    return hasPermission(role, requiredPermission);
  });
}

export function getRouteTitle(path: string): string {
  const item = NAVIGATION_ITEMS.find((nav) => nav.path === path);
  if (item) return item.label;
  if (path.startsWith('/file-analysis')) return 'Sample Deep Inspection';
  if (path === '/login') return 'Analyst Authentication';
  return 'SOC Command Center';
}

export function getRouteDescription(path: string): string {
  const item = NAVIGATION_ITEMS.find((nav) => nav.path === path);
  if (item?.description) return item.description;
  return 'Malware Classification & Automated Threat Defense';
}
