import type { UserRole } from '../types';

export interface AdminUserItem {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  status: 'Active' | 'Inactive';
  lastActive: string;
  createdDate: string;
}

export interface PlatformIntegration {
  id: string;
  name: string;
  category: 'EDR' | 'SIEM' | 'Network Tap' | 'Firewall';
  status: 'Connected' | 'Degraded' | 'Disconnected';
  lastSync: string;
}

export interface PlatformAuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  ipAddress: string;
}

export const MOCK_ADMIN_USERS: AdminUserItem[] = [
  {
    id: 'usr-901',
    name: 'Alex Rivera',
    email: 'a.rivera@defense.threatlens.ai',
    role: 'Security Analyst',
    status: 'Active',
    lastActive: '2026-08-30T08:50:12Z',
    createdDate: '2025-11-10Z',
  },
  {
    id: 'usr-902',
    name: 'Sarah Chen',
    email: 's.chen@defense.threatlens.ai',
    role: 'SOC Team Member',
    status: 'Active',
    lastActive: '2026-08-30T08:42:00Z',
    createdDate: '2025-12-01Z',
  },
  {
    id: 'usr-903',
    name: 'Marcus Vance',
    email: 'm.vance@defense.threatlens.ai',
    role: 'Administrator',
    status: 'Active',
    lastActive: '2026-08-30T08:58:00Z',
    createdDate: '2025-09-15Z',
  },
  {
    id: 'usr-904',
    name: 'Dr. Elena Rostova',
    email: 'e.rostova@defense.threatlens.ai',
    role: 'Researcher',
    status: 'Active',
    lastActive: '2026-08-30T07:15:30Z',
    createdDate: '2026-01-20Z',
  },
  {
    id: 'usr-905',
    name: 'David K.',
    email: 'd.k@defense.threatlens.ai',
    role: 'Security Analyst',
    status: 'Inactive',
    lastActive: '2026-08-15T14:20:00Z',
    createdDate: '2026-02-14Z',
  },
];

export const MOCK_INTEGRATIONS: PlatformIntegration[] = [
  { id: 'int-1', name: 'CrowdStrike Falcon EDR', category: 'EDR', status: 'Connected', lastSync: '2 mins ago' },
  { id: 'int-2', name: 'Splunk Enterprise SIEM', category: 'SIEM', status: 'Connected', lastSync: '1 min ago' },
  { id: 'int-3', name: 'Suricata Probe Cluster', category: 'Network Tap', status: 'Connected', lastSync: 'Just now' },
  { id: 'int-4', name: 'Palo Alto Panorama Firewall', category: 'Firewall', status: 'Degraded', lastSync: '18 mins ago' },
];

export const MOCK_AUDIT_LOGS: PlatformAuditLog[] = [
  { id: 'aud-1', timestamp: '2026-08-30T08:58:00Z', actor: 'Marcus Vance', action: 'UPDATED_ROLE_PERMISSIONS', target: 'Security Analyst Role Matrix', ipAddress: '10.240.1.12' },
  { id: 'aud-2', timestamp: '2026-08-30T08:45:10Z', actor: 'Alex Rivera', action: 'SUBMITTED_ISOLATION_REQUEST', target: 'AD-DC01.corp.internal', ipAddress: '10.240.12.44' },
  { id: 'aud-3', timestamp: '2026-08-30T08:12:00Z', actor: 'Marcus Vance', action: 'API_KEY_ROTATED', target: 'Splunk SIEM Connector', ipAddress: '10.240.1.12' },
];
