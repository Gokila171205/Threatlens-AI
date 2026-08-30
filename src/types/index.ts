export type UserRole = 'Security Analyst' | 'SOC Team Member' | 'Administrator' | 'Researcher';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export type SampleStatus = 'queued' | 'analyzing' | 'completed' | 'failed';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarUrl?: string;
  department: string;
  clearanceLevel: string;
  lastLogin: string;
}

export interface NavigationItem {
  id: string;
  label: string;
  path: string;
  icon: string;
  badge?: string | number;
  badgeColor?: SeverityLevel | 'neutral';
  roles: UserRole[];
  description?: string;
}

export interface MalwareSample {
  id: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  sha256: string;
  md5: string;
  ssdeep?: string;
  submissionTime: string;
  status: SampleStatus;
  verdict: Verdict;
  threatScore: number; // 0 to 100
  threatFamily?: string;
  confidence: number; // 0 to 100
  mitreTechniquesCount: number;
  yaraMatchesCount: number;
  tags: string[];
}

export interface SocAlert {
  id: string;
  title: string;
  severity: SeverityLevel;
  timestamp: string;
  sourceIp: string;
  targetHost: string;
  sampleHash?: string;
  threatFamily?: string;
  status: 'Open' | 'Under Investigation' | 'Closed - Resolved' | 'Closed - False Positive';
  assignedTo?: string;
  slaRemainingMinutes: number;
}

export interface SystemNotification {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
  timestamp: string;
  read: boolean;
  link?: string;
}
