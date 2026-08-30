import { MOCK_MALWARE_SAMPLES, MOCK_ALERTS, MOCK_NOTIFICATIONS, MOCK_USER } from '../data/mockData';
import { SAMPLE_STATIC_REPORTS } from '../data/mockStaticAnalysisData';
import { MOCK_CLASSIFICATION_REPORT, MOCK_FAMILY_CATALOG } from '../data/mockClassificationData';
import {
  MOCK_ACTIVE_THREATS,
  MOCK_DETECTION_LOGS,
  MOCK_MALWARE_TRACKING,
  MOCK_SUSPICIOUS_TIMELINE
} from '../data/mockMonitoringData';
import { MOCK_DETAILED_ALERTS } from '../data/mockAlertsData';
import {
  MOCK_ANALYTICS_METRICS,
  MOCK_FAMILY_DISTRIBUTION_ANALYTICS,
  MOCK_CONFIDENCE_BRACKETS,
  MOCK_SECURITY_REPORTS
} from '../data/mockAnalyticsData';
import { MOCK_ADMIN_USERS, MOCK_INTEGRATIONS, MOCK_AUDIT_LOGS } from '../data/mockAdminData';
import { MOCK_RESEARCH_DATASET } from '../data/mockResearchData';
import type { StaticAnalysisReport } from '../data/mockStaticAnalysisData';
import type { MalwareClassificationDetail, MalwareFamilyCatalog } from '../data/mockClassificationData';
import type {
  ActiveThreatItem,
  DetectionLogEvent,
  MalwareTrackingItem,
  SuspiciousActivityItem
} from '../data/mockMonitoringData';
import type { AlertDetailItem } from '../data/mockAlertsData';
import type { SecurityReportItem } from '../data/mockAnalyticsData';
import type { AdminUserItem, PlatformIntegration, PlatformAuditLog } from '../data/mockAdminData';
import type { DatasetSample } from '../data/mockResearchData';
import type { MalwareSample, SocAlert, SystemNotification, UserProfile, UserRole } from '../types';

let currentDetailedAlerts = [...MOCK_DETAILED_ALERTS];
let currentSecurityReports = [...MOCK_SECURITY_REPORTS];
let currentAdminUsers = [...MOCK_ADMIN_USERS];

/**
 * ThreatLens AI API Service Client
 * Designed for immediate plug-and-play replacement with real FastAPI / REST / WebSocket endpoints.
 */
export const ThreatLensApi = {
  // User & Authentication
  getCurrentUser: async (): Promise<UserProfile> => {
    await new Promise((res) => setTimeout(res, 80));
    return { ...MOCK_USER };
  },

  updateUserRole: async (role: UserRole): Promise<UserProfile> => {
    await new Promise((res) => setTimeout(res, 120));
    MOCK_USER.role = role;
    return { ...MOCK_USER };
  },

  // Admin User Management API
  getAdminUsers: async (): Promise<AdminUserItem[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...currentAdminUsers];
  },

  updateAdminUserRole: async (userId: string, newRole: UserRole): Promise<AdminUserItem> => {
    await new Promise((res) => setTimeout(res, 120));
    const u = currentAdminUsers.find((user) => user.id === userId);
    if (!u) throw new Error('User not found');
    u.role = newRole;
    return { ...u };
  },

  toggleAdminUserStatus: async (userId: string): Promise<AdminUserItem> => {
    await new Promise((res) => setTimeout(res, 120));
    const u = currentAdminUsers.find((user) => user.id === userId);
    if (!u) throw new Error('User not found');
    u.status = u.status === 'Active' ? 'Inactive' : 'Active';
    return { ...u };
  },

  getIntegrations: async (): Promise<PlatformIntegration[]> => {
    await new Promise((res) => setTimeout(res, 80));
    return [...MOCK_INTEGRATIONS];
  },

  getAuditLogs: async (): Promise<PlatformAuditLog[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...MOCK_AUDIT_LOGS];
  },

  // Researcher API
  getResearchDataset: async (): Promise<DatasetSample[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...MOCK_RESEARCH_DATASET];
  },

  // Malware Samples
  getSamples: async (): Promise<MalwareSample[]> => {
    await new Promise((res) => setTimeout(res, 150));
    return [...MOCK_MALWARE_SAMPLES];
  },

  getSampleById: async (id: string): Promise<MalwareSample | undefined> => {
    await new Promise((res) => setTimeout(res, 100));
    return MOCK_MALWARE_SAMPLES.find((s) => s.id === id || s.sha256 === id);
  },

  // Static Analysis Report API
  getStaticAnalysisReport: async (_filename: string): Promise<StaticAnalysisReport> => {
    await new Promise((res) => setTimeout(res, 120));
    return SAMPLE_STATIC_REPORTS['invoice.exe'];
  },

  submitFileForAnalysis: async (_file: File): Promise<{ taskId: string; estimatedTimeSec: number }> => {
    await new Promise((res) => setTimeout(res, 300));
    return {
      taskId: `task_scan_${Math.random().toString(36).substring(2, 9)}`,
      estimatedTimeSec: 4,
    };
  },

  // ML Malware Classification API
  getClassificationReport: async (_sampleId: string): Promise<MalwareClassificationDetail> => {
    await new Promise((res) => setTimeout(res, 140));
    return { ...MOCK_CLASSIFICATION_REPORT };
  },

  getFamilyCatalog: async (): Promise<MalwareFamilyCatalog[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...MOCK_FAMILY_CATALOG];
  },

  // Threat Monitoring API
  getActiveThreats: async (): Promise<ActiveThreatItem[]> => {
    await new Promise((res) => setTimeout(res, 120));
    return [...MOCK_ACTIVE_THREATS];
  },

  getDetectionLogs: async (): Promise<DetectionLogEvent[]> => {
    await new Promise((res) => setTimeout(res, 140));
    return [...MOCK_DETECTION_LOGS];
  },

  getMalwareTracking: async (): Promise<MalwareTrackingItem[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...MOCK_MALWARE_TRACKING];
  },

  getSuspiciousTimeline: async (): Promise<SuspiciousActivityItem[]> => {
    await new Promise((res) => setTimeout(res, 110));
    return [...MOCK_SUSPICIOUS_TIMELINE];
  },

  // Detailed SOC Alerts API
  getDetailedAlerts: async (): Promise<AlertDetailItem[]> => {
    await new Promise((res) => setTimeout(res, 120));
    return [...currentDetailedAlerts];
  },

  updateAlertStatus: async (alertId: string, newStatus: AlertDetailItem['status']): Promise<AlertDetailItem> => {
    await new Promise((res) => setTimeout(res, 150));
    const target = currentDetailedAlerts.find((a) => a.id === alertId);
    if (!target) throw new Error(`Alert ${alertId} not found`);
    target.status = newStatus;
    target.detectionHistory.push({
      timestamp: new Date().toISOString().substring(11, 19) + ' UTC',
      event: `Status updated to ${newStatus}`,
      actor: 'SOC Analyst Action',
    });
    return { ...target };
  },

  assignAlertAnalyst: async (alertId: string, analystName: string): Promise<AlertDetailItem> => {
    await new Promise((res) => setTimeout(res, 150));
    const target = currentDetailedAlerts.find((a) => a.id === alertId);
    if (!target) throw new Error(`Alert ${alertId} not found`);
    target.assignedAnalyst = analystName;
    target.detectionHistory.push({
      timestamp: new Date().toISOString().substring(11, 19) + ' UTC',
      event: `Investigation assigned to ${analystName}`,
      actor: 'SOC Dispatch',
    });
    return { ...target };
  },

  // Analytics API
  getAnalyticsSummary: async () => {
    await new Promise((res) => setTimeout(res, 120));
    return {
      metrics: MOCK_ANALYTICS_METRICS,
      families: MOCK_FAMILY_DISTRIBUTION_ANALYTICS,
      confidenceBrackets: MOCK_CONFIDENCE_BRACKETS,
    };
  },

  // Security Reports API
  getSecurityReports: async (): Promise<SecurityReportItem[]> => {
    await new Promise((res) => setTimeout(res, 100));
    return [...currentSecurityReports];
  },

  createSecurityReport: async (
    title: string,
    type: SecurityReportItem['type'],
    period: string
  ): Promise<SecurityReportItem> => {
    await new Promise((res) => setTimeout(res, 250));
    const newReport: SecurityReportItem = {
      id: `REP-2026-${Math.floor(1000 + Math.random() * 9000)}`,
      title,
      type,
      generatedDate: new Date().toISOString(),
      generatedBy: `${MOCK_USER.name} (${MOCK_USER.role})`,
      period,
      status: 'Generated',
      threatCount: 1429,
      summary: `Automated ${type} covering ${period}. Analyzed telemetry ingestion stream and NeuralPE vector metrics.`,
      keyFindings: [
        'High prevalence of LockBit 3.0 ransomware in target sample stream.',
        'Zero critical SLA breaches registered during the reporting window.',
      ],
      recommendedActions: [
        'Ensure all EDR agents are updated with latest behavioral signature definitions.',
      ],
      iocs: [
        'SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      ],
    };
    currentSecurityReports.unshift(newReport);
    return newReport;
  },

  // SOC Alerts Legacy List
  getAlerts: async (): Promise<SocAlert[]> => {
    await new Promise((res) => setTimeout(res, 120));
    return [...MOCK_ALERTS];
  },

  // Notifications
  getNotifications: async (): Promise<SystemNotification[]> => {
    await new Promise((res) => setTimeout(res, 60));
    return [...MOCK_NOTIFICATIONS];
  },

  markNotificationRead: async (id: string): Promise<void> => {
    const notif = MOCK_NOTIFICATIONS.find((n) => n.id === id);
    if (notif) notif.read = true;
  },
};
