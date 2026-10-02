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

import { threatlensApi } from './threatlensApi';

let currentDetailedAlerts = [...MOCK_DETAILED_ALERTS];
let currentSecurityReports = [...MOCK_SECURITY_REPORTS];
let currentAdminUsers = [...MOCK_ADMIN_USERS];

/**
 * ThreatLens AI API Service Client
 * Seamless bridge connecting UI components to live FastAPI backend with automatic fallback.
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
    try {
      const scans = await threatlensApi.listScans();
      if (scans && scans.length > 0) {
        const mapped: MalwareSample[] = scans.map((s) => ({
          id: s.id,
          fileName: s.filename,
          fileType: s.is_pe ? 'PE Executable' : 'Binary Artifact',
          fileSize: s.file_size_bytes,
          sha256: s.sha256,
          md5: s.sha256.slice(0, 32),
          submissionTime: s.scanned_at,
          status: 'completed',
          threatScore: s.threat_score,
          verdict: s.classification === 'MALICIOUS' ? 'malicious' : (s.classification === 'SUSPICIOUS' ? 'suspicious' : 'clean'),
          threatFamily: s.classification === 'MALICIOUS' ? 'ML Random Forest Detection' : 'Clean Binary',
          confidence: 95,
          mitreTechniquesCount: s.threat_score >= 70 ? 2 : 0,
          yaraMatchesCount: s.threat_score >= 70 ? 3 : 0,
          tags: s.is_pe ? ['PE32', 'Executable'] : ['Generic'],
        }));
        return [...mapped, ...MOCK_MALWARE_SAMPLES];
      }
    } catch {
      // Fallback
    }
    return [...MOCK_MALWARE_SAMPLES];
  },

  getSampleById: async (id: string): Promise<MalwareSample | undefined> => {
    try {
      const scan = await threatlensApi.getScanDetails(id);
      if (scan) {
        return {
          id: scan.id,
          fileName: scan.filename,
          fileType: scan.static_analysis?.is_pe ? 'PE Executable' : 'Binary Artifact',
          fileSize: scan.file_size_bytes,
          sha256: scan.sha256,
          md5: scan.md5 || scan.sha256.slice(0, 32),
          submissionTime: scan.scanned_at,
          status: 'completed',
          threatScore: scan.threat_score,
          verdict: scan.classification === 'MALICIOUS' ? 'malicious' : (scan.classification === 'SUSPICIOUS' ? 'suspicious' : 'clean'),
          threatFamily: scan.classification === 'MALICIOUS' ? 'ML Random Forest Detection' : 'Clean Binary',
          confidence: Math.round((scan.confidence || 0.95) * 100),
          mitreTechniquesCount: (scan.mitre_techniques || []).length,
          yaraMatchesCount: (scan.indicators || []).length,
          tags: scan.static_analysis?.is_pe ? ['PE32', 'Executable'] : ['Generic'],
        };
      }
    } catch {
      // Fallback
    }
    return MOCK_MALWARE_SAMPLES.find((s) => s.id === id || s.sha256 === id);
  },

  // Static Analysis Report API
  getStaticAnalysisReport: async (_filename: string): Promise<StaticAnalysisReport> => {
    await new Promise((res) => setTimeout(res, 120));
    return SAMPLE_STATIC_REPORTS['invoice.exe'];
  },

  submitFileForAnalysis: async (file: File): Promise<{ taskId: string; estimatedTimeSec: number }> => {
    try {
      const scanRes = await threatlensApi.scanFile(file);
      return {
        taskId: scanRes.id,
        estimatedTimeSec: 2,
      };
    } catch {
      return {
        taskId: `task_scan_${Math.random().toString(36).substring(2, 9)}`,
        estimatedTimeSec: 4,
      };
    }
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
    try {
      const realAlerts = await threatlensApi.listAlerts();
      if (realAlerts && realAlerts.length > 0) {
        const mapped: ActiveThreatItem[] = realAlerts.map((a) => ({
          id: a.id,
          detectedTime: a.created_at,
          fileName: a.filename,
          fileHash: a.sha256,
          malwareFamily: a.title,
          severity: (a.threat_level.toLowerCase() || 'medium') as any,
          riskScore: a.threat_score,
          status: a.status === 'OPEN' ? 'Active Outbreak' : (a.status === 'INVESTIGATING' ? 'Under Triage' : 'Remediated'),
          assignedAnalyst: 'SOC Analyst',
          targetHost: 'ENDPOINT-AGENT-01.corp.internal',
        }));
        return [...mapped, ...MOCK_ACTIVE_THREATS];
      }
    } catch {
      // Fallback
    }
    return [...MOCK_ACTIVE_THREATS];
  },

  getDetectionLogs: async (): Promise<DetectionLogEvent[]> => {
    try {
      const scans = await threatlensApi.listScans();
      if (scans && scans.length > 0) {
        const mapped: DetectionLogEvent[] = scans.map((s) => ({
          id: s.id,
          timestamp: s.scanned_at,
          event: `ML Static Analysis Verdict: ${s.classification}`,
          fileName: s.filename,
          source: 'ThreatLens Random Forest Classifier',
          severity: (s.threat_level.toLowerCase() || 'low') as any,
          status: 'Triaged',
          details: `Calibrated risk score: ${s.threat_score}/100. SHA256: ${s.sha256.slice(0, 16)}...`,
        }));
        return [...mapped, ...MOCK_DETECTION_LOGS];
      }
    } catch {
      // Fallback
    }
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
    try {
      const realAlerts = await threatlensApi.listAlerts();
      if (realAlerts && realAlerts.length > 0) {
        const mapped: AlertDetailItem[] = realAlerts.map((a) => ({
          id: a.id,
          title: a.title,
          severity: (a.threat_level.toLowerCase() || 'high') as any,
          source: 'ThreatLens ML Sensor & Static Engine',
          affectedFile: a.filename,
          fileHash: a.sha256,
          malwareFamily: a.classification === 'MALICIOUS' ? 'Malware Threat' : 'Suspicious Artifact',
          createdTime: a.created_at,
          status: a.status === 'OPEN' ? 'Open' : (a.status === 'INVESTIGATING' ? 'Under Investigation' : 'Closed - Resolved'),
          assignedAnalyst: 'SOC Analyst',
          targetHost: 'ENDPOINT-AGENT-01.corp.internal',
          sourceIp: '10.240.12.50',
          riskScore: a.threat_score,
          classification: (a.classification.toLowerCase() || 'suspicious') as any,
          recommendedAction: a.description,
          relatedIndicators: [
            `SHA-256: ${a.sha256}`,
            `Threat Risk Score: ${a.threat_score}/100`,
            `Indicators Flagged: ${a.indicators_count}`,
          ],
          detectionHistory: [
            {
              timestamp: a.created_at.substring(11, 19) + ' UTC',
              event: `Alert generated by ML Classifier (${a.threat_level})`,
              actor: 'ThreatLens Rules',
            },
          ],
        }));
        return [...mapped, ...currentDetailedAlerts];
      }
    } catch {
      // Fallback
    }
    return [...currentDetailedAlerts];
  },

  updateAlertStatus: async (alertId: string, newStatus: AlertDetailItem['status']): Promise<AlertDetailItem> => {
    try {
      const backendStatusMap: Record<string, string> = {
        'Open': 'OPEN',
        'Under Investigation': 'INVESTIGATING',
        'Closed - Resolved': 'RESOLVED',
        'Closed - False Positive': 'DISMISSED',
      };
      const backendStatus = backendStatusMap[newStatus] || 'OPEN';
      await threatlensApi.updateAlert(alertId, { status: backendStatus });
    } catch {
      // Offline fallback
    }

    const target = currentDetailedAlerts.find((a) => a.id === alertId);
    if (target) {
      target.status = newStatus;
      target.detectionHistory.push({
        timestamp: new Date().toISOString().substring(11, 19) + ' UTC',
        event: `Status updated to ${newStatus}`,
        actor: 'SOC Analyst Action',
      });
      return { ...target };
    }
    return {
      id: alertId,
      title: 'Alert Status Updated',
      severity: 'medium',
      source: 'ThreatLens SOC',
      affectedFile: 'sample.exe',
      fileHash: 'unknown',
      malwareFamily: 'Triage',
      createdTime: new Date().toISOString(),
      status: newStatus,
      assignedAnalyst: 'SOC Analyst',
      targetHost: 'ENDPOINT.corp',
      sourceIp: '10.0.0.1',
      riskScore: 50,
      classification: 'suspicious',
      recommendedAction: 'Verify endpoint logs',
      relatedIndicators: [],
      detectionHistory: [],
    };
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
    try {
      const analytics = await threatlensApi.getMonitoringAnalytics();
      if (analytics) {
        return {
          metrics: MOCK_ANALYTICS_METRICS,
          families: MOCK_FAMILY_DISTRIBUTION_ANALYTICS,
          confidenceBrackets: MOCK_CONFIDENCE_BRACKETS,
          mitreCoverage: analytics.mitre_attack_distribution,
          entropyDistribution: analytics.entropy_distribution,
        };
      }
    } catch {
      // Fallback
    }
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
