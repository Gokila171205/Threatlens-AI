/**
 ThreatLens AI - Typed API Client for Real Malware Detection & SOC Monitoring Endpoints
 */

import { httpClient } from './httpClient';

export interface StaticIndicator {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface SectionSummary {
  name: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  is_packed: boolean;
  is_suspicious: boolean;
}

export interface StaticAnalysisReport {
  filename: string;
  file_size_kb: number;
  is_pe: boolean;
  subsystem: string;
  machine: string;
  overall_entropy: number;
  sections: SectionSummary[];
  suspicious_apis: Record<string, string[]>;
  suspicious_strings: Array<{ pattern: string; sample: string }>;
  indicators: StaticIndicator[];
  yara_matches?: any[];
  raw_features: Record<string, any>;
  feature_names: string[];
}

export interface MLPrediction {
  threat_score: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  probabilities: { benign: number; malicious: number };
  top_contributing_features: Array<{
    feature: string;
    value: number;
    importance: number;
    impact: number;
  }>;
  model_info: {
    model_name: string;
    algorithm: string;
    version: string;
  };
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  severity: string;
  details?: string;
}

export interface BehavioralIndicator {
  indicator_id: string;
  name: string;
  category: string;
  severity: string;
  mitre_id: string;
  description: string;
  matched_events_count?: number;
  sample_match?: string;
}

export interface BehavioralEvent {
  event_id: string;
  scan_id: string;
  file_id?: string;
  timestamp: string;
  event_type: string;
  process_name?: string;
  parent_process?: string;
  target?: string;
  source?: string;
  destination?: string;
  port?: number;
  command?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  indicator?: string;
  description: string;
  metadata?: Record<string, any>;
}

export interface BehavioralAnalysisReport {
  behavioral_score: number;
  behavioral_risk_score?: number;
  behavioral_risk_level?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  behavioral_classification: string;
  total_events?: number;
  suspicious_events_count?: number;
  severity_distribution?: Record<string, number>;
  behavior_categories?: Record<string, number>;
  behavioral_indicators?: BehavioralIndicator[];
  mitre_attack_techniques: MitreTechnique[];
  telemetry_summary: {
    total_file_modifications: number;
    total_registry_modifications: number;
    total_network_connections: number;
    total_spawned_processes: number;
  };
  behavior_summary?: string;
  recommended_investigations?: string[];
  events?: BehavioralEvent[];
}

export interface CombinedVerdict {
  final_threat_score: number;
  threat_risk_score?: number;
  final_classification: string;
  fusion_mode: string;
  static_score: number;
  behavioral_score?: number;
  static_weight: number;
  behavioral_weight: number;
  mitre_count?: number;
}

export interface RiskFactorItem {
  factor_id: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence_source: string;
}

export interface FileRiskHistoryResponse {
  sha256: string;
  filename: string;
  total_scans: number;
  first_seen: string;
  last_seen: string;
  risk_trajectory: 'increased' | 'decreased' | 'stable';
  classification_history: string[];
  threat_score_history: number[];
  behavioral_score_history: Array<number | null>;
  alert_count: number;
  scans_summary: Array<{
    scan_id: string;
    scanned_at: string;
    threat_score: number;
    classification: string;
    has_behavioral: boolean;
  }>;
}

export interface ThreatTrendResponse {
  time_window: string;
  total_scans: number;
  benign_scans: number;
  suspicious_scans: number;
  malicious_scans: number;
  avg_threat_score: number;
  highest_threat_score: number;
  avg_behavioral_risk_score: number;
  high_risk_scan_count: number;
  critical_alert_count: number;
  timeline: Array<{
    timestamp: string;
    scans: number;
    malicious: number;
    behavioral_events: number;
  }>;
  status: string;
  message?: string;
}

export interface ThreatPredictionReport {
  scan_id: string;
  filename: string;
  sha256: string;
  threat_risk_score: number;
  threat_risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  confidence_label: string;
  static_ml_score: number;
  behavioral_risk_score?: number;
  primary_risk_factors: RiskFactorItem[];
  behavioral_indicators: BehavioralIndicator[];
  supporting_evidence: Record<string, any>;
  historical_context: Record<string, any>;
  trend: Record<string, any>;
  recommended_actions: string[];
}

export interface ScanResult {
  id: string;
  filename: string;
  file_size_bytes: number;
  sha256: string;
  md5?: string;
  scanned_at: string;
  status: string;
  threat_score: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  static_analysis: StaticAnalysisReport;
  ml_prediction: MLPrediction;
  behavioral_analysis?: BehavioralAnalysisReport | null;
  combined_verdict?: CombinedVerdict | null;
  mitre_techniques: MitreTechnique[];
  indicators: StaticIndicator[];
  yara_matches?: any[];
  model_name?: string;
  model_version?: string;
}

export interface ScanSummaryItem {
  id: string;
  filename: string;
  sha256: string;
  file_size_bytes: number;
  scanned_at: string;
  threat_score: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_pe: boolean;
  status: string;
  model_name?: string;
}

export interface AlertItem {
  id: string;
  scan_id: string;
  filename: string;
  sha256: string;
  threat_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  classification: string;
  created_at: string;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
  is_read: boolean;
  title: string;
  description: string;
  indicators_count: number;
}

export interface MonitoringOverview {
  total_scans: number;
  malicious_count: number;
  suspicious_count: number;
  benign_count: number;
  open_alerts: number;
  avg_threat_score: number;
  threat_level_distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  recent_scans: ScanSummaryItem[];
  recent_alerts: AlertItem[];
}

export interface AnalyticsData {
  daily_timeline: Array<{
    date: string;
    total: number;
    malicious: number;
    clean: number;
  }>;
  threat_types: Record<string, number>;
  mitre_attack_distribution: Array<{
    technique: string;
    count: number;
  }>;
  entropy_distribution: Record<string, number>;
  summary_kpis?: any;
  heuristic_family_tags?: any[];
  confidence_brackets?: any[];
  threat_level_distribution?: Record<string, number>;
}

export const threatlensApi = {
  /**
   * Uploads and executes safe static malware scan + ML classification.
   */
  async scanFile(file: File): Promise<ScanResult> {
    const formData = new FormData();
    formData.append('file', file);
    return httpClient.request<ScanResult>('/scans/file', {
      method: 'POST',
      body: formData,
    });
  },

  /**
   * Lists scans with optional limit and classification filter.
   */
  async listScans(limit: number = 50, classification?: string): Promise<ScanSummaryItem[]> {
    const query = new URLSearchParams();
    query.set('limit', limit.toString());
    if (classification) query.set('classification', classification);
    return httpClient.request<ScanSummaryItem[]>(`/scans?${query.toString()}`);
  },

  /**
   * Retrieves full analysis report by scan ID.
   */
  async getScanDetails(scanId: string): Promise<ScanResult> {
    return httpClient.request<ScanResult>(`/scans/${scanId}`);
  },

  /**
   * Submits behavioral sandbox telemetry (Milestone 3).
   */
  async submitBehavioralTelemetry(scanId: string, telemetry: any): Promise<ScanResult> {
    return httpClient.request<ScanResult>(`/scans/${scanId}/behavioral`, {
      method: 'POST',
      body: JSON.stringify(telemetry),
    });
  },

  /**
   * Retrieves behavioral analysis report for a scan (Milestone 3, Step 4).
   */
  async getBehavioralReport(scanId: string): Promise<BehavioralAnalysisReport> {
    return httpClient.request<BehavioralAnalysisReport>(`/behavioral/${scanId}`);
  },

  /**
   * Submits normalized behavioral events for a scan.
   */
  async submitBehavioralEvents(scanId: string, events: BehavioralEvent[]): Promise<BehavioralAnalysisReport> {
    return httpClient.request<BehavioralAnalysisReport>(`/behavioral/events`, {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId, events }),
    });
  },

  /**
   * Retrieves security alerts.
   */
  async listAlerts(status?: string, limit: number = 50): Promise<AlertItem[]> {
    const query = new URLSearchParams();
    query.set('limit', limit.toString());
    if (status) query.set('status', status);
    return httpClient.request<AlertItem[]>(`/alerts?${query.toString()}`);
  },

  /**
   * Updates status or read state of an alert.
   */
  async updateAlert(alertId: string, updates: { status?: string; is_read?: boolean }): Promise<AlertItem> {
    return httpClient.request<AlertItem>(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  },

  /**
   * Resolves an alert.
   */
  async resolveAlert(alertId: string): Promise<AlertItem> {
    return httpClient.request<AlertItem>(`/alerts/${alertId}/resolve`, {
      method: 'POST',
    });
  },

  /**
   * Aggregated real-time metrics for SOC Monitoring dashboard.
   */
  async getMonitoringOverview(): Promise<MonitoringOverview> {
    return httpClient.request<MonitoringOverview>('/monitoring/overview');
  },

  /**
   * Time-series and MITRE ATT&CK analytics data.
   */
  async getMonitoringAnalytics(): Promise<AnalyticsData> {
    return httpClient.request<AnalyticsData>('/monitoring/analytics');
  },

  /**
   * Retrieves full threat prediction assessment report for a scan (Milestone 3, Step 5).
   */
  async getThreatPrediction(scanId: string): Promise<ThreatPredictionReport> {
    return httpClient.request<ThreatPredictionReport>(`/threat-prediction/${scanId}`);
  },

  /**
   * Retrieves file risk history across repeated scans.
   */
  async getFileRiskHistory(scanId: string): Promise<FileRiskHistoryResponse> {
    return httpClient.request<FileRiskHistoryResponse>(`/threat-prediction/${scanId}/history`);
  },

  /**
   * Retrieves multi-window threat trends (24h, 7d, 30d).
   */
  async getThreatTrends(window: '24h' | '7d' | '30d' = '7d'): Promise<ThreatTrendResponse> {
    return httpClient.request<ThreatTrendResponse>(`/threat-prediction/trends?window=${window}`);
  },

  /**
   * Investigation Reports API (Phase 4)
   */
  async listReports(limit: number = 50): Promise<any[]> {
    return httpClient.request<any[]>(`/reports?limit=${limit}`);
  },

  async createReport(payload: {
    title: string;
    type?: string;
    period?: string;
    scan_id?: string;
    filename?: string;
    threat_score?: number;
    classification?: string;
    summary?: string;
  }): Promise<any> {
    return httpClient.request<any>('/reports', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getReport(reportId: string): Promise<any> {
    return httpClient.request<any>(`/reports/${reportId}`);
  },

  async deleteReport(reportId: string): Promise<any> {
    return httpClient.request<any>(`/reports/${reportId}`, {
      method: 'DELETE',
    });
  },

  /**
   * Admin User Management API (Phase 7)
   */
  async getAdminUsers(): Promise<{ success: boolean; users: any[] }> {
    return httpClient.request<{ success: boolean; users: any[] }>('/admin/users');
  },

  async createAdminUser(payload: {
    name: string;
    email: string;
    password: string;
    role: string;
    department?: string;
  }): Promise<any> {
    return httpClient.request<any>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateAdminUser(userId: string, payload: {
    name?: string;
    role?: string;
    department?: string;
    status?: string;
  }): Promise<any> {
    return httpClient.request<any>(`/admin/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async deleteAdminUser(userId: string): Promise<any> {
    return httpClient.request<any>(`/admin/users/${userId}`, {
      method: 'DELETE',
    });
  },
};

