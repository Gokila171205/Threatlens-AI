import type { SeverityLevel } from '../types';

export interface MalwareFamilyShare {
  family: string;
  category: string;
  count: number;
  percentage: number;
  severity: SeverityLevel;
}

export interface ConfidenceBracket {
  bracket: string;
  count: number;
  percentage: number;
}

export interface SecurityReportItem {
  id: string;
  title: string;
  type: 'Malware Classification Report' | 'Threat Monitoring Report' | 'Security Analytics Report' | 'Investigation Report';
  generatedDate: string;
  generatedBy: string;
  period: string;
  status: 'Generated' | 'Processing' | 'Archived';
  threatCount: number;
  summary: string;
  keyFindings: string[];
  recommendedActions: string[];
  iocs: string[];
}

export const MOCK_ANALYTICS_METRICS = {
  totalScanned: 12842,
  maliciousDetected: 984,
  suspiciousDetected: 445,
  cleanRatio: '88.9%',
  avgRiskScore: 78.4,
  avgInferenceMs: 48,
  avgSandboxLatencySec: 3.2,
};

export const MOCK_FAMILY_DISTRIBUTION_ANALYTICS: MalwareFamilyShare[] = [
  { family: 'LockBit 3.0', category: 'Crypto Ransomware', count: 482, percentage: 33.7, severity: 'critical' },
  { family: 'Cobalt Strike', category: 'C2 Malleable Beacon', count: 324, percentage: 22.6, severity: 'critical' },
  { family: 'Emotet Trojan', category: 'Polymorphic Downloader', count: 218, percentage: 15.2, severity: 'high' },
  { family: 'AgentTesla', category: 'Credential Infostealer', count: 184, percentage: 12.8, severity: 'high' },
  { family: 'RedLine Stealer', category: 'Browser Keylogger', count: 126, percentage: 8.8, severity: 'medium' },
  { family: 'Mirai Variant', category: 'Linux IoT Botnet', count: 95, percentage: 6.9, severity: 'medium' },
];

export const MOCK_CONFIDENCE_BRACKETS: ConfidenceBracket[] = [
  { bracket: '95% – 100% (High Certainty)', count: 812, percentage: 56.8 },
  { bracket: '85% – 94% (Moderate Certainty)', count: 420, percentage: 29.4 },
  { bracket: '75% – 84% (Low Certainty)', count: 145, percentage: 10.1 },
  { bracket: '< 75% (Manual Triage Required)', count: 52, percentage: 3.7 },
];

export const MOCK_SECURITY_REPORTS: SecurityReportItem[] = [
  {
    id: 'REP-2026-0881',
    title: 'Monthly Malware Ingestion & Classification Forensic Summary',
    type: 'Malware Classification Report',
    generatedDate: '2026-08-30T08:00:00Z',
    generatedBy: 'Alex Rivera (Security Analyst)',
    period: 'August 2026',
    status: 'Generated',
    threatCount: 1429,
    summary: 'Executive summary covering 12,842 scanned payloads, identifying 1,429 threat Detections across LockBit 3.0, Cobalt Strike, and Emotet variants.',
    keyFindings: [
      'LockBit 3.0 ransomware accounts for 33.7% of critical endpoint incidents with Volume Shadow Copy deletion tactics.',
      'Cobalt Strike beaconing detected targeting Active Directory domain controller AD-DC01.corp.internal.',
      'NeuralPE classifier achieved 94.2% mean Bayesian confidence across 1,429 classified samples.',
    ],
    recommendedActions: [
      'Enforce EDR host isolation policy for endpoints exhibiting VSSADMIN shadow deletion attempts.',
      'Deploy egress TLS beaconing inspection rules targeting ASN 49505 Hostkey IP ranges.',
      'Rotate domain administrator Kerberos TGT tickets across internal AD infrastructure.',
    ],
    iocs: [
      'SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      'C2 IP: 185.220.101.5:443 (Tor Exit Node)',
      'URL: http://c2-dropper.example.com/payload.bin',
    ],
  },
  {
    id: 'REP-2026-0880',
    title: 'Weekly SOC Threat Monitoring & Telemetry Ingestion Audit',
    type: 'Threat Monitoring Report',
    generatedDate: '2026-08-28T12:30:00Z',
    generatedBy: 'Sarah Chen (SOC Team Lead)',
    period: 'Aug 21 - Aug 28, 2026',
    status: 'Generated',
    threatCount: 384,
    summary: 'Weekly monitoring report auditing Suricata probe network logs, EDR process executions, and macro dropper detections.',
    keyFindings: [
      '384 threats logged over 7 days with zero SLA breaches on Critical alerts.',
      'Suricata Probe #2 registered 142 network C2 beaconing attempts.',
    ],
    recommendedActions: [
      'Update YARA rule corpus with SUSP_PowerShell_C2_Gen signature.',
    ],
    iocs: [
      'SHA-256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      'IP: 45.142.214.99',
    ],
  },
  {
    id: 'REP-2026-0879',
    title: 'Threat Vector & Incident Risk Distribution Analysis',
    type: 'Security Analytics Report',
    generatedDate: '2026-08-25T16:00:00Z',
    generatedBy: 'Dr. Elena Rostova (Researcher)',
    period: 'Last 30 Days',
    status: 'Archived',
    threatCount: 912,
    summary: 'Analytical study on threat vector distribution, payload section entropy distribution, and classifier accuracy metrics.',
    keyFindings: [
      '56 text section packed payloads identified with entropy > 7.8.',
    ],
    recommendedActions: [
      'Retrain NeuralPE classifier model weights on high-entropy packer samples.',
    ],
    iocs: [
      'SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    ],
  },
];
