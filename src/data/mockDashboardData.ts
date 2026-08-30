import type { SeverityLevel, Verdict } from '../types';

export interface DetectionItem {
  id: string;
  fileName: string;
  fileType: string;
  sha256: string;
  detectionTime: string;
  classification: Verdict;
  severity: SeverityLevel;
  riskScore: number; // 0-100
  threatFamily?: string;
  status: 'Completed' | 'Sandbox Ingest' | 'Dynamic Queue';
  targetHost?: string;
  c2Ip?: string;
}

export interface MetricSummary {
  filesScanned: number;
  filesScannedDelta: string;
  threatsDetected: number;
  threatsDetectedDelta: string;
  highCriticalThreats: number;
  highCriticalDelta: string;
  activeInvestigations: number;
  activeInvestigationsDelta: string;
}

export interface TimeSeriesPoint {
  timestamp: string;
  totalScanned: number;
  malicious: number;
  suspicious: number;
}

export interface FamilyDistribution {
  family: string;
  type: string;
  count: number;
  percentage: number;
  severity: SeverityLevel;
}

export const MOCK_DASHBOARD_METRICS: MetricSummary = {
  filesScanned: 12842,
  filesScannedDelta: '+8.4% vs prev 24h',
  threatsDetected: 1429,
  threatsDetectedDelta: '+12.1% (984 Malicious, 445 Suspicious)',
  highCriticalThreats: 84,
  highCriticalDelta: '14 Critical SLA Active',
  activeInvestigations: 12,
  activeInvestigationsDelta: '4 Assigned to Current Analyst',
};

export const MOCK_TIMELINE_DATA: TimeSeriesPoint[] = [
  { timestamp: '00:00', totalScanned: 480, malicious: 32, suspicious: 18 },
  { timestamp: '03:00', totalScanned: 320, malicious: 14, suspicious: 12 },
  { timestamp: '06:00', totalScanned: 640, malicious: 58, suspicious: 24 },
  { timestamp: '09:00', totalScanned: 1120, malicious: 114, suspicious: 42 },
  { timestamp: '12:00', totalScanned: 1480, malicious: 168, suspicious: 56 },
  { timestamp: '15:00', totalScanned: 1350, malicious: 142, suspicious: 49 },
  { timestamp: '18:00', totalScanned: 920, malicious: 88, suspicious: 31 },
  { timestamp: '21:00', totalScanned: 710, malicious: 62, suspicious: 22 },
];

export const MOCK_FAMILY_DISTRIBUTION: FamilyDistribution[] = [
  { family: 'LockBit 3.0', type: 'Crypto Ransomware', count: 482, percentage: 33.7, severity: 'critical' },
  { family: 'Cobalt Strike', type: 'C2 Malleable Beacon', count: 324, percentage: 22.6, severity: 'critical' },
  { family: 'Emotet', type: 'Polymorphic Trojan', count: 218, percentage: 15.2, severity: 'high' },
  { family: 'AgentTesla', type: 'Credential Infostealer', count: 184, percentage: 12.8, severity: 'high' },
  { family: 'RedLine', type: 'Stealer / Keylogger', count: 126, percentage: 8.8, severity: 'medium' },
  { family: 'Mirai Variant', type: 'Linux IoT Botnet', count: 95, percentage: 6.9, severity: 'medium' },
];

export const MOCK_RECENT_DETECTIONS: DetectionItem[] = [
  {
    id: 'det-901',
    fileName: 'payload_enc_v3.bin.exe',
    fileType: 'PE32+ Executable (GUI) x86-64',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    detectionTime: '2026-08-30T08:14:10Z',
    classification: 'malicious',
    severity: 'critical',
    riskScore: 98,
    threatFamily: 'LockBit 3.0 Ransomware',
    status: 'Completed',
    targetHost: 'FIN-FILESRV-04.corp.internal',
    c2Ip: '185.220.101.5',
  },
  {
    id: 'det-902',
    fileName: 'beacon_x64_stage.dll',
    fileType: 'PE32+ Executable (DLL) x86-64',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    detectionTime: '2026-08-30T07:54:10Z',
    classification: 'malicious',
    severity: 'critical',
    riskScore: 94,
    threatFamily: 'Cobalt Strike Beacon',
    status: 'Completed',
    targetHost: 'AD-DC01.corp.internal',
    c2Ip: '45.142.214.99',
  },
  {
    id: 'det-903',
    fileName: 'invoice_Q3_payment_receipt.docm',
    fileType: 'Microsoft Word Document (VBA Macro)',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    detectionTime: '2026-08-30T07:32:00Z',
    classification: 'malicious',
    severity: 'high',
    riskScore: 89,
    threatFamily: 'Emotet Banking Trojan',
    status: 'Completed',
    targetHost: 'HR-WS-229.corp.internal',
    c2Ip: '104.244.42.1',
  },
  {
    id: 'det-904',
    fileName: 'client_statement_revised.exe',
    fileType: 'PE32 Executable (.NET Assembly)',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    detectionTime: '2026-08-30T06:50:11Z',
    classification: 'malicious',
    severity: 'high',
    riskScore: 85,
    threatFamily: 'AgentTesla Infostealer',
    status: 'Completed',
    targetHost: 'ENG-BUILD-01.corp.internal',
  },
  {
    id: 'det-905',
    fileName: 'updater_service_daemon.tmp',
    fileSize: 198000,
    fileType: 'ELF 64-bit LSB pie executable',
    sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    detectionTime: '2026-08-30T06:12:40Z',
    classification: 'suspicious',
    severity: 'medium',
    riskScore: 68,
    threatFamily: 'Generic Linux Miner',
    status: 'Completed',
    targetHost: 'DEV-SRV-11.corp.internal',
  },
  {
    id: 'det-906',
    fileName: 'sys_diag_helper.dll',
    fileType: 'PE32 Executable (DLL)',
    sha256: '3a181144a0760186574b0282f2f435e7e3b0c44298fc1c149afbf4c8996fb924',
    detectionTime: '2026-08-30T05:40:00Z',
    classification: 'suspicious',
    severity: 'medium',
    riskScore: 54,
    threatFamily: 'Unsigned Utility Binary',
    status: 'Sandbox Ingest',
    targetHost: 'SALES-LAP-09.corp.internal',
  },
  {
    id: 'det-907',
    fileName: 'MicrosoftEdgeUpdateSetup.exe',
    fileType: 'PE32 Executable (GUI) Signed',
    sha256: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    detectionTime: '2026-08-30T04:20:00Z',
    classification: 'clean',
    severity: 'low',
    riskScore: 2,
    threatFamily: 'Clean Microsoft Binary',
    status: 'Completed',
    targetHost: 'CORP-WIN11-88.corp.internal',
  },
] as DetectionItem[];
