import type { Verdict, SeverityLevel } from '../types';

export interface ClassificationEvidenceItem {
  type: 'Static Indicator' | 'Suspicious String' | 'API Import' | 'YARA Match' | 'Authenticode Signature' | 'Network C2 IOC';
  title: string;
  detail: string;
  weightContribution: number; // e.g. +24% weight to classification
  severity: SeverityLevel;
}

export interface MalwareClassificationDetail {
  sampleId: string;
  fileName: string;
  sha256: string;
  predictedFamily: string;
  familyCategory: string;
  confidence: number; // 0.0 to 100.0 (Model Certainty)
  riskScore: number;  // 0 to 100 (Security Impact Risk)
  severity: SeverityLevel;
  verdict: Verdict;
  status: 'Confirmed Malicious' | 'Suspicious' | 'Clean' | 'In Queue';
  modelVersion: string;
  inferenceTimeMs: number;
  evidence: ClassificationEvidenceItem[];
}

export interface MalwareFamilyCatalog {
  family: string;
  category: string;
  detections: number;
  severity: SeverityLevel;
  avgConfidence: number;
  lastDetected: string;
  topIndicator: string;
}

export const MOCK_CLASSIFICATION_REPORT: MalwareClassificationDetail = {
  sampleId: 'smp-7721-emt',
  fileName: 'invoice_Q3_payment_receipt.docm',
  sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  predictedFamily: 'Emotet Banking Trojan (Gen-5)',
  familyCategory: 'Polymorphic Downloader / Infostealer',
  confidence: 94.2, // Model Certainty
  riskScore: 82,   // Security Risk
  severity: 'high',
  verdict: 'malicious',
  status: 'Confirmed Malicious',
  modelVersion: 'NeuralPE-x64 v4.2 (2.1B Params)',
  inferenceTimeMs: 48,
  evidence: [
    {
      type: 'YARA Match',
      title: 'SUSP_PowerShell_C2_Gen',
      detail: 'Rule matched encoded PowerShell WebClient payload downloader pattern in macro text stream',
      weightContribution: 32,
      severity: 'high',
    },
    {
      type: 'Suspicious String',
      title: 'Disable Realtime Defender Monitoring',
      detail: 'Set-MpPreference -DisableRealtimeMonitoring $true command detected in extracted string table',
      weightContribution: 26,
      severity: 'high',
    },
    {
      type: 'API Import',
      title: 'Memory Injection Win32 APIs',
      detail: 'Imported VirtualAlloc, WriteProcessMemory, and CreateRemoteThread from kernel32.dll',
      weightContribution: 22,
      severity: 'high',
    },
    {
      type: 'Network C2 IOC',
      title: 'Known ASN 49505 C2 Dropper URL',
      detail: 'Extracted URL http://c2-dropper.example.com/payload.bin matches active threat feed',
      weightContribution: 12,
      severity: 'critical',
    },
    {
      type: 'Static Indicator',
      title: 'Packed Data Section High Entropy',
      detail: 'Section .data exhibits 7.91 entropy exceeding 7.2 threshold',
      weightContribution: 8,
      severity: 'medium',
    },
  ],
};

export const MOCK_FAMILY_CATALOG: MalwareFamilyCatalog[] = [
  {
    family: 'LockBit 3.0',
    category: 'Crypto Ransomware',
    detections: 482,
    severity: 'critical',
    avgConfidence: 98.4,
    lastDetected: '2026-08-30T08:14:10Z',
    topIndicator: 'VSSADMIN.EXE Volume Shadow Deletion',
  },
  {
    family: 'Cobalt Strike',
    category: 'C2 Malleable Beacon',
    detections: 324,
    severity: 'critical',
    avgConfidence: 96.8,
    lastDetected: '2026-08-30T07:54:10Z',
    topIndicator: 'Reflective DLL Injection / JA3 TLS',
  },
  {
    family: 'Emotet Trojan',
    category: 'Polymorphic Downloader',
    detections: 218,
    severity: 'high',
    avgConfidence: 94.2,
    lastDetected: '2026-08-30T07:32:00Z',
    topIndicator: 'VBA Encoded PowerShell DownloadString',
  },
  {
    family: 'AgentTesla',
    category: 'Credential Infostealer',
    detections: 184,
    severity: 'high',
    avgConfidence: 92.0,
    lastDetected: '2026-08-30T06:50:11Z',
    topIndicator: 'SMTP Exfiltration & LSASS Memory Hook',
  },
  {
    family: 'RedLine Stealer',
    category: 'Browser Keylogger',
    detections: 126,
    severity: 'medium',
    avgConfidence: 89.5,
    lastDetected: '2026-08-30T05:20:00Z',
    topIndicator: 'SQLite Crypto Cookie Vault Harvesting',
  },
  {
    family: 'Mirai Variant',
    category: 'Linux IoT Botnet',
    detections: 95,
    severity: 'medium',
    avgConfidence: 86.1,
    lastDetected: '2026-08-30T03:40:00Z',
    topIndicator: 'Unstripped ELF Telnet Brute Force',
  },
];
