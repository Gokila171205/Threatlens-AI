import type { SeverityLevel } from '../types';

export interface ActiveThreatItem {
  id: string;
  detectedTime: string;
  fileName: string;
  fileHash: string;
  malwareFamily: string;
  severity: SeverityLevel;
  riskScore: number;
  status: 'Active Outbreak' | 'Containment Pending' | 'Under Triage' | 'Remediated';
  assignedAnalyst: string;
  targetHost: string;
}

export interface DetectionLogEvent {
  id: string;
  timestamp: string;
  event: string;
  fileName: string;
  source: string;
  severity: SeverityLevel;
  status: 'Logged' | 'Triaged' | 'Escalated';
  details: string;
}

export interface MalwareTrackingItem {
  family: string;
  category: string;
  detections: number;
  firstSeen: string;
  lastSeen: string;
  status: 'Active Outbreak' | 'Monitored Threat' | 'Dormant / Contained';
  impactedEndpoints: number;
}

export interface SuspiciousActivityItem {
  id: string;
  timestamp: string;
  techniqueId: string; // MITRE Technique ID
  techniqueName: string;
  actorOrProcess: string;
  targetHost: string;
  severity: SeverityLevel;
  indicatorText: string;
  phase: 'Initial Access' | 'Execution' | 'Persistence' | 'Defense Evasion' | 'Credential Access' | 'Lateral Movement' | 'Command and Control';
}

export const MOCK_ACTIVE_THREATS: ActiveThreatItem[] = [
  {
    id: 'TRT-2026-9041',
    detectedTime: '2026-08-30T08:54:10Z',
    fileName: 'payload_enc_v3.bin.exe',
    fileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    malwareFamily: 'LockBit 3.0 Ransomware',
    severity: 'critical',
    riskScore: 98,
    status: 'Active Outbreak',
    assignedAnalyst: 'Alex Rivera',
    targetHost: 'FIN-FILESRV-04.corp.internal',
  },
  {
    id: 'TRT-2026-9040',
    detectedTime: '2026-08-30T08:32:00Z',
    fileName: 'beacon_x64_stage.dll',
    fileHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    malwareFamily: 'Cobalt Strike Beacon',
    severity: 'critical',
    riskScore: 94,
    status: 'Containment Pending',
    assignedAnalyst: 'Sarah Chen',
    targetHost: 'AD-DC01.corp.internal',
  },
  {
    id: 'TRT-2026-9039',
    detectedTime: '2026-08-30T07:45:18Z',
    fileName: 'invoice_Q3_payment_receipt.docm',
    fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    malwareFamily: 'Emotet Banking Trojan',
    severity: 'high',
    riskScore: 89,
    status: 'Under Triage',
    assignedAnalyst: 'Marcus Vance',
    targetHost: 'HR-WS-229.corp.internal',
  },
  {
    id: 'TRT-2026-9038',
    detectedTime: '2026-08-30T06:12:40Z',
    fileName: 'client_statement_revised.exe',
    fileHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    malwareFamily: 'AgentTesla Infostealer',
    severity: 'high',
    riskScore: 85,
    status: 'Under Triage',
    assignedAnalyst: 'Dr. Elena Rostova',
    targetHost: 'ENG-BUILD-01.corp.internal',
  },
  {
    id: 'TRT-2026-9037',
    detectedTime: '2026-08-30T05:20:11Z',
    fileName: 'updater_service_daemon.tmp',
    fileHash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    malwareFamily: 'Generic Linux Miner',
    severity: 'medium',
    riskScore: 68,
    status: 'Remediated',
    assignedAnalyst: 'Alex Rivera',
    targetHost: 'DEV-SRV-11.corp.internal',
  },
];

export const MOCK_DETECTION_LOGS: DetectionLogEvent[] = [
  {
    id: 'log-8841',
    timestamp: '2026-08-30T08:58:14.210Z',
    event: 'MALWARE_PAYLOAD_EXECUTION_ATTEMPT',
    fileName: 'payload_enc_v3.bin.exe',
    source: 'EDR Agent FIN-FILESRV-04',
    severity: 'critical',
    status: 'Escalated',
    details: 'Process payload_enc_v3.bin.exe attempted to terminate Volume Shadow Copy Service via vssadmin.exe delete shadows /all /quiet',
  },
  {
    id: 'log-8842',
    timestamp: '2026-08-30T08:54:12.890Z',
    event: 'C2_TLS_BEACON_ESTABLISHED',
    fileName: 'beacon_x64_stage.dll',
    source: 'Suricata Probe #2',
    severity: 'critical',
    status: 'Escalated',
    details: 'Outbound TLS 1.3 connection to 185.220.101.5:443 with JA3 fingerprint 72c64be9cd7959b3 (Tor Exit Node ASN 208312)',
  },
  {
    id: 'log-8843',
    timestamp: '2026-08-30T08:42:09.112Z',
    event: 'LSASS_MEMORY_READ_ATTEMPT',
    fileName: 'lsass_dump_x64.exe',
    source: 'EDR Agent ENG-BUILD-01',
    severity: 'high',
    status: 'Triaged',
    details: 'Process requested PROCESS_VM_READ handle rights on LSASS.exe (PID 648) to harvest Kerberos ticket cached credentials',
  },
  {
    id: 'log-8844',
    timestamp: '2026-08-30T08:30:59.601Z',
    event: 'OBFUSCATED_POWERSHELL_SPAWNED',
    fileName: 'invoice_Q3_payment_receipt.docm',
    source: 'Word Macro Monitor',
    severity: 'high',
    status: 'Triaged',
    details: 'WINWORD.EXE spawned powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -e aW52b2tlLWV4cHJlc3Npb24...',
  },
  {
    id: 'log-8845',
    timestamp: '2026-08-30T08:15:22.000Z',
    event: 'REGISTRY_RUN_KEY_PERSISTENCE_ADDED',
    fileName: 'client_statement_revised.exe',
    source: 'Sysmon Event ID 13',
    severity: 'medium',
    status: 'Logged',
    details: 'Created HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater -> C:\\Users\\Public\\client_statement_revised.exe',
  },
  {
    id: 'log-8846',
    timestamp: '2026-08-30T08:00:19.450Z',
    event: 'HIGH_ENTROPY_PACKED_FILE_DROPPED',
    fileName: 'updater_service_daemon.tmp',
    source: 'Sandbox Engine #4',
    severity: 'medium',
    status: 'Logged',
    details: 'File updater_service_daemon.tmp written to /tmp with section .data entropy 7.91 indicating compressed ELF payload',
  },
];

export const MOCK_MALWARE_TRACKING: MalwareTrackingItem[] = [
  {
    family: 'LockBit 3.0',
    category: 'Crypto Ransomware',
    detections: 482,
    firstSeen: '2026-07-14T10:00:00Z',
    lastSeen: '2026-08-30T08:54:10Z',
    status: 'Active Outbreak',
    impactedEndpoints: 14,
  },
  {
    family: 'Cobalt Strike',
    category: 'C2 Malleable Beacon',
    detections: 324,
    firstSeen: '2026-06-01T04:20:00Z',
    lastSeen: '2026-08-30T08:32:00Z',
    status: 'Active Outbreak',
    impactedEndpoints: 9,
  },
  {
    family: 'Emotet Trojan',
    category: 'Polymorphic Downloader',
    detections: 218,
    firstSeen: '2026-05-12T12:30:00Z',
    lastSeen: '2026-08-30T07:45:18Z',
    status: 'Monitored Threat',
    impactedEndpoints: 6,
  },
  {
    family: 'AgentTesla',
    category: 'Credential Infostealer',
    detections: 184,
    firstSeen: '2026-04-20T08:15:00Z',
    lastSeen: '2026-08-30T06:12:40Z',
    status: 'Monitored Threat',
    impactedEndpoints: 4,
  },
  {
    family: 'RedLine Stealer',
    category: 'Browser Keylogger',
    detections: 126,
    firstSeen: '2026-03-10T14:10:00Z',
    lastSeen: '2026-08-30T05:20:00Z',
    status: 'Dormant / Contained',
    impactedEndpoints: 0,
  },
];

export const MOCK_SUSPICIOUS_TIMELINE: SuspiciousActivityItem[] = [
  {
    id: 'act-01',
    timestamp: '08:58:14 UTC',
    techniqueId: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
    actorOrProcess: 'vssadmin.exe (PID 4912)',
    targetHost: 'FIN-FILESRV-04.corp.internal',
    severity: 'critical',
    indicatorText: 'Attempted command: vssadmin.exe delete shadows /all /quiet to wipe Volume Shadow Copy backups',
    phase: 'Defense Evasion',
  },
  {
    id: 'act-02',
    timestamp: '08:54:12 UTC',
    techniqueId: 'T1071.001',
    techniqueName: 'Application Layer Protocol: Web Protocols',
    actorOrProcess: 'rundll32.exe (PID 3810)',
    targetHost: 'AD-DC01.corp.internal',
    severity: 'critical',
    indicatorText: 'Outbound HTTPS beaconing to C2 IP 185.220.101.5:443 matching Cobalt Strike Malleable profile',
    phase: 'Command and Control',
  },
  {
    id: 'act-03',
    timestamp: '08:42:09 UTC',
    techniqueId: 'T1003.001',
    techniqueName: 'OS Credential Dumping: LSASS Memory',
    actorOrProcess: 'lsass_dump_x64.exe (PID 2104)',
    targetHost: 'ENG-BUILD-01.corp.internal',
    severity: 'high',
    indicatorText: 'Memory handle opened on LSASS.exe with read access rights for Mimikatz ticket harvesting',
    phase: 'Credential Access',
  },
  {
    id: 'act-04',
    timestamp: '08:30:59 UTC',
    techniqueId: 'T1059.001',
    techniqueName: 'Command and Scripting Interpreter: PowerShell',
    actorOrProcess: 'WINWORD.EXE (PID 1840)',
    targetHost: 'HR-WS-229.corp.internal',
    severity: 'high',
    indicatorText: 'Word process spawned hidden PowerShell instance executing Base64 encoded WebClient payload download',
    phase: 'Execution',
  },
  {
    id: 'act-05',
    timestamp: '08:15:22 UTC',
    techniqueId: 'T1547.001',
    techniqueName: 'Boot or Logon Autostart Execution: Registry Run Keys',
    actorOrProcess: 'client_statement_revised.exe',
    targetHost: 'SALES-LAP-09.corp.internal',
    severity: 'medium',
    indicatorText: 'Added registry value under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for automatic reboot persistence',
    phase: 'Persistence',
  },
];
