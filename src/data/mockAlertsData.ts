import type { SeverityLevel, Verdict } from '../types';

export interface AlertDetailItem {
  id: string;
  title: string;
  severity: SeverityLevel;
  source: string;
  affectedFile: string;
  fileHash: string;
  malwareFamily: string;
  createdTime: string;
  status: 'Open' | 'Under Investigation' | 'Closed - Resolved' | 'Closed - False Positive';
  assignedAnalyst: string;
  targetHost: string;
  sourceIp: string;
  riskScore: number;
  classification: Verdict;
  recommendedAction: string;
  relatedIndicators: string[];
  detectionHistory: { timestamp: string; event: string; actor: string }[];
}

export const MOCK_DETAILED_ALERTS: AlertDetailItem[] = [
  {
    id: 'ALT-2026-8819',
    title: 'Lateral Movement Beacon detected on AD-DC01.CORP',
    severity: 'critical',
    source: 'Suricata Probe #2 & EDR Sentinel',
    affectedFile: 'beacon_x64_stage.dll',
    fileHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    malwareFamily: 'Cobalt Strike Malleable C2',
    createdTime: '2026-08-30T07:54:10Z',
    status: 'Open',
    assignedAnalyst: 'Alex Rivera',
    targetHost: 'AD-DC01.corp.internal',
    sourceIp: '10.240.12.44',
    riskScore: 98,
    classification: 'malicious',
    recommendedAction: 'Isolate host AD-DC01.corp.internal via EDR agent, block C2 IP 185.220.101.5 on perimeter firewall, and revoke Kerberos TGT tickets.',
    relatedIndicators: [
      'C2 IP: 185.220.101.5:443 (Tor Exit ASN 208312)',
      'JA3 Fingerprint: 72c64be9cd7959b3',
      'Process: rundll32.exe (PID 3810)',
      'Reflective DLL Hollowing in LSASS Memory',
    ],
    detectionHistory: [
      { timestamp: '07:54:10 UTC', event: 'Outbound TLS 1.3 C2 Beacon Established', actor: 'Suricata Probe #2' },
      { timestamp: '07:54:15 UTC', event: 'Reflective DLL Injection into rundll32.exe', actor: 'EDR Agent' },
      { timestamp: '07:54:20 UTC', event: 'Alert ALT-2026-8819 Raised & Escalated to Tier 3', actor: 'ThreatLens Rules' },
    ],
  },
  {
    id: 'ALT-2026-8818',
    title: 'Volume Shadow Copy Deletion initiated via VSSADMIN.EXE',
    severity: 'critical',
    source: 'Sysmon Event ID 1 & EDR Sentinel',
    affectedFile: 'payload_enc_v3.bin.exe',
    fileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    malwareFamily: 'LockBit 3.0 Ransomware',
    createdTime: '2026-08-30T07:32:00Z',
    status: 'Under Investigation',
    assignedAnalyst: 'Sarah Chen',
    targetHost: 'FIN-FILESRV-04.corp.internal',
    sourceIp: '192.168.100.82',
    riskScore: 94,
    classification: 'malicious',
    recommendedAction: 'Terminate process payload_enc_v3.bin.exe immediately, disconnect storage volume FIN-FILESRV-04, and initiate snapshot recovery.',
    relatedIndicators: [
      'Command: vssadmin.exe delete shadows /all /quiet',
      'High-entropy packed file: payload_enc_v3.bin.exe',
      'Target Share: \\\\FIN-FILESRV-04\\FinanceData',
    ],
    detectionHistory: [
      { timestamp: '07:32:00 UTC', event: 'Process payload_enc_v3.bin.exe written to C:\\Public', actor: 'Sysmon' },
      { timestamp: '07:32:05 UTC', event: 'VSSADMIN Shadow Deletion Command Executed', actor: 'EDR Agent' },
      { timestamp: '07:32:10 UTC', event: 'Investigation Assigned to Sarah Chen', actor: 'SOC Automator' },
    ],
  },
  {
    id: 'ALT-2026-8817',
    title: 'Outbound Encrypted C2 Beacon to ASN 49505 (Hostkey B.V.)',
    severity: 'high',
    source: 'Suricata Probe #4',
    affectedFile: 'invoice_Q3_payment_receipt.docm',
    fileHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    malwareFamily: 'Emotet Banking Trojan',
    createdTime: '2026-08-30T06:45:18Z',
    status: 'Under Investigation',
    assignedAnalyst: 'Marcus Vance',
    targetHost: 'HR-WS-229.corp.internal',
    sourceIp: '10.240.18.109',
    riskScore: 89,
    classification: 'malicious',
    recommendedAction: 'Kill WINWORD.EXE and spawned PowerShell instances, clear mail spool for HR-WS-229, and block hostkey C2 IP range.',
    relatedIndicators: [
      'URL: http://c2-dropper.example.com/payload.bin',
      'IP: 45.142.214.99 (ASN 49505 Hostkey B.V.)',
      'Obfuscated PowerShell WebClient DownloadString',
    ],
    detectionHistory: [
      { timestamp: '06:45:18 UTC', event: 'Malicious Office Macro Executed in Word', actor: 'Macro Monitor' },
      { timestamp: '06:45:22 UTC', event: 'PowerShell Payload Download Started', actor: 'Suricata Probe #4' },
    ],
  },
  {
    id: 'ALT-2026-8816',
    title: 'Credential Dumping attempt against LSASS process memory',
    severity: 'high',
    source: 'Sysmon Event ID 10',
    affectedFile: 'client_statement_revised.exe',
    fileHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    malwareFamily: 'AgentTesla Infostealer',
    createdTime: '2026-08-30T06:12:40Z',
    status: 'Open',
    assignedAnalyst: 'Unassigned',
    targetHost: 'ENG-BUILD-01.corp.internal',
    sourceIp: '10.240.12.19',
    riskScore: 85,
    classification: 'malicious',
    recommendedAction: 'Force password reset for all users logged into ENG-BUILD-01 and audit LSASS process memory handles.',
    relatedIndicators: [
      'Target Process: LSASS.exe (PID 648)',
      'Requested Access: PROCESS_VM_READ (0x0010)',
      'Mimikatz / AgentTesla Credential Harvesting Pattern',
    ],
    detectionHistory: [
      { timestamp: '06:12:40 UTC', event: 'LSASS Memory Handle Open Detected', actor: 'Sysmon' },
    ],
  },
  {
    id: 'ALT-2026-8815',
    title: 'Unsigned kernel driver load attempt (BYOVD attack pattern)',
    severity: 'medium',
    source: 'Windows Kernel Defender',
    affectedFile: 'updater_service_daemon.tmp',
    fileHash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    malwareFamily: 'Generic Linux / Kernel Exploit',
    createdTime: '2026-08-30T05:20:11Z',
    status: 'Closed - Resolved',
    assignedAnalyst: 'Alex Rivera',
    targetHost: 'DEV-SRV-11.corp.internal',
    sourceIp: '10.240.40.77',
    riskScore: 68,
    classification: 'suspicious',
    recommendedAction: 'Driver load blocked by hypervisor Driver Signature Enforcement. No further host isolation needed.',
    relatedIndicators: [
      'Unsigned Driver: RTCore64.sys vulnerable variant',
      'HVCI Integrity Block Event 3033',
    ],
    detectionHistory: [
      { timestamp: '05:20:11 UTC', event: 'Driver Load Blocked by HVCI', actor: 'Kernel Guard' },
      { timestamp: '05:30:00 UTC', event: 'Resolved by Alex Rivera', actor: 'Analyst Action' },
    ],
  },
  {
    id: 'ALT-2026-8814',
    title: 'Suspicious PowerShell EncodedCommand execution from macro',
    severity: 'medium',
    source: 'Sysmon Event ID 1',
    affectedFile: 'sales_q3_forecast.xlsm',
    fileHash: '3a181144a0760186574b0282f2f435e7e3b0c44298fc1c149afbf4c8996fb924',
    malwareFamily: 'PowerShell Script Vector',
    createdTime: '2026-08-30T04:40:50Z',
    status: 'Closed - False Positive',
    assignedAnalyst: 'Marcus Vance',
    targetHost: 'SALES-LAP-09.corp.internal',
    sourceIp: '10.240.18.22',
    riskScore: 45,
    classification: 'suspicious',
    recommendedAction: 'Legitimate IT administration maintenance script. Verified FP.',
    relatedIndicators: [
      'Script: Get-WmiObject Win32_OperatingSystem',
      'Parent: EXCEL.EXE',
    ],
    detectionHistory: [
      { timestamp: '04:40:50 UTC', event: 'PowerShell Script Flagged', actor: 'Sysmon' },
      { timestamp: '05:10:00 UTC', event: 'Marked False Positive by Marcus Vance', actor: 'Analyst Action' },
    ],
  },
];
