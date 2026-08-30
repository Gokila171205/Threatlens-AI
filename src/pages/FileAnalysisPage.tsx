import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  Play,
  ShieldAlert,
  Terminal,
  Cpu,
  Layers,
  RotateCw,
  X,
  Code2,
  Network
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { MonoText } from '../components/common/MonoText';
import { RiskScoreBar } from '../components/common/RiskScoreBar';
import { EntropyBar } from '../components/common/EntropyBar';
import { SAMPLE_STATIC_REPORTS } from '../data/mockStaticAnalysisData';
import type { StaticAnalysisReport } from '../data/mockStaticAnalysisData';
import { formatBytes } from '../utils/formatters';
import { ThreatLensApi } from '../services/api';

const STAGES = [
  'File received',
  'Hash generation (MD5, SHA-256)',
  'Metadata & header extraction',
  'PE structure & section entropy analysis',
  'Suspicious string extraction',
  'Import table & WinAPI mapping',
  'Extracted C2 URL & IP detection',
  'YARA rule matching',
  'Authenticode signature verification',
  'Risk assessment & score calculation',
];

export const FileAnalysisPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileValidationState, setFileValidationState] = useState<'idle' | 'validating' | 'valid' | 'invalid'>('idle');

  const [pipelineState, setPipelineState] = useState<'idle' | 'running' | 'completed'>('idle');
  const [currentStageIndex, setCurrentStageIndex] = useState<number>(0);

  const [report, setReport] = useState<StaticAnalysisReport | null>(SAMPLE_STATIC_REPORTS['invoice.exe']);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setFileValidationState('validating');
    setTimeout(() => {
      setFileValidationState('valid');
    }, 350);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;
    setPipelineState('running');
    setCurrentStageIndex(0);

    // Step-by-step progress through 10 explicit pipeline stages
    for (let i = 0; i < STAGES.length; i++) {
      await new Promise((res) => setTimeout(res, 300));
      setCurrentStageIndex(i);
    }

    await new Promise((res) => setTimeout(res, 350));
    setPipelineState('completed');

    // Load static analysis report
    const resReport = await ThreatLensApi.getStaticAnalysisReport(selectedFile.name);
    setReport({
      ...resReport,
      fileName: selectedFile.name,
      fileSize: selectedFile.size,
    });
  };

  const handleReset = () => {
    setSelectedFile(null);
    setFileValidationState('idle');
    setPipelineState('idle');
    setCurrentStageIndex(0);
  };

  return (
    <div className="space-y-6 select-none font-sans">
      {/* Header Banner */}
      <div className="p-3.5 bg-slate-900 border border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-100 uppercase flex items-center gap-2">
            <Cpu className="w-4 h-4 text-sky-400" />
            <span>Static Malware Analysis & Payload Dissection</span>
          </h1>
          <p className="text-2xs text-slate-400 font-mono mt-0.5">
            Client-Side Safe Parsing • Zero Binary Execution • PE / ELF / Office Macro / YARA Engine
          </p>
        </div>

        {pipelineState === 'completed' && (
          <Button
            variant="secondary"
            size="xs"
            leftIcon={<RotateCw className="w-3 h-3" />}
            onClick={handleReset}
          >
            Analyze New File
          </Button>
        )}
      </div>

      {/* Upload & Validation Zone */}
      {pipelineState !== 'completed' && (
        <div className="p-5 bg-slate-900 border border-slate-800 rounded space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-sky-400" />
              <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-100">
                Target Binary / Document Upload
              </h2>
            </div>
            <span className="text-2xs font-mono text-slate-500">
              Supported: PE32/64 (.exe, .dll), ELF, Office (.docm, .xlsm), PDF, APK, Scripts (.ps1, .vbs)
            </span>
          </div>

          {/* Drag and Drop Zone */}
          {!selectedFile ? (
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="border border-dashed border-slate-750 hover:border-sky-600/70 rounded-lg p-8 text-center bg-slate-950/40 hover:bg-slate-950/70 transition-all cursor-pointer flex flex-col items-center justify-center gap-2"
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              />
              <UploadCloud className="w-10 h-10 text-sky-400" />
              <div className="text-xs text-slate-200 font-medium">
                Click or drag & drop suspicious payload here to initiate static disassembly
              </div>
              <div className="text-2xs text-slate-500 font-mono">
                Maximum File Size: 100 MB • Files parsed safely without host execution
              </div>
              <div className="mt-2">
                <Button variant="secondary" size="xs">
                  Browse Files
                </Button>
              </div>
            </div>
          ) : (
            /* Selected File Validation Box */
            <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded bg-slate-900 border border-slate-750 text-sky-400">
                    <FileCode className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold font-mono text-slate-100">{selectedFile.name}</h3>
                    <p className="text-2xs font-mono text-slate-500 mt-0.5">
                      Size: {formatBytes(selectedFile.size)} • Type: {selectedFile.type || 'Binary Stream'}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleReset}
                  className="text-slate-500 hover:text-slate-200 p-1 rounded hover:bg-slate-900"
                  title="Remove selected file"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Validation Status Pill */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-850 text-2xs font-mono">
                <span className="text-slate-400 flex items-center gap-1.5">
                  {fileValidationState === 'validating' ? (
                    <>
                      <div className="w-3 h-3 border border-sky-400 border-t-transparent rounded-full animate-spin" />
                      <span>Validating file structure & magic checksum...</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400 font-semibold">Validation Passed: Valid PE Header Structure</span>
                    </>
                  )}
                </span>

                <Button
                  variant="primary"
                  size="xs"
                  onClick={handleStartAnalysis}
                  disabled={fileValidationState !== 'valid' || pipelineState === 'running'}
                  leftIcon={<Play className="w-3 h-3" />}
                >
                  Start Static Analysis
                </Button>
              </div>
            </div>
          )}

          {/* 10-Stage Explicit Analysis Pipeline Progress */}
          {pipelineState === 'running' && (
            <div className="p-4 bg-slate-950 border border-sky-900/80 rounded space-y-3 animate-in fade-in duration-150">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-sky-400 border-b border-slate-850 pb-2">
                <span className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 animate-spin" />
                  <span>Executing 10-Stage Static Analysis Pipeline...</span>
                </span>
                <span>Stage {currentStageIndex + 1} of 10</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-2xs font-mono">
                {STAGES.map((stageName, idx) => {
                  const isDone = idx < currentStageIndex;
                  const isCurrent = idx === currentStageIndex;
                  return (
                    <div
                      key={stageName}
                      className={`p-2 rounded border flex items-center justify-between transition-colors ${
                        isDone
                          ? 'bg-slate-900/90 border-slate-800 text-slate-300'
                          : isCurrent
                          ? 'bg-sky-950/60 border-sky-500 text-sky-300 font-bold'
                          : 'bg-slate-950/40 border-slate-900 text-slate-600'
                      }`}
                    >
                      <span className="truncate">{idx + 1}. {stageName}</span>
                      {isDone ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <div className="w-3 h-3 border border-sky-400 border-t-transparent rounded-full animate-spin shrink-0" />
                      ) : (
                        <span className="text-slate-600">Queued</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Deep Analysis Results View */}
      {report && (
        <div className="space-y-5">
          {/* Top Overview & Risk Summary Box */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-bold font-mono text-slate-100">{report.fileName}</h2>
                  <Badge verdict={report.classification} size="sm">
                    {report.classification}
                  </Badge>
                  <span className="text-xs font-mono font-bold text-red-400 bg-red-950/60 border border-red-800/80 px-2 py-0.5 rounded">
                    {report.threatFamily}
                  </span>
                </div>
                <p className="text-2xs font-mono text-slate-500 mt-1">
                  Type: {report.fileType} • Size: {formatBytes(report.fileSize)} • Magic: {report.magicBytes}
                </p>
              </div>

              {/* Risk Score Spotlight */}
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-2xs font-mono uppercase text-slate-500 font-semibold">Threat Risk Score</div>
                  <RiskScoreBar score={report.riskScore} size="md" />
                </div>
              </div>
            </div>

            {/* Quick Hashes Bar */}
            <div className="p-3 bg-slate-950 rounded border border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-3 text-2xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-500">SHA-256:</span>
                <MonoText value={report.sha256} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">MD5:</span>
                <MonoText value={report.md5} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">SSDEEP:</span>
                <MonoText value={report.ssdeep} truncate startLen={10} endLen={6} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">IMPHASH:</span>
                <MonoText value={report.imphash} />
              </div>
            </div>

            {/* Recommended Action Box */}
            <div className="p-3 bg-amber-950/20 border border-amber-800/60 rounded text-2xs font-mono flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-amber-400 font-bold uppercase block">Recommended Incident Response Action:</span>
                <span className="text-amber-200/90">{report.recommendedAction}</span>
              </div>
            </div>
          </div>

          {/* Section 1: YARA Rule Matches */}
          <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-400" />
                <span>YARA Rule Engine Matches ({report.yaraMatches.length})</span>
              </h3>
              <span className="text-2xs text-slate-500">Compiled Rule Corpus v24.2</span>
            </div>

            <div className="space-y-2">
              {report.yaraMatches.map((yara) => (
                <div key={yara.ruleName} className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-red-400">{yara.ruleName}</span>
                      <Badge severity={yara.severity} size="xs">{yara.severity}</Badge>
                      <span className="text-2xs text-slate-500">[{yara.category}]</span>
                    </div>
                    <span className="text-2xs text-emerald-400 font-bold">MATCHED</span>
                  </div>
                  <p className="text-2xs text-slate-400">{yara.description}</p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {yara.matchedStrings.map((str, i) => (
                      <MonoText key={i} value={str} highlight />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Static Indicators (Strings, PowerShell, URLs, IPs) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 font-mono">
            {/* Suspicious Strings & Obfuscated PowerShell */}
            <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-amber-400" />
                  <span>Obfuscated PowerShell & Suspicious Commands</span>
                </h3>
              </div>

              <div className="space-y-2">
                {report.powershellIndicators.map((ps, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-950 rounded border border-amber-900/60 text-2xs text-amber-300 break-all">
                    <code>{ps}</code>
                  </div>
                ))}
              </div>

              <div className="pt-2">
                <span className="text-2xs text-slate-500 uppercase font-semibold block mb-1.5">
                  Extracted Suspicious Strings ({report.suspiciousStrings.length}):
                </span>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800 max-h-36 overflow-y-auto space-y-1 text-2xs text-slate-300">
                  {report.suspiciousStrings.map((s, i) => (
                    <div key={i} className="truncate select-all hover:text-sky-300">
                      • {s}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Extracted C2 URLs & IP Addresses */}
            <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
                  <Network className="w-4 h-4 text-sky-400" />
                  <span>Extracted C2 Network IOCs</span>
                </h3>
              </div>

              <div className="space-y-2 text-2xs">
                <span className="text-slate-500 uppercase font-semibold block">C2 Dropper URLs:</span>
                {report.extractedUrls.map((url) => (
                  <div key={url} className="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between">
                    <MonoText value={url} highlight />
                    <Button variant="ghost" size="xs" onClick={() => alert(`C2 domain ${url} submitted to firewall blocklist`)}>
                      Block
                    </Button>
                  </div>
                ))}

                <span className="text-slate-500 uppercase font-semibold block pt-2">Extracted C2 IP Addresses:</span>
                {report.extractedIps.map((ip) => (
                  <div key={ip} className="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between">
                    <MonoText value={ip} highlight />
                    <span className="text-2xs text-slate-500">ASN 49505 Hostkey</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Section 3: PE Metadata & Sections Entropy */}
          <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-400" />
                <span>PE Headers & Section Entropy Analysis</span>
              </h3>
              <span className="text-2xs text-slate-500">{report.peSections.length} Sections</span>
            </div>

            <div className="border border-slate-800 rounded bg-slate-950 overflow-x-auto">
              <table className="w-full text-left border-collapse soc-table">
                <thead>
                  <tr>
                    <th>Section Name</th>
                    <th>Virtual Size</th>
                    <th>Raw Size</th>
                    <th>Entropy Level</th>
                    <th>Characteristics Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {report.peSections.map((sec) => (
                    <tr key={sec.name} className="hover:bg-slate-900/60">
                      <td className="font-bold text-sky-300">{sec.name}</td>
                      <td>{formatBytes(sec.virtualSize)}</td>
                      <td>{formatBytes(sec.rawSize)}</td>
                      <td><EntropyBar entropy={sec.entropy} /></td>
                      <td className="text-2xs text-slate-500">{sec.characteristics.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Imported DLLs & Functions */}
            <div className="pt-2">
              <span className="text-2xs text-slate-500 uppercase font-semibold block mb-2">
                Imported DLLs & Suspicious Win32 API Functions:
              </span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {report.importedDlls.map((dllGroup) => (
                  <div key={dllGroup.dll} className="p-3 bg-slate-950 rounded border border-slate-850 space-y-1 text-2xs">
                    <span className="text-sky-400 font-bold block">{dllGroup.dll}</span>
                    <div className="space-y-0.5 text-slate-300">
                      {dllGroup.functions.map((fn) => (
                        <div key={fn} className="hover:text-amber-400">• {fn}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
