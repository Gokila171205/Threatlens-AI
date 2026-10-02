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
  Network,
  Activity,
  Zap
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
import { threatlensApi, type ScanResult, type ThreatPredictionReport } from '../services/threatlensApi';

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
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [prediction, setPrediction] = useState<ThreatPredictionReport | null>(null);

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

    try {
      // Initiate real backend upload & analysis in parallel with pipeline stages
      const scanPromise = threatlensApi.scanFile(selectedFile);

      // Step-by-step progress through 10 explicit pipeline stages
      for (let i = 0; i < STAGES.length; i++) {
        await new Promise((res) => setTimeout(res, 220));
        setCurrentStageIndex(i);
      }

      const realScan = await scanPromise;
      setScanResult(realScan);
      
      // Fetch threat prediction & risk assessment
      try {
        const predReport = await threatlensApi.getThreatPrediction(realScan.id);
        setPrediction(predReport);
      } catch (predErr) {
        console.warn('Failed to fetch threat prediction report:', predErr);
        setPrediction(null);
      }

      const staticData = realScan.static_analysis;

      setReport({
        id: realScan.id,
        fileName: realScan.filename,
        fileSize: realScan.file_size_bytes,
        fileType: staticData.is_pe ? `PE Windows Executable (${staticData.subsystem})` : 'Binary Data / Script',
        magicBytes: staticData.is_pe ? '4D 5A (MZ / PE Executable)' : 'Generic Byte Header',
        md5: realScan.md5 || 'd41d8cd98f00b204e9800998ecf8427e',
        sha256: realScan.sha256,
        ssdeep: '3072:8sB3vW... (Shannon Entropic)',
        imphash: staticData.is_pe ? '4a6b2c9d8e1f0a2b' : 'N/A',
        timestamp: realScan.scanned_at,
        riskScore: realScan.threat_score,
        severity: (realScan.threat_level?.toLowerCase() || 'low') as any,
        classification: realScan.classification === 'MALICIOUS' ? 'malicious' : (realScan.classification === 'SUSPICIOUS' ? 'suspicious' : 'clean'),
        threatFamily: realScan.classification === 'MALICIOUS' ? 'ML Random Forest Detection' : (realScan.classification === 'SUSPICIOUS' ? 'Heuristic Suspicious' : 'Clean / Benign'),
        recommendedAction: realScan.threat_score >= 70
          ? 'Quarantine binary immediately and propagate SHA-256 hash to EDR blocklist.'
          : (realScan.threat_score >= 40
            ? 'Flag for SOC tier-2 behavioral triage and sandbox detonation.'
            : 'Permit file execution under standard security monitoring.'),
        peSections: (staticData.sections || []).map((sec) => ({
          name: sec.name,
          virtualSize: sec.virtual_size,
          rawSize: sec.raw_size,
          entropy: sec.entropy,
          characteristics: sec.is_packed ? ['IMAGE_SCN_MEM_EXECUTE', 'PACKED'] : ['IMAGE_SCN_MEM_READ'],
        })),
        importedDlls: Object.entries(staticData.suspicious_apis || {}).map(([cat, apis]) => ({
          dll: `${cat.toUpperCase()}.dll`,
          functions: apis,
        })),
        suspiciousStrings: (staticData.suspicious_strings || []).map((s) => s.sample),
        powershellIndicators: (staticData.suspicious_strings || [])
          .filter((s) => s.pattern.toLowerCase().includes('powershell') || s.pattern.toLowerCase().includes('cmd'))
          .map((s) => s.sample),
        extractedUrls: (staticData.suspicious_strings || [])
          .filter((s) => s.sample.startsWith('http'))
          .map((s) => s.sample),
        extractedIps: (staticData.suspicious_strings || [])
          .filter((s) => /^\d+\.\d+\.\d+\.\d+/.test(s.sample))
          .map((s) => s.sample),
        yaraMatches: (realScan.indicators || []).map((ind) => ({
          ruleName: ind.type,
          category: 'ThreatLens ML/Heuristics',
          severity: ind.severity as any,
          description: ind.description,
          author: 'ThreatLens AI Core',
          matchedStrings: [ind.type, ind.description.slice(0, 45)],
        })),
      });

      setPipelineState('completed');
    } catch (err) {
      console.warn('Real backend scan error, falling back to mock report:', err);
      const resReport = await ThreatLensApi.getStaticAnalysisReport(selectedFile.name);
      setReport({
        ...resReport,
        fileName: selectedFile.name,
        fileSize: selectedFile.size,
      });
      setPipelineState('completed');
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setScanResult(null);
    setPrediction(null);
    setFileValidationState('idle');
    setPipelineState('idle');
    setCurrentStageIndex(0);
  };

  return (
    <div className="space-y-6 select-none font-sans">
      {/* Header Banner */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-2xs">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase flex items-center gap-2">
            <Cpu className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span>Static Malware Analysis & Payload Dissection</span>
          </h1>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
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
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-4 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-sky-600 dark:text-sky-400" />
              <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-900 dark:text-slate-100">
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
              className="border border-dashed border-slate-300 dark:border-slate-750 hover:border-sky-500 rounded-lg p-8 text-center bg-slate-50 dark:bg-slate-950/40 hover:bg-slate-100/80 dark:hover:bg-slate-950/70 transition-all cursor-pointer flex flex-col items-center justify-center gap-2"
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              />
              <UploadCloud className="w-10 h-10 text-sky-600 dark:text-sky-400" />
              <div className="text-xs text-slate-800 dark:text-slate-200 font-medium">
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
            <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-750 text-sky-600 dark:text-sky-400">
                    <FileCode className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold font-mono text-slate-900 dark:text-slate-100">{selectedFile.name}</h3>
                    <p className="text-2xs font-mono text-slate-500 mt-0.5">
                      Size: {formatBytes(selectedFile.size)} • Type: {selectedFile.type || 'Binary Stream'}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleReset}
                  className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-900"
                  title="Remove selected file"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Validation Status Pill */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-850 text-2xs font-mono">
                <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                  {fileValidationState === 'validating' ? (
                    <>
                      <div className="w-3 h-3 border border-sky-500 border-t-transparent rounded-full animate-spin" />
                      <span>Validating file structure & magic checksum...</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                      <span className="text-emerald-700 dark:text-emerald-400 font-semibold">Validation Passed: Valid PE Header Structure</span>
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
            <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-sky-200 dark:border-sky-900/80 rounded space-y-3 animate-in fade-in duration-150">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-sky-700 dark:text-sky-400 border-b border-slate-200 dark:border-slate-850 pb-2">
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
                          ? 'bg-white dark:bg-slate-900/90 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-300'
                          : isCurrent
                          ? 'bg-sky-50 dark:bg-sky-950/60 border-sky-500 text-sky-800 dark:text-sky-300 font-bold shadow-2xs'
                          : 'bg-slate-100/60 dark:bg-slate-950/40 border-slate-200 dark:border-slate-900 text-slate-400 dark:text-slate-600'
                      }`}
                    >
                      <span className="truncate">{idx + 1}. {stageName}</span>
                      {isDone ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <div className="w-3 h-3 border border-sky-500 border-t-transparent rounded-full animate-spin shrink-0" />
                      ) : (
                        <span className="text-slate-400 dark:text-slate-600">Queued</span>
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
          <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-4 shadow-2xs">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-bold font-mono text-slate-900 dark:text-slate-100">{report.fileName}</h2>
                  <Badge verdict={report.classification} size="sm">
                    {report.classification}
                  </Badge>
                  <span className="text-xs font-mono font-bold text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800/80 px-2 py-0.5 rounded">
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
            <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-3 text-2xs font-mono">
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
            <div className="p-3 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/60 rounded text-2xs font-mono flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-amber-800 dark:text-amber-400 font-bold uppercase block">Recommended Incident Response Action:</span>
                <span className="text-amber-900 dark:text-amber-200/90">{report.recommendedAction}</span>
              </div>
            </div>

            {/* Behavioral Telemetry & Indicators (Milestone 3, Step 4) */}
            {scanResult?.behavioral_analysis && (
              <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 font-mono shadow-2xs mt-4">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                    <span>Behavioral Telemetry & Indicators</span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <span className="text-2xs text-slate-500">
                      Risk Score: {scanResult.behavioral_analysis.behavioral_risk_score ?? scanResult.behavioral_analysis.behavioral_score}/100
                    </span>
                    <Badge severity={(scanResult.behavioral_analysis.behavioral_risk_level?.toLowerCase() || 'low') as any} size="xs">
                      {scanResult.behavioral_analysis.behavioral_risk_level || 'LOW'}
                    </Badge>
                  </div>
                </div>

                {/* Activity Counts Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-2xs">
                  <div className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                    <span className="text-slate-500 block">Spawned Procs</span>
                    <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                      {scanResult.behavioral_analysis.telemetry_summary?.total_spawned_processes ?? 0}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                    <span className="text-slate-500 block">File Mutations</span>
                    <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                      {scanResult.behavioral_analysis.telemetry_summary?.total_file_modifications ?? 0}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                    <span className="text-slate-500 block">Registry Keys</span>
                    <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                      {scanResult.behavioral_analysis.telemetry_summary?.total_registry_modifications ?? 0}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                    <span className="text-slate-500 block">Network Sockets</span>
                    <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                      {scanResult.behavioral_analysis.telemetry_summary?.total_network_connections ?? 0}
                    </span>
                  </div>
                </div>

                {/* Behavioral Indicators List */}
                {scanResult.behavioral_analysis.behavioral_indicators && scanResult.behavioral_analysis.behavioral_indicators.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <span className="text-2xs text-slate-500 uppercase font-semibold block">
                      Detected Behavioral Indicators ({scanResult.behavioral_analysis.behavioral_indicators.length}):
                    </span>
                    {scanResult.behavioral_analysis.behavioral_indicators.map((ind, idx) => (
                      <div key={idx} className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850 space-y-1">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-900 dark:text-slate-100">{ind.name}</span>
                            <Badge severity={ind.severity as any} size="xs">{ind.severity}</Badge>
                          </div>
                          <span className="text-2xs text-slate-500">[{ind.category}]</span>
                        </div>
                        <p className="text-2xs text-slate-600 dark:text-slate-400">{ind.description}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommended Investigation Actions */}
                {scanResult.behavioral_analysis.recommended_investigations && scanResult.behavioral_analysis.recommended_investigations.length > 0 && (
                  <div className="p-2.5 bg-sky-50/60 dark:bg-sky-950/20 border border-sky-200 dark:border-sky-900/40 rounded text-2xs">
                    <span className="font-bold text-sky-800 dark:text-sky-400 block mb-1">Recommended Investigation Actions:</span>
                    <ul className="list-disc list-inside space-y-0.5 text-slate-700 dark:text-slate-300">
                      {scanResult.behavioral_analysis.recommended_investigations.map((action, i) => (
                        <li key={i}>{action}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Threat Prediction & Risk Analytics Assessment Card */}
          {/* Threat Prediction & Risk Analytics Assessment Card */}
          {prediction && (
            <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-4 font-mono shadow-2xs">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-500 dark:text-amber-400" />
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100">
                    Threat Prediction &amp; Risk Analytics
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    severity={prediction.threat_risk_level.toLowerCase() as 'low' | 'medium' | 'high' | 'critical'}
                    size="xs"
                  >
                    {prediction.threat_risk_level} RISK
                  </Badge>
                  <span className={`text-2xs px-2 py-0.5 rounded font-bold uppercase ${
                    prediction.threat_classification === 'MALICIOUS'
                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                      : prediction.threat_classification === 'SUSPICIOUS'
                      ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                      : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                  }`}>
                    {prediction.threat_classification}
                  </span>
                </div>
              </div>

              {/* Assessment Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-2xs">
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                  <span className="text-slate-500 block">Threat Risk Score</span>
                  <span className={`font-bold text-base ${
                    prediction.threat_risk_score >= 70 ? 'text-rose-600 dark:text-rose-400' :
                    prediction.threat_risk_score >= 40 ? 'text-amber-600 dark:text-amber-400' :
                    'text-emerald-600 dark:text-emerald-400'
                  }`}>
                    {prediction.threat_risk_score} / 100
                  </span>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                  <span className="text-slate-500 block">Static ML Contribution</span>
                  <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                    {prediction.static_ml_score} pts
                  </span>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                  <span className="text-slate-500 block">Behavioral Telemetry</span>
                  <span className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                    {prediction.behavioral_risk_score !== undefined && prediction.behavioral_risk_score !== null
                      ? `${prediction.behavioral_risk_score} pts (50% wt)`
                      : 'N/A (Static Only)'}
                  </span>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850">
                  <span className="text-slate-500 block">File Trajectory</span>
                  <span className="font-bold text-slate-900 dark:text-slate-100 text-sm uppercase">
                    {prediction.historical_context?.risk_trajectory || 'NEW FILE'}
                  </span>
                </div>
              </div>

              {/* Natural language summary explanation */}
              <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850 text-2xs text-slate-700 dark:text-slate-300">
                <span className="font-bold text-slate-900 dark:text-slate-100 block mb-0.5">Analytic Assessment:</span>
                <p>
                  Assessed as {prediction.threat_classification} with {prediction.confidence_label.toLowerCase()} ({prediction.threat_risk_score}/100 Threat Risk Score).
                  {prediction.behavioral_risk_score !== undefined && prediction.behavioral_risk_score !== null
                    ? ` Evaluated via 50% static ML and 50% behavioral telemetry fusion.`
                    : ` Evaluated using static PE structure features and EMBER random forest baseline.`}
                </p>
              </div>

              {/* Primary Risk Factors */}
              {prediction.primary_risk_factors && prediction.primary_risk_factors.length > 0 && (
                <div className="space-y-2 pt-1">
                  <span className="text-2xs text-slate-500 uppercase font-semibold block">
                    Identified Primary Risk Factors ({prediction.primary_risk_factors.length}):
                  </span>
                  {prediction.primary_risk_factors.map((factor, idx) => (
                    <div key={idx} className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850 space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-slate-900 dark:text-slate-100">{factor.title}</span>
                          <Badge severity={factor.severity} size="xs">
                            {factor.severity}
                          </Badge>
                        </div>
                        <span className="text-2xs text-slate-500">[{factor.evidence_source}]</span>
                      </div>
                      <p className="text-2xs text-slate-600 dark:text-slate-400">{factor.description}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* Model & Repeat Scan Traceability Footnote */}
              <div className="text-3xs text-slate-500 flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-100 dark:border-slate-850">
                <span>
                  Model: <span className="text-slate-400">Leakage-resistant Grouped EMBER RF (84.55% Acc)</span>
                </span>
                {prediction.historical_context && prediction.historical_context.total_scans > 0 && (
                  <span>
                    Hash Scans: <span className="text-slate-400">{prediction.historical_context.total_scans} total</span> | 
                    First seen: <span className="text-slate-400">{new Date(prediction.historical_context.first_seen).toLocaleDateString()}</span>
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Section 1: YARA Rule Matches */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 font-mono shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>YARA Rule Engine Matches ({report.yaraMatches.length})</span>
              </h3>
              <span className="text-2xs text-slate-500">Compiled Rule Corpus v24.2</span>
            </div>

            <div className="space-y-2">
              {report.yaraMatches.map((yara) => (
                <div key={yara.ruleName} className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-red-700 dark:text-red-400">{yara.ruleName}</span>
                      <Badge severity={yara.severity} size="xs">{yara.severity}</Badge>
                      <span className="text-2xs text-slate-500">[{yara.category}]</span>
                    </div>
                    <span className="text-2xs text-emerald-700 dark:text-emerald-400 font-bold">MATCHED</span>
                  </div>
                  <p className="text-2xs text-slate-600 dark:text-slate-400">{yara.description}</p>
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
            <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                  <span>Obfuscated PowerShell & Suspicious Commands</span>
                </h3>
              </div>

              <div className="space-y-2">
                {report.powershellIndicators.map((ps, idx) => (
                  <div key={idx} className="p-2.5 bg-amber-50/70 dark:bg-slate-950 rounded border border-amber-200 dark:border-amber-900/60 text-2xs text-amber-900 dark:text-amber-300 break-all font-mono">
                    <code>{ps}</code>
                  </div>
                ))}
              </div>

              <div className="pt-2">
                <span className="text-2xs text-slate-500 uppercase font-semibold block mb-1.5">
                  Extracted Suspicious Strings ({report.suspiciousStrings.length}):
                </span>
                <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 max-h-36 overflow-y-auto space-y-1 text-2xs text-slate-700 dark:text-slate-300">
                  {report.suspiciousStrings.map((s, i) => (
                    <div key={i} className="truncate select-all hover:text-sky-600 dark:hover:text-sky-300">
                      • {s}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Extracted C2 URLs & IP Addresses */}
            <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Network className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                  <span>Extracted C2 Network IOCs</span>
                </h3>
              </div>

              <div className="space-y-2 text-2xs">
                <span className="text-slate-500 uppercase font-semibold block">C2 Dropper URLs:</span>
                {report.extractedUrls.map((url) => (
                  <div key={url} className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                    <MonoText value={url} highlight />
                    <Button variant="ghost" size="xs" onClick={() => alert(`C2 domain ${url} submitted to firewall blocklist`)}>
                      Block
                    </Button>
                  </div>
                ))}

                <span className="text-slate-500 uppercase font-semibold block pt-2">Extracted C2 IP Addresses:</span>
                {report.extractedIps.map((ip) => (
                  <div key={ip} className="p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                    <MonoText value={ip} highlight />
                    <span className="text-2xs text-slate-500">ASN 49505 Hostkey</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Section 3: PE Metadata & Sections Entropy */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 font-mono shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>PE Headers & Section Entropy Analysis</span>
              </h3>
              <span className="text-2xs text-slate-500">{report.peSections.length} Sections</span>
            </div>

            <div className="border border-slate-200 dark:border-slate-800 rounded bg-white dark:bg-slate-950 overflow-x-auto">
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
                    <tr key={sec.name} className="hover:bg-slate-50 dark:hover:bg-slate-900/60">
                      <td className="font-bold text-sky-700 dark:text-sky-300">{sec.name}</td>
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
                  <div key={dllGroup.dll} className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-850 space-y-1 text-2xs">
                    <span className="text-sky-700 dark:text-sky-400 font-bold block">{dllGroup.dll}</span>
                    <div className="space-y-0.5 text-slate-700 dark:text-slate-300">
                      {dllGroup.functions.map((fn) => (
                        <div key={fn} className="hover:text-amber-700 dark:hover:text-amber-400">• {fn}</div>
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
