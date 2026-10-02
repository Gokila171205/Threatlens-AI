import React, { useState, useEffect } from 'react';
import {
  BarChart2,
  Activity,
  Layers,
  ShieldAlert,
  Zap,
  RotateCw
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { ThreatTimelineChart } from '../components/common/ThreatTimelineChart';
import { RiskScoreBar } from '../components/common/RiskScoreBar';
import { LoadingState } from '../components/ui/LoadingState';
import { ThreatLensApi } from '../services/api';
import { MOCK_TIMELINE_DATA } from '../data/mockDashboardData';
import type { MalwareFamilyShare, ConfidenceBracket } from '../data/mockAnalyticsData';

export const AnalyticsPage: React.FC = () => {
  const [dateRange, setDateRange] = useState<'24h' | '7d' | '30d' | '90d'>('24h');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const [metrics, setMetrics] = useState<{
    totalScanned: number;
    maliciousDetected: number;
    suspiciousDetected: number;
    cleanRatio: string;
    avgRiskScore: number;
    avgInferenceMs: number;
    avgSandboxLatencySec: number;
  } | null>(null);

  const [families, setFamilies] = useState<MalwareFamilyShare[]>([]);
  const [confidenceBrackets, setConfidenceBrackets] = useState<ConfidenceBracket[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [threatLevels, setThreatLevels] = useState<Record<string, number>>({
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  });

  useEffect(() => {
    async function loadData() {
      setIsLoading(true);
      const data = await ThreatLensApi.getAnalyticsSummary();
      setMetrics(data.metrics);
      setFamilies(data.families);
      setConfidenceBrackets(data.confidenceBrackets);
      if (data.timeline && data.timeline.length > 0) {
        setTimeline(data.timeline);
      } else {
        setTimeline(MOCK_TIMELINE_DATA);
      }
      if (data.threatLevelDistribution) {
        setThreatLevels({
          CRITICAL: data.threatLevelDistribution.CRITICAL || 0,
          HIGH: data.threatLevelDistribution.HIGH || 0,
          MEDIUM: data.threatLevelDistribution.MEDIUM || 0,
          LOW: data.threatLevelDistribution.LOW || 0,
        });
      }
      setIsLoading(false);
    }
    loadData();
  }, []);

  if (isLoading || !metrics) {
    return <LoadingState message="Calculating SOC Threat Analytics & Vector Distribution..." />;
  }

  return (
    <div className="space-y-6 select-none font-sans">
      {/* Top Banner Header */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-2xs">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span>Threat Vector Trends & Incident Analytics</span>
          </h1>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            Statistical Telemetry Analysis • NeuralPE Model Accuracy & Performance Audit
          </p>
        </div>

        {/* Date Range Selector & Refresh */}
        <div className="flex items-center gap-2 shrink-0 font-mono text-2xs">
          <div className="inline-flex items-center bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded p-0.5">
            {(['24h', '7d', '30d', '90d'] as const).map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setDateRange(range)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  dateRange === range
                    ? 'bg-white dark:bg-sky-950 text-sky-700 dark:text-sky-400 font-bold border border-slate-300 dark:border-sky-800/80 shadow-2xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {range.toUpperCase()}
              </button>
            ))}
          </div>

          <Button
            variant="secondary"
            size="xs"
            leftIcon={<RotateCw className="w-3 h-3" />}
            onClick={() => {
              setIsLoading(true);
              setTimeout(() => setIsLoading(false), 400);
            }}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* 4 Top KPI Analytics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <span className="text-2xs text-slate-500 uppercase">Detection Volume</span>
          <div className="mt-2">
            <span className="text-xl font-bold text-slate-900 dark:text-slate-100">{metrics.totalScanned.toLocaleString()}</span>
            <div className="text-2xs text-sky-600 dark:text-sky-400 mt-0.5 font-medium">{metrics.cleanRatio} Clean Payload Ratio</div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <span className="text-2xs text-slate-500 uppercase">Malicious Threat Detections</span>
          <div className="mt-2">
            <span className="text-xl font-bold text-red-600 dark:text-red-400">{metrics.maliciousDetected}</span>
            <div className="text-2xs text-slate-500 dark:text-slate-400 mt-0.5">+{metrics.suspiciousDetected} Suspicious Flagged</div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <span className="text-2xs text-slate-500 uppercase">Mean Security Risk Score</span>
          <div className="mt-2">
            <RiskScoreBar score={metrics.avgRiskScore} size="sm" />
            <div className="text-2xs text-slate-500 dark:text-slate-400 mt-1">Target Impact Threshold</div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <span className="text-2xs text-slate-500 uppercase">NeuralPE Inference Speed</span>
          <div className="mt-2">
            <span className="text-xl font-bold text-emerald-700 dark:text-emerald-400">{metrics.avgInferenceMs} ms</span>
            <div className="text-2xs text-slate-500 dark:text-slate-400 mt-0.5">Sandbox: {metrics.avgSandboxLatencySec}s avg</div>
          </div>
        </div>
      </div>

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 font-mono">
        {/* Section 1: Malware Detection & Ingestion Velocity Trend */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-600 dark:text-sky-400" />
              <span>1. Malware Detection & Ingestion Velocity Trend</span>
            </h2>
            <span className="text-2xs text-slate-500">Range: {dateRange.toUpperCase()}</span>
          </div>

          <ThreatTimelineChart data={timeline} />
        </div>

        {/* Section 2: Severity Distribution Ratios */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              <span>2. Severity Trend & Incident Ratio Breakdown</span>
            </h2>
            <span className="text-2xs text-slate-500">
              Total: {metrics.totalScanned} Scans
            </span>
          </div>

          {(() => {
            const total = Math.max(metrics.totalScanned, 1);
            const critPct = Math.round(((threatLevels.CRITICAL || 0) / total) * 100);
            const highPct = Math.round(((threatLevels.HIGH || 0) / total) * 100);
            const medPct = Math.round(((threatLevels.MEDIUM || 0) / total) * 100);
            const lowPct = Math.round(((threatLevels.LOW || 0) / total) * 100);

            return (
              <div className="space-y-3 text-2xs pt-2">
                <div className="space-y-1">
                  <div className="flex justify-between font-bold">
                    <span className="text-red-700 dark:text-red-400">Critical Severity (Risk ≥ 85)</span>
                    <span className="text-slate-800 dark:text-slate-200">{threatLevels.CRITICAL || 0} Threats ({critPct}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-2 rounded overflow-hidden border border-slate-200 dark:border-slate-800">
                    <div className="bg-red-500 h-full transition-all" style={{ width: `${critPct}%` }} />
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between font-bold">
                    <span className="text-orange-800 dark:text-orange-400">High Severity (Risk 70-84)</span>
                    <span className="text-slate-800 dark:text-slate-200">{threatLevels.HIGH || 0} Threats ({highPct}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-2 rounded overflow-hidden border border-slate-200 dark:border-slate-800">
                    <div className="bg-orange-500 h-full transition-all" style={{ width: `${highPct}%` }} />
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between font-bold">
                    <span className="text-amber-800 dark:text-amber-400">Medium Severity (Risk 40-69)</span>
                    <span className="text-slate-800 dark:text-slate-200">{threatLevels.MEDIUM || 0} Threats ({medPct}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-2 rounded overflow-hidden border border-slate-200 dark:border-slate-800">
                    <div className="bg-amber-500 h-full transition-all" style={{ width: `${medPct}%` }} />
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between font-bold">
                    <span className="text-emerald-800 dark:text-emerald-400">Low Severity (Risk &lt; 40)</span>
                    <span className="text-slate-800 dark:text-slate-200">{threatLevels.LOW || 0} Threats ({lowPct}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-2 rounded overflow-hidden border border-slate-200 dark:border-slate-800">
                    <div className="bg-emerald-500 h-full transition-all" style={{ width: `${lowPct}%` }} />
                  </div>
                </div>
              </div>
            );
          })()}
        </div>

        {/* Section 3: Heuristic & YARA Signature Tags */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>3. Heuristic & YARA Signature Tags</span>
              </h2>
              <span className="text-2xs text-slate-400">Rule-based tags • EMBER RF is binary classifier</span>
            </div>
            <span className="text-2xs text-slate-500">{families.length} Clusters</span>
          </div>

          <div className="space-y-2.5">
            {families.length === 0 ? (
              <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 text-xs text-slate-500 italic">
                Zero heuristic threat signatures recorded in current database scans.
              </div>
            ) : (
              families.map((fam) => (
                <div key={fam.family} className="space-y-1 text-2xs">
                  <div className="flex justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-900 dark:text-slate-100">{fam.family}</span>
                      <span className="text-slate-500 text-2xs">({fam.category})</span>
                    </div>
                    <span className="font-bold text-slate-800 dark:text-slate-200">{fam.count} ({fam.percentage}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded overflow-hidden border border-slate-200 dark:border-slate-850">
                    <div
                      className={`h-full ${
                        fam.severity === 'critical' ? 'bg-red-500' : fam.severity === 'high' ? 'bg-orange-500' : 'bg-amber-500'
                      }`}
                      style={{ width: `${Math.min(fam.percentage, 100)}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Section 4: Classification Model Confidence Brackets */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Zap className="w-4 h-4 text-sky-600 dark:text-sky-400" />
              <span>4. NeuralPE Classifier Certainty Brackets</span>
            </h2>
            <span className="text-2xs text-slate-500">Model Accuracy Audit</span>
          </div>

          <div className="space-y-2.5">
            {confidenceBrackets.map((b) => (
              <div key={b.bracket} className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-1 text-2xs">
                <div className="flex justify-between">
                  <span className="font-bold text-sky-700 dark:text-sky-300">{b.bracket}</span>
                  <span className="text-slate-800 dark:text-slate-200 font-bold">{b.count} Samples ({b.percentage}%)</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-900 h-1.5 rounded overflow-hidden">
                  <div className="bg-sky-500 h-full" style={{ width: `${b.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
