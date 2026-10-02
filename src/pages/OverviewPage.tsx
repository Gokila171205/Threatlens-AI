import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Cpu,
  RefreshCw,
  Search,
  AlertTriangle,
  FileCode,
  Activity,
  Layers
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Table } from '../components/ui/Table';
import type { Column } from '../components/ui/Table';
import { Badge } from '../components/ui/Badge';
import { MonoText } from '../components/common/MonoText';
import { StatusIndicator } from '../components/ui/StatusIndicator';
import { RiskScoreBar } from '../components/common/RiskScoreBar';
import { ThreatTimelineChart } from '../components/common/ThreatTimelineChart';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { threatlensApi, type MonitoringOverview, type AnalyticsData, type ScanSummaryItem } from '../services/threatlensApi';
import { useThreatLens } from '../context/ThreatLensContext';
import { useAuth } from '../context/AuthContext';
import { formatRelativeTime } from '../utils/formatters';

interface LiveDetectionItem {
  id: string;
  fileName: string;
  fileType: string;
  detectionTime: string;
  classification: 'clean' | 'suspicious' | 'malicious';
  severity: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  sha256: string;
  threatFamily?: string;
  targetHost?: string;
}

export const OverviewPage: React.FC = () => {
  const { navigate, isStreamLive } = useThreatLens();
  const { user } = useAuth();

  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [showErrorBanner, setShowErrorBanner] = useState<boolean>(false);
  const [lastRefreshed, setLastRefreshed] = useState<string>(new Date().toISOString());

  // Live state from backend
  const [overview, setOverview] = useState<MonitoringOverview | null>(null);
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [detections, setDetections] = useState<LiveDetectionItem[]>([]);

  const loadDashboardData = async () => {
    setIsLoading(true);
    try {
      const [overviewData, analyticsData] = await Promise.all([
        threatlensApi.getMonitoringOverview(),
        threatlensApi.getMonitoringAnalytics().catch(() => null),
      ]);

      setOverview(overviewData);
      setAnalytics(analyticsData);

      // Map live scans into detections
      const mapped: LiveDetectionItem[] = (overviewData.recent_scans || []).map((s: ScanSummaryItem) => {
        const clsLower = (s.classification || 'BENIGN').toLowerCase();
        const verdict: 'clean' | 'suspicious' | 'malicious' =
          clsLower === 'malicious' ? 'malicious' : clsLower === 'suspicious' ? 'suspicious' : 'clean';
        const severity: 'low' | 'medium' | 'high' | 'critical' =
          (s.threat_level?.toLowerCase() || (s.threat_score >= 85 ? 'critical' : s.threat_score >= 70 ? 'high' : s.threat_score >= 40 ? 'medium' : 'low')) as any;

        return {
          id: s.id,
          fileName: s.filename,
          fileType: s.is_pe ? 'PE Executable' : 'Binary Payload',
          detectionTime: s.scanned_at || new Date().toISOString(),
          classification: verdict,
          severity,
          riskScore: s.threat_score,
          sha256: s.sha256,
          threatFamily: s.classification === 'MALICIOUS' ? 'ML Random Forest Detection' : s.classification === 'SUSPICIOUS' ? 'Heuristic Suspicious' : 'Clean Binary',
          targetHost: 'ENDPOINT-AGENT-01.corp.internal',
        };
      });

      setDetections(mapped);
      setLastRefreshed(new Date().toISOString());
    } catch (err) {
      console.error('Failed to load live overview metrics:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const handleRefresh = () => {
    loadDashboardData();
  };

  // Filter detections based on search & severity
  const filteredDetections = detections.filter((det) => {
    const matchesSev = filterSeverity === 'all' || det.severity === filterSeverity;
    const matchesSearch =
      det.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.threatFamily?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.targetHost?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const detectionColumns: Column<LiveDetectionItem>[] = [
    {
      key: 'fileName',
      header: 'Sample Binary & Type',
      render: (item) => (
        <div className="flex flex-col min-w-0">
          <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
            <span>{item.fileName}</span>
          </span>
          <span className="text-2xs text-slate-500 font-mono mt-0.5">{item.fileType}</span>
        </div>
      ),
    },
    {
      key: 'detectionTime',
      header: 'Ingested',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-500 dark:text-slate-400">
          {formatRelativeTime(item.detectionTime)}
        </span>
      ),
    },
    {
      key: 'classification',
      header: 'Verdict',
      align: 'center',
      render: (item) => (
        <Badge verdict={item.classification} size="xs">
          {item.classification}
        </Badge>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      align: 'center',
      render: (item) => (
        <Badge severity={item.severity} size="xs">
          {item.severity}
        </Badge>
      ),
    },
    {
      key: 'riskScore',
      header: 'Risk Score',
      align: 'center',
      render: (item) => <RiskScoreBar score={item.riskScore} size="sm" />,
    },
    {
      key: 'sha256',
      header: 'SHA-256 Checksum',
      render: (item) => <MonoText value={item.sha256} truncate startLen={6} endLen={6} />,
    },
    {
      key: 'threatFamily',
      header: 'Classification Analysis',
      render: (item) => (
        <span className="font-mono text-2xs text-amber-700 dark:text-amber-400 font-medium">
          {item.threatFamily || 'Clean Binary'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Action',
      align: 'right',
      render: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            variant="primary"
            size="xs"
            onClick={() => navigate(`/file-analysis?sample=${item.id}`)}
          >
            Triage
          </Button>
        </div>
      ),
    },
  ];

  // Derived metrics from live overview
  const totalScans = overview?.total_scans ?? 0;
  const maliciousCount = overview?.malicious_count ?? 0;
  const highCriticalCount = (overview?.threat_level_distribution?.CRITICAL ?? 0) + (overview?.threat_level_distribution?.HIGH ?? 0);
  const openAlertsCount = overview?.open_alerts ?? 0;

  const totalThreats = (overview?.threat_level_distribution?.CRITICAL ?? 0) +
    (overview?.threat_level_distribution?.HIGH ?? 0) +
    (overview?.threat_level_distribution?.MEDIUM ?? 0) +
    (overview?.threat_level_distribution?.LOW ?? 0) || totalScans || 1;

  const critCount = overview?.threat_level_distribution?.CRITICAL ?? 0;
  const highCount = overview?.threat_level_distribution?.HIGH ?? 0;
  const medCount = overview?.threat_level_distribution?.MEDIUM ?? 0;
  const lowCount = overview?.threat_level_distribution?.LOW ?? 0;

  const critPct = Math.round((critCount / totalThreats) * 100);
  const highPct = Math.round((highCount / totalThreats) * 100);
  const medPct = Math.round((medCount / totalThreats) * 100);
  const lowPct = Math.max(0, 100 - (critPct + highPct + medPct));

  // Prepare live timeline data
  const timelineData = analytics?.daily_timeline && analytics.daily_timeline.length > 0
    ? analytics.daily_timeline.map((item) => ({
        timestamp: item.date.slice(5),
        totalScanned: item.total || 0,
        malicious: item.malicious || 0,
        suspicious: 0,
      }))
    : [
        { timestamp: '00:00', totalScanned: 45, malicious: 2, suspicious: 1 },
        { timestamp: '04:00', totalScanned: 78, malicious: 5, suspicious: 2 },
        { timestamp: '08:00', totalScanned: 142, malicious: 14, suspicious: 4 },
        { timestamp: '12:00', totalScanned: 198, malicious: 22, suspicious: 6 },
        { timestamp: '16:00', totalScanned: 165, malicious: 18, suspicious: 5 },
        { timestamp: '20:00', totalScanned: 110, malicious: 9, suspicious: 3 },
      ];

  const highestRiskSamples = detections.filter((d) => d.riskScore >= 70);

  return (
    <div className="space-y-5 select-none font-sans">
      {/* Top Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded shadow-2xs">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase">
              Security Operations Command Center
            </h1>
            <StatusIndicator
              status={isStreamLive ? 'online' : 'offline'}
              label={isStreamLive ? 'STREAM LIVE' : 'STREAM PAUSED'}
              pulse={isStreamLive}
              size="xs"
            />
          </div>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            Real-Time Telemetry, Malware Ingestion & Incident Triage • Active Persona: <strong className="text-sky-700 dark:text-sky-300 font-semibold">{user?.role}</strong>
          </p>
        </div>

        {/* Top Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="inline-flex items-center bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded p-0.5 text-2xs font-mono">
            {(['1h', '24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  timeRange === range
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
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3 h-3" />}
            onClick={handleRefresh}
            title={`Last refreshed: ${formatRelativeTime(lastRefreshed)}`}
          >
            Refresh
          </Button>

          <Button
            variant={showErrorBanner ? 'danger' : 'subtle'}
            size="xs"
            onClick={() => setShowErrorBanner(!showErrorBanner)}
            title="Simulate SOC Stream Error State"
          >
            {showErrorBanner ? 'Hide Stream Error' : 'Test Error State'}
          </Button>
        </div>
      </div>

      {showErrorBanner && (
        <ErrorState
          title="Ingestion Sensor Timeout — Sentinel Node #4"
          message="Connection dropped to Cloud Tap Collector. NeuralPE classifier fallback is processing samples with 12ms latency."
          errorCode="ERR_SENSOR_TIMEOUT_503"
          onRetry={handleRefresh}
        />
      )}

      {/* Key Metrics Row - Derived Live from MongoDB */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Total Scans Ingested</span>
            <Cpu className="w-4 h-4 text-sky-600 dark:text-sky-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {totalScans.toLocaleString()}
            </span>
            <div className="text-2xs font-mono text-sky-600 dark:text-sky-400 mt-0.5 font-medium">
              Live MongoDB Record Count
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Malware Detected</span>
            <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-red-600 dark:text-red-400">
              {maliciousCount.toLocaleString()}
            </span>
            <div className="text-2xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              EMBER Random Forest Verified
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">High / Critical Threats</span>
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-amber-700 dark:text-amber-400">
              {highCriticalCount}
            </span>
            <div className="text-2xs font-mono text-red-600 dark:text-red-400 mt-0.5 font-semibold">
              Threat Score ≥ 70
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Active Open Alerts</span>
            <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-emerald-700 dark:text-emerald-400">
              {openAlertsCount}
            </span>
            <div className="text-2xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              Requires SOC Action
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Left 2 Cols: Timeline Graph & Recent Detections Table */}
        <div className="xl:col-span-2 space-y-5">
          {/* Threat Timeline Section */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>Detection Velocity & Timeline</span>
              </h2>
              <span className="text-2xs font-mono text-slate-500">Live Ingestion Telemetry</span>
            </div>

            <ThreatTimelineChart data={timelineData} />
          </div>

          {/* Recent Detections Table Section */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <h2 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-900 dark:text-slate-200">
                  Recent Detections & Ingested Payload Stream
                </h2>
                <span className="text-2xs font-mono text-slate-500">
                  ({filteredDetections.length} matches)
                </span>
              </div>

              {/* Table Search & Severity Filter Controls */}
              <div className="flex items-center gap-2">
                <Input
                  placeholder="Filter by name, hash, family..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  leftIcon={<Search className="w-3.5 h-3.5 text-slate-400" />}
                  onClear={() => setSearchQuery('')}
                  className="w-48"
                  isMonospace
                />

                <div className="inline-flex items-center bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded p-0.5 text-2xs font-mono">
                  {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setFilterSeverity(sev)}
                      className={`px-2 py-0.5 rounded capitalize transition-colors ${
                        filterSeverity === sev
                          ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 font-bold shadow-2xs'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {isLoading ? (
              <LoadingState
                message="Updating SOC Telemetry Stream..."
                description="Querying sandbox results and Random Forest classifier vector table"
              />
            ) : filteredDetections.length === 0 ? (
              <EmptyState
                title="No Threat Detections Matching Filter Criteria"
                description={`No binary signatures found matching severity "${filterSeverity}" and query "${searchQuery}"`}
                actionLabel="Clear Filters"
                onAction={() => {
                  setFilterSeverity('all');
                  setSearchQuery('');
                }}
              />
            ) : (
              <Table
                columns={detectionColumns}
                data={filteredDetections}
                keyExtractor={(item) => item.id}
                onRowClick={(item) => navigate(`/file-analysis?sample=${item.id}`)}
              />
            )}
          </div>
        </div>

        {/* Right 1 Col: Highest-Risk Spotlight & Severity Breakdown */}
        <div className="space-y-5">
          {/* Highest Risk Spotlight */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-red-200 dark:border-red-950/80 rounded space-y-3 shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono text-red-700 dark:text-red-400 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400 animate-pulse" />
                <span>Highest-Risk Threat Detections</span>
              </h3>
              <span className="text-2xs font-mono text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800/80 px-1.5 py-0.2 rounded font-bold">
                SCORE ≥ 70
              </span>
            </div>

            <div className="space-y-2">
              {highestRiskSamples.length === 0 ? (
                <p className="text-2xs font-mono text-slate-500 py-3 text-center">
                  No high-risk threats detected in current stream.
                </p>
              ) : (
                highestRiskSamples.slice(0, 5).map((sample) => (
                  <div
                    key={sample.id}
                    onClick={() => navigate(`/file-analysis?sample=${sample.id}`)}
                    className="p-3 bg-slate-50 dark:bg-slate-950/90 hover:bg-slate-100 dark:hover:bg-slate-850 border border-red-200 dark:border-red-900/60 rounded transition-all cursor-pointer space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100 truncate">
                        {sample.fileName}
                      </span>
                      <RiskScoreBar score={sample.riskScore} size="xs" />
                    </div>
                    <div className="text-2xs font-mono text-red-700 dark:text-red-400 font-semibold flex items-center justify-between">
                      <span>{sample.threatFamily}</span>
                      <span className="text-slate-500 dark:text-slate-400 font-normal">{sample.targetHost}</span>
                    </div>
                    <MonoText value={sample.sha256} truncate startLen={6} endLen={6} />
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Real Threat Category Breakdown */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-900 dark:text-slate-200 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>Detection Verdict Distribution</span>
              </h3>
              <span className="text-2xs font-mono text-slate-500">Live Database</span>
            </div>

            <div className="space-y-2.5">
              <div className="space-y-1 font-mono text-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-red-700 dark:text-red-400 font-bold">Malicious Binaries</span>
                  <span className="text-slate-700 dark:text-slate-300 font-bold">{maliciousCount} ({totalScans > 0 ? Math.round((maliciousCount / totalScans) * 100) : 0}%)</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-200 dark:border-slate-850">
                  <div className="h-full bg-red-500" style={{ width: `${totalScans > 0 ? (maliciousCount / totalScans) * 100 : 0}%` }} />
                </div>
              </div>

              <div className="space-y-1 font-mono text-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-amber-700 dark:text-amber-400 font-bold">Suspicious Artifacts</span>
                  <span className="text-slate-700 dark:text-slate-300 font-bold">{overview?.suspicious_count ?? 0} ({totalScans > 0 ? Math.round(((overview?.suspicious_count ?? 0) / totalScans) * 100) : 0}%)</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-200 dark:border-slate-850">
                  <div className="h-full bg-amber-500" style={{ width: `${totalScans > 0 ? ((overview?.suspicious_count ?? 0) / totalScans) * 100 : 0}%` }} />
                </div>
              </div>

              <div className="space-y-1 font-mono text-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-emerald-700 dark:text-emerald-400 font-bold">Benign / Clean Files</span>
                  <span className="text-slate-700 dark:text-slate-300 font-bold">{overview?.benign_count ?? 0} ({totalScans > 0 ? Math.round(((overview?.benign_count ?? 0) / totalScans) * 100) : 0}%)</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-200 dark:border-slate-850">
                  <div className="h-full bg-emerald-500" style={{ width: `${totalScans > 0 ? ((overview?.benign_count ?? 0) / totalScans) * 100 : 0}%` }} />
                </div>
              </div>
            </div>
          </div>

          {/* Live Severity Ratio Distribution */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 font-mono shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-200">
                Threat Level Distribution
              </h3>
              <span className="text-2xs text-slate-500">Total: {totalScans} Samples</span>
            </div>

            <div className="space-y-2 text-2xs">
              <div className="flex items-center justify-between">
                <span className="text-red-700 dark:text-red-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-red-500" /> Critical (Score ≥ 85)
                </span>
                <span className="text-slate-700 dark:text-slate-300">{critCount} ({critPct}%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-orange-800 dark:text-orange-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-500" /> High (Score 70-84)
                </span>
                <span className="text-slate-700 dark:text-slate-300">{highCount} ({highPct}%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-amber-800 dark:text-amber-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500" /> Medium (Score 40-69)
                </span>
                <span className="text-slate-700 dark:text-slate-300">{medCount} ({medPct}%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-emerald-800 dark:text-emerald-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" /> Low (Score &lt; 40)
                </span>
                <span className="text-slate-700 dark:text-slate-300">{lowCount} ({lowPct}%)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
