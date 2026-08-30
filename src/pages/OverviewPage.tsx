import React, { useState } from 'react';
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
import {
  MOCK_DASHBOARD_METRICS,
  MOCK_TIMELINE_DATA,
  MOCK_FAMILY_DISTRIBUTION,
  MOCK_RECENT_DETECTIONS
} from '../data/mockDashboardData';
import type { DetectionItem } from '../data/mockDashboardData';
import { useThreatLens } from '../context/ThreatLensContext';
import { useAuth } from '../context/AuthContext';
import { formatRelativeTime } from '../utils/formatters';

export const OverviewPage: React.FC = () => {
  const { navigate, isStreamLive } = useThreatLens();
  const { user } = useAuth();

  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [showErrorBanner, setShowErrorBanner] = useState<boolean>(false);
  const [lastRefreshed, setLastRefreshed] = useState<string>(new Date().toISOString());

  const handleRefresh = () => {
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      setLastRefreshed(new Date().toISOString());
    }, 600);
  };

  // Filter detections based on search & severity
  const filteredDetections = MOCK_RECENT_DETECTIONS.filter((det) => {
    const matchesSev = filterSeverity === 'all' || det.severity === filterSeverity;
    const matchesSearch =
      det.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.threatFamily?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      det.targetHost?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const detectionColumns: Column<DetectionItem>[] = [
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
      key: 'threatFamily',
      header: 'Classified Family',
      render: (item) => (
        <span className="font-mono text-xs text-amber-700 dark:text-amber-300 font-semibold">
          {item.threatFamily || 'Unclassified'}
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
          <Button
            variant="subtle"
            size="xs"
            onClick={() => alert(`Resubmitting ${item.fileName} to Hyper-V Sandbox...`)}
          >
            Re-scan
          </Button>
        </div>
      ),
    },
  ];

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
          {/* Time Range Selector */}
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

          {/* Refresh Control */}
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

          {/* Simulated Error Toggle */}
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

      {/* Simulated Error Banner */}
      {showErrorBanner && (
        <ErrorState
          title="Ingestion Sensor Timeout — Sentinel Node #4"
          message="Connection dropped to Cloud Tap Collector. NeuralPE classifier fallback is processing samples with 12ms latency."
          errorCode="ERR_SENSOR_TIMEOUT_503"
          onRetry={handleRefresh}
        />
      )}

      {/* Key Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Files Scanned (24h)</span>
            <Cpu className="w-4 h-4 text-sky-600 dark:text-sky-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {MOCK_DASHBOARD_METRICS.filesScanned.toLocaleString()}
            </span>
            <div className="text-2xs font-mono text-sky-600 dark:text-sky-400 mt-0.5 font-medium">
              {MOCK_DASHBOARD_METRICS.filesScannedDelta}
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Threats Detected</span>
            <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-red-600 dark:text-red-400">
              {MOCK_DASHBOARD_METRICS.threatsDetected.toLocaleString()}
            </span>
            <div className="text-2xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              {MOCK_DASHBOARD_METRICS.threatsDetectedDelta}
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
              {MOCK_DASHBOARD_METRICS.highCriticalThreats}
            </span>
            <div className="text-2xs font-mono text-red-600 dark:text-red-400 mt-0.5 font-semibold">
              {MOCK_DASHBOARD_METRICS.highCriticalDelta}
            </div>
          </div>
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col justify-between shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-2xs font-mono uppercase tracking-wider">Active Investigations</span>
            <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-xl font-bold font-mono text-emerald-700 dark:text-emerald-400">
              {MOCK_DASHBOARD_METRICS.activeInvestigations}
            </span>
            <div className="text-2xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
              {MOCK_DASHBOARD_METRICS.activeInvestigationsDelta}
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
                <span>Threat Activity & Ingestion Velocity Over Time</span>
              </h2>
              <span className="text-2xs font-mono text-slate-500">Interval: 3 Hours</span>
            </div>

            <ThreatTimelineChart data={MOCK_TIMELINE_DATA} />
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
                description="Querying sandbox results and NeuralPE classifier vector table"
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

        {/* Right 1 Col: Highest-Risk Spotlight, Family Distribution, Severity Breakdown */}
        <div className="space-y-5">
          {/* Highest Risk Spotlight */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-red-200 dark:border-red-950/80 rounded space-y-3 shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono text-red-700 dark:text-red-400 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400 animate-pulse" />
                <span>Highest-Risk Threat Detections</span>
              </h3>
              <span className="text-2xs font-mono text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800/80 px-1.5 py-0.2 rounded font-bold">
                SCORE ≥ 90
              </span>
            </div>

            <div className="space-y-2">
              {MOCK_RECENT_DETECTIONS.filter((d) => d.riskScore >= 90).map((sample) => (
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
              ))}
            </div>
          </div>

          {/* Malware Family Breakdown */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-900 dark:text-slate-200 flex items-center gap-2">
                <Layers className="w-4 h-4 text-sky-600 dark:text-sky-400" />
                <span>Active Malware Family Prevalence</span>
              </h3>
              <span className="text-2xs font-mono text-slate-500">30-Day Cluster</span>
            </div>

            <div className="space-y-2.5">
              {MOCK_FAMILY_DISTRIBUTION.map((fam) => (
                <div key={fam.family} className="space-y-1 font-mono text-2xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-800 dark:text-slate-200 font-bold">{fam.family}</span>
                      <span className="text-slate-500">({fam.type})</span>
                    </div>
                    <span className="text-slate-700 dark:text-slate-300 font-bold">{fam.count} ({fam.percentage}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-200 dark:border-slate-850">
                    <div
                      className={`h-full ${
                        fam.severity === 'critical'
                          ? 'bg-red-500'
                          : fam.severity === 'high'
                          ? 'bg-orange-500'
                          : 'bg-amber-500'
                      }`}
                      style={{ width: `${fam.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Severity Distribution Ratio */}
          <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-3 font-mono shadow-2xs">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-200">
                Severity Ratio Distribution
              </h3>
              <span className="text-2xs text-slate-500">Total: 1,429 Threats</span>
            </div>

            <div className="space-y-2 text-2xs">
              <div className="flex items-center justify-between">
                <span className="text-red-700 dark:text-red-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-red-500" /> Critical (Score ≥ 85)
                </span>
                <span className="text-slate-700 dark:text-slate-300">257 (18%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-orange-800 dark:text-orange-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-500" /> High (Score 70-84)
                </span>
                <span className="text-slate-700 dark:text-slate-300">400 (28%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-amber-800 dark:text-amber-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500" /> Medium (Score 40-69)
                </span>
                <span className="text-slate-700 dark:text-slate-300">486 (34%)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-emerald-800 dark:text-emerald-400 font-bold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" /> Low (Score &lt; 40)
                </span>
                <span className="text-slate-700 dark:text-slate-300">286 (20%)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
