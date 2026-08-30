import React, { useState, useEffect } from 'react';
import {
  Radio,
  Activity,
  ChevronLeft,
  ChevronRight,
  RotateCw
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Table } from '../components/ui/Table';
import type { Column } from '../components/ui/Table';
import { Badge } from '../components/ui/Badge';
import { RiskScoreBar } from '../components/common/RiskScoreBar';
import { StatusIndicator } from '../components/ui/StatusIndicator';
import { LoadingState } from '../components/ui/LoadingState';
import { EmptyState } from '../components/ui/EmptyState';
import { ErrorState } from '../components/ui/ErrorState';
import { SocFilterBar } from '../components/common/SocFilterBar';
import type { SocFilterParams } from '../components/common/SocFilterBar';
import { ThreatLensApi } from '../services/api';
import type {
  ActiveThreatItem,
  DetectionLogEvent,
  MalwareTrackingItem,
  SuspiciousActivityItem
} from '../data/mockMonitoringData';
import { useThreatLens } from '../context/ThreatLensContext';
import { formatRelativeTime } from '../utils/formatters';

export const ThreatMonitoringPage: React.FC = () => {
  const { navigate, isStreamLive } = useThreatLens();

  const [activeTab, setActiveTab] = useState<'active' | 'logs' | 'tracking' | 'timeline'>('active');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [hasError, setHasError] = useState<boolean>(false);

  const [activeThreats, setActiveThreats] = useState<ActiveThreatItem[]>([]);
  const [detectionLogs, setDetectionLogs] = useState<DetectionLogEvent[]>([]);
  const [malwareTracking, setMalwareTracking] = useState<MalwareTrackingItem[]>([]);
  const [suspiciousTimeline, setSuspiciousTimeline] = useState<SuspiciousActivityItem[]>([]);

  // Filter state
  const [filters, setFilters] = useState<SocFilterParams>({
    search: '',
    severity: 'all',
    status: 'all',
    family: 'all',
    minRiskScore: 0,
  });

  // Pagination state for detection logs
  const [logPage, setLogPage] = useState<number>(1);
  const pageSize = 4;

  useEffect(() => {
    async function loadData() {
      setIsLoading(true);
      setHasError(false);
      try {
        const [threats, logs, tracking, timeline] = await Promise.all([
          ThreatLensApi.getActiveThreats(),
          ThreatLensApi.getDetectionLogs(),
          ThreatLensApi.getMalwareTracking(),
          ThreatLensApi.getSuspiciousTimeline(),
        ]);
        setActiveThreats(threats);
        setDetectionLogs(logs);
        setMalwareTracking(tracking);
        setSuspiciousTimeline(timeline);
      } catch {
        setHasError(true);
      } finally {
        setIsLoading(false);
      }
    }
    loadData();
  }, []);

  const handleResetFilters = () => {
    setFilters({
      search: '',
      severity: 'all',
      status: 'all',
      family: 'all',
      minRiskScore: 0,
    });
  };

  // Filter Active Threats
  const filteredThreats = activeThreats.filter((t) => {
    const matchesSev = filters.severity === 'all' || t.severity === filters.severity;
    const matchesStatus = filters.status === 'all' || t.status === filters.status;
    const matchesFam = filters.family === 'all' || t.malwareFamily.includes(filters.family);
    const matchesRisk = t.riskScore >= filters.minRiskScore;
    const matchesSearch =
      t.id.toLowerCase().includes(filters.search.toLowerCase()) ||
      t.fileName.toLowerCase().includes(filters.search.toLowerCase()) ||
      t.targetHost.toLowerCase().includes(filters.search.toLowerCase()) ||
      t.assignedAnalyst.toLowerCase().includes(filters.search.toLowerCase());
    return matchesSev && matchesStatus && matchesFam && matchesRisk && matchesSearch;
  });

  // Filter Detection Logs
  const filteredLogs = detectionLogs.filter((l) => {
    const matchesSev = filters.severity === 'all' || l.severity === filters.severity;
    const matchesSearch =
      l.id.toLowerCase().includes(filters.search.toLowerCase()) ||
      l.event.toLowerCase().includes(filters.search.toLowerCase()) ||
      l.fileName.toLowerCase().includes(filters.search.toLowerCase()) ||
      l.source.toLowerCase().includes(filters.search.toLowerCase()) ||
      l.details.toLowerCase().includes(filters.search.toLowerCase());
    return matchesSev && matchesSearch;
  });

  // Pagination for logs
  const totalLogPages = Math.ceil(filteredLogs.length / pageSize) || 1;
  const paginatedLogs = filteredLogs.slice((logPage - 1) * pageSize, logPage * pageSize);

  // Active Threats Table Columns
  const activeThreatColumns: Column<ActiveThreatItem>[] = [
    {
      key: 'id',
      header: 'Threat ID',
      render: (item) => <span className="font-mono font-bold text-xs text-sky-700 dark:text-sky-400">{item.id}</span>,
    },
    {
      key: 'detectedTime',
      header: 'Detected',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-500 dark:text-slate-400">
          {formatRelativeTime(item.detectedTime)}
        </span>
      ),
    },
    {
      key: 'fileName',
      header: 'Target Payload & Host',
      render: (item) => (
        <div className="flex flex-col min-w-0">
          <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
            {item.fileName}
          </span>
          <span className="text-2xs text-slate-500 font-mono mt-0.5">{item.targetHost}</span>
        </div>
      ),
    },
    {
      key: 'malwareFamily',
      header: 'Malware Family',
      render: (item) => (
        <span className="font-mono text-xs font-bold text-red-700 dark:text-red-300">{item.malwareFamily}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      align: 'center',
      render: (item) => <Badge severity={item.severity} size="xs">{item.severity}</Badge>,
    },
    {
      key: 'riskScore',
      header: 'Risk Score',
      align: 'center',
      render: (item) => <RiskScoreBar score={item.riskScore} size="sm" />,
    },
    {
      key: 'status',
      header: 'Status',
      align: 'center',
      render: (item) => (
        <span
          className={`font-mono text-2xs font-bold px-2 py-0.5 rounded border ${
            item.status === 'Active Outbreak'
              ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/70 dark:text-red-400 dark:border-red-800/80 animate-pulse'
              : item.status === 'Containment Pending'
              ? 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/70 dark:text-amber-400 dark:border-amber-800/80'
              : item.status === 'Under Triage'
              ? 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/70 dark:text-sky-400 dark:border-sky-800/80'
              : 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/70 dark:text-emerald-400 dark:border-emerald-800/80'
          }`}
        >
          {item.status}
        </span>
      ),
    },
    {
      key: 'assignedAnalyst',
      header: 'Assigned',
      render: (item) => (
        <span className="font-mono text-xs text-sky-700 dark:text-sky-300 font-medium">{item.assignedAnalyst}</span>
      ),
    },
    {
      key: 'actions',
      header: 'Action',
      align: 'right',
      render: () => (
        <Button
          variant="primary"
          size="xs"
          onClick={() => navigate('/alerts')}
        >
          Investigate
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-5 select-none font-sans">
      {/* Header Banner */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-2xs">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase">
              Threat Monitoring & Sensor Telemetry Stream
            </h1>
            <StatusIndicator
              status={isStreamLive ? 'online' : 'offline'}
              label={isStreamLive ? 'STREAM LIVE' : 'STREAM PAUSED'}
              pulse={isStreamLive}
              size="xs"
            />
          </div>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            4 Suricata Probes • 12 EDR Nodes • Real-Time Ingestion Buffer
          </p>
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
          Refresh Sensors
        </Button>
      </div>

      {/* Error Fallback State */}
      {hasError && (
        <ErrorState
          title="Telemetry Ingestion Interrupted"
          message="Failed to connect to primary Suricata tap buffer. Sensor cluster fallback active."
          onRetry={() => window.location.reload()}
        />
      )}

      {/* Reusable Filter Bar */}
      <SocFilterBar
        filters={filters}
        onChange={setFilters}
        onReset={handleResetFilters}
      />

      {/* Navigation View Switcher Tabs */}
      <div className="flex items-center border-b border-slate-200 dark:border-slate-800 gap-2 font-mono text-xs">
        <button
          type="button"
          onClick={() => setActiveTab('active')}
          className={`px-4 py-2 border-b-2 font-semibold transition-colors ${
            activeTab === 'active'
              ? 'border-sky-600 dark:border-sky-500 text-sky-700 dark:text-sky-400 bg-slate-50 dark:bg-slate-900/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          Active Threats ({filteredThreats.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('logs')}
          className={`px-4 py-2 border-b-2 font-semibold transition-colors ${
            activeTab === 'logs'
              ? 'border-sky-600 dark:border-sky-500 text-sky-700 dark:text-sky-400 bg-slate-50 dark:bg-slate-900/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          Detection Logs ({filteredLogs.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('tracking')}
          className={`px-4 py-2 border-b-2 font-semibold transition-colors ${
            activeTab === 'tracking'
              ? 'border-sky-600 dark:border-sky-500 text-sky-700 dark:text-sky-400 bg-slate-50 dark:bg-slate-900/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          Malware Tracking ({malwareTracking.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('timeline')}
          className={`px-4 py-2 border-b-2 font-semibold transition-colors ${
            activeTab === 'timeline'
              ? 'border-sky-600 dark:border-sky-500 text-sky-700 dark:text-sky-400 bg-slate-50 dark:bg-slate-900/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          Suspicious Activity Timeline ({suspiciousTimeline.length})
        </button>
      </div>

      {/* View 1: Active Threats Table */}
      {activeTab === 'active' && (
        <div className="space-y-3">
          {isLoading ? (
            <LoadingState message="Fetching Active Threat Records..." />
          ) : filteredThreats.length === 0 ? (
            <EmptyState
              title="No Active Threats Matching Filter Parameters"
              description="Adjust severity, status, or search query parameters in the SOC filter bar above."
              actionLabel="Reset Filters"
              onAction={handleResetFilters}
            />
          ) : (
            <Table
              columns={activeThreatColumns}
              data={filteredThreats}
              keyExtractor={(item) => item.id}
            />
          )}
        </div>
      )}

      {/* View 2: Detection Logs Table */}
      {activeTab === 'logs' && (
        <div className="space-y-3 font-mono">
          <div className="flex items-center justify-between">
            <span className="text-2xs text-slate-500 dark:text-slate-400">
              Showing page {logPage} of {totalLogPages} ({filteredLogs.length} total events)
            </span>

            {/* Pagination Controls */}
            <div className="flex items-center gap-1.5">
              <Button
                variant="subtle"
                size="xs"
                disabled={logPage <= 1}
                leftIcon={<ChevronLeft className="w-3 h-3" />}
                onClick={() => setLogPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <span className="text-2xs text-slate-800 dark:text-slate-300 font-bold px-2">
                {logPage} / {totalLogPages}
              </span>
              <Button
                variant="subtle"
                size="xs"
                disabled={logPage >= totalLogPages}
                rightIcon={<ChevronRight className="w-3 h-3" />}
                onClick={() => setLogPage((p) => Math.min(totalLogPages, p + 1))}
              >
                Next
              </Button>
            </div>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded bg-white dark:bg-slate-950 overflow-x-auto shadow-2xs">
            <table className="w-full text-left border-collapse soc-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Event Name</th>
                  <th>Payload Target</th>
                  <th>Sensor Source</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Event Log Details</th>
                </tr>
              </thead>
              <tbody>
                {paginatedLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-900/60 transition-colors">
                    <td className="text-2xs text-slate-500 dark:text-slate-400">{log.timestamp}</td>
                    <td className="font-bold text-xs text-sky-700 dark:text-sky-400">{log.event}</td>
                    <td className="text-xs text-slate-900 dark:text-slate-200 font-semibold">{log.fileName}</td>
                    <td className="text-2xs text-slate-500 dark:text-slate-400">{log.source}</td>
                    <td><Badge severity={log.severity} size="xs">{log.severity}</Badge></td>
                    <td>
                      <span className="text-2xs font-bold text-amber-800 dark:text-amber-400 px-1.5 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800/80">
                        {log.status}
                      </span>
                    </td>
                    <td className="text-2xs text-slate-600 dark:text-slate-300 truncate max-w-xs" title={log.details}>
                      {log.details}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* View 3: Malware Tracking Table */}
      {activeTab === 'tracking' && (
        <div className="space-y-3 font-mono">
          <div className="border border-slate-200 dark:border-slate-800 rounded bg-white dark:bg-slate-950 overflow-x-auto shadow-2xs">
            <table className="w-full text-left border-collapse soc-table">
              <thead>
                <tr>
                  <th>Malware Family & Category</th>
                  <th>Total Detections</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                  <th>Impacted Endpoints</th>
                  <th>Tracking Status</th>
                </tr>
              </thead>
              <tbody>
                {malwareTracking.map((item) => (
                  <tr key={item.family} className="hover:bg-slate-50 dark:hover:bg-slate-900/60 transition-colors">
                    <td>
                      <div className="flex flex-col">
                        <span className="font-bold text-xs text-slate-900 dark:text-slate-100">{item.family}</span>
                        <span className="text-2xs text-slate-500">{item.category}</span>
                      </div>
                    </td>
                    <td className="font-bold text-red-600 dark:text-red-400">{item.detections}</td>
                    <td className="text-2xs text-slate-500 dark:text-slate-400">{formatRelativeTime(item.firstSeen)}</td>
                    <td className="text-2xs text-slate-500 dark:text-slate-400">{formatRelativeTime(item.lastSeen)}</td>
                    <td className="font-bold text-sky-700 dark:text-sky-300">{item.impactedEndpoints} hosts</td>
                    <td>
                      <span
                        className={`text-2xs font-bold px-2 py-0.5 rounded border ${
                          item.status === 'Active Outbreak'
                            ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950 dark:text-red-400 dark:border-red-800 animate-pulse'
                            : item.status === 'Monitored Threat'
                            ? 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-400 dark:border-amber-800'
                            : 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-400 dark:border-emerald-800'
                        }`}
                      >
                        {item.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* View 4: Suspicious Activity Timeline */}
      {activeTab === 'timeline' && (
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-4 font-mono shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-600 dark:text-sky-400" />
              <span>Chronological Attack Vector Investigation Timeline</span>
            </h3>
            <span className="text-2xs text-slate-500">MITRE ATT&CK Matrix Mapping</span>
          </div>

          <div className="space-y-3 relative pl-4 border-l-2 border-slate-200 dark:border-slate-800">
            {suspiciousTimeline.map((item) => (
              <div key={item.id} className="relative group">
                {/* Timeline node dot */}
                <div className="absolute -left-[21px] top-1.5 w-3 h-3 rounded-full bg-white dark:bg-slate-950 border-2 border-sky-500 group-hover:bg-sky-500 transition-colors" />

                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-1.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-sky-50 dark:bg-sky-950 text-sky-700 dark:text-sky-400 border border-sky-200 dark:border-sky-800 text-2xs font-bold">
                        {item.techniqueId}
                      </span>
                      <span className="text-xs font-bold text-slate-900 dark:text-slate-100">{item.techniqueName}</span>
                      <Badge severity={item.severity} size="xs">{item.severity}</Badge>
                    </div>
                    <span className="text-2xs text-slate-500">{item.timestamp}</span>
                  </div>

                  <div className="flex items-center gap-3 text-2xs text-slate-500 dark:text-slate-400">
                    <span>Process: <strong className="text-slate-800 dark:text-slate-200">{item.actorOrProcess}</strong></span>
                    <span>•</span>
                    <span>Host: <strong className="text-slate-800 dark:text-slate-200">{item.targetHost}</strong></span>
                    <span>•</span>
                    <span className="text-amber-700 dark:text-amber-400 font-semibold">[{item.phase}]</span>
                  </div>

                  <div className="p-2 bg-amber-50/60 dark:bg-slate-900 rounded border border-amber-200 dark:border-slate-850 text-2xs text-amber-900 dark:text-amber-300 break-all">
                    <code>{item.indicatorText}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
