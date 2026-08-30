import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  X,
  UserCheck,
  Search,
  Filter,
  ArrowUpRight,
  Shield,
  RotateCw
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Dropdown } from '../components/ui/Dropdown';
import { Table } from '../components/ui/Table';
import type { Column } from '../components/ui/Table';
import { Badge } from '../components/ui/Badge';
import { MonoText } from '../components/common/MonoText';
import { RiskScoreBar } from '../components/common/RiskScoreBar';
import { LoadingState } from '../components/ui/LoadingState';
import { EmptyState } from '../components/ui/EmptyState';
import { ThreatLensApi } from '../services/api';
import type { AlertDetailItem } from '../data/mockAlertsData';
import { formatRelativeTime } from '../utils/formatters';
import { useThreatLens } from '../context/ThreatLensContext';

export const AlertsPage: React.FC = () => {
  const { navigate } = useThreatLens();

  const [alerts, setAlerts] = useState<AlertDetailItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertDetailItem | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const loadAlerts = async () => {
    setIsLoading(true);
    const data = await ThreatLensApi.getDetailedAlerts();
    setAlerts(data);
    setIsLoading(false);
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleUpdateStatus = async (alertId: string, newStatus: AlertDetailItem['status']) => {
    const updated = await ThreatLensApi.updateAlertStatus(alertId, newStatus);
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(updated);
    }
  };

  const handleAssignAnalyst = async (alertId: string, analystName: string) => {
    const updated = await ThreatLensApi.assignAlertAnalyst(alertId, analystName);
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(updated);
    }
  };

  // Filtered Alert Dataset
  const filteredAlerts = alerts.filter((item) => {
    const matchesSev = severityFilter === 'all' || item.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || item.status === statusFilter;
    const matchesSearch =
      item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.affectedFile.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.malwareFamily.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.targetHost.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesStatus && matchesSearch;
  });

  // KPI Counts
  const totalActive = alerts.filter((a) => a.status === 'Open' || a.status === 'Under Investigation').length;
  const totalCritical = alerts.filter((a) => a.severity === 'critical' && a.status !== 'Closed - Resolved').length;
  const totalUnassigned = alerts.filter((a) => a.assignedAnalyst === 'Unassigned' && a.status !== 'Closed - Resolved').length;

  const alertColumns: Column<AlertDetailItem>[] = [
    {
      key: 'severity',
      header: 'Severity',
      align: 'center',
      render: (item) => <Badge severity={item.severity} size="xs">{item.severity}</Badge>,
    },
    {
      key: 'title',
      header: 'Alert Title & ID',
      render: (item) => (
        <div className="flex flex-col min-w-0">
          <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate flex items-center gap-1.5">
            <span className="text-sky-600 dark:text-sky-400 font-bold">{item.id}</span>
            <span>• {item.title}</span>
          </span>
          <span className="text-2xs text-slate-500 font-mono mt-0.5">Target: {item.targetHost}</span>
        </div>
      ),
    },
    {
      key: 'source',
      header: 'Sensor Source',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-500 dark:text-slate-400">{item.source}</span>
      ),
    },
    {
      key: 'affectedFile',
      header: 'Affected File',
      render: (item) => (
        <span className="font-mono text-xs text-sky-700 dark:text-sky-300 font-medium">{item.affectedFile}</span>
      ),
    },
    {
      key: 'malwareFamily',
      header: 'Malware Family',
      render: (item) => (
        <span className="font-mono text-xs text-red-700 dark:text-red-300 font-semibold">{item.malwareFamily}</span>
      ),
    },
    {
      key: 'createdTime',
      header: 'Created',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-500 dark:text-slate-400">
          {formatRelativeTime(item.createdTime)}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      align: 'center',
      render: (item) => (
        <span
          className={`font-mono text-2xs font-bold px-2 py-0.5 rounded border ${
            item.status === 'Open'
              ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/70 dark:text-red-400 dark:border-red-800/80 animate-pulse'
              : item.status === 'Under Investigation'
              ? 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/70 dark:text-sky-400 dark:border-sky-800/80'
              : item.status === 'Closed - False Positive'
              ? 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-950/70 dark:text-slate-400 dark:border-slate-800'
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
        <span
          className={`font-mono text-2xs font-medium ${
            item.assignedAnalyst === 'Unassigned' ? 'text-amber-700 dark:text-amber-400 font-bold' : 'text-slate-700 dark:text-slate-300'
          }`}
        >
          {item.assignedAnalyst}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Triage',
      align: 'right',
      render: (item) => (
        <Button
          variant="secondary"
          size="xs"
          onClick={(e) => {
            e.stopPropagation();
            setSelectedAlert(item);
          }}
        >
          Inspect
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-5 select-none font-sans relative">
      {/* Top Banner Header */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-2xs">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
            <span>SOC Incident Alerts & Triage Management</span>
          </h1>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            Centralized Alert Desk • Automated Triage Rules • EDR & Suricata Stream Integration
          </p>
        </div>

        <Button
          variant="secondary"
          size="xs"
          leftIcon={<RotateCw className="w-3 h-3" />}
          onClick={loadAlerts}
        >
          Refresh Alert Queue
        </Button>
      </div>

      {/* TOP AREA KPI Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono">
        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex items-center justify-between shadow-2xs">
          <div>
            <span className="text-2xs text-slate-500 uppercase block">Active Alert Queue</span>
            <span className="text-xl font-bold text-slate-900 dark:text-slate-100">{totalActive} Alerts</span>
          </div>
          <Shield className="w-5 h-5 text-sky-600 dark:text-sky-400" />
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex items-center justify-between shadow-2xs">
          <div>
            <span className="text-2xs text-slate-500 uppercase block">Critical Severity SLA Active</span>
            <span className="text-xl font-bold text-red-600 dark:text-red-400">{totalCritical} SLA Breaches</span>
          </div>
          <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400" />
        </div>

        <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex items-center justify-between shadow-2xs">
          <div>
            <span className="text-2xs text-slate-500 uppercase block">Unassigned Analyst Triage</span>
            <span className="text-xl font-bold text-amber-700 dark:text-amber-400">{totalUnassigned} Unassigned</span>
          </div>
          <UserCheck className="w-5 h-5 text-amber-600 dark:text-amber-400" />
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded font-mono text-2xs space-y-2.5 shadow-2xs">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2 text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
            <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">
              Alert Queue Query Controls
            </span>
          </div>
          <span className="text-2xs text-slate-500">Matching: {filteredAlerts.length} Alerts</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
          <Input
            placeholder="Search by ID, title, payload name, host..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            leftIcon={<Search className="w-3.5 h-3.5 text-slate-400" />}
            onClear={() => setSearchQuery('')}
            isMonospace
          />

          <Dropdown
            label="Filter Severity"
            value={severityFilter}
            onChange={setSeverityFilter}
            options={[
              { value: 'all', label: 'All Severities' },
              { value: 'critical', label: 'Critical Severity' },
              { value: 'high', label: 'High Severity' },
              { value: 'medium', label: 'Medium Severity' },
              { value: 'low', label: 'Low Severity' },
            ]}
          />

          <Dropdown
            label="Filter Status"
            value={statusFilter}
            onChange={setStatusFilter}
            options={[
              { value: 'all', label: 'All Statuses' },
              { value: 'Open', label: 'Open' },
              { value: 'Under Investigation', label: 'Under Investigation' },
              { value: 'Closed - Resolved', label: 'Closed - Resolved' },
              { value: 'Closed - False Positive', label: 'Closed - False Positive' },
            ]}
          />
        </div>
      </div>

      {/* Alert Table View */}
      {isLoading ? (
        <LoadingState message="Loading SOC Alert Queue..." />
      ) : filteredAlerts.length === 0 ? (
        <EmptyState
          title="No SOC Alerts Found"
          description="No alerts match the selected search query and severity filters."
          actionLabel="Clear Filters"
          onAction={() => {
            setSearchQuery('');
            setSeverityFilter('all');
            setStatusFilter('all');
          }}
        />
      ) : (
        <Table
          columns={alertColumns}
          data={filteredAlerts}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => setSelectedAlert(item)}
        />
      )}

      {/* ALERT DETAIL DRAWER / SPLIT PANE */}
      {selectedAlert && (
        <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 z-50 shadow-2xl p-5 overflow-y-auto space-y-4 font-mono text-2xs animate-in slide-in-from-right duration-200">
          {/* Drawer Header */}
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-sky-700 dark:text-sky-400">{selectedAlert.id}</span>
              <Badge severity={selectedAlert.severity} size="xs">{selectedAlert.severity}</Badge>
            </div>
            <button
              type="button"
              onClick={() => setSelectedAlert(null)}
              className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-100 p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Title & Verdict */}
          <div>
            <h2 className="text-xs font-bold text-slate-900 dark:text-slate-100">{selectedAlert.title}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-2xs text-amber-700 dark:text-amber-400 font-bold">
                Malware Family: {selectedAlert.malwareFamily}
              </span>
              <span className="text-slate-500">• Host: {selectedAlert.targetHost}</span>
            </div>
          </div>

          {/* Alert Property Grid */}
          <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 grid grid-cols-2 gap-2 text-2xs">
            <div>
              <span className="text-slate-500 block">Created Timestamp</span>
              <span className="text-slate-800 dark:text-slate-300 font-semibold">{selectedAlert.createdTime}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Sensor Source</span>
              <span className="text-slate-800 dark:text-slate-300 font-semibold">{selectedAlert.source}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Target Payload File</span>
              <span className="text-sky-700 dark:text-sky-300 font-semibold">{selectedAlert.affectedFile}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Source IP Address</span>
              <span className="text-slate-800 dark:text-slate-300 font-semibold">{selectedAlert.sourceIp}</span>
            </div>
          </div>

          {/* Risk Score Spotlight */}
          <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <span className="text-slate-600 dark:text-slate-400 uppercase font-semibold">Security Impact Risk Score</span>
            <RiskScoreBar score={selectedAlert.riskScore} size="sm" />
          </div>

          {/* SHA-256 Hash */}
          <div className="space-y-1">
            <span className="text-slate-500 uppercase block">Target SHA-256 Checksum</span>
            <MonoText value={selectedAlert.fileHash} />
          </div>

          {/* Recommended Incident Response Action */}
          <div className="p-3 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800/80 rounded space-y-1">
            <span className="text-red-700 dark:text-red-400 font-bold uppercase flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
              Recommended Incident Response Action:
            </span>
            <p className="text-slate-800 dark:text-slate-200">{selectedAlert.recommendedAction}</p>
          </div>

          {/* Related Indicators List */}
          <div className="space-y-1.5">
            <span className="text-slate-600 dark:text-slate-400 uppercase font-semibold block">Extracted Threat Indicators</span>
            <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-1">
              {selectedAlert.relatedIndicators.map((ind, i) => (
                <div key={i} className="text-amber-700 dark:text-amber-300 font-medium">
                  • {ind}
                </div>
              ))}
            </div>
          </div>

          {/* Detection History Timeline */}
          <div className="space-y-1.5">
            <span className="text-slate-600 dark:text-slate-400 uppercase font-semibold block">Detection Audit History</span>
            <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-2">
              {selectedAlert.detectionHistory.map((hist, i) => (
                <div key={i} className="flex items-center justify-between text-2xs">
                  <span className="text-slate-600 dark:text-slate-400">{hist.timestamp} - {hist.event}</span>
                  <span className="text-sky-700 dark:text-sky-400 font-semibold">{hist.actor}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Assignment Selector */}
          <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 space-y-2">
            <span className="text-slate-600 dark:text-slate-400 uppercase font-semibold block">Assign SOC Analyst</span>
            <div className="flex items-center gap-2">
              <select
                value={selectedAlert.assignedAnalyst}
                onChange={(e) => handleAssignAnalyst(selectedAlert.id, e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-750 text-slate-900 dark:text-slate-100 rounded px-2.5 py-1 text-2xs font-mono focus:outline-none focus:border-sky-500 flex-1 shadow-2xs"
              >
                <option value="Unassigned">Unassigned</option>
                <option value="Alex Rivera">Alex Rivera (Security Analyst)</option>
                <option value="Sarah Chen">Sarah Chen (SOC Team Member)</option>
                <option value="Marcus Vance">Marcus Vance (Administrator)</option>
                <option value="Dr. Elena Rostova">Dr. Elena Rostova (Researcher)</option>
              </select>
            </div>
          </div>

          {/* Action Triggers */}
          <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <span className="text-slate-600 dark:text-slate-400 uppercase font-semibold block mb-1">Triage Actions</span>
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant="secondary"
                size="xs"
                onClick={() => handleUpdateStatus(selectedAlert.id, 'Under Investigation')}
                disabled={selectedAlert.status === 'Under Investigation'}
              >
                Mark Under Investigation
              </Button>
              <Button
                variant="primary"
                size="xs"
                onClick={() => handleUpdateStatus(selectedAlert.id, 'Closed - Resolved')}
                disabled={selectedAlert.status === 'Closed - Resolved'}
              >
                Mark Resolved
              </Button>
              <Button
                variant="subtle"
                size="xs"
                onClick={() => handleUpdateStatus(selectedAlert.id, 'Closed - False Positive')}
                disabled={selectedAlert.status === 'Closed - False Positive'}
              >
                Mark False Positive
              </Button>
              <Button
                variant="outline"
                size="xs"
                rightIcon={<ArrowUpRight className="w-3 h-3" />}
                onClick={() => navigate(`/file-analysis?sample=${selectedAlert.affectedFile}`)}
              >
                Inspect Sample
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
