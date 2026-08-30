import React from 'react';
import { Search, Filter, RotateCcw } from 'lucide-react';
import { Input } from '../ui/Input';
import { Dropdown } from '../ui/Dropdown';

export interface SocFilterParams {
  search: string;
  severity: string;
  status: string;
  family: string;
  minRiskScore: number;
}

export interface SocFilterBarProps {
  filters: SocFilterParams;
  onChange: (filters: SocFilterParams) => void;
  onReset?: () => void;
  familiesList?: string[];
  statusesList?: string[];
  className?: string;
}

export const SocFilterBar: React.FC<SocFilterBarProps> = ({
  filters,
  onChange,
  onReset,
  familiesList = ['All Families', 'LockBit 3.0', 'Cobalt Strike', 'Emotet Trojan', 'AgentTesla', 'RedLine Stealer', 'Mirai Variant'],
  statusesList = ['All Statuses', 'Active Outbreak', 'Containment Pending', 'Under Triage', 'Remediated'],
  className,
}) => {
  const handleSearchChange = (val: string) => {
    onChange({ ...filters, search: val });
  };

  const handleSeverityChange = (val: string) => {
    onChange({ ...filters, severity: val });
  };

  const handleStatusChange = (val: string) => {
    onChange({ ...filters, status: val });
  };

  const handleFamilyChange = (val: string) => {
    onChange({ ...filters, family: val });
  };

  const handleRiskChange = (val: number) => {
    onChange({ ...filters, minRiskScore: val });
  };

  return (
    <div className={`p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded font-mono text-2xs space-y-3 shadow-2xs ${className || ''}`}>
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2 text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
          <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">
            SOC Telemetry Filters & Parameter Builder
          </span>
        </div>
        {onReset && (
          <button
            type="button"
            onClick={onReset}
            className="text-2xs text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 flex items-center gap-1 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Query Filters</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 items-end">
        {/* Search Input */}
        <Input
          label="Search Query"
          placeholder="Search Threat ID, payload, host..."
          value={filters.search}
          onChange={(e) => handleSearchChange(e.target.value)}
          leftIcon={<Search className="w-3.5 h-3.5 text-slate-400" />}
          onClear={() => handleSearchChange('')}
          isMonospace
        />

        {/* Severity Selector */}
        <Dropdown
          label="Severity"
          value={filters.severity}
          onChange={handleSeverityChange}
          options={[
            { value: 'all', label: 'All Severities' },
            { value: 'critical', label: 'Critical Severity' },
            { value: 'high', label: 'High Severity' },
            { value: 'medium', label: 'Medium Severity' },
            { value: 'low', label: 'Low Severity' },
          ]}
        />

        {/* Status Selector */}
        <Dropdown
          label="Incident Status"
          value={filters.status}
          onChange={handleStatusChange}
          options={statusesList.map((s) => ({
            value: s === 'All Statuses' ? 'all' : s,
            label: s,
          }))}
        />

        {/* Family Selector */}
        <Dropdown
          label="Malware Family"
          value={filters.family}
          onChange={handleFamilyChange}
          options={familiesList.map((f) => ({
            value: f === 'All Families' ? 'all' : f,
            label: f,
          }))}
        />

        {/* Min Risk Score Threshold Selector */}
        <Dropdown
          label="Min Risk Score"
          value={filters.minRiskScore.toString()}
          onChange={(val) => handleRiskChange(parseInt(val, 10))}
          options={[
            { value: '0', label: 'All Risk Scores (0+)' },
            { value: '50', label: 'Medium Risk (50+)' },
            { value: '75', label: 'High Risk (75+)' },
            { value: '90', label: 'Critical Risk (90+)' },
          ]}
        />
      </div>
    </div>
  );
};
