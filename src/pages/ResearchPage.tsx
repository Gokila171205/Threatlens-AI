import React, { useState, useEffect } from 'react';
import {
  Database,
  Download,
  Search,
  Code2,
  FileCode,
  ArrowUpRight,
  RotateCw
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Table } from '../components/ui/Table';
import type { Column } from '../components/ui/Table';
import { MonoText } from '../components/common/MonoText';
import { EntropyBar } from '../components/common/EntropyBar';
import { LoadingState } from '../components/ui/LoadingState';
import { ThreatLensApi } from '../services/api';
import type { DatasetSample } from '../data/mockResearchData';
import { formatRelativeTime } from '../utils/formatters';
import { useThreatLens } from '../context/ThreatLensContext';

export const ResearchPage: React.FC = () => {
  const { navigate } = useThreatLens();

  const [dataset, setDataset] = useState<DatasetSample[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const loadDataset = async () => {
    setIsLoading(true);
    const data = await ThreatLensApi.getResearchDataset();
    setDataset(data);
    setIsLoading(false);
  };

  useEffect(() => {
    loadDataset();
  }, []);

  const filteredDataset = dataset.filter(
    (s) =>
      s.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.family.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.yaraRule.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const datasetColumns: Column<DatasetSample>[] = [
    {
      key: 'fileName',
      header: 'Sample Binary & Type',
      render: (item) => (
        <div className="flex flex-col min-w-0 font-mono">
          <span className="font-bold text-xs text-slate-900 dark:text-slate-100 truncate flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" />
            <span>{item.fileName}</span>
          </span>
          <span className="text-2xs text-slate-500 mt-0.5">{item.type}</span>
        </div>
      ),
    },
    {
      key: 'family',
      header: 'Threat Family',
      render: (item) => (
        <span className="font-mono text-xs text-amber-700 dark:text-amber-300 font-semibold">{item.family}</span>
      ),
    },
    {
      key: 'sha256',
      header: 'SHA-256 Checksum',
      render: (item) => <MonoText value={item.sha256} truncate startLen={6} endLen={6} />,
    },
    {
      key: 'entropy',
      header: 'Entropy',
      align: 'center',
      render: (item) => <EntropyBar entropy={item.entropy} />,
    },
    {
      key: 'yaraRule',
      header: 'Primary YARA Rule',
      render: (item) => (
        <span className="font-mono text-2xs text-red-700 dark:text-red-400 font-bold bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800/80 px-2 py-0.5 rounded">
          {item.yaraRule}
        </span>
      ),
    },
    {
      key: 'addedDate',
      header: 'Ingested Date',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-500 dark:text-slate-400">
          {formatRelativeTime(item.addedDate)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      align: 'right',
      render: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            variant="primary"
            size="xs"
            leftIcon={<ArrowUpRight className="w-3 h-3" />}
            onClick={() => navigate(`/file-analysis?sample=${item.id}`)}
          >
            Dissect
          </Button>
          <Button
            variant="subtle"
            size="xs"
            leftIcon={<Download className="w-3 h-3" />}
            onClick={() => alert(`Exporting YARA & sample package for ${item.fileName}...`)}
          >
            Export
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6 select-none font-sans">
      {/* Top Banner Header */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-2xs">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-900 dark:text-slate-100 uppercase flex items-center gap-2">
            <Database className="w-4 h-4 text-sky-600 dark:text-sky-400" />
            <span>Malware Research Corpus & Dataset Explorer</span>
          </h1>
          <p className="text-2xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            Structured Genetic Datasets • YARA Rule Corpus • Historical Malware Intelligence
          </p>
        </div>

        <Button
          variant="secondary"
          size="xs"
          leftIcon={<RotateCw className="w-3 h-3" />}
          onClick={loadDataset}
        >
          Refresh Research Corpus
        </Button>
      </div>

      {/* Dataset Filter Bar */}
      <div className="p-3.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded font-mono text-2xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <span className="font-bold text-slate-800 dark:text-slate-200 uppercase">Search Research Corpus</span>
        </div>

        <Input
          placeholder="Filter dataset by name, hash, family, YARA rule..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          leftIcon={<Search className="w-3.5 h-3.5 text-slate-400" />}
          onClear={() => setSearchQuery('')}
          className="w-80"
          isMonospace
        />
      </div>

      {/* Dataset Table */}
      {isLoading ? (
        <LoadingState message="Loading Structured Malware Research Corpus..." />
      ) : (
        <Table
          columns={datasetColumns}
          data={filteredDataset}
          keyExtractor={(item) => item.id}
          onRowClick={(item) => navigate(`/file-analysis?sample=${item.id}`)}
        />
      )}
    </div>
  );
};
