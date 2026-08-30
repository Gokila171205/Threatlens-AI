import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { useThreatLens } from '../context/ThreatLensContext';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { MonoText } from '../components/common/MonoText';
import { Badge } from '../components/ui/Badge';
import { Search, FileSearch, ShieldAlert, ArrowRight } from 'lucide-react';
import { MOCK_MALWARE_SAMPLES, MOCK_ALERTS } from '../data/mockData';
import { useKeyboardShortcut } from '../hooks/useKeyboardShortcut';

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isSearchModalOpen, setIsSearchModalOpen, navigate } = useThreatLens();
  const [searchQuery, setSearchQuery] = useState('');

  // Enable Ctrl+K hotkey globally
  useKeyboardShortcut('k', () => setIsSearchModalOpen(true), true);

  const filteredSamples = MOCK_MALWARE_SAMPLES.filter(
    (s) =>
      s.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.sha256.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.threatFamily?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const filteredAlerts = MOCK_ALERTS.filter(
    (a) =>
      a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.targetHost.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.sourceIp.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelectSample = (sampleId: string) => {
    setIsSearchModalOpen(false);
    navigate(`/file-analysis?sample=${sampleId}`);
  };

  const handleSelectAlert = () => {
    setIsSearchModalOpen(false);
    navigate('/alerts');
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-200 flex flex-row">
      {/* Persistent Collapsible Sidebar */}
      <Sidebar />

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col min-w-0 overflow-x-hidden">
        <Topbar />
        <main className="flex-1 p-4 md:p-6 overflow-y-auto">
          {children}
        </main>
      </div>

      {/* Global Quick Search Modal */}
      <Modal
        isOpen={isSearchModalOpen}
        onClose={() => setIsSearchModalOpen(false)}
        title={
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-sky-400" />
            <span>Global Threat & Hash Intelligence Search</span>
          </div>
        }
        subtitle="Search across active malware samples, telemetry hashes, C2 IP addresses, and SOC incidents"
        size="lg"
      >
        <div className="space-y-4">
          <Input
            placeholder="Type SHA-256 hash, file name, threat family (e.g. LockBit), or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            leftIcon={<Search className="w-4 h-4 text-slate-500" />}
            onClear={() => setSearchQuery('')}
            autoFocus
          />

          <div className="space-y-3 pt-2">
            {/* Samples Result */}
            <div>
              <div className="text-2xs font-semibold uppercase tracking-wider text-slate-500 font-mono mb-2 flex items-center justify-between">
                <span>Malware Samples ({filteredSamples.length})</span>
                <span className="text-slate-600 font-mono">Press Enter to inspect</span>
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {filteredSamples.length === 0 ? (
                  <div className="p-3 text-center text-xs text-slate-500 bg-slate-950/40 rounded border border-slate-850">
                    No matching malware signatures found
                  </div>
                ) : (
                  filteredSamples.map((sample) => (
                    <div
                      key={sample.id}
                      onClick={() => handleSelectSample(sample.id)}
                      className="p-2.5 bg-slate-950/70 hover:bg-slate-850 border border-slate-800 rounded flex items-center justify-between cursor-pointer group transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <FileSearch className="w-4 h-4 text-sky-400 shrink-0" />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-slate-200 group-hover:text-sky-300 font-mono truncate">
                              {sample.fileName}
                            </span>
                            <Badge verdict={sample.verdict} size="xs">
                              {sample.verdict}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <MonoText value={sample.sha256} truncate startLen={6} endLen={6} />
                            {sample.threatFamily && (
                              <span className="text-2xs text-amber-400 font-mono">
                                [{sample.threatFamily}]
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 text-slate-500 group-hover:text-slate-300 shrink-0">
                        <span className="text-2xs font-mono text-slate-400 font-bold">
                          Score: {sample.threatScore}/100
                        </span>
                        <ArrowRight className="w-3.5 h-3.5 text-sky-400" />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Alerts Result */}
            <div className="pt-2 border-t border-slate-800">
              <div className="text-2xs font-semibold uppercase tracking-wider text-slate-500 font-mono mb-2">
                Active Incidents ({filteredAlerts.length})
              </div>
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {filteredAlerts.slice(0, 3).map((alert) => (
                  <div
                    key={alert.id}
                    onClick={handleSelectAlert}
                    className="p-2.5 bg-slate-950/70 hover:bg-slate-850 border border-slate-800 rounded flex items-center justify-between cursor-pointer group transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-2xs font-mono text-slate-400">{alert.id}</span>
                          <Badge severity={alert.severity} size="xs">
                            {alert.severity}
                          </Badge>
                        </div>
                        <span className="text-xs text-slate-300 font-medium truncate block mt-0.5">
                          {alert.title}
                        </span>
                      </div>
                    </div>
                    <span className="text-2xs font-mono text-slate-500 shrink-0">
                      {alert.targetHost}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
};
