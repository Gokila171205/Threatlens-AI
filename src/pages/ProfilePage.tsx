import React from 'react';
import { Shield, CheckCircle2 } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { MonoText } from '../components/common/MonoText';
import { useThreatLens } from '../context/ThreatLensContext';
import type { UserRole } from '../types';

const ROLES_INFO: { role: UserRole; title: string; description: string; permissions: string[] }[] = [
  {
    role: 'Security Analyst',
    title: 'Security Analyst (Tier 1-3)',
    description: 'Investigates malware payloads, performs sandbox analysis, triages SOC incidents, and generates IOC feeds.',
    permissions: ['File Sandbox Execution', 'MITRE ATT&CK Mapping', 'Alert Triage & Escalation', 'IOC Extraction'],
  },
  {
    role: 'SOC Team Member',
    title: 'SOC Team Member / Operator',
    description: 'Monitors real-time telemetry, tracks SLA response times, isolates affected endpoints, and updates incident statuses.',
    permissions: ['Live Sensor Telemetry', 'EDR Host Isolation', 'SLA Response Tracking', 'Case Notes Collaboration'],
  },
  {
    role: 'Administrator',
    title: 'Platform Administrator',
    description: 'Configures integration webhooks, manages analyst roles, monitors cluster health, and audits API keys.',
    permissions: ['RBAC Management', 'Cluster Scale Settings', 'Audit Log Access', 'API Key Rotation'],
  },
  {
    role: 'Researcher',
    title: 'AI Threat Researcher',
    description: 'Inspects neural embedding weights, tests YARA/Sigma rules against sample corpora, and tunes ML confidence thresholds.',
    permissions: ['NeuralPE Telemetry', 'YARA/Sigma Rule Deployment', 'Bayesian Drift Analysis', 'Raw Disassembly Access'],
  },
];

export const ProfilePage: React.FC = () => {
  const { currentUser, activeRole, setActiveRole } = useThreatLens();

  return (
    <div className="space-y-6">
      {/* Analyst Credentials Card */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded bg-sky-950 border border-sky-700/80 flex items-center justify-center text-sky-400 font-mono text-base font-bold">
              {currentUser.name.split(' ').map((n) => n[0]).join('')}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100">{currentUser.name}</h2>
                <span className="text-2xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/80 px-2 py-0.5 rounded font-bold">
                  {currentUser.clearanceLevel}
                </span>
              </div>
              <p className="text-2xs font-mono text-slate-400 mt-0.5">
                {currentUser.email} • {currentUser.department}
              </p>
            </div>
          </div>

          <div className="text-right text-2xs font-mono text-slate-500">
            <div>User ID: <span className="text-slate-300">{currentUser.id}</span></div>
            <div>Session: <span className="text-emerald-400 font-semibold">Active (TLS 1.3 / MFA Verified)</span></div>
          </div>
        </div>

        {/* API Tokens & Clearance info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-2xs font-mono">
          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
            <span className="text-slate-500 block uppercase">Analyst REST API Key</span>
            <div className="flex items-center justify-between">
              <MonoText value="tl_live_99af081b29efb7189c4501a4e" />
              <Button variant="ghost" size="xs" onClick={() => alert('API key rotated')}>
                Rotate
              </Button>
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
            <span className="text-slate-500 block uppercase">Hardware Security Token</span>
            <div className="flex items-center justify-between">
              <span className="text-slate-300">YubiKey 5 FIPS (SN: 9812401)</span>
              <span className="text-emerald-400 font-bold">● Valid</span>
            </div>
          </div>
        </div>
      </div>

      {/* Role-Aware Navigation Switcher */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider font-mono text-slate-100">
              Role-Aware Navigation & Permissions Selector
            </h3>
          </div>
          <span className="text-2xs font-mono text-slate-500">
            Click any operational persona to switch navigation & privileges in real time
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {ROLES_INFO.map((item) => {
            const isActive = activeRole === item.role;
            return (
              <div
                key={item.role}
                onClick={() => setActiveRole(item.role)}
                className={`p-4 rounded border transition-all cursor-pointer space-y-2.5 ${
                  isActive
                    ? 'bg-sky-950/30 border-sky-500 shadow-md ring-1 ring-sky-500/50'
                    : 'bg-slate-900/80 hover:bg-slate-850 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className={`font-mono text-xs font-bold ${isActive ? 'text-sky-300' : 'text-slate-200'}`}>
                    {item.title}
                  </span>
                  {isActive ? (
                    <span className="flex items-center gap-1 text-2xs font-mono font-bold text-sky-400 bg-sky-950 px-2 py-0.5 rounded border border-sky-800">
                      <CheckCircle2 className="w-3 h-3" /> ACTIVE
                    </span>
                  ) : (
                    <span className="text-2xs font-mono text-slate-500">Click to switch</span>
                  )}
                </div>

                <p className="text-2xs text-slate-400 leading-relaxed">
                  {item.description}
                </p>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {item.permissions.map((p) => (
                    <span
                      key={p}
                      className="text-2xs font-mono px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-850"
                    >
                      ✓ {p}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
