import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  UserPlus,
  Users,
  Settings,
  Activity,
  Layers,
  CheckCircle2,
  RotateCw
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Table } from '../components/ui/Table';
import type { Column } from '../components/ui/Table';
import { Modal } from '../components/ui/Modal';
import { LoadingState } from '../components/ui/LoadingState';
import { ThreatLensApi } from '../services/api';
import type { AdminUserItem, PlatformIntegration, PlatformAuditLog } from '../data/mockAdminData';
import type { UserRole } from '../types';
import { formatRelativeTime } from '../utils/formatters';

const ALL_ROLES: UserRole[] = [
  'Security Analyst',
  'SOC Team Member',
  'Administrator',
  'Researcher'
];

export const AdminPage: React.FC = () => {
  const [users, setUsers] = useState<AdminUserItem[]>([]);
  const [integrations, setIntegrations] = useState<PlatformIntegration[]>([]);
  const [auditLogs, setAuditLogs] = useState<PlatformAuditLog[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Add User Modal
  const [isAddUserOpen, setIsAddUserOpen] = useState<boolean>(false);
  const [newUserName, setNewUserName] = useState<string>('');
  const [newUserEmail, setNewUserEmail] = useState<string>('');
  const [newUserRole, setNewUserRole] = useState<UserRole>('Security Analyst');

  const loadAdminData = async () => {
    setIsLoading(true);
    const [uList, intList, logList] = await Promise.all([
      ThreatLensApi.getAdminUsers(),
      ThreatLensApi.getIntegrations(),
      ThreatLensApi.getAuditLogs(),
    ]);
    setUsers(uList);
    setIntegrations(intList);
    setAuditLogs(logList);
    setIsLoading(false);
  };

  useEffect(() => {
    loadAdminData();
  }, []);

  const handleToggleStatus = async (userId: string) => {
    const updated = await ThreatLensApi.toggleAdminUserStatus(userId);
    setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
  };

  const handleRoleChange = async (userId: string, role: UserRole) => {
    const updated = await ThreatLensApi.updateAdminUserRole(userId, role);
    setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
  };

  const handleAddUserSubmit = () => {
    if (!newUserName || !newUserEmail) return;
    const newUser: AdminUserItem = {
      id: `usr-${Math.floor(900 + Math.random() * 100)}`,
      name: newUserName,
      email: newUserEmail,
      role: newUserRole,
      status: 'Active',
      lastActive: 'Just now',
      createdDate: new Date().toISOString().substring(0, 10),
    };
    setUsers((prev) => [newUser, ...prev]);
    setIsAddUserOpen(false);
    setNewUserName('');
    setNewUserEmail('');
  };

  const userColumns: Column<AdminUserItem>[] = [
    {
      key: 'name',
      header: 'Platform User & Email',
      render: (item) => (
        <div className="flex flex-col min-w-0 font-mono">
          <span className="font-bold text-xs text-slate-100">{item.name}</span>
          <span className="text-2xs text-slate-500">{item.email}</span>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Assigned Role',
      render: (item) => (
        <select
          value={item.role}
          onChange={(e) => handleRoleChange(item.id, e.target.value as UserRole)}
          className="bg-slate-950 border border-slate-750 text-sky-400 font-mono font-semibold rounded px-2 py-1 text-2xs focus:outline-none focus:border-sky-500"
        >
          {ALL_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      ),
    },
    {
      key: 'status',
      header: 'Account Status',
      align: 'center',
      render: (item) => (
        <span
          className={`font-mono text-2xs font-bold px-2 py-0.5 rounded border ${
            item.status === 'Active'
              ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800/80'
              : 'bg-slate-950/70 text-slate-400 border-slate-800'
          }`}
        >
          {item.status}
        </span>
      ),
    },
    {
      key: 'lastActive',
      header: 'Last Active',
      render: (item) => (
        <span className="font-mono text-2xs text-slate-400">
          {item.lastActive.includes('Z') ? formatRelativeTime(item.lastActive) : item.lastActive}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Action',
      align: 'right',
      render: (item) => (
        <Button
          variant={item.status === 'Active' ? 'subtle' : 'secondary'}
          size="xs"
          onClick={() => handleToggleStatus(item.id)}
        >
          {item.status === 'Active' ? 'Deactivate' : 'Activate'}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6 select-none font-sans">
      {/* Top Banner Header */}
      <div className="p-3.5 bg-slate-900 border border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-sm font-bold tracking-wider font-mono text-slate-100 uppercase flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            <span>Platform Administration & Access Control</span>
          </h1>
          <p className="text-2xs text-slate-400 font-mono mt-0.5">
            Role Access Matrix • EDR / SIEM Connectors • Audit Trail Logging
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="xs"
            leftIcon={<RotateCw className="w-3 h-3" />}
            onClick={loadAdminData}
          >
            Refresh Configuration
          </Button>
          <Button
            variant="primary"
            size="xs"
            leftIcon={<UserPlus className="w-3 h-3" />}
            onClick={() => setIsAddUserOpen(true)}
          >
            Provision User
          </Button>
        </div>
      </div>

      {/* User Management Section */}
      <div className="space-y-3 font-mono">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
            <Users className="w-4 h-4 text-sky-400" />
            <span>1. User Provisioning & Centralized Role Management</span>
          </h2>
          <span className="text-2xs text-slate-500">Total Users: {users.length}</span>
        </div>

        {isLoading ? (
          <LoadingState message="Loading Platform User Directory..." />
        ) : (
          <Table columns={userColumns} data={users} keyExtractor={(item) => item.id} />
        )}
      </div>

      {/* Integrations & Security Policies Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 font-mono">
        {/* Platform Integrations */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-sky-400" />
              <span>2. Security Integrations & Sensors</span>
            </h3>
          </div>

          <div className="space-y-2">
            {integrations.map((int) => (
              <div key={int.id} className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between text-2xs">
                <div>
                  <span className="font-bold text-slate-100 block">{int.name}</span>
                  <span className="text-slate-500">Sync: {int.lastSync}</span>
                </div>
                <span
                  className={`font-bold px-2 py-0.5 rounded border ${
                    int.status === 'Connected'
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : 'bg-amber-950 text-amber-400 border-amber-800'
                  }`}
                >
                  {int.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Platform Security Policies */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
              <Settings className="w-4 h-4 text-amber-400" />
              <span>3. Enforced Platform Security Policies</span>
            </h3>
          </div>

          <div className="space-y-2 text-2xs">
            <div className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-200 block">Strict Zero Trust Authorization Matrix</span>
                <span className="text-slate-500">11 Explicit Permissions scoped by persona</span>
              </div>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>

            <div className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-200 block">NeuralPE Classifier Confidence Cutoff</span>
                <span className="text-slate-500">Enforce manual triage on predictions &lt; 75%</span>
              </div>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>

            <div className="p-2.5 bg-slate-950 rounded border border-slate-800 flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-200 block">Sanitized Sandbox Execution Safety</span>
                <span className="text-slate-500">Air-gapped Hyper-V isolate mode enabled</span>
              </div>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Platform Activity Audit Log */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-100 flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <span>4. Administrative Platform Audit Log</span>
          </h3>
        </div>

        <div className="border border-slate-800 rounded bg-slate-950 overflow-x-auto">
          <table className="w-full text-left border-collapse soc-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Actor</th>
                <th>Action Performed</th>
                <th>Target Resource</th>
                <th>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/60">
                  <td className="text-2xs text-slate-400">{log.timestamp}</td>
                  <td className="font-bold text-sky-300 text-2xs">{log.actor}</td>
                  <td className="font-bold text-amber-300 text-2xs">{log.action}</td>
                  <td className="text-slate-200 text-2xs">{log.target}</td>
                  <td className="text-slate-500 text-2xs">{log.ipAddress}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add User Modal */}
      <Modal isOpen={isAddUserOpen} onClose={() => setIsAddUserOpen(false)} title="Provision New Platform User">
        <div className="space-y-4 font-mono text-2xs">
          <Input
            label="Full Name"
            placeholder="e.g. Elena Rostova"
            value={newUserName}
            onChange={(e) => setNewUserName(e.target.value)}
            isMonospace
          />

          <Input
            label="Defense Email Address"
            placeholder="e.g. e.rostova@defense.threatlens.ai"
            value={newUserEmail}
            onChange={(e) => setNewUserEmail(e.target.value)}
            isMonospace
          />

          <div>
            <label className="block text-2xs font-mono font-medium text-slate-300 mb-1">
              Select Role Assignment
            </label>
            <select
              value={newUserRole}
              onChange={(e) => setNewUserRole(e.target.value as UserRole)}
              className="bg-slate-950 border border-slate-750 text-slate-100 font-mono rounded px-3 py-1.5 text-2xs focus:outline-none focus:border-sky-500 w-full"
            >
              {ALL_ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <Button variant="ghost" size="xs" onClick={() => setIsAddUserOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" size="xs" onClick={handleAddUserSubmit}>
              Provision Account
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
