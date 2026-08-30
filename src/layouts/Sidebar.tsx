import React from 'react';
import { clsx } from 'clsx';
import {
  LayoutDashboard,
  FileSearch,
  Cpu,
  Radio,
  ShieldAlert,
  BarChart3,
  FileText,
  UserCheck,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  Terminal
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { useAuth } from '../context/AuthContext';
import { getFilteredNavigation } from '../routes/routes';
import type { SeverityLevel } from '../types';

const ICON_MAP: Record<string, React.ReactNode> = {
  LayoutDashboard: <LayoutDashboard className="w-4 h-4" />,
  FileSearch: <FileSearch className="w-4 h-4" />,
  Cpu: <Cpu className="w-4 h-4" />,
  Radio: <Radio className="w-4 h-4" />,
  ShieldAlert: <ShieldAlert className="w-4 h-4" />,
  BarChart3: <BarChart3 className="w-4 h-4" />,
  FileText: <FileText className="w-4 h-4" />,
  UserCheck: <UserCheck className="w-4 h-4" />,
};

export const Sidebar: React.FC = () => {
  const { currentPath, navigate, sidebarCollapsed, setSidebarCollapsed } = useThreatLens();
  const { user } = useAuth();

  const navItems = getFilteredNavigation(user?.role);

  const getBadgeStyle = (color?: SeverityLevel | 'neutral') => {
    switch (color) {
      case 'critical':
        return 'bg-red-950 text-red-400 border-red-800/80 animate-pulse';
      case 'high':
        return 'bg-orange-950 text-orange-400 border-orange-800/80';
      case 'medium':
        return 'bg-amber-950 text-amber-400 border-amber-800/80';
      case 'info':
        return 'bg-sky-950 text-sky-400 border-sky-800/80';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <aside
      className={clsx(
        'h-screen bg-slate-950 border-r border-slate-800 flex flex-col transition-all duration-200 select-none z-30 shrink-0 sticky top-0',
        sidebarCollapsed ? 'w-16' : 'w-60'
      )}
    >
      {/* Brand Header */}
      <div className="h-13 border-b border-slate-800/80 flex items-center justify-between px-3.5 bg-slate-950/80">
        <div className="flex items-center gap-2.5 overflow-hidden">
          <div className="w-8 h-8 rounded bg-sky-950/90 border border-sky-700/80 flex items-center justify-center text-sky-400 shrink-0 shadow-inner">
            <Shield className="w-4 h-4 text-sky-400" />
          </div>
          {!sidebarCollapsed && (
            <div className="flex flex-col min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-xs tracking-wider text-slate-100 uppercase font-mono">
                  ThreatLens
                </span>
                <span className="text-2xs font-semibold px-1 py-0.2 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  AI
                </span>
              </div>
              <span className="text-2xs text-slate-500 font-mono">v2.4-enterprise</span>
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="text-slate-500 hover:text-slate-200 p-1 rounded hover:bg-slate-900 transition-colors"
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {sidebarCollapsed ? (
            <ChevronRight className="w-3.5 h-3.5" />
          ) : (
            <ChevronLeft className="w-3.5 h-3.5" />
          )}
        </button>
      </div>

      {/* Role Indicator Banner */}
      {!sidebarCollapsed && (
        <div className="px-3.5 py-2 border-b border-slate-900 bg-slate-900/40">
          <div className="text-2xs text-slate-500 uppercase tracking-widest font-mono font-medium">
            Active Persona
          </div>
          <div className="text-xs text-sky-300 font-semibold truncate flex items-center gap-1.5 mt-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shrink-0" />
            <span>{user?.role || 'Guest'}</span>
          </div>
        </div>
      )}

      {/* Navigation List */}
      <nav className="flex-1 px-2 py-3 space-y-1 overflow-y-auto">
        {!sidebarCollapsed && (
          <div className="px-2 pb-1.5 text-2xs font-semibold uppercase tracking-wider text-slate-500 font-mono">
            Accessible Modules ({navItems.length})
          </div>
        )}
        {navItems.map((item) => {
          const isActive = currentPath === item.path || currentPath.startsWith(item.path + '/');
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => navigate(item.path)}
              className={clsx(
                'w-full flex items-center gap-2.5 px-2.5 py-2 rounded text-xs transition-colors group relative font-medium text-left',
                isActive
                  ? 'bg-slate-900 text-sky-400 border border-slate-750 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
              )}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <div
                className={clsx(
                  'shrink-0 flex items-center justify-center',
                  isActive ? 'text-sky-400' : 'text-slate-400 group-hover:text-slate-200'
                )}
              >
                {ICON_MAP[item.icon] || <Terminal className="w-4 h-4" />}
              </div>

              {!sidebarCollapsed && (
                <span className="flex-1 truncate tracking-tight">{item.label}</span>
              )}

              {!sidebarCollapsed && item.badge !== undefined && (
                <span
                  className={clsx(
                    'text-2xs px-1.5 py-0.2 rounded border font-mono font-semibold',
                    getBadgeStyle(item.badgeColor)
                  )}
                >
                  {item.badge}
                </span>
              )}

              {/* Collapsed Active Indicator Pill */}
              {sidebarCollapsed && isActive && (
                <div className="absolute right-1 w-1 h-4 bg-sky-400 rounded-full" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine Status Bottom Panel */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/90 text-2xs font-mono">
        {!sidebarCollapsed ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                <span>Sandbox Ingest</span>
              </span>
              <span className="text-emerald-400 font-semibold">99.98%</span>
            </div>
            <div className="w-full bg-slate-900 h-1 rounded-full overflow-hidden">
              <div className="bg-emerald-500 h-full w-[99.9%]" />
            </div>
            <div className="flex items-center justify-between text-slate-500 text-2xs pt-1 border-t border-slate-900">
              <span>Auth Token</span>
              <span className="text-emerald-400 font-semibold">TLS Active</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title="Sandbox Pipeline Operational 99.98%">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
        )}
      </div>
    </aside>
  );
};
