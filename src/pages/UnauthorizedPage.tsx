import React from 'react';
import { ShieldAlert, ArrowLeft, LogOut } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { useAuth } from '../context/AuthContext';
import { useThreatLens } from '../context/ThreatLensContext';

export interface UnauthorizedPageProps {
  requiredPermission?: string;
  moduleName?: string;
}

export const UnauthorizedPage: React.FC<UnauthorizedPageProps> = ({
  requiredPermission = 'manage_settings',
  moduleName = 'Restricted Administration Module',
}) => {
  const { user, logout } = useAuth();
  const { navigate } = useThreatLens();

  return (
    <div className="min-h-[75vh] flex flex-col items-center justify-center p-6 text-center select-none font-sans">
      <div className="w-full max-w-lg p-6 bg-slate-900 border border-red-900/60 rounded shadow-2xl space-y-4">
        <div className="w-12 h-12 rounded bg-red-950/80 border border-red-800/80 flex items-center justify-center text-red-400 mx-auto">
          <ShieldAlert className="w-6 h-6" />
        </div>

        <div>
          <span className="text-2xs font-mono bg-red-950 text-red-400 border border-red-800/80 px-2 py-0.5 rounded font-bold uppercase">
            HTTP 403 • ACCESS DENIED
          </span>
          <h2 className="text-base font-bold text-slate-100 mt-2 font-mono">
            Security Clearance Level Insufficient
          </h2>
          <p className="text-2xs text-slate-400 mt-1 max-w-md mx-auto">
            Your active persona <strong className="text-sky-300 font-mono">[{user?.role || 'Guest'}]</strong> does not possess the <code className="text-amber-400 font-mono">[{requiredPermission}]</code> clearance required to access <strong className="text-slate-200">{moduleName}</strong>.
          </p>
        </div>

        <div className="p-3 bg-slate-950 rounded border border-slate-800 text-2xs font-mono text-left space-y-1">
          <div className="flex justify-between text-slate-400">
            <span>Logged User:</span>
            <span className="text-slate-200 font-semibold">{user?.email}</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Clearance Tag:</span>
            <span className="text-red-400 font-semibold">{user?.clearanceLevel}</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Violation Audit Event:</span>
            <span className="text-slate-500">AUDIT_EVT_UNAUTH_ACCESS_ATTEMPT</span>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-2 pt-2">
          <Button
            variant="primary"
            size="sm"
            leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}
            onClick={() => navigate('/overview')}
          >
            Return to SOC Overview
          </Button>
          <Button
            variant="subtle"
            size="sm"
            onClick={() => navigate('/profile')}
          >
            Request Role Escalation
          </Button>
          <Button
            variant="ghost"
            size="sm"
            leftIcon={<LogOut className="w-3.5 h-3.5" />}
            onClick={() => {
              logout();
              navigate('/login');
            }}
          >
            Logout
          </Button>
        </div>
      </div>
    </div>
  );
};
