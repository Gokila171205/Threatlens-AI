import React, { useState } from 'react';
import { Shield, Lock, Mail, KeyRound, AlertTriangle, ArrowRight, ShieldCheck, Sun, Moon } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { useAuth } from '../context/AuthContext';
import { useThreatLens } from '../context/ThreatLensContext';
import { useTheme } from '../context/ThemeContext';
import type { UserRole } from '../types';

export const LoginPage: React.FC = () => {
  const { login, loginAsRole, isLoading, error } = useAuth();
  const { navigate } = useThreatLens();
  const { theme, toggleTheme } = useTheme();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setFormError('Analyst email or identifier is required');
      return;
    }
    setIsSubmitting(true);
    setFormError(null);

    try {
      await login({ email, password, mfaCode });
      navigate('/overview');
    } catch (err: any) {
      setFormError(err.message || 'Invalid security credentials');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickLogin = async (role: UserRole) => {
    setIsSubmitting(true);
    setFormError(null);
    try {
      await loginAsRole(role);
      navigate('/overview');
    } catch (err: any) {
      setFormError(err.message || 'Persona quick authentication failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-threat-bg text-threat-text flex flex-col items-center justify-center p-4 select-none relative font-sans transition-colors">
      {/* Theme Toggle Button in top right */}
      <div className="absolute top-4 right-4 z-20">
        <button
          type="button"
          onClick={toggleTheme}
          className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shadow-2xs"
          title={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
          aria-label={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
        >
          {theme === 'dark' ? (
            <Moon className="w-4 h-4 text-sky-400" />
          ) : (
            <Sun className="w-4 h-4 text-amber-500" />
          )}
        </button>
      </div>

      {/* Subtle security background grid overlay */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#94a3b815_1px,transparent_1px),linear-gradient(to_bottom,#94a3b815_1px,transparent_1px)] dark:bg-[linear-gradient(to_right,#1f293715_1px,transparent_1px),linear-gradient(to_bottom,#1f293715_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />

      <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded shadow-2xl z-10 overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/70 text-center flex flex-col items-center">
          <div className="w-10 h-10 rounded bg-sky-100 dark:bg-sky-950 border border-sky-300 dark:border-sky-700/80 flex items-center justify-center text-sky-600 dark:text-sky-400 mb-2 shadow-inner">
            <Shield className="w-5 h-5" />
          </div>
          <div className="flex items-center gap-1.5">
            <h1 className="text-sm font-bold tracking-wider uppercase font-mono text-slate-900 dark:text-slate-100">
              ThreatLens
            </h1>
            <span className="text-2xs font-semibold px-1 py-0.2 rounded bg-sky-100 text-sky-700 border border-sky-200 dark:bg-sky-500/20 dark:text-sky-300 dark:border-sky-500/30">
              AI
            </span>
          </div>
          <p className="text-2xs text-slate-500 font-mono mt-1">
            Enterprise Threat Detection & Malware Analysis Gateway
          </p>
          <div className="mt-2.5 px-2.5 py-0.5 rounded bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-800 dark:text-amber-400 text-2xs font-mono flex items-center gap-1.5">
            <Lock className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            <span>RESTRICTED ACCESS • TLS 1.3 MFA MANDATED</span>
          </div>
        </div>

        {/* Login Form */}
        <div className="p-5 space-y-4">
          {(formError || error) && (
            <div className="p-3 rounded border border-red-200 dark:border-red-900/80 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-2xs font-mono flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
              <span>{formError || error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-3">
            <Input
              label="Analyst Email / ID"
              placeholder="e.g. a.rivera@defense.threatlens.ai"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              leftIcon={<Mail className="w-3.5 h-3.5 text-slate-400" />}
              isMonospace
              required
            />

            <Input
              label="Security Clearance Passcode"
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              leftIcon={<Lock className="w-3.5 h-3.5 text-slate-400" />}
              isMonospace
            />

            <Input
              label="Security Key / MFA Token (Optional)"
              placeholder="6-digit TOTP or YubiKey OTP"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              leftIcon={<KeyRound className="w-3.5 h-3.5 text-slate-400" />}
              isMonospace
            />

            <Button
              type="submit"
              variant="primary"
              size="md"
              className="w-full mt-2"
              isLoading={isSubmitting || isLoading}
              rightIcon={<ArrowRight className="w-4 h-4" />}
            >
              Authenticate & Launch Session
            </Button>
          </form>

          {/* Persona Quick Login Selector for Testing */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <div className="text-2xs font-mono uppercase text-slate-500 font-semibold text-center">
              Quick Persona Authentication (SOC Test Mode)
            </div>
            <div className="grid grid-cols-2 gap-2 text-2xs font-mono">
              <Button
                variant="subtle"
                size="xs"
                onClick={() => handleQuickLogin('Security Analyst')}
                disabled={isSubmitting}
              >
                Security Analyst
              </Button>
              <Button
                variant="subtle"
                size="xs"
                onClick={() => handleQuickLogin('SOC Team Member')}
                disabled={isSubmitting}
              >
                SOC Operator
              </Button>
              <Button
                variant="subtle"
                size="xs"
                onClick={() => handleQuickLogin('Administrator')}
                disabled={isSubmitting}
              >
                Administrator
              </Button>
              <Button
                variant="subtle"
                size="xs"
                onClick={() => handleQuickLogin('Researcher')}
                disabled={isSubmitting}
              >
                AI Researcher
              </Button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-center text-2xs font-mono text-slate-500 flex items-center justify-between px-5">
          <span>ThreatLens AI v2.4</span>
          <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
            <ShieldCheck className="w-3 h-3" /> FIPS 140-2 Verified
          </span>
        </div>
      </div>
    </div>
  );
};
