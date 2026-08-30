import type { SeverityLevel, Verdict } from '../types';

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatHash(hash: string, startLength = 6, endLength = 6): string {
  if (!hash || hash.length <= startLength + endLength) return hash;
  return `${hash.substring(0, startLength)}...${hash.substring(hash.length - endLength)}`;
}

export function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch {
    return isoString;
  }
}

export function formatRelativeTime(isoString: string): string {
  try {
    const diffMs = Date.now() - new Date(isoString).getTime();
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  } catch {
    return isoString;
  }
}

export function getSeverityClasses(severity: SeverityLevel): { text: string; bg: string; border: string; dot: string } {
  switch (severity) {
    case 'critical':
      return {
        text: 'text-red-700 dark:text-red-400',
        bg: 'bg-red-50 dark:bg-red-950/40',
        border: 'border-red-200 dark:border-red-800/60',
        dot: 'bg-red-500'
      };
    case 'high':
      return {
        text: 'text-orange-800 dark:text-orange-400',
        bg: 'bg-orange-50 dark:bg-orange-950/40',
        border: 'border-orange-200 dark:border-orange-800/60',
        dot: 'bg-orange-500'
      };
    case 'medium':
      return {
        text: 'text-amber-800 dark:text-amber-400',
        bg: 'bg-amber-50 dark:bg-amber-950/40',
        border: 'border-amber-200 dark:border-amber-800/60',
        dot: 'bg-amber-500'
      };
    case 'low':
      return {
        text: 'text-emerald-800 dark:text-emerald-400',
        bg: 'bg-emerald-50 dark:bg-emerald-950/40',
        border: 'border-emerald-200 dark:border-emerald-800/60',
        dot: 'bg-emerald-500'
      };
    case 'info':
    default:
      return {
        text: 'text-sky-800 dark:text-sky-400',
        bg: 'bg-sky-50 dark:bg-sky-950/40',
        border: 'border-sky-200 dark:border-sky-800/60',
        dot: 'bg-sky-500'
      };
  }
}

export function getVerdictClasses(verdict: Verdict): { text: string; bg: string; border: string } {
  switch (verdict) {
    case 'malicious':
      return {
        text: 'text-red-700 dark:text-red-400 font-semibold',
        bg: 'bg-red-50 dark:bg-red-950/50',
        border: 'border-red-200 dark:border-red-700/70'
      };
    case 'suspicious':
      return {
        text: 'text-amber-800 dark:text-amber-400 font-semibold',
        bg: 'bg-amber-50 dark:bg-amber-950/50',
        border: 'border-amber-200 dark:border-amber-700/70'
      };
    case 'clean':
      return {
        text: 'text-emerald-800 dark:text-emerald-400 font-semibold',
        bg: 'bg-emerald-50 dark:bg-emerald-950/50',
        border: 'border-emerald-200 dark:border-emerald-700/70'
      };
    case 'unknown':
    default:
      return {
        text: 'text-slate-700 dark:text-slate-400',
        bg: 'bg-slate-100 dark:bg-slate-900/60',
        border: 'border-slate-200 dark:border-slate-700/60'
      };
  }
}
