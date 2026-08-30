import React from 'react';
import { clsx } from 'clsx';

export interface EntropyBarProps {
  entropy: number; // 0.0 to 8.0
  className?: string;
}

export const EntropyBar: React.FC<EntropyBarProps> = ({ entropy, className }) => {
  const percentage = (entropy / 8.0) * 100;

  let fillClass = 'bg-emerald-500';
  let badgeClass = 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-400 dark:border-emerald-800/80';

  if (entropy >= 7.2) {
    fillClass = 'bg-red-500';
    badgeClass = 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/60 dark:text-red-400 dark:border-red-800/80';
  } else if (entropy >= 6.0) {
    fillClass = 'bg-amber-500';
    badgeClass = 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/60 dark:text-amber-400 dark:border-amber-800/80';
  }

  return (
    <div className={clsx('inline-flex items-center gap-2 font-mono text-2xs select-none', className)}>
      <span className={clsx('font-bold px-1.5 py-0.2 rounded border shrink-0', badgeClass)}>
        {entropy.toFixed(2)} / 8.0
      </span>
      <div className="w-16 h-1.5 bg-slate-200 dark:bg-slate-900 rounded overflow-hidden border border-slate-300 dark:border-slate-800">
        <div
          className={clsx('h-full transition-all duration-300', fillClass)}
          style={{ width: `${Math.min(100, Math.max(0, percentage))}%` }}
        />
      </div>
      {entropy >= 7.2 && (
        <span className="text-2xs text-red-600 dark:text-red-400 font-bold uppercase tracking-tight">
          [PACKED]
        </span>
      )}
    </div>
  );
};
