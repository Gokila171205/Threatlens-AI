import React from 'react';
import { clsx } from 'clsx';

export interface EntropyBarProps {
  entropy: number; // 0.0 to 8.0
  className?: string;
}

export const EntropyBar: React.FC<EntropyBarProps> = ({ entropy, className }) => {
  const percentage = (entropy / 8.0) * 100;

  let colorClass = 'bg-emerald-500 text-emerald-400 border-emerald-800/80';
  if (entropy >= 7.2) {
    colorClass = 'bg-red-500 text-red-400 border-red-800/80';
  } else if (entropy >= 6.0) {
    colorClass = 'bg-amber-500 text-amber-400 border-amber-800/80';
  }

  return (
    <div className={clsx('inline-flex items-center gap-2 font-mono text-2xs select-none', className)}>
      <span className={clsx('font-bold px-1.5 py-0.2 rounded border shrink-0', colorClass.split(' ')[1])}>
        {entropy.toFixed(2)} / 8.0
      </span>
      <div className="w-16 h-1.5 bg-slate-900 rounded overflow-hidden border border-slate-800">
        <div
          className={clsx('h-full transition-all duration-300', colorClass.split(' ')[0])}
          style={{ width: `${Math.min(100, Math.max(0, percentage))}%` }}
        />
      </div>
      {entropy >= 7.2 && (
        <span className="text-2xs text-red-400 font-bold uppercase tracking-tight">
          [PACKED]
        </span>
      )}
    </div>
  );
};
