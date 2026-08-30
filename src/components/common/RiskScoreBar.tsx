import React from 'react';
import { clsx } from 'clsx';

export interface RiskScoreBarProps {
  score: number;
  showNumeric?: boolean;
  size?: 'xs' | 'sm' | 'md';
  className?: string;
}

export const RiskScoreBar: React.FC<RiskScoreBarProps> = ({
  score,
  showNumeric = true,
  size = 'sm',
  className,
}) => {
  // Determine color coding based on risk score thresholds
  let scoreColor = 'text-emerald-700 bg-emerald-50 border-emerald-200 dark:text-emerald-400 dark:bg-emerald-950/60 dark:border-emerald-800/80';
  let barFill = 'bg-emerald-500';

  if (score >= 85) {
    scoreColor = 'text-red-700 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-950/60 dark:border-red-800/80';
    barFill = 'bg-red-500';
  } else if (score >= 70) {
    scoreColor = 'text-orange-800 bg-orange-50 border-orange-200 dark:text-orange-400 dark:bg-orange-950/60 dark:border-orange-800/80';
    barFill = 'bg-orange-500';
  } else if (score >= 40) {
    scoreColor = 'text-amber-800 bg-amber-50 border-amber-200 dark:text-amber-400 dark:bg-amber-950/60 dark:border-amber-800/80';
    barFill = 'bg-amber-500';
  }

  const heightStyles = {
    xs: 'h-1 w-12',
    sm: 'h-1.5 w-16',
    md: 'h-2 w-20',
  };

  return (
    <div className={clsx('inline-flex items-center gap-2 font-mono select-none', className)}>
      {showNumeric && (
        <span
          className={clsx(
            'text-2xs font-bold px-1.5 py-0.2 rounded border shrink-0',
            scoreColor
          )}
        >
          {score}/100
        </span>
      )}
      <div className={clsx('bg-slate-200 dark:bg-slate-900 rounded-full overflow-hidden border border-slate-300 dark:border-slate-800', heightStyles[size])}>
        <div
          className={clsx('h-full transition-all duration-300', barFill)}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>
    </div>
  );
};
