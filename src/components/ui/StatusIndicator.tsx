import React from 'react';
import { clsx } from 'clsx';

export interface StatusIndicatorProps {
  status: 'online' | 'busy' | 'offline' | 'warning' | 'critical' | 'processing';
  label?: string;
  pulse?: boolean;
  size?: 'xs' | 'sm' | 'md';
  className?: string;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  pulse = false,
  size = 'sm',
  className,
}) => {
  const statusColors = {
    online: 'bg-emerald-500 ring-emerald-500/20',
    busy: 'bg-amber-500 ring-amber-500/20',
    offline: 'bg-slate-400 dark:bg-slate-500 ring-slate-500/20',
    warning: 'bg-amber-500 ring-amber-500/20',
    critical: 'bg-red-500 ring-red-500/20',
    processing: 'bg-sky-500 ring-sky-500/20',
  };

  const dotSizes = {
    xs: 'w-1.5 h-1.5',
    sm: 'w-2 h-2',
    md: 'w-2.5 h-2.5',
  };

  return (
    <div className={clsx('inline-flex items-center gap-2 select-none', className)}>
      <span className="relative flex items-center justify-center">
        {pulse && (
          <span
            className={clsx(
              'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
              statusColors[status]
            )}
          />
        )}
        <span
          className={clsx(
            'relative inline-flex rounded-full ring-2',
            dotSizes[size],
            statusColors[status]
          )}
        />
      </span>
      {label && <span className="text-xs text-slate-700 dark:text-slate-300 font-medium">{label}</span>}
    </div>
  );
};
