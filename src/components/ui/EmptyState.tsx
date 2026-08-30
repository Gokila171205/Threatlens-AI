import React from 'react';
import { clsx } from 'clsx';
import { Database } from 'lucide-react';
import { Button } from './Button';

export interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionLabel,
  onAction,
  className,
}) => {
  return (
    <div className={clsx('flex flex-col items-center justify-center p-12 text-center border border-dashed border-slate-300 dark:border-slate-800 rounded bg-slate-50 dark:bg-slate-950/40', className)}>
      <div className="w-10 h-10 rounded bg-slate-200/80 dark:bg-slate-900 border border-slate-300 dark:border-slate-800 flex items-center justify-center text-slate-500 mb-3">
        {icon || <Database className="w-5 h-5" />}
      </div>
      <h4 className="text-xs font-semibold text-slate-800 dark:text-slate-200 uppercase tracking-wide">
        {title}
      </h4>
      {description && (
        <p className="text-2xs text-slate-500 dark:text-slate-400 mt-1 max-w-sm">
          {description}
        </p>
      )}
      {actionLabel && onAction && (
        <div className="mt-4">
          <Button variant="secondary" size="xs" onClick={onAction}>
            {actionLabel}
          </Button>
        </div>
      )}
    </div>
  );
};
