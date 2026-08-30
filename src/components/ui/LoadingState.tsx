import React from 'react';
import { clsx } from 'clsx';
import { ShieldAlert } from 'lucide-react';

export interface LoadingStateProps {
  message?: string;
  description?: string;
  variant?: 'spinner' | 'skeleton' | 'radar';
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Processing threat intelligence...',
  description = 'Parsing PE headers, dynamic heuristics, and neural embeddings',
  variant = 'spinner',
  className,
}) => {
  if (variant === 'skeleton') {
    return (
      <div className={clsx('w-full space-y-3 animate-pulse p-4', className)}>
        <div className="h-4 bg-slate-800 rounded w-1/3" />
        <div className="h-10 bg-slate-850 rounded w-full" />
        <div className="h-24 bg-slate-850 rounded w-full" />
        <div className="grid grid-cols-3 gap-3">
          <div className="h-16 bg-slate-850 rounded" />
          <div className="h-16 bg-slate-850 rounded" />
          <div className="h-16 bg-slate-850 rounded" />
        </div>
      </div>
    );
  }

  return (
    <div className={clsx('flex flex-col items-center justify-center p-12 text-center', className)}>
      <div className="relative flex items-center justify-center mb-4">
        <div className="w-12 h-12 border-2 border-slate-800 border-t-sky-500 rounded-full animate-spin" />
        <ShieldAlert className="w-5 h-5 text-sky-400 absolute" />
      </div>
      <h3 className="text-xs font-semibold text-slate-200 tracking-wide font-mono uppercase">
        {message}
      </h3>
      {description && (
        <p className="text-2xs text-slate-400 mt-1 max-w-sm font-mono">
          {description}
        </p>
      )}
    </div>
  );
};
