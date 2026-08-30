import React from 'react';
import { clsx } from 'clsx';
import type { SeverityLevel, Verdict } from '../../types';
import { getSeverityClasses, getVerdictClasses } from '../../utils/formatters';

export interface BadgeProps {
  children: React.ReactNode;
  severity?: SeverityLevel;
  verdict?: Verdict;
  variant?: 'outline' | 'subtle' | 'solid';
  size?: 'xs' | 'sm' | 'md';
  className?: string;
  dot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  severity,
  verdict,
  variant = 'subtle',
  size = 'sm',
  className,
  dot = false,
}) => {
  const sizeStyles = {
    xs: 'text-2xs px-1.5 py-0.2 rounded-sm gap-1',
    sm: 'text-2xs px-2 py-0.5 rounded gap-1.5 font-medium tracking-wide',
    md: 'text-xs px-2.5 py-1 rounded gap-1.5 font-medium',
  };

  let colorClasses = 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700';
  let dotColor = 'bg-slate-400';

  if (severity) {
    const sev = getSeverityClasses(severity);
    dotColor = sev.dot;
    if (variant === 'subtle') {
      colorClasses = `${sev.bg} ${sev.text} ${sev.border}`;
    } else if (variant === 'outline') {
      colorClasses = `bg-transparent ${sev.text} ${sev.border}`;
    } else {
      colorClasses = `${sev.dot} text-white border-transparent font-semibold`;
    }
  } else if (verdict) {
    const verd = getVerdictClasses(verdict);
    colorClasses = `${verd.bg} ${verd.text} ${verd.border}`;
  }

  return (
    <span
      className={clsx(
        'inline-flex items-center select-none border capitalize',
        sizeStyles[size],
        colorClasses,
        className
      )}
    >
      {dot && <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', dotColor)} />}
      <span>{children}</span>
    </span>
  );
};
