import React from 'react';
import { Loader2 } from 'lucide-react';
import { clsx } from 'clsx';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline' | 'subtle';
  size?: 'xs' | 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  className,
  variant = 'secondary',
  size = 'sm',
  isLoading = false,
  disabled,
  leftIcon,
  rightIcon,
  ...props
}) => {
  const baseStyles = 'inline-flex items-center justify-center font-medium transition-colors select-none focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50 disabled:cursor-not-allowed border';

  const sizeStyles = {
    xs: 'text-2xs px-2 py-1 gap-1 rounded-sm',
    sm: 'text-xs px-2.5 py-1.5 gap-1.5 rounded',
    md: 'text-sm px-3.5 py-2 gap-2 rounded',
    lg: 'text-base px-4 py-2.5 gap-2 rounded',
  };

  const variantStyles = {
    primary: 'bg-sky-600 hover:bg-sky-500 text-white border-sky-600 hover:border-sky-500 shadow-xs',
    secondary: 'bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200 dark:border-slate-700 dark:hover:border-slate-600',
    danger: 'bg-red-50 hover:bg-red-100 text-red-700 border-red-200 dark:bg-red-950/80 dark:hover:bg-red-900/90 dark:text-red-300 dark:border-red-800/80',
    ghost: 'bg-transparent hover:bg-slate-100 text-slate-700 border-transparent hover:border-slate-200 dark:hover:bg-slate-800/60 dark:text-slate-300 dark:hover:border-slate-700/50',
    outline: 'bg-transparent hover:bg-slate-100 text-slate-800 border-slate-300 hover:border-slate-400 dark:hover:bg-slate-850 dark:text-slate-200 dark:border-slate-700 dark:hover:border-slate-500',
    subtle: 'bg-slate-100/80 hover:bg-slate-200/80 text-slate-700 border-slate-200 dark:bg-slate-900/90 dark:hover:bg-slate-800 dark:text-slate-300 dark:border-slate-800',
  };

  return (
    <button
      className={clsx(
        baseStyles,
        sizeStyles[size],
        variantStyles[variant],
        className
      )}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <Loader2 className="w-3.5 h-3.5 animate-spin text-current" />
      ) : leftIcon ? (
        <span className="shrink-0 flex items-center">{leftIcon}</span>
      ) : null}
      <span>{children}</span>
      {!isLoading && rightIcon && (
        <span className="shrink-0 flex items-center">{rightIcon}</span>
      )}
    </button>
  );
};
