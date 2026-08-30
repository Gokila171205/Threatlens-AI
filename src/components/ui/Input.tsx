import React, { forwardRef } from 'react';
import { clsx } from 'clsx';
import { X } from 'lucide-react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightElement?: React.ReactNode;
  onClear?: () => void;
  isMonospace?: boolean;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(({
  label,
  error,
  helperText,
  leftIcon,
  rightElement,
  onClear,
  isMonospace = false,
  className,
  value,
  disabled,
  id,
  ...props
}, ref) => {
  const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

  return (
    <div className="flex flex-col gap-1 w-full text-left">
      {label && (
        <label htmlFor={inputId} className="text-2xs font-medium uppercase tracking-wider text-slate-400">
          {label}
        </label>
      )}
      <div className="relative flex items-center w-full">
        {leftIcon && (
          <div className="absolute left-2.5 flex items-center pointer-events-none text-slate-400">
            {leftIcon}
          </div>
        )}
        <input
          ref={ref}
          id={inputId}
          value={value}
          disabled={disabled}
          className={clsx(
            'w-full bg-slate-900/90 border text-slate-200 placeholder-slate-500 rounded text-xs px-3 py-1.5 transition-colors',
            'focus:outline-none focus:ring-1 focus:ring-sky-500 focus:border-sky-500',
            'disabled:opacity-50 disabled:bg-slate-950 disabled:cursor-not-allowed',
            error ? 'border-red-600 focus:ring-red-500 focus:border-red-500' : 'border-slate-800 hover:border-slate-700',
            leftIcon ? 'pl-8' : '',
            (rightElement || onClear) ? 'pr-8' : '',
            isMonospace ? 'font-mono' : 'font-sans',
            className
          )}
          {...props}
        />
        {onClear && value && !disabled && (
          <button
            type="button"
            onClick={onClear}
            className="absolute right-2 text-slate-500 hover:text-slate-300 p-0.5"
            tabIndex={-1}
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
        {rightElement && !onClear && (
          <div className="absolute right-2.5 flex items-center">
            {rightElement}
          </div>
        )}
      </div>
      {error && <span className="text-2xs text-red-400">{error}</span>}
      {helperText && !error && <span className="text-2xs text-slate-500">{helperText}</span>}
    </div>
  );
});

Input.displayName = 'Input';
