import React, { useState, useRef, useEffect } from 'react';
import { clsx } from 'clsx';
import { ChevronDown } from 'lucide-react';

export interface DropdownOption {
  value: string;
  label: string;
  icon?: React.ReactNode;
  badge?: string;
  disabled?: boolean;
}

export interface DropdownProps {
  options: DropdownOption[];
  value: string;
  onChange: (value: string) => void;
  label?: string;
  placeholder?: string;
  className?: string;
  disabled?: boolean;
}

export const Dropdown: React.FC<DropdownProps> = ({
  options,
  value,
  onChange,
  label,
  placeholder = 'Select option...',
  className,
  disabled = false,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const selectedOption = options.find((opt) => opt.value === value);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className={clsx('relative flex flex-col gap-1 text-left', className)} ref={dropdownRef}>
      {label && (
        <span className="text-2xs font-medium uppercase tracking-wider text-slate-600 dark:text-slate-400 font-mono">
          {label}
        </span>
      )}
      <button
        type="button"
        disabled={disabled}
        onClick={() => setIsOpen(!isOpen)}
        className={clsx(
          'inline-flex items-center justify-between gap-2 px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border rounded text-slate-800 dark:text-slate-200 transition-colors shadow-2xs',
          'focus:outline-none focus:ring-1 focus:ring-sky-500',
          disabled ? 'opacity-50 cursor-not-allowed' : 'border-slate-300 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700 cursor-pointer',
          isOpen ? 'border-sky-500 ring-1 ring-sky-500/30' : ''
        )}
      >
        <span className="truncate flex items-center gap-2">
          {selectedOption?.icon}
          <span>{selectedOption ? selectedOption.label : placeholder}</span>
        </span>
        <ChevronDown className={clsx('w-3.5 h-3.5 text-slate-400 transition-transform duration-150', isOpen && 'rotate-180')} />
      </button>

      {isOpen && !disabled && (
        <div className="absolute top-full left-0 mt-1 w-full min-w-[160px] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-750 rounded shadow-xl py-1 z-50 animate-in fade-in-50 duration-100">
          {options.map((option) => (
            <button
              key={option.value}
              type="button"
              disabled={option.disabled}
              onClick={() => {
                onChange(option.value);
                setIsOpen(false);
              }}
              className={clsx(
                'w-full flex items-center justify-between px-3 py-1.5 text-xs text-left transition-colors',
                option.disabled ? 'opacity-40 cursor-not-allowed text-slate-400 dark:text-slate-500' : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200',
                option.value === value ? 'bg-sky-50 dark:bg-sky-950/70 text-sky-700 dark:text-sky-400 font-medium' : ''
              )}
            >
              <div className="flex items-center gap-2 truncate">
                {option.icon}
                <span>{option.label}</span>
              </div>
              {option.badge && (
                <span className="text-2xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-1.5 py-0.5 rounded border border-slate-200 dark:border-transparent">
                  {option.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
