import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { clsx } from 'clsx';
import { formatHash } from '../../utils/formatters';

export interface MonoTextProps {
  value: string;
  truncate?: boolean;
  startLen?: number;
  endLen?: number;
  copyable?: boolean;
  highlight?: boolean;
  className?: string;
}

export const MonoText: React.FC<MonoTextProps> = ({
  value,
  truncate = false,
  startLen = 8,
  endLen = 8,
  copyable = true,
  highlight = false,
  className,
}) => {
  const [copied, setCopied] = useState(false);

  const displayValue = truncate ? formatHash(value, startLen, endLen) : value;

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 font-mono text-2xs px-1.5 py-0.5 rounded transition-colors group select-all',
        highlight
          ? 'bg-sky-950/60 text-sky-300 border border-sky-800/60'
          : 'bg-slate-900 text-slate-300 border border-slate-800/80',
        className
      )}
      title={value}
    >
      <span className="truncate">{displayValue}</span>
      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          className="opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity text-slate-400 hover:text-slate-200"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="w-3 h-3 text-emerald-400" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
        </button>
      )}
    </span>
  );
};
