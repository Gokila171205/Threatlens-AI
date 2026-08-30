import React from 'react';
import { clsx } from 'clsx';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
  icon?: React.ReactNode;
}

export interface TabsProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (tabId: string) => void;
  className?: string;
}

export const Tabs: React.FC<TabsProps> = ({
  tabs,
  activeTab,
  onChange,
  className,
}) => {
  return (
    <div className={clsx('flex items-center border-b border-slate-800 gap-1 px-1 bg-slate-950/40', className)}>
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={clsx(
              'inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium border-b-2 -mb-px transition-colors select-none',
              isActive
                ? 'border-sky-500 text-sky-400 bg-slate-900/60'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            )}
          >
            {tab.icon && <span className="w-3.5 h-3.5 flex items-center">{tab.icon}</span>}
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={clsx(
                  'px-1.5 py-0.2 text-2xs rounded-full font-mono',
                  isActive
                    ? 'bg-sky-950 text-sky-300 border border-sky-800/80'
                    : 'bg-slate-800 text-slate-400'
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
