import React from 'react';
import { clsx } from 'clsx';
import { ChevronDown, ChevronUp } from 'lucide-react';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  render?: (item: T, index: number) => React.ReactNode;
  width?: string;
  align?: 'left' | 'center' | 'right';
  sortable?: boolean;
  className?: string;
}

export interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T, index: number) => string | number;
  onRowClick?: (item: T) => void;
  selectedId?: string | number;
  sortColumn?: string;
  sortDirection?: 'asc' | 'desc';
  onSort?: (columnKey: string) => void;
  isLoading?: boolean;
  emptyMessage?: string;
  className?: string;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  selectedId,
  sortColumn,
  sortDirection,
  onSort,
  isLoading,
  emptyMessage = 'No records found matching criteria',
  className,
}: TableProps<T>) {
  return (
    <div className={clsx('w-full overflow-x-auto border border-slate-200 dark:border-slate-800 rounded bg-white dark:bg-slate-950/60 shadow-2xs', className)}>
      <table className="w-full text-left border-collapse soc-table">
        <thead>
          <tr>
            {columns.map((col) => {
              const isSorted = sortColumn === col.key;
              return (
                <th
                  key={col.key}
                  style={{ width: col.width }}
                  className={clsx(
                    col.sortable ? 'cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800/80 transition-colors' : '',
                    col.align === 'center' ? 'text-center' : col.align === 'right' ? 'text-right' : 'text-left',
                    col.className
                  )}
                  onClick={() => col.sortable && onSort?.(col.key)}
                >
                  <div className={clsx(
                    'inline-flex items-center gap-1.5',
                    col.align === 'center' ? 'justify-center w-full' : col.align === 'right' ? 'justify-end w-full' : ''
                  )}>
                    <span>{col.header}</span>
                    {col.sortable && (
                      <span className="text-slate-400 dark:text-slate-500 inline-flex flex-col">
                        {isSorted && sortDirection === 'asc' ? (
                          <ChevronUp className="w-3 h-3 text-sky-600 dark:text-sky-400" />
                        ) : isSorted && sortDirection === 'desc' ? (
                          <ChevronDown className="w-3 h-3 text-sky-600 dark:text-sky-400" />
                        ) : (
                          <ChevronDown className="w-3 h-3 opacity-40" />
                        )}
                      </span>
                    )}
                  </div>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-900/60">
          {isLoading ? (
            <tr>
              <td colSpan={columns.length} className="py-12 text-center text-slate-500">
                <div className="flex flex-col items-center justify-center gap-2">
                  <div className="w-5 h-5 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
                  <span className="text-xs font-mono">Streaming records...</span>
                </div>
              </td>
            </tr>
          ) : data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="py-12 text-center text-slate-500 text-xs">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((item, idx) => {
              const rowId = keyExtractor(item, idx);
              const isSelected = selectedId !== undefined && selectedId === rowId;
              return (
                <tr
                  key={rowId}
                  onClick={() => onRowClick?.(item)}
                  className={clsx(
                    'transition-colors text-slate-800 dark:text-slate-300',
                    onRowClick ? 'cursor-pointer' : '',
                    isSelected ? 'bg-sky-50 dark:bg-sky-950/40 border-l-2 border-l-sky-500' : 'hover:bg-slate-50 dark:hover:bg-slate-900/50'
                  )}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={clsx(
                        col.align === 'center' ? 'text-center' : col.align === 'right' ? 'text-right' : 'text-left',
                        col.className
                      )}
                    >
                      {col.render ? col.render(item, idx) : (item as Record<string, any>)[col.key]}
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
