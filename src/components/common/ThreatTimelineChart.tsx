import React, { useState } from 'react';
import type { TimeSeriesPoint } from '../../data/mockDashboardData';

export interface ThreatTimelineChartProps {
  data: TimeSeriesPoint[];
}

export const ThreatTimelineChart: React.FC<ThreatTimelineChartProps> = ({ data }) => {
  const [hoveredPoint, setHoveredPoint] = useState<TimeSeriesPoint | null>(null);

  const maxScanned = Math.max(...data.map((d) => d.totalScanned), 1500);

  return (
    <div className="w-full space-y-2">
      {/* Legend & Hover Info */}
      <div className="flex items-center justify-between text-2xs font-mono text-slate-400">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-sky-500" />
            <span>Files Ingested</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-red-500" />
            <span>Malicious (Ransomware/C2)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-amber-500" />
            <span>Suspicious</span>
          </span>
        </div>

        {hoveredPoint ? (
          <span className="text-slate-200 font-bold bg-slate-900 border border-slate-750 px-2 py-0.5 rounded">
            [{hoveredPoint.timestamp}] Ingested: {hoveredPoint.totalScanned} | Malicious: {hoveredPoint.malicious} | Suspicious: {hoveredPoint.suspicious}
          </span>
        ) : (
          <span className="text-slate-500">Hover bar for hourly breakdown</span>
        )}
      </div>

      {/* SVG Bar Chart */}
      <div className="h-44 w-full bg-slate-950/80 border border-slate-800 rounded p-3 relative flex items-end justify-between gap-2 overflow-hidden">
        {data.map((point) => {
          const totalHeightPct = (point.totalScanned / maxScanned) * 100;
          const maliciousHeightPct = (point.malicious / point.totalScanned) * 100;
          const suspiciousHeightPct = (point.suspicious / point.totalScanned) * 100;

          return (
            <div
              key={point.timestamp}
              onMouseEnter={() => setHoveredPoint(point)}
              onMouseLeave={() => setHoveredPoint(null)}
              className="flex-1 flex flex-col items-center justify-end h-full group cursor-pointer relative"
            >
              {/* Stacked Bar Container */}
              <div className="w-full max-w-[28px] bg-slate-900/80 rounded-t overflow-hidden flex flex-col justify-end transition-all group-hover:bg-slate-850 group-hover:border-sky-500 border border-transparent" style={{ height: `${totalHeightPct}%` }}>
                {/* Malicious Fill (Red) */}
                <div
                  className="w-full bg-red-500/90 transition-all"
                  style={{ height: `${maliciousHeightPct}%` }}
                />
                {/* Suspicious Fill (Amber) */}
                <div
                  className="w-full bg-amber-500/80 transition-all"
                  style={{ height: `${suspiciousHeightPct}%` }}
                />
                {/* Clean Base (Sky) */}
                <div
                  className="w-full bg-sky-600/40 flex-1"
                />
              </div>

              {/* Time Label */}
              <span className="text-2xs font-mono text-slate-500 mt-2 group-hover:text-slate-200">
                {point.timestamp}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
