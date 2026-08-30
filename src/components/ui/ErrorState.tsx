import React from 'react';
import { clsx } from 'clsx';
import { AlertOctagon, RotateCw } from 'lucide-react';
import { Button } from './Button';

export interface ErrorStateProps {
  title?: string;
  message?: string;
  errorCode?: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Analysis Ingestion Failure',
  message = 'An unexpected telemetry interruption occurred while querying the ThreatLens AI classification service.',
  errorCode = 'ERR_DETECTION_STREAM_503',
  onRetry,
  className,
}) => {
  return (
    <div className={clsx('p-5 rounded border border-red-900/60 bg-red-950/20 flex flex-col md:flex-row items-start md:items-center justify-between gap-4', className)}>
      <div className="flex items-start gap-3">
        <div className="p-2 rounded bg-red-950/80 border border-red-800/80 text-red-400 shrink-0">
          <AlertOctagon className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h4 className="text-xs font-semibold text-red-300">{title}</h4>
            <span className="text-2xs font-mono bg-red-950 text-red-400 border border-red-800/50 px-1.5 py-0.2 rounded">
              {errorCode}
            </span>
          </div>
          <p className="text-2xs text-red-300/80 mt-1 max-w-xl">
            {message}
          </p>
        </div>
      </div>
      {onRetry && (
        <Button
          variant="danger"
          size="xs"
          leftIcon={<RotateCw className="w-3 h-3" />}
          onClick={onRetry}
        >
          Retry Request
        </Button>
      )}
    </div>
  );
};
