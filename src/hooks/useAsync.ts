import { useState, useCallback, useEffect } from 'react';
import { ApiError } from '../services/httpClient';

export interface UseAsyncState<T> {
  data: T | null;
  isLoading: boolean;
  error: ApiError | null;
}

export function useAsync<T>(
  asyncFunction: () => Promise<T>,
  immediate = true
): UseAsyncState<T> & { execute: () => Promise<T | null> } {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(immediate);
  const [error, setError] = useState<ApiError | null>(null);

  const execute = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await asyncFunction();
      setData(response);
      setIsLoading(false);
      return response;
    } catch (err) {
      const apiErr =
        err instanceof ApiError
          ? err
          : new ApiError(500, 'An unexpected threat platform error occurred.', 'ERR_UNKNOWN');
      setError(apiErr);
      setIsLoading(false);
      return null;
    }
  }, [asyncFunction]);

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [execute, immediate]);

  return { data, isLoading, error, execute };
}
