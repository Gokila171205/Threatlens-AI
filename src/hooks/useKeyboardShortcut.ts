import { useEffect } from 'react';

export function useKeyboardShortcut(key: string, callback: () => void, ctrlOrCmd = false) {
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const isCtrlOrCmd = event.ctrlKey || event.metaKey;
      if (ctrlOrCmd) {
        if (isCtrlOrCmd && event.key.toLowerCase() === key.toLowerCase()) {
          event.preventDefault();
          callback();
        }
      } else {
        if (event.key.toLowerCase() === key.toLowerCase() && !(event.target as HTMLElement)?.matches('input, textarea')) {
          callback();
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [key, callback, ctrlOrCmd]);
}
