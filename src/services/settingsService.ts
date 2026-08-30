import { ThreatLensApi } from './api';
import type { PlatformIntegration, PlatformAuditLog } from '../data/mockAdminData';

export const settingsService = {
  getIntegrations: async (): Promise<PlatformIntegration[]> => {
    return ThreatLensApi.getIntegrations();
  },

  getAuditLogs: async (): Promise<PlatformAuditLog[]> => {
    return ThreatLensApi.getAuditLogs();
  },
};
