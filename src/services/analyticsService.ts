import { ThreatLensApi } from './api';

export const analyticsService = {
  getAnalyticsSummary: async () => {
    return ThreatLensApi.getAnalyticsSummary();
  },
};
