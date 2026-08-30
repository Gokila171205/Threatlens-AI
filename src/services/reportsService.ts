import { ThreatLensApi } from './api';
import type { SecurityReportItem } from '../data/mockAnalyticsData';

export const reportsService = {
  getSecurityReports: async (): Promise<SecurityReportItem[]> => {
    return ThreatLensApi.getSecurityReports();
  },

  createSecurityReport: async (
    title: string,
    type: SecurityReportItem['type'],
    period: string
  ): Promise<SecurityReportItem> => {
    return ThreatLensApi.createSecurityReport(title, type, period);
  },
};
