import { ThreatLensApi } from './api';
import type { AlertDetailItem } from '../data/mockAlertsData';
import type { SocAlert } from '../types';

export const alertsService = {
  getDetailedAlerts: async (): Promise<AlertDetailItem[]> => {
    return ThreatLensApi.getDetailedAlerts();
  },

  updateAlertStatus: async (alertId: string, newStatus: AlertDetailItem['status']): Promise<AlertDetailItem> => {
    return ThreatLensApi.updateAlertStatus(alertId, newStatus);
  },

  assignAlertAnalyst: async (alertId: string, analystName: string): Promise<AlertDetailItem> => {
    return ThreatLensApi.assignAlertAnalyst(alertId, analystName);
  },

  getAlerts: async (): Promise<SocAlert[]> => {
    return ThreatLensApi.getAlerts();
  },
};
