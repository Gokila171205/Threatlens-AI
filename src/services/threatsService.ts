import { ThreatLensApi } from './api';
import type {
  ActiveThreatItem,
  DetectionLogEvent,
  MalwareTrackingItem,
  SuspiciousActivityItem
} from '../data/mockMonitoringData';

export const threatsService = {
  getActiveThreats: async (): Promise<ActiveThreatItem[]> => {
    return ThreatLensApi.getActiveThreats();
  },

  getDetectionLogs: async (): Promise<DetectionLogEvent[]> => {
    return ThreatLensApi.getDetectionLogs();
  },

  getMalwareTracking: async (): Promise<MalwareTrackingItem[]> => {
    return ThreatLensApi.getMalwareTracking();
  },

  getSuspiciousTimeline: async (): Promise<SuspiciousActivityItem[]> => {
    return ThreatLensApi.getSuspiciousTimeline();
  },
};
