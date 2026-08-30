import { ThreatLensApi } from './api';
import type { MalwareClassificationDetail, MalwareFamilyCatalog } from '../data/mockClassificationData';

export const classificationService = {
  getClassificationReport: async (sampleId: string): Promise<MalwareClassificationDetail> => {
    return ThreatLensApi.getClassificationReport(sampleId);
  },

  getFamilyCatalog: async (): Promise<MalwareFamilyCatalog[]> => {
    return ThreatLensApi.getFamilyCatalog();
  },
};
