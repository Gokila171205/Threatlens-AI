import { ThreatLensApi } from './api';
import type { MalwareSample } from '../types';

export const filesService = {
  submitFileForAnalysis: async (file: File): Promise<{ taskId: string; estimatedTimeSec: number }> => {
    return ThreatLensApi.submitFileForAnalysis(file);
  },

  getSamples: async (): Promise<MalwareSample[]> => {
    return ThreatLensApi.getSamples();
  },

  getSampleById: async (id: string): Promise<MalwareSample | undefined> => {
    return ThreatLensApi.getSampleById(id);
  },
};
