import { ThreatLensApi } from './api';
import type { StaticAnalysisReport } from '../data/mockStaticAnalysisData';

export const analysisService = {
  getStaticAnalysisReport: async (filename: string): Promise<StaticAnalysisReport> => {
    return ThreatLensApi.getStaticAnalysisReport(filename);
  },
};
