import { ThreatLensApi } from './api';
import type { UserProfile, UserRole } from '../types';

export const authService = {
  getCurrentUser: async (): Promise<UserProfile> => {
    return ThreatLensApi.getCurrentUser();
  },

  updateUserRole: async (role: UserRole): Promise<UserProfile> => {
    return ThreatLensApi.updateUserRole(role);
  },
};
