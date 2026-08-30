import { ThreatLensApi } from './api';
import type { AdminUserItem } from '../data/mockAdminData';
import type { UserRole } from '../types';

export const usersService = {
  getAdminUsers: async (): Promise<AdminUserItem[]> => {
    return ThreatLensApi.getAdminUsers();
  },

  updateAdminUserRole: async (userId: string, newRole: UserRole): Promise<AdminUserItem> => {
    return ThreatLensApi.updateAdminUserRole(userId, newRole);
  },

  toggleAdminUserStatus: async (userId: string): Promise<AdminUserItem> => {
    return ThreatLensApi.toggleAdminUserStatus(userId);
  },
};
