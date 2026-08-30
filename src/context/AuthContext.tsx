import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { UserRole } from '../types';
import type { UserSession, LoginCredentials } from '../types/auth';
import type { Permission } from '../types/auth';
import { AuthService } from '../services/auth';
import { hasPermission, hasAnyPermission, hasAllPermissions } from '../utils/permissions';

interface AuthContextType {
  user: UserSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (credentials: LoginCredentials) => Promise<void>;
  loginAsRole: (role: UserRole) => Promise<void>;
  logout: () => void;
  can: (permission: Permission) => boolean;
  canAny: (permissions: Permission[]) => boolean;
  canAll: (permissions: Permission[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Rehydrate session from localStorage
    const existing = AuthService.getCurrentSession();
    if (existing) {
      setUser(existing);
    }
    setIsLoading(false);
  }, []);

  const login = async (credentials: LoginCredentials) => {
    setIsLoading(true);
    setError(null);
    try {
      const session = await AuthService.login(credentials);
      setUser(session);
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Verify analyst credentials.');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const loginAsRole = async (role: UserRole) => {
    setIsLoading(true);
    setError(null);
    try {
      const session = await AuthService.loginAsRole(role);
      setUser(session);
    } catch (err: any) {
      setError(err.message || 'Persona authentication failed.');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = useCallback(() => {
    AuthService.logout();
    setUser(null);
    setError(null);
  }, []);

  const can = useCallback(
    (permission: Permission) => {
      return hasPermission(user?.role, permission);
    },
    [user?.role]
  );

  const canAny = useCallback(
    (permissions: Permission[]) => {
      return hasAnyPermission(user?.role, permissions);
    },
    [user?.role]
  );

  const canAll = useCallback(
    (permissions: Permission[]) => {
      return hasAllPermissions(user?.role, permissions);
    },
    [user?.role]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        error,
        login,
        loginAsRole,
        logout,
        can,
        canAny,
        canAll,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
