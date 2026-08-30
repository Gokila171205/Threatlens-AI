import React, { createContext, useContext, useState, useEffect } from 'react';
import type { UserProfile, UserRole, SystemNotification } from '../types';
import { ThreatLensApi } from '../services/api';

interface ThreatLensContextType {
  currentUser: UserProfile;
  activeRole: UserRole;
  setActiveRole: (role: UserRole) => Promise<void>;
  currentPath: string;
  navigate: (path: string) => void;
  notifications: SystemNotification[];
  unreadCount: number;
  markAsRead: (id: string) => void;
  isStreamLive: boolean;
  setIsStreamLive: React.Dispatch<React.SetStateAction<boolean>>;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  isSearchModalOpen: boolean;
  setIsSearchModalOpen: (open: boolean) => void;
}

const ThreatLensContext = createContext<ThreatLensContextType | undefined>(undefined);

export const ThreatLensProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<UserProfile>({
    id: 'usr_soc_9412',
    name: 'Alex Rivera',
    email: 'a.rivera@defense.threatlens.ai',
    role: 'Security Analyst',
    department: 'Global SOC Operations Tier 3',
    clearanceLevel: 'DEFCON-2 / RESTRICTED',
    lastLogin: new Date().toISOString(),
  });

  const [currentPath, setCurrentPath] = useState<string>(() => {
    return window.location.pathname !== '/' ? window.location.pathname : '/overview';
  });

  const [notifications, setNotifications] = useState<SystemNotification[]>([]);
  const [isStreamLive, setIsStreamLive] = useState<boolean>(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [isSearchModalOpen, setIsSearchModalOpen] = useState<boolean>(false);

  useEffect(() => {
    ThreatLensApi.getCurrentUser().then(setCurrentUser);
    ThreatLensApi.getNotifications().then(setNotifications);
  }, []);

  const navigate = (path: string) => {
    setCurrentPath(path);
    window.history.pushState({}, '', path);
  };

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || '/overview');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const setActiveRole = async (role: UserRole) => {
    const updated = await ThreatLensApi.updateUserRole(role);
    setCurrentUser(updated);
  };

  const markAsRead = async (id: string) => {
    await ThreatLensApi.markNotificationRead(id);
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <ThreatLensContext.Provider
      value={{
        currentUser,
        activeRole: currentUser.role,
        setActiveRole,
        currentPath,
        navigate,
        notifications,
        unreadCount,
        markAsRead,
        isStreamLive,
        setIsStreamLive,
        sidebarCollapsed,
        setSidebarCollapsed,
        isSearchModalOpen,
        setIsSearchModalOpen,
      }}
    >
      {children}
    </ThreatLensContext.Provider>
  );
};

export function useThreatLens() {
  const context = useContext(ThreatLensContext);
  if (!context) {
    throw new Error('useThreatLens must be used within a ThreatLensProvider');
  }
  return context;
}
