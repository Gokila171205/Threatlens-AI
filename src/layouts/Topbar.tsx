import React, { useState, useRef, useEffect } from 'react';
import {
  Search,
  Bell,
  Radio,
  ChevronDown,
  Shield,
  CheckCircle,
  LogOut,
  User,
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { useAuth } from '../context/AuthContext';
import { getRouteTitle, getRouteDescription } from '../routes/routes';
import type { UserRole } from '../types';
import { formatRelativeTime } from '../utils/formatters';

const ALL_ROLES: UserRole[] = [
  'Security Analyst',
  'SOC Team Member',
  'Administrator',
  'Researcher'
];

export const Topbar: React.FC = () => {
  const {
    currentPath,
    notifications,
    unreadCount,
    markAsRead,
    isStreamLive,
    setIsStreamLive,
    setIsSearchModalOpen,
    navigate
  } = useThreatLens();

  const { user, logout, loginAsRole } = useAuth();

  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const [notifDropdownOpen, setNotifDropdownOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);

  const roleMenuRef = useRef<HTMLDivElement>(null);
  const notifMenuRef = useRef<HTMLDivElement>(null);
  const profileMenuRef = useRef<HTMLDivElement>(null);

  const pageTitle = getRouteTitle(currentPath);
  const pageDesc = getRouteDescription(currentPath);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (roleMenuRef.current && !roleMenuRef.current.contains(event.target as Node)) {
        setRoleDropdownOpen(false);
      }
      if (notifMenuRef.current && !notifMenuRef.current.contains(event.target as Node)) {
        setNotifDropdownOpen(false);
      }
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setProfileMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-13 border-b border-slate-800 bg-slate-950/90 sticky top-0 z-20 px-4 flex items-center justify-between gap-4 backdrop-blur-sm">
      {/* Left: Breadcrumbs & Page Description */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex flex-col">
          <div className="flex items-center gap-2 text-2xs font-mono text-slate-500">
            <span className="hover:text-slate-400 cursor-pointer">ThreatLens AI</span>
            <span>/</span>
            <span className="text-slate-300 font-semibold">{pageTitle}</span>
          </div>
          <span className="text-xs font-semibold text-slate-100 truncate tracking-tight">
            {pageDesc}
          </span>
        </div>
      </div>

      {/* Center/Right: Actions & Controls */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Global Quick Search Button */}
        <button
          type="button"
          onClick={() => setIsSearchModalOpen(true)}
          className="hidden md:flex items-center gap-2 bg-slate-900 border border-slate-800 hover:border-slate-700 px-3 py-1.5 rounded text-xs text-slate-400 hover:text-slate-200 transition-colors w-64 justify-between"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-2xs font-mono text-slate-400">Search hashes, IOCs, CVEs...</span>
          </div>
          <kbd className="text-2xs font-mono bg-slate-950 text-slate-400 border border-slate-800 px-1.5 py-0.2 rounded">
            Ctrl+K
          </kbd>
        </button>

        {/* Live Stream Telemetry Toggle */}
        <button
          type="button"
          onClick={() => setIsStreamLive(!isStreamLive)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-2xs font-mono border transition-colors ${
            isStreamLive
              ? 'bg-emerald-950/50 border-emerald-800 text-emerald-400'
              : 'bg-slate-900 border-slate-800 text-slate-500 hover:text-slate-300'
          }`}
          title="Toggle live telemetry feed"
        >
          <Radio className={`w-3 h-3 ${isStreamLive ? 'animate-pulse text-emerald-400' : 'text-slate-500'}`} />
          <span className="font-semibold">{isStreamLive ? 'INGEST LIVE' : 'INGEST PAUSED'}</span>
        </button>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notifMenuRef}>
          <button
            type="button"
            onClick={() => setNotifDropdownOpen(!notifDropdownOpen)}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-slate-800/80 relative transition-colors"
            title="System & Threat Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-600 text-white rounded-full text-2xs font-mono flex items-center justify-center font-bold">
                {unreadCount}
              </span>
            )}
          </button>

          {notifDropdownOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-800 rounded shadow-2xl py-1 z-50 animate-in fade-in-50 duration-100">
              <div className="px-3 py-2 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200 uppercase font-mono">
                  System Intelligence Feed
                </span>
                <span className="text-2xs text-slate-500 font-mono">
                  {unreadCount} unread
                </span>
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-850">
                {notifications.length === 0 ? (
                  <div className="p-4 text-center text-xs text-slate-500">
                    No new intelligence alerts
                  </div>
                ) : (
                  notifications.map((notif) => (
                    <div
                      key={notif.id}
                      onClick={() => markAsRead(notif.id)}
                      className={`p-3 text-left hover:bg-slate-850/60 cursor-pointer transition-colors ${
                        !notif.read ? 'bg-sky-950/20' : ''
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <h4 className="text-xs font-medium text-slate-200">{notif.title}</h4>
                        {!notif.read && (
                          <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                        )}
                      </div>
                      <p className="text-2xs text-slate-400 mt-1 line-clamp-2">
                        {notif.message}
                      </p>
                      <span className="text-2xs text-slate-500 font-mono mt-1.5 block">
                        {formatRelativeTime(notif.timestamp)}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Role Switcher Dropdown */}
        <div className="relative" ref={roleMenuRef}>
          <button
            type="button"
            onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs text-slate-200 transition-colors"
          >
            <Shield className="w-3.5 h-3.5 text-sky-400" />
            <div className="flex flex-col text-left">
              <span className="text-2xs text-slate-500 leading-none">Role</span>
              <span className="text-xs font-semibold leading-tight">{user?.role || 'Guest'}</span>
            </div>
            <ChevronDown className={`w-3.5 h-3.5 text-slate-500 transition-transform ${roleDropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          {roleDropdownOpen && (
            <div className="absolute right-0 mt-2 w-52 bg-slate-900 border border-slate-750 rounded shadow-2xl py-1 z-50">
              <div className="px-3 py-1.5 text-2xs text-slate-500 uppercase font-mono border-b border-slate-800 font-medium">
                Switch Operational Role
              </div>
              {ALL_ROLES.map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => {
                    loginAsRole(r);
                    setRoleDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs text-left transition-colors ${
                    user?.role === r
                      ? 'bg-sky-950/70 text-sky-400 font-semibold'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <span>{r}</span>
                  {user?.role === r && <CheckCircle className="w-3.5 h-3.5 text-sky-400" />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Profile & Session Dropdown Menu */}
        <div className="relative pl-2 border-l border-slate-800" ref={profileMenuRef}>
          <button
            type="button"
            onClick={() => setProfileMenuOpen(!profileMenuOpen)}
            className="flex items-center gap-2 text-left hover:opacity-90 transition-opacity"
          >
            <div className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-mono text-xs font-semibold">
              {user?.avatarInitials || 'AR'}
            </div>
            <div className="hidden xl:flex flex-col">
              <span className="text-xs font-medium text-slate-200">{user?.name || 'Alex Rivera'}</span>
              <span className="text-2xs font-mono text-emerald-400">{user?.clearanceLevel || 'DEFCON-2'}</span>
            </div>
          </button>

          {profileMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-750 rounded shadow-2xl py-1 z-50 animate-in fade-in-50 duration-100">
              <div className="px-3 py-2 border-b border-slate-800">
                <p className="text-xs font-semibold text-slate-100">{user?.name}</p>
                <p className="text-2xs text-slate-400 font-mono truncate">{user?.email}</p>
                <span className="text-2xs text-emerald-400 font-mono font-bold mt-1 block">
                  ● {user?.role}
                </span>
              </div>
              <div className="py-1">
                <button
                  type="button"
                  onClick={() => {
                    setProfileMenuOpen(false);
                    navigate('/profile');
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 text-left"
                >
                  <User className="w-3.5 h-3.5 text-sky-400" />
                  <span>Analyst Profile & Keys</span>
                </button>
              </div>
              <div className="border-t border-slate-800 pt-1">
                <button
                  type="button"
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400 hover:bg-red-950/40 text-left font-medium"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out Session</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
