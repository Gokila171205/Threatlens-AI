import React from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { ThreatLensProvider, useThreatLens } from './context/ThreatLensContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './components/ui/Toast';
import { AppLayout } from './layouts/AppLayout';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { FileAnalysisPage } from './pages/FileAnalysisPage';
import { MalwareClassificationPage } from './pages/MalwareClassificationPage';
import { ThreatMonitoringPage } from './pages/ThreatMonitoringPage';
import { AlertsPage } from './pages/AlertsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { ReportsPage } from './pages/ReportsPage';
import { ResearchPage } from './pages/ResearchPage';
import { AdminPage } from './pages/AdminPage';
import { ProfilePage } from './pages/ProfilePage';
import { UnauthorizedPage } from './pages/UnauthorizedPage';
import { ROUTES, ROUTE_PERMISSIONS } from './routes/routes';
import { LoadingState } from './components/ui/LoadingState';

const RouteDispatcher: React.FC = () => {
  const { currentPath } = useThreatLens();
  const { isAuthenticated, isLoading, can } = useAuth();

  // If loading auth state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-threat-bg text-threat-text flex items-center justify-center">
        <LoadingState
          message="Verifying ThreatLens Security Session..."
          description="Authenticating JWT signature and evaluating RBAC permissions"
        />
      </div>
    );
  }

  // If on login route or unauthenticated
  if (currentPath === ROUTES.LOGIN || !isAuthenticated) {
    return <LoginPage />;
  }

  // Permission check helper
  const renderProtectedRoute = (Component: React.ComponentType, path: string) => {
    const requiredPermission = ROUTE_PERMISSIONS[path];
    if (requiredPermission && !can(requiredPermission)) {
      return (
        <UnauthorizedPage
          requiredPermission={requiredPermission}
          moduleName={path.substring(1).replace('-', ' ').toUpperCase()}
        />
      );
    }
    return <Component />;
  };

  const renderContent = () => {
    if (currentPath === ROUTES.OVERVIEW || currentPath === '/') {
      return renderProtectedRoute(OverviewPage, ROUTES.OVERVIEW);
    }
    if (currentPath.startsWith(ROUTES.FILE_ANALYSIS)) {
      return renderProtectedRoute(FileAnalysisPage, ROUTES.FILE_ANALYSIS);
    }
    if (currentPath === ROUTES.MALWARE_CLASSIFICATION) {
      return renderProtectedRoute(MalwareClassificationPage, ROUTES.MALWARE_CLASSIFICATION);
    }
    if (currentPath === ROUTES.THREAT_MONITORING) {
      return renderProtectedRoute(ThreatMonitoringPage, ROUTES.THREAT_MONITORING);
    }
    if (currentPath === ROUTES.ALERTS) {
      return renderProtectedRoute(AlertsPage, ROUTES.ALERTS);
    }
    if (currentPath === ROUTES.ANALYTICS) {
      return renderProtectedRoute(AnalyticsPage, ROUTES.ANALYTICS);
    }
    if (currentPath === ROUTES.REPORTS) {
      return renderProtectedRoute(ReportsPage, ROUTES.REPORTS);
    }
    if (currentPath === ROUTES.RESEARCH) {
      return renderProtectedRoute(ResearchPage, ROUTES.RESEARCH);
    }
    if (currentPath === ROUTES.ADMIN) {
      return renderProtectedRoute(AdminPage, ROUTES.ADMIN);
    }
    if (currentPath === ROUTES.PROFILE) {
      return <ProfilePage />;
    }

    // Default fallback to Overview
    return renderProtectedRoute(OverviewPage, ROUTES.OVERVIEW);
  };

  return <AppLayout>{renderContent()}</AppLayout>;
};

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ThreatLensProvider>
          <ToastProvider>
            <RouteDispatcher />
          </ToastProvider>
        </ThreatLensProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
