import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import Shell from './components/layout/Shell';
import LoginView from './views/LoginView';
import DashboardView from './views/DashboardView';
import FindingsView from './views/FindingsView';
import ThreatIntelView from './views/ThreatIntelView';
import KubernetesView from './views/KubernetesView';
import GitLabView from './views/GitLabView';
import SupplyChainView from './views/SupplyChainView';
import ComplianceView from './views/ComplianceView';
import SpaceComplianceView from './views/SpaceComplianceView';
import PipelineView from './views/PipelineView';
import AiAssistantView from './views/AiAssistantView';
import ReportsView from './views/ReportsView';
import SettingsView from './views/SettingsView';
import AdminView from './views/AdminView';
import MissionControlView from './views/MissionControlView';
import AttackSurfaceView from './views/AttackSurfaceView';
import AnalyticsView from './views/AnalyticsView';
import IaCSecurityView from './views/IaCSecurityView';
import APISecurityView from './views/APISecurityView';
import IntegrationsView from './views/IntegrationsView';
import PasswordChangeModal from './components/PasswordChangeModal';

// AI Touchpoint System - Space-Grade Security Intelligence
import { AITouchpointProvider } from './components/ai-touchpoint';

// Protected Route wrapper
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, requirePasswordChange } = useAuthStore();

  if (isLoading) {
    return (
      <div className="h-screen w-screen bg-dws-darker flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-joe-blue border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading J.O.E. Arsenal...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Force password change if required (DoD compliance)
  if (requirePasswordChange) {
    return <PasswordChangeModal />;
  }

  return <>{children}</>;
}

// Admin Route wrapper
function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuthStore();

  if (user?.role !== 'administrator') {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <AITouchpointProvider>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<LoginView />} />

      {/* Protected Routes */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Shell />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardView />} />
        <Route path="findings" element={<FindingsView />} />
        <Route path="threat-intel" element={<ThreatIntelView />} />
        <Route path="iac-security" element={<IaCSecurityView />} />
        <Route path="api-security" element={<APISecurityView />} />
        <Route path="kubernetes" element={<KubernetesView />} />
        <Route path="gitlab" element={<GitLabView />} />
        <Route path="supply-chain" element={<SupplyChainView />} />
        <Route path="compliance" element={<ComplianceView />} />
        <Route path="space-compliance" element={<SpaceComplianceView />} />
        <Route path="pipeline" element={<PipelineView />} />
        <Route path="ai-assistant" element={<AiAssistantView />} />
        <Route path="mission-control" element={<MissionControlView />} />
        <Route path="attack-surface" element={<AttackSurfaceView />} />
        <Route path="integrations" element={<IntegrationsView />} />
        <Route path="analytics" element={<AnalyticsView />} />
        <Route path="reports" element={<ReportsView />} />
        <Route path="settings" element={<SettingsView />} />

        {/* Admin Only Routes */}
        <Route
          path="admin"
          element={
            <AdminRoute>
              <AdminView />
            </AdminRoute>
          }
        />
      </Route>

        {/* Catch all */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AITouchpointProvider>
  );
}
