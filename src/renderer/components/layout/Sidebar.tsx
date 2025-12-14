import { NavLink, useLocation } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import {
  LayoutDashboard,
  ShieldAlert,
  Package,
  ClipboardCheck,
  GitBranch,
  Bot,
  FileText,
  Settings,
  Users,
  ChevronLeft,
  ChevronRight,
  Rocket,
  Container,
  GitlabIcon,
  Target,
  Crosshair,
  Satellite,
  Brain,
  Cloud,
  Globe,
  Link2,
  Bell
} from 'lucide-react';
import { useState } from 'react';

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/findings', label: 'Security Findings', icon: ShieldAlert },
  { path: '/threat-intel', label: 'Threat Intelligence', icon: Target },
  { path: '/iac-security', label: 'IaC Security', icon: Cloud },
  { path: '/api-security', label: 'API Security', icon: Globe },
  { path: '/kubernetes', label: 'Kubernetes Security', icon: Container },
  { path: '/gitlab', label: 'GitLab Security', icon: GitlabIcon },
  { path: '/supply-chain', label: 'Supply Chain', icon: Package },
  { path: '/compliance', label: 'Compliance', icon: ClipboardCheck },
  { path: '/space-compliance', label: 'Space-Grade', icon: Satellite },
  { path: '/pipeline', label: 'Pipeline Security', icon: GitBranch },
  { path: '/ai-assistant', label: 'AI Assistant', icon: Bot },
  { path: '/mission-control', label: 'Mission Control', icon: Rocket },
  { path: '/attack-surface', label: 'Attack Surface', icon: Crosshair },
  { path: '/integrations', label: 'Integrations', icon: Link2 },
  { path: '/analytics', label: 'Analytics', icon: Brain },
  { path: '/reports', label: 'Reports', icon: FileText }
];

const bottomNavItems = [
  { path: '/settings', label: 'Settings', icon: Settings },
  { path: '/admin', label: 'User Management', icon: Users, adminOnly: true }
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const { user } = useAuthStore();
  const location = useLocation();

  return (
    <aside
      className={`
        ${collapsed ? 'w-20' : 'w-64'}
        h-full bg-dws-darker border-r border-dws-border
        flex flex-col transition-all duration-300 ease-in-out
      `}
    >
      {/* Logo Section */}
      <div className="p-4 border-b border-dws-border">
        {/* Official Dark Wolf Solutions Logo */}
        <div className={`flex items-center ${collapsed ? 'justify-center' : ''}`}>
          <img
            src="/src/renderer/assets/dark-wolf-logo.png"
            alt="Dark Wolf Solutions"
            className={`${collapsed ? 'w-12 h-auto' : 'w-full max-w-[180px] h-auto'} object-contain`}
          />
        </div>

        {/* J.O.E. Title */}
        {!collapsed && (
          <div className="mt-4 pl-1">
            <span className="font-heading font-bold text-joe-blue text-sm">J.O.E.</span>
            <span className="text-xs text-gray-500 ml-1">DevSecOps Arsenal</span>
          </div>
        )}
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto scrollbar-hide">
        {navItems.map(({ path, label, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200
              ${isActive
                ? 'bg-joe-blue/10 text-joe-blue border-l-2 border-joe-blue -ml-px'
                : 'text-gray-400 hover:bg-dws-card hover:text-white'
              }
              ${collapsed ? 'justify-center' : ''}`
            }
            title={collapsed ? label : undefined}
          >
            <Icon size={20} className="flex-shrink-0" />
            {!collapsed && <span className="font-medium">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Bottom Navigation */}
      <div className="py-4 px-3 border-t border-dws-border space-y-1">
        {bottomNavItems.map(({ path, label, icon: Icon, adminOnly }) => {
          // Hide admin-only items for non-admins
          if (adminOnly && user?.role !== 'administrator') return null;

          return (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200
                ${isActive
                  ? 'bg-joe-blue/10 text-joe-blue border-l-2 border-joe-blue -ml-px'
                  : 'text-gray-400 hover:bg-dws-card hover:text-white'
                }
                ${collapsed ? 'justify-center' : ''}`
              }
              title={collapsed ? label : undefined}
            >
              <Icon size={20} className="flex-shrink-0" />
              {!collapsed && <span className="font-medium">{label}</span>}
            </NavLink>
          );
        })}

        {/* Collapse Toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={`
            flex items-center gap-3 px-3 py-2.5 rounded-lg w-full
            text-gray-500 hover:bg-dws-card hover:text-white transition-all duration-200
            ${collapsed ? 'justify-center' : ''}
          `}
        >
          {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
          {!collapsed && <span className="font-medium">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
