import { useAuthStore } from '../../store/authStore';
import { Minus, Square, X, User, LogOut, Bell } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function Header() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  // Close menus when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleWindowControl = async (action: 'minimize' | 'maximize' | 'close') => {
    if (window.electronAPI) {
      switch (action) {
        case 'minimize':
          await window.electronAPI.minimizeWindow();
          break;
        case 'maximize':
          await window.electronAPI.maximizeWindow();
          break;
        case 'close':
          await window.electronAPI.closeWindow();
          break;
      }
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header data-testid="header" className="h-10 bg-dws-darker border-b border-dws-border flex items-center justify-between px-4 titlebar-drag">
      {/* Left: App Title */}
      <div className="flex items-center gap-2 titlebar-no-drag">
        <span className="text-sm font-medium text-gray-300">
          <span className="text-joe-blue font-bold">J.O.E.</span>
          <span className="text-gray-500 mx-1">|</span>
          <span>DevSecOps Arsenal</span>
        </span>
      </div>

      {/* Center: Search (optional placeholder) */}
      <div className="flex-1 max-w-md mx-4 titlebar-no-drag">
        {/* Can add global search here */}
      </div>

      {/* Right: User & Window Controls */}
      <div className="flex items-center gap-2 titlebar-no-drag">
        {/* Notifications */}
        <div ref={notifRef} className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            data-testid="notifications-button"
            className="p-1.5 rounded hover:bg-dws-card transition-colors relative"
          >
            <Bell size={16} className="text-gray-400" />
            {/* Notification Badge */}
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-alert-critical rounded-full" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-72 bg-dws-card border border-dws-border rounded-lg shadow-xl z-50">
              <div className="p-3 border-b border-dws-border">
                <h3 className="font-semibold text-white">Notifications</h3>
              </div>
              <div className="p-3 space-y-2 max-h-64 overflow-y-auto">
                <div className="p-2 rounded bg-alert-critical/10 border border-alert-critical/20">
                  <p className="text-sm text-alert-critical font-medium">3 Critical vulnerabilities</p>
                  <p className="text-xs text-gray-400">Found in latest scan</p>
                </div>
                <div className="p-2 rounded bg-alert-warning/10 border border-alert-warning/20">
                  <p className="text-sm text-alert-warning font-medium">SBOM outdated</p>
                  <p className="text-xs text-gray-400">Last generated 7 days ago</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* User Menu */}
        <div ref={menuRef} className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            data-testid="user-menu-button"
            className="flex items-center gap-2 px-2 py-1 rounded hover:bg-dws-card transition-colors"
          >
            <div className="w-6 h-6 rounded-full bg-joe-blue/20 flex items-center justify-center">
              <User size={14} className="text-joe-blue" />
            </div>
            <span className="text-sm text-gray-300">{user?.displayName}</span>
          </button>

          {showUserMenu && (
            <div className="absolute right-0 top-full mt-2 w-56 bg-dws-card border border-dws-border rounded-lg shadow-xl z-50">
              <div className="p-3 border-b border-dws-border">
                <p className="font-medium text-white">{user?.displayName}</p>
                <p className="text-xs text-gray-400">{user?.email}</p>
                <span className={`inline-block mt-1 text-xs px-2 py-0.5 rounded-full ${
                  user?.role === 'administrator'
                    ? 'bg-joe-blue/20 text-joe-blue'
                    : 'bg-dws-green/20 text-dws-green'
                }`}>
                  {user?.role === 'administrator' ? 'Administrator' : 'Standard User'}
                </span>
              </div>
              <div className="p-2">
                <button
                  onClick={handleLogout}
                  data-testid="logout-button"
                  className="w-full flex items-center gap-2 px-3 py-2 rounded text-left text-gray-300 hover:bg-dws-elevated transition-colors"
                >
                  <LogOut size={16} />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Window Controls (Windows style) */}
        <div className="flex items-center ml-2 border-l border-dws-border pl-2">
          <button
            onClick={() => handleWindowControl('minimize')}
            data-testid="window-minimize-button"
            className="p-1.5 rounded hover:bg-dws-card transition-colors"
            title="Minimize"
          >
            <Minus size={14} className="text-gray-400" />
          </button>
          <button
            onClick={() => handleWindowControl('maximize')}
            data-testid="window-maximize-button"
            className="p-1.5 rounded hover:bg-dws-card transition-colors"
            title="Maximize"
          >
            <Square size={12} className="text-gray-400" />
          </button>
          <button
            onClick={() => handleWindowControl('close')}
            data-testid="window-close-button"
            className="p-1.5 rounded hover:bg-alert-critical transition-colors"
            title="Close"
          >
            <X size={14} className="text-gray-400 hover:text-white" />
          </button>
        </div>
      </div>
    </header>
  );
}
