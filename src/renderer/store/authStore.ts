import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// SECURITY: Clear any persisted auth state on app load
// This ensures users must always authenticate on app start
if (typeof window !== 'undefined') {
  const storedAuth = localStorage.getItem('joe-auth-storage');
  if (storedAuth) {
    try {
      const parsed = JSON.parse(storedAuth);
      // Clear authentication-related fields but keep settings
      if (parsed.state) {
        parsed.state.user = null;
        parsed.state.token = null;
        parsed.state.isAuthenticated = false;
        localStorage.setItem('joe-auth-storage', JSON.stringify(parsed));
      }
    } catch {
      // If parsing fails, remove entirely
      localStorage.removeItem('joe-auth-storage');
    }
  }
}

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: 'administrator' | 'standard';
  email?: string;
  createdAt: string;
  lastLogin?: string;
  requirePasswordChange?: boolean;
  phone?: string;
}

// PIN authentication storage
const PIN_STORAGE_KEY = 'joe-pin-auth';
const REMEMBERED_USER_KEY = 'joe-remembered-user';

interface PinAuthData {
  pin: string;
  username: string;
  setupAt: number;
}

// Get stored PIN data
const getStoredPinData = (): PinAuthData | null => {
  try {
    const data = localStorage.getItem(PIN_STORAGE_KEY);
    if (data) {
      return JSON.parse(data);
    }
  } catch {
    // Invalid data
  }
  return null;
};

// Get remembered user for PIN login
const getRememberedUser = (): User | null => {
  try {
    const data = localStorage.getItem(REMEMBERED_USER_KEY);
    if (data) {
      return JSON.parse(data);
    }
  } catch {
    // Invalid data
  }
  return null;
};

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  requirePasswordChange: boolean;
  passwordExpiresAt: string | null;

  // 2FA state
  require2FA: boolean;
  pending2FAPhone: string | null;
  pending2FAUsername: string | null;
  twoFactorEnabled: boolean;

  // PIN state
  hasPinSetup: boolean;
  rememberedUser: User | null;

  // Actions
  login: (username: string, password: string) => Promise<boolean | 'require2FA'>;
  loginWithPin: (pin: string) => Promise<boolean>;
  verify2FA: (code: string) => Promise<boolean>;
  logout: () => void;
  changePassword: (oldPassword: string, newPassword: string) => Promise<boolean>;
  setupPin: (pin: string) => void;
  clearPin: () => void;
  setup2FA: () => Promise<{ success: boolean; message?: string; qrCode?: string; secret?: string }>;
  confirm2FASetup: (code: string) => Promise<{ success: boolean; message?: string }>;
  disable2FA: () => Promise<boolean>;
  get2FAStatus: () => Promise<{ enabled: boolean; phone?: string | null }>;
  setUser: (user: User | null) => void;
  setLoading: (loading: boolean) => void;
  clearError: () => void;
  clearPasswordChangeRequirement: () => void;
  clear2FARequirement: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      requirePasswordChange: false,
      passwordExpiresAt: null,

      // 2FA state
      require2FA: false,
      pending2FAPhone: null,
      pending2FAUsername: null,
      twoFactorEnabled: false,

      // PIN state - initialize from localStorage
      hasPinSetup: !!getStoredPinData(),
      rememberedUser: getRememberedUser(),

      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null, require2FA: false });

        try {
          // Use Electron IPC for authentication
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.login(username, password);

            // Check if 2FA is required
            if (result.require2FA) {
              set({
                isLoading: false,
                require2FA: true,
                pending2FAPhone: result.phone || null,
                pending2FAUsername: username,
                error: null
              });
              return 'require2FA';
            }

            if (result.success && result.user) {
              const user = {
                ...result.user,
                displayName: (result.user as { name?: string; displayName?: string }).name || (result.user as { displayName?: string }).displayName,
                role: (result.user as { role: string }).role === 'admin' ? 'administrator' : (result.user as { role: string }).role
              } as User;

              set({
                user,
                token: 'session-' + Date.now(),
                isAuthenticated: true,
                isLoading: false,
                error: null,
                requirePasswordChange: result.requirePasswordChange || false,
                twoFactorEnabled: result.twoFactorEnabled || false,
                require2FA: false,
                pending2FAPhone: null,
                pending2FAUsername: null
              });
              return true;
            } else {
              set({
                isLoading: false,
                error: result.error || 'Login failed'
              });
              return false;
            }
          } else {
            // Development fallback - simulate login with persistent credentials
            const storedCredentials = localStorage.getItem('joe-dev-credentials');
            const devCredentials: Record<string, { hash: string; changed: boolean; passwordChangedAt?: number }> = storedCredentials
              ? JSON.parse(storedCredentials)
              : {
                  'mhoch': { hash: btoa('darkwolf'), changed: false, passwordChangedAt: 0 },
                  'jscholer': { hash: btoa('darkwolf'), changed: false, passwordChangedAt: 0 }
                };

            const devUsers: Record<string, User> = {
              'mhoch': {
                id: '1',
                username: 'mhoch',
                displayName: 'Michael Hoch',
                role: 'administrator',
                email: 'michael.hoch@darkwolfsolutions.com',
                createdAt: new Date().toISOString(),
                phone: '+12569980887'
              },
              'jscholer': {
                id: '2',
                username: 'jscholer',
                displayName: 'Joseph Scholer',
                role: 'standard',
                email: 'joseph.scholer@darkwolfsolutions.com',
                createdAt: new Date().toISOString()
              }
            };

            const userKey = username.toLowerCase();
            const userCreds = devCredentials[userKey];
            const user = devUsers[userKey];

            if (user && userCreds && userCreds.hash === btoa(password)) {
              // Check password expiration (30 days)
              const thirtyDays = 30 * 24 * 60 * 60 * 1000;
              const passwordExpired = userCreds.passwordChangedAt
                ? Date.now() - userCreds.passwordChangedAt > thirtyDays
                : true; // Never changed = require change

              set({
                user,
                token: 'dev-token-' + Date.now(),
                isAuthenticated: true,
                isLoading: false,
                error: null,
                requirePasswordChange: !userCreds.changed || passwordExpired
              });
              return true;
            } else {
              set({
                isLoading: false,
                error: 'Invalid username or password'
              });
              return false;
            }
          }
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : 'Login failed'
          });
          return false;
        }
      },

      loginWithPin: async (pin: string) => {
        set({ isLoading: true, error: null });

        try {
          const storedPinData = getStoredPinData();
          const rememberedUser = getRememberedUser();

          if (!storedPinData || !rememberedUser) {
            set({ isLoading: false, error: 'No PIN configured. Please login with password.' });
            return false;
          }

          if (storedPinData.pin !== pin) {
            set({ isLoading: false, error: 'Invalid PIN' });
            return false;
          }

          // PIN is valid - authenticate the user
          set({
            user: rememberedUser,
            token: 'pin-session-' + Date.now(),
            isAuthenticated: true,
            isLoading: false,
            error: null,
            requirePasswordChange: false
          });

          return true;
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : 'PIN login failed'
          });
          return false;
        }
      },

      setupPin: (pin: string) => {
        const currentUser = get().user;
        if (!currentUser) {return;}

        // Store PIN data
        const pinData: PinAuthData = {
          pin,
          username: currentUser.username,
          setupAt: Date.now()
        };
        localStorage.setItem(PIN_STORAGE_KEY, JSON.stringify(pinData));

        // Store remembered user
        localStorage.setItem(REMEMBERED_USER_KEY, JSON.stringify(currentUser));

        set({
          hasPinSetup: true,
          rememberedUser: currentUser
        });
      },

      clearPin: () => {
        localStorage.removeItem(PIN_STORAGE_KEY);
        localStorage.removeItem(REMEMBERED_USER_KEY);
        set({
          hasPinSetup: false,
          rememberedUser: null
        });
      },

      verify2FA: async (code: string) => {
        set({ isLoading: true, error: null });

        try {
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.verify2FA(code);

            if (result.success && result.user) {
              const user = {
                ...result.user,
                displayName: (result.user as { name?: string; displayName?: string }).name || (result.user as { displayName?: string }).displayName,
                role: (result.user as { role: string }).role === 'admin' ? 'administrator' : (result.user as { role: string }).role
              } as User;

              set({
                user,
                token: 'session-' + Date.now(),
                isAuthenticated: true,
                isLoading: false,
                error: null,
                requirePasswordChange: result.requirePasswordChange || false,
                require2FA: false,
                pending2FAPhone: null,
                pending2FAUsername: null,
                twoFactorEnabled: true
              });
              return true;
            } else {
              set({
                isLoading: false,
                error: result.error || '2FA verification failed'
              });
              return false;
            }
          }
          return false;
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : '2FA verification failed'
          });
          return false;
        }
      },

      logout: () => {
        if (window.electronAPI) {
          window.electronAPI.auth.logout();
        }
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
          requirePasswordChange: false,
          require2FA: false,
          pending2FAPhone: null,
          pending2FAUsername: null,
          passwordExpiresAt: null
        });
      },

      changePassword: async (oldPassword: string, newPassword: string) => {
        set({ isLoading: true, error: null });

        try {
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.changePassword(oldPassword, newPassword);

            if (result.success) {
              set({
                isLoading: false,
                requirePasswordChange: false,
                passwordExpiresAt: result.expiresAt || null,
                error: null
              });
              return true;
            } else {
              set({
                isLoading: false,
                error: result.error || 'Password change failed'
              });
              return false;
            }
          } else {
            // Dev fallback - persist the new password
            const currentUser = get().user;
            if (currentUser) {
              const storedCredentials = localStorage.getItem('joe-dev-credentials');
              const devCredentials: Record<string, { hash: string; changed: boolean; passwordChangedAt?: number }> = storedCredentials
                ? JSON.parse(storedCredentials)
                : {};

              const userKey = currentUser.username.toLowerCase();

              // Verify old password
              if (devCredentials[userKey]?.hash !== btoa(oldPassword)) {
                set({ isLoading: false, error: 'Current password is incorrect' });
                return false;
              }

              // Save new password with timestamp
              devCredentials[userKey] = {
                hash: btoa(newPassword),
                changed: true,
                passwordChangedAt: Date.now()
              };
              localStorage.setItem('joe-dev-credentials', JSON.stringify(devCredentials));

              // Calculate expiration (30 days from now)
              const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

              set({
                isLoading: false,
                requirePasswordChange: false,
                passwordExpiresAt: expiresAt.toISOString(),
                error: null
              });
              return true;
            }
            set({ isLoading: false, error: 'No user logged in' });
            return false;
          }
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : 'Password change failed'
          });
          return false;
        }
      },

      setup2FA: async () => {
        set({ isLoading: true, error: null });

        try {
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.setup2FA();
            set({ isLoading: false, error: result.error || null });
            return {
              success: result.success,
              message: result.message,
              qrCode: result.qrCode,
              secret: result.secret
            };
          }
          return { success: false, message: 'API not available' };
        } catch (error) {
          const message = error instanceof Error ? error.message : '2FA setup failed';
          set({ isLoading: false, error: message });
          return { success: false, message };
        }
      },

      confirm2FASetup: async (code: string) => {
        set({ isLoading: true, error: null });

        try {
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.confirm2FASetup(code);
            if (result.success) {
              set({
                isLoading: false,
                twoFactorEnabled: true,
                error: null
              });
            } else {
              set({ isLoading: false, error: result.error || null });
            }
            return { success: result.success, message: result.message };
          }
          return { success: false, message: 'API not available' };
        } catch (error) {
          const message = error instanceof Error ? error.message : '2FA confirmation failed';
          set({ isLoading: false, error: message });
          return { success: false, message };
        }
      },

      disable2FA: async () => {
        set({ isLoading: true, error: null });

        try {
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.disable2FA();
            if (result.success) {
              set({
                isLoading: false,
                twoFactorEnabled: false,
                error: null
              });
            } else {
              set({ isLoading: false, error: result.error || null });
            }
            return result.success;
          }
          return false;
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : 'Failed to disable 2FA'
          });
          return false;
        }
      },

      get2FAStatus: async () => {
        if (window.electronAPI) {
          return await window.electronAPI.auth.get2FAStatus();
        }
        return { enabled: false, phone: null };
      },

      setUser: (user: User | null) => {
        set({ user, isAuthenticated: !!user });
      },

      setLoading: (isLoading: boolean) => {
        set({ isLoading });
      },

      clearError: () => {
        set({ error: null });
      },

      clearPasswordChangeRequirement: () => {
        set({ requirePasswordChange: false });
      },

      clear2FARequirement: () => {
        set({
          require2FA: false,
          pending2FAPhone: null,
          pending2FAUsername: null
        });
      }
    }),
    {
      name: 'joe-auth-storage',
      // SECURITY: Do NOT persist authentication state - require login on every app start
      // Only persist non-sensitive settings like 2FA enabled status for UX hints
      partialize: () => ({
        // Empty - no auth state persisted for security
        // User must always login when app starts
      })
    }
  )
);
