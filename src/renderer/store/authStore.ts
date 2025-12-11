import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: 'administrator' | 'standard';
  email?: string;
  createdAt: string;
  lastLogin?: string;
  requirePasswordChange?: boolean;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  requirePasswordChange: boolean;

  // Actions
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  changePassword: (oldPassword: string, newPassword: string) => Promise<boolean>;
  setUser: (user: User | null) => void;
  setLoading: (loading: boolean) => void;
  clearError: () => void;
  clearPasswordChangeRequirement: () => void;
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

      login: async (username: string, password: string) => {
        set({ isLoading: true, error: null });

        try {
          // Use Electron IPC for authentication
          if (window.electronAPI) {
            const result = await window.electronAPI.auth.login(username, password);

            if (result.success && result.user) {
              const user = {
                ...result.user,
                displayName: result.user.name || result.user.displayName,
                role: result.user.role === 'admin' ? 'administrator' : result.user.role
              } as User;

              set({
                user,
                token: result.token as string || 'session-' + Date.now(),
                isAuthenticated: true,
                isLoading: false,
                error: null,
                requirePasswordChange: result.requirePasswordChange || false
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
            // Development fallback - simulate login
            const devUsers: Record<string, { password: string; user: User; requirePasswordChange: boolean }> = {
              'mhoch': {
                password: 'admin123',
                requirePasswordChange: true,
                user: {
                  id: '1',
                  username: 'mhoch',
                  displayName: 'Michael Hoch',
                  role: 'administrator',
                  email: 'michael@darkwolfsolutions.com',
                  createdAt: new Date().toISOString()
                }
              },
              'jscholer': {
                password: 'user123',
                requirePasswordChange: true,
                user: {
                  id: '2',
                  username: 'jscholer',
                  displayName: 'Joseph Scholer',
                  role: 'standard',
                  email: 'joseph@darkwolfsolutions.com',
                  createdAt: new Date().toISOString()
                }
              }
            };

            const userEntry = devUsers[username.toLowerCase()];
            if (userEntry && userEntry.password === password) {
              set({
                user: userEntry.user,
                token: 'dev-token-' + Date.now(),
                isAuthenticated: true,
                isLoading: false,
                error: null,
                requirePasswordChange: userEntry.requirePasswordChange
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

      logout: () => {
        if (window.electronAPI) {
          window.electronAPI.auth.logout();
        }
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          error: null,
          requirePasswordChange: false
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
            // Dev fallback
            set({
              isLoading: false,
              requirePasswordChange: false,
              error: null
            });
            return true;
          }
        } catch (error) {
          set({
            isLoading: false,
            error: error instanceof Error ? error.message : 'Password change failed'
          });
          return false;
        }
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
      }
    }),
    {
      name: 'joe-auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated
      })
    }
  )
);
