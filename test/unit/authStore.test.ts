import { describe, it, expect, beforeEach, vi } from 'vitest';
import { localStorageMock, mockElectronAPI } from '../setup';

// We need to test the auth store behavior
describe('AuthStore', () => {
  beforeEach(() => {
    localStorageMock.clear();
    vi.clearAllMocks();
  });

  describe('Initial State', () => {
    it('should start with unauthenticated state', async () => {
      // Import fresh to test initial state
      vi.resetModules();
      const { useAuthStore } = await import('@store/authStore');

      const state = useAuthStore.getState();
      expect(state.isAuthenticated).toBe(false);
      expect(state.user).toBe(null);
      expect(state.token).toBe(null);
    });

    it('should clear auth state from localStorage on load', async () => {
      // Setup: simulate persisted auth state
      localStorageMock.setItem('joe-auth-storage', JSON.stringify({
        state: {
          user: { id: '1', username: 'test' },
          token: 'old-token',
          isAuthenticated: true
        }
      }));

      // Import the module (triggers the clearing code)
      vi.resetModules();
      await import('@store/authStore');

      // Verify localStorage was cleared
      const stored = localStorageMock.getItem('joe-auth-storage');
      expect(stored).not.toBe(null);

      const parsed = JSON.parse(stored!);
      expect(parsed.state.user).toBe(null);
      expect(parsed.state.token).toBe(null);
      expect(parsed.state.isAuthenticated).toBe(false);
    });
  });

  describe('Login', () => {
    it('should authenticate with Electron API when available', async () => {
      vi.resetModules();

      // Mock successful login
      mockElectronAPI.auth.login.mockResolvedValue({
        success: true,
        user: {
          id: '1',
          username: 'mhoch',
          name: 'Michael Hoch',
          role: 'admin',
          email: 'test@test.com'
        },
        twoFactorEnabled: false
      });

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      const result = await store.login('mhoch', 'testpass');

      expect(result).toBe(true);
      expect(mockElectronAPI.auth.login).toHaveBeenCalledWith('mhoch', 'testpass');

      const newState = useAuthStore.getState();
      expect(newState.isAuthenticated).toBe(true);
      expect(newState.user?.username).toBe('mhoch');
    });

    it('should return require2FA when 2FA is needed', async () => {
      vi.resetModules();

      mockElectronAPI.auth.login.mockResolvedValue({
        success: false,
        require2FA: true,
        phone: '+1234567890'
      });

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      const result = await store.login('mhoch', 'testpass');

      expect(result).toBe('require2FA');

      const newState = useAuthStore.getState();
      expect(newState.require2FA).toBe(true);
      expect(newState.pending2FAPhone).toBe('+1234567890');
      expect(newState.isAuthenticated).toBe(false);
    });

    it('should handle login failure', async () => {
      vi.resetModules();

      mockElectronAPI.auth.login.mockResolvedValue({
        success: false,
        error: 'Invalid credentials'
      });

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      const result = await store.login('mhoch', 'wrongpass');

      expect(result).toBe(false);

      const newState = useAuthStore.getState();
      expect(newState.isAuthenticated).toBe(false);
      expect(newState.error).toBe('Invalid credentials');
    });
  });

  describe('Logout', () => {
    it('should clear all auth state on logout', async () => {
      vi.resetModules();

      // Setup: first login
      mockElectronAPI.auth.login.mockResolvedValue({
        success: true,
        user: { id: '1', username: 'mhoch', name: 'Test', role: 'admin' }
      });
      mockElectronAPI.auth.logout.mockResolvedValue(undefined);

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      await store.login('mhoch', 'testpass');
      expect(useAuthStore.getState().isAuthenticated).toBe(true);

      // Now logout
      store.logout();

      const newState = useAuthStore.getState();
      expect(newState.isAuthenticated).toBe(false);
      expect(newState.user).toBe(null);
      expect(newState.token).toBe(null);
      expect(mockElectronAPI.auth.logout).toHaveBeenCalled();
    });
  });

  describe('PIN Authentication', () => {
    it('should setup PIN for current user', async () => {
      vi.resetModules();

      mockElectronAPI.auth.login.mockResolvedValue({
        success: true,
        user: { id: '1', username: 'mhoch', name: 'Test', role: 'admin' }
      });

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      await store.login('mhoch', 'testpass');
      store.setupPin('1234');

      const newState = useAuthStore.getState();
      expect(newState.hasPinSetup).toBe(true);

      // Verify PIN is stored in localStorage
      const pinData = localStorageMock.getItem('joe-pin-auth');
      expect(pinData).not.toBe(null);
      const parsed = JSON.parse(pinData!);
      expect(parsed.pin).toBe('1234'); // Note: This is the security issue!
      expect(parsed.username).toBe('mhoch');
    });

    it('should login with valid PIN', async () => {
      vi.resetModules();

      // Setup PIN storage manually
      localStorageMock.setItem('joe-pin-auth', JSON.stringify({
        pin: '1234',
        username: 'mhoch',
        setupAt: Date.now()
      }));
      localStorageMock.setItem('joe-remembered-user', JSON.stringify({
        id: '1',
        username: 'mhoch',
        displayName: 'Michael Hoch',
        role: 'administrator'
      }));

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      const result = await store.loginWithPin('1234');

      expect(result).toBe(true);
      const newState = useAuthStore.getState();
      expect(newState.isAuthenticated).toBe(true);
      expect(newState.user?.username).toBe('mhoch');
    });

    it('should reject invalid PIN', async () => {
      vi.resetModules();

      localStorageMock.setItem('joe-pin-auth', JSON.stringify({
        pin: '1234',
        username: 'mhoch',
        setupAt: Date.now()
      }));
      localStorageMock.setItem('joe-remembered-user', JSON.stringify({
        id: '1',
        username: 'mhoch',
        displayName: 'Michael Hoch',
        role: 'administrator'
      }));

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      const result = await store.loginWithPin('9999');

      expect(result).toBe(false);
      const newState = useAuthStore.getState();
      expect(newState.isAuthenticated).toBe(false);
      expect(newState.error).toBe('Invalid PIN');
    });

    it('should clear PIN on clearPin()', async () => {
      vi.resetModules();

      localStorageMock.setItem('joe-pin-auth', JSON.stringify({
        pin: '1234',
        username: 'mhoch',
        setupAt: Date.now()
      }));
      localStorageMock.setItem('joe-remembered-user', JSON.stringify({
        id: '1',
        username: 'mhoch',
        displayName: 'Test',
        role: 'administrator'
      }));

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      store.clearPin();

      expect(localStorageMock.getItem('joe-pin-auth')).toBe(null);
      expect(localStorageMock.getItem('joe-remembered-user')).toBe(null);

      const newState = useAuthStore.getState();
      expect(newState.hasPinSetup).toBe(false);
      expect(newState.rememberedUser).toBe(null);
    });
  });

  describe('Password Change', () => {
    it('should require password change after first login in dev mode', async () => {
      vi.resetModules();

      // Remove electronAPI to trigger dev fallback
      (globalThis.window as unknown as { electronAPI?: unknown }).electronAPI = undefined;

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      // First login with default credentials
      const result = await store.login('mhoch', 'darkwolf');

      expect(result).toBe(true);
      const newState = useAuthStore.getState();
      expect(newState.requirePasswordChange).toBe(true);
    });
  });

  describe('Security: Auth Persistence', () => {
    it('should NOT persist auth state between page loads (security requirement)', async () => {
      vi.resetModules();

      mockElectronAPI.auth.login.mockResolvedValue({
        success: true,
        user: { id: '1', username: 'mhoch', name: 'Test', role: 'admin' }
      });

      // Re-enable electronAPI
      (globalThis.window as unknown as { electronAPI: typeof mockElectronAPI }).electronAPI = mockElectronAPI;

      const { useAuthStore } = await import('@store/authStore');
      const store = useAuthStore.getState();

      await store.login('mhoch', 'testpass');
      expect(useAuthStore.getState().isAuthenticated).toBe(true);

      // Simulate page reload by reimporting
      vi.resetModules();
      const { useAuthStore: freshStore } = await import('@store/authStore');

      // Auth should NOT be persisted
      const freshState = freshStore.getState();
      expect(freshState.isAuthenticated).toBe(false);
      expect(freshState.user).toBe(null);
    });
  });
});
