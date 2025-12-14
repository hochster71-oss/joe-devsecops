import { beforeAll, afterEach, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
    get length() {
      return Object.keys(store).length;
    },
    key: (index: number) => Object.keys(store)[index] || null
  };
})();

Object.defineProperty(globalThis, 'localStorage', {
  value: localStorageMock,
  writable: true
});

// Mock window.electronAPI
const mockElectronAPI = {
  auth: {
    login: vi.fn(),
    logout: vi.fn(),
    getCurrentUser: vi.fn(),
    changePassword: vi.fn(),
    verify2FA: vi.fn(),
    setup2FA: vi.fn(),
    confirm2FASetup: vi.fn(),
    disable2FA: vi.fn(),
    get2FAStatus: vi.fn(),
    getAuditLog: vi.fn(),
    getSessionStatus: vi.fn()
  },
  security: {
    runAudit: vi.fn(),
    autoFix: vi.fn()
  },
  database: {
    query: vi.fn(),
    run: vi.fn(),
    get: vi.fn(),
    all: vi.fn()
  }
};

Object.defineProperty(globalThis, 'window', {
  value: {
    ...globalThis.window,
    electronAPI: mockElectronAPI,
    localStorage: localStorageMock
  },
  writable: true
});

// Clear mocks between tests
afterEach(() => {
  vi.clearAllMocks();
  localStorageMock.clear();
});

// Export for use in tests
export { mockElectronAPI, localStorageMock };
