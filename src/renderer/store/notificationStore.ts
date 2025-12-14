/**
 * J.O.E. DevSecOps Arsenal - Notification Store
 * Zustand store for managing notifications and alert configurations
 */

import { create } from 'zustand';

// Types
export type NotificationChannel = 'slack' | 'teams' | 'email' | 'desktop';
export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NotificationCategory =
  | 'vulnerability'
  | 'compliance'
  | 'scan-complete'
  | 'scan-failed'
  | 'threshold-breach'
  | 'security-event'
  | 'system';

export interface NotificationPayload {
  id: string;
  title: string;
  message: string;
  severity: NotificationSeverity;
  category: NotificationCategory;
  timestamp: string;
  read: boolean;
  actionUrl?: string;
  findings?: Array<{ id: string; title: string; severity: string }>;
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  conditions: {
    severities: NotificationSeverity[];
    categories: NotificationCategory[];
    minCount?: number;
    frameworks?: string[];
  };
  channels: NotificationChannel[];
  throttleMinutes: number;
  createdAt: string;
  updatedAt: string;
}

export interface ChannelConfig {
  slack?: {
    enabled: boolean;
    webhookUrl: string;
    channel?: string;
  };
  teams?: {
    enabled: boolean;
    webhookUrl: string;
  };
  email?: {
    enabled: boolean;
    smtpHost: string;
    smtpPort: number;
    fromAddress: string;
    toAddresses: string[];
  };
  desktop?: {
    enabled: boolean;
    sound: boolean;
    showPreview: boolean;
  };
}

interface NotificationState {
  // State
  notifications: NotificationPayload[];
  alertRules: AlertRule[];
  channelConfig: ChannelConfig;
  unreadCount: number;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchNotifications: () => Promise<void>;
  addNotification: (notification: Omit<NotificationPayload, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearNotifications: () => void;
  deleteNotification: (id: string) => void;

  // Alert Rules
  fetchAlertRules: () => Promise<void>;
  createAlertRule: (rule: Omit<AlertRule, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>;
  updateAlertRule: (id: string, updates: Partial<AlertRule>) => Promise<void>;
  deleteAlertRule: (id: string) => Promise<void>;
  toggleAlertRule: (id: string) => Promise<void>;

  // Channel Configuration
  fetchChannelConfig: () => Promise<void>;
  updateChannelConfig: (channel: NotificationChannel, config: Partial<ChannelConfig[keyof ChannelConfig]>) => Promise<void>;
  testChannel: (channel: NotificationChannel) => Promise<{ success: boolean; error?: string }>;

  // Send notifications
  sendNotification: (payload: Omit<NotificationPayload, 'id' | 'timestamp' | 'read'>) => Promise<void>;
}

export const useNotificationStore = create<NotificationState>((set, get) => ({
  // Initial state
  notifications: [],
  alertRules: [],
  channelConfig: {
    slack: { enabled: false, webhookUrl: '' },
    teams: { enabled: false, webhookUrl: '' },
    email: { enabled: false, smtpHost: '', smtpPort: 587, fromAddress: '', toAddresses: [] },
    desktop: { enabled: true, sound: true, showPreview: true }
  },
  unreadCount: 0,
  isLoading: false,
  error: null,

  // Fetch notifications from backend
  fetchNotifications: async () => {
    set({ isLoading: true, error: null });
    try {
      const history = await window.electronAPI?.notifications?.getHistory?.() || [];
      const notifications = (history as Array<{ payload: NotificationPayload }>).map((h) => ({
        ...h.payload,
        read: false
      }));
      set({
        notifications,
        unreadCount: notifications.length,
        isLoading: false
      });
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Add a new notification locally
  addNotification: (notification) => {
    const newNotification: NotificationPayload = {
      ...notification,
      id: `notif-${Date.now()}`,
      timestamp: new Date().toISOString(),
      read: false
    };

    set((state) => ({
      notifications: [newNotification, ...state.notifications].slice(0, 100),
      unreadCount: state.unreadCount + 1
    }));
  },

  // Mark notification as read
  markAsRead: (id) => {
    set((state) => ({
      notifications: state.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      ),
      unreadCount: Math.max(0, state.unreadCount - 1)
    }));
  },

  // Mark all as read
  markAllAsRead: () => {
    set((state) => ({
      notifications: state.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0
    }));
  },

  // Clear all notifications
  clearNotifications: () => {
    set({ notifications: [], unreadCount: 0 });
  },

  // Delete a notification
  deleteNotification: (id) => {
    set((state) => {
      const notification = state.notifications.find((n) => n.id === id);
      return {
        notifications: state.notifications.filter((n) => n.id !== id),
        unreadCount: notification && !notification.read
          ? Math.max(0, state.unreadCount - 1)
          : state.unreadCount
      };
    });
  },

  // Fetch alert rules
  fetchAlertRules: async () => {
    set({ isLoading: true, error: null });
    try {
      const rules = await window.electronAPI?.notifications?.getAlertRules?.() || [];
      set({ alertRules: rules as AlertRule[], isLoading: false });
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Create alert rule
  createAlertRule: async (rule) => {
    set({ isLoading: true, error: null });
    try {
      const now = new Date().toISOString();
      const newRule: AlertRule = {
        ...rule,
        id: `rule-${Date.now()}`,
        createdAt: now,
        updatedAt: now
      };

      await window.electronAPI?.notifications?.createAlertRule?.(newRule);

      set((state) => ({
        alertRules: [...state.alertRules, newRule],
        isLoading: false
      }));
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Update alert rule
  updateAlertRule: async (id, updates) => {
    set({ isLoading: true, error: null });
    try {
      await window.electronAPI?.notifications?.updateAlertRule?.(id, updates);

      set((state) => ({
        alertRules: state.alertRules.map((r) =>
          r.id === id ? { ...r, ...updates, updatedAt: new Date().toISOString() } : r
        ),
        isLoading: false
      }));
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Delete alert rule
  deleteAlertRule: async (id) => {
    set({ isLoading: true, error: null });
    try {
      await window.electronAPI?.notifications?.deleteAlertRule?.(id);

      set((state) => ({
        alertRules: state.alertRules.filter((r) => r.id !== id),
        isLoading: false
      }));
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Toggle alert rule enabled status
  toggleAlertRule: async (id) => {
    const rule = get().alertRules.find((r) => r.id === id);
    if (rule) {
      await get().updateAlertRule(id, { enabled: !rule.enabled });
    }
  },

  // Fetch channel configuration
  fetchChannelConfig: async () => {
    set({ isLoading: true, error: null });
    try {
      const config = await window.electronAPI?.notifications?.getChannelConfig?.() || {};
      set({ channelConfig: config, isLoading: false });
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Update channel configuration
  updateChannelConfig: async (channel, config) => {
    set({ isLoading: true, error: null });
    try {
      await window.electronAPI?.notifications?.updateChannelConfig?.(channel, config);

      set((state) => ({
        channelConfig: {
          ...state.channelConfig,
          [channel]: { ...state.channelConfig[channel], ...config }
        },
        isLoading: false
      }));
    } catch (error) {
      set({ error: String(error), isLoading: false });
    }
  },

  // Test channel connection
  testChannel: async (channel) => {
    try {
      const result = await window.electronAPI?.notifications?.testChannel?.(channel);
      return result || { success: false, error: 'No response' };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  },

  // Send notification through all configured channels
  sendNotification: async (payload) => {
    try {
      await window.electronAPI?.notifications?.send?.(payload);
      get().addNotification(payload);
    } catch (error) {
      console.error('Failed to send notification:', error);
    }
  }
}));

// Type declarations consolidated in src/types/electron.d.ts
