/**
 * J.O.E. DevSecOps Arsenal - Virtual Spaces Store
 * Zustand store for managing DoD-hardened Kubernetes namespaces
 *
 * Features:
 * - Kind cluster lifecycle management
 * - Ephemeral namespace creation with DoD hardening
 * - Pod Security Standards (Restricted/Baseline/Privileged)
 * - Network Policies (Deny-All, Limited Egress, Allow-All)
 * - RBAC with tiered access (Team, Elevated, Admin)
 * - Code import/export with security scanning
 */

import { create } from 'zustand';

// Types
export type SpaceTier = 'team' | 'elevated' | 'admin';
export type ClusterStatus = 'offline' | 'starting' | 'ready' | 'error' | 'not-installed';
export type SpaceStatus = 'creating' | 'ready' | 'scanning' | 'importing' | 'exporting' | 'destroying' | 'destroyed' | 'error';

export interface VirtualSpace {
  id: string;
  name: string;
  owner: string;
  tier: SpaceTier;
  status: SpaceStatus;
  namespace: string;
  createdAt: string;
  expiresAt: string;
  codeSource?: {
    type: 'git' | 'upload';
    url?: string;
    path?: string;
  };
  scanResults?: {
    vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    lastScanned: string;
  };
}

export interface SpaceTierInfo {
  name: string;
  pssLevel: 'restricted' | 'baseline' | 'privileged';
  networkPolicy: 'deny-all' | 'limited-egress' | 'allow-all';
  resourceQuota: {
    cpu: string;
    memory: string;
    pods: number;
  };
  allowPrivileged: boolean;
  allowHostPath: boolean;
  allowedOwners?: string[];
}

export interface ClusterInfo {
  status: ClusterStatus;
  name: string;
  nodes: number;
  version?: string;
  error?: string;
}

export interface ImportResult {
  success: boolean;
  filesImported: number;
  size: string;
  scanTriggered: boolean;
  error?: string;
}

export interface ExportResult {
  success: boolean;
  exportPath: string;
  artifactsExported: string[];
  error?: string;
}

export interface ScanResult {
  spaceId: string;
  scanTime: string;
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    file?: string;
    line?: number;
    description: string;
    remediation: string;
  }>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

interface VirtualSpacesState {
  // State
  spaces: VirtualSpace[];
  activeSpace: VirtualSpace | null;
  clusterInfo: ClusterInfo;
  tiers: Record<SpaceTier, SpaceTierInfo>;
  isLoading: boolean;
  error: string | null;

  // Scan results
  lastScanResult: ScanResult | null;
  isScanning: boolean;

  // Import/Export state
  isImporting: boolean;
  isExporting: boolean;
  lastImportResult: ImportResult | null;
  lastExportResult: ExportResult | null;

  // Actions
  initializeCluster: () => Promise<void>;
  destroyCluster: () => Promise<void>;
  refreshClusterStatus: () => Promise<void>;

  createSpace: (config: { name: string; owner: string; tier: SpaceTier; ttlMinutes?: number }) => Promise<VirtualSpace>;
  destroySpace: (spaceId: string) => Promise<void>;
  selectSpace: (spaceId: string | null) => void;
  refreshSpaces: () => Promise<void>;
  extendSpace: (spaceId: string, additionalMinutes: number) => Promise<void>;

  importCode: (source: { type: 'git' | 'upload'; url?: string; path?: string }) => Promise<ImportResult>;
  exportArtifacts: (artifacts: string[]) => Promise<ExportResult>;
  scanActiveSpace: () => Promise<ScanResult>;

  canCreateTier: (tier: SpaceTier, owner: string) => Promise<boolean>;
  fetchTiers: () => Promise<void>;

  clearError: () => void;
}

export const useVirtualSpacesStore = create<VirtualSpacesState>((set, get) => ({
  // Initial state
  spaces: [],
  activeSpace: null,
  clusterInfo: {
    status: 'offline',
    name: '',
    nodes: 0
  },
  tiers: {
    team: {
      name: 'Team Space',
      pssLevel: 'restricted',
      networkPolicy: 'deny-all',
      resourceQuota: { cpu: '2', memory: '4Gi', pods: 10 },
      allowPrivileged: false,
      allowHostPath: false
    },
    elevated: {
      name: 'Elevated Space (Joseph Scholer)',
      pssLevel: 'baseline',
      networkPolicy: 'limited-egress',
      resourceQuota: { cpu: '4', memory: '8Gi', pods: 20 },
      allowPrivileged: false,
      allowHostPath: true,
      allowedOwners: ['joseph.scholer', 'jscholer', 'joseph']
    },
    admin: {
      name: 'Admin Space (Michael Hoch)',
      pssLevel: 'privileged',
      networkPolicy: 'allow-all',
      resourceQuota: { cpu: '8', memory: '16Gi', pods: 50 },
      allowPrivileged: true,
      allowHostPath: true,
      allowedOwners: ['michael.hoch', 'mhoch', 'michael', 'admin']
    }
  },
  isLoading: false,
  error: null,
  lastScanResult: null,
  isScanning: false,
  isImporting: false,
  isExporting: false,
  lastImportResult: null,
  lastExportResult: null,

  // Cluster lifecycle
  initializeCluster: async () => {
    set({ isLoading: true, error: null });
    try {
      if (window.electronAPI?.virtualSpaces?.initCluster) {
        console.log('[Virtual Spaces] Initializing kind cluster...');
        const result = await window.electronAPI.virtualSpaces.initCluster();
        set({
          clusterInfo: {
            status: result.status as ClusterStatus,
            name: result.name,
            nodes: result.nodes,
            version: result.version,
            error: result.error
          },
          isLoading: false
        });

        // Also refresh spaces after cluster init
        await get().refreshSpaces();
      } else {
        set({
          error: 'Virtual Spaces API not available',
          isLoading: false
        });
      }
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to initialize cluster',
        isLoading: false
      });
    }
  },

  destroyCluster: async () => {
    set({ isLoading: true, error: null });
    try {
      if (window.electronAPI?.virtualSpaces?.destroyCluster) {
        console.log('[Virtual Spaces] Destroying kind cluster...');
        await window.electronAPI.virtualSpaces.destroyCluster();
        set({
          clusterInfo: { status: 'offline', name: '', nodes: 0 },
          spaces: [],
          activeSpace: null,
          isLoading: false
        });
      }
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to destroy cluster',
        isLoading: false
      });
    }
  },

  refreshClusterStatus: async () => {
    try {
      if (window.electronAPI?.virtualSpaces?.getClusterStatus) {
        const result = await window.electronAPI.virtualSpaces.getClusterStatus();
        set({
          clusterInfo: {
            status: result.status as ClusterStatus,
            name: result.name,
            nodes: result.nodes,
            version: result.version,
            error: result.error
          }
        });
      }
    } catch (error) {
      console.error('[Virtual Spaces] Failed to refresh cluster status:', error);
    }
  },

  // Space lifecycle
  createSpace: async (config) => {
    set({ isLoading: true, error: null });
    try {
      if (!window.electronAPI?.virtualSpaces?.createSpace) {
        throw new Error('Virtual Spaces API not available');
      }

      console.log('[Virtual Spaces] Creating space:', config.name, 'tier:', config.tier);
      const apiSpace = await window.electronAPI.virtualSpaces.createSpace(config);
      const space = apiSpace as VirtualSpace;

      set(state => ({
        spaces: [...state.spaces, space],
        activeSpace: space,
        isLoading: false
      }));

      return space;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Failed to create space';
      set({ error: errorMsg, isLoading: false });
      throw error;
    }
  },

  destroySpace: async (spaceId) => {
    set({ isLoading: true, error: null });
    try {
      if (window.electronAPI?.virtualSpaces?.destroySpace) {
        console.log('[Virtual Spaces] Destroying space:', spaceId);
        await window.electronAPI.virtualSpaces.destroySpace(spaceId);

        set(state => ({
          spaces: state.spaces.filter(s => s.id !== spaceId),
          activeSpace: state.activeSpace?.id === spaceId ? null : state.activeSpace,
          isLoading: false
        }));
      }
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to destroy space',
        isLoading: false
      });
    }
  },

  selectSpace: (spaceId) => {
    if (spaceId === null) {
      set({ activeSpace: null });
    } else {
      const space = get().spaces.find(s => s.id === spaceId);
      set({ activeSpace: space || null });
    }
  },

  refreshSpaces: async () => {
    try {
      if (window.electronAPI?.virtualSpaces?.listSpaces) {
        const apiSpaces = await window.electronAPI.virtualSpaces.listSpaces();
        const spaces = (apiSpaces || []) as VirtualSpace[];
        set({ spaces });

        // Update active space if it exists
        const { activeSpace } = get();
        if (activeSpace) {
          const updated = spaces.find(s => s.id === activeSpace.id);
          if (updated) {
            set({ activeSpace: updated });
          }
        }
      }
    } catch (error) {
      console.error('[Virtual Spaces] Failed to refresh spaces:', error);
    }
  },

  extendSpace: async (spaceId, additionalMinutes) => {
    try {
      if (window.electronAPI?.virtualSpaces?.extendSpace) {
        await window.electronAPI.virtualSpaces.extendSpace(spaceId, additionalMinutes);
        await get().refreshSpaces();
      }
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to extend space'
      });
    }
  },

  // Code operations
  importCode: async (source) => {
    const { activeSpace } = get();
    if (!activeSpace) {
      throw new Error('No active space selected');
    }

    set({ isImporting: true, error: null, lastImportResult: null });
    try {
      if (!window.electronAPI?.virtualSpaces?.importCode) {
        throw new Error('Virtual Spaces API not available');
      }

      console.log('[Virtual Spaces] Importing code to space:', activeSpace.id);
      const apiResult = await window.electronAPI.virtualSpaces.importCode(activeSpace.id, source);
      const result: ImportResult = {
        success: apiResult.success,
        filesImported: apiResult.filesImported,
        size: apiResult.path || '0',
        scanTriggered: true,
        error: apiResult.error
      };

      set({
        isImporting: false,
        lastImportResult: result
      });

      // Refresh space to update status
      await get().refreshSpaces();

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Import failed';
      set({
        error: errorMsg,
        isImporting: false,
        lastImportResult: { success: false, filesImported: 0, size: '0', scanTriggered: false, error: errorMsg }
      });
      throw error;
    }
  },

  exportArtifacts: async (artifacts) => {
    const { activeSpace } = get();
    if (!activeSpace) {
      throw new Error('No active space selected');
    }

    set({ isExporting: true, error: null, lastExportResult: null });
    try {
      if (!window.electronAPI?.virtualSpaces?.exportArtifacts) {
        throw new Error('Virtual Spaces API not available');
      }

      console.log('[Virtual Spaces] Exporting artifacts from space:', activeSpace.id);
      const apiResult = await window.electronAPI.virtualSpaces.exportArtifacts(activeSpace.id, artifacts);
      const result: ExportResult = {
        success: apiResult.success,
        exportPath: apiResult.exportPath,
        artifactsExported: apiResult.artifacts || [],
        error: apiResult.error
      };

      set({
        isExporting: false,
        lastExportResult: result
      });

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Export failed';
      set({
        error: errorMsg,
        isExporting: false,
        lastExportResult: { success: false, exportPath: '', artifactsExported: [], error: errorMsg }
      });
      throw error;
    }
  },

  scanActiveSpace: async () => {
    const { activeSpace } = get();
    if (!activeSpace) {
      throw new Error('No active space selected');
    }

    set({ isScanning: true, error: null, lastScanResult: null });
    try {
      if (!window.electronAPI?.virtualSpaces?.scanSpace) {
        throw new Error('Virtual Spaces API not available');
      }

      console.log('[Virtual Spaces] Scanning space:', activeSpace.id);
      const apiResult = await window.electronAPI.virtualSpaces.scanSpace(activeSpace.id);
      const result: ScanResult = {
        spaceId: activeSpace.id,
        scanTime: apiResult.scanTime,
        vulnerabilities: (apiResult.findings || []).map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
          file: f.file,
          line: f.line,
          description: f.description || '',
          remediation: f.remediation || ''
        })),
        summary: apiResult.summary
      };

      set({
        isScanning: false,
        lastScanResult: result
      });

      // Refresh space to update scan results
      await get().refreshSpaces();

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Scan failed';
      set({
        error: errorMsg,
        isScanning: false
      });
      throw error;
    }
  },

  // Tier management
  canCreateTier: async (tier, owner) => {
    try {
      if (window.electronAPI?.virtualSpaces?.canCreateTier) {
        return await window.electronAPI.virtualSpaces.canCreateTier(tier, owner);
      }
      // Fallback: check locally
      const tierInfo = get().tiers[tier];
      if (!tierInfo.allowedOwners) {return true;}
      return tierInfo.allowedOwners.some(allowed =>
        owner.toLowerCase().includes(allowed.toLowerCase())
      );
    } catch {
      return false;
    }
  },

  fetchTiers: async () => {
    try {
      if (window.electronAPI?.virtualSpaces?.getTiers) {
        const tiers = await window.electronAPI.virtualSpaces.getTiers();
        set({ tiers: tiers as Record<SpaceTier, SpaceTierInfo> });
      }
    } catch (error) {
      console.error('[Virtual Spaces] Failed to fetch tiers:', error);
    }
  },

  clearError: () => set({ error: null })
}));
