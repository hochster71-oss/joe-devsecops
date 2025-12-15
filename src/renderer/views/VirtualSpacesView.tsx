/**
 * J.O.E. Virtual Spaces View
 *
 * DoD-Hardened Kubernetes Namespaces for Secure Code Analysis
 * - Kind Cluster Management
 * - Ephemeral Workspaces with Tiered Access
 * - Pod Security Standards (Restricted/Baseline/Privileged)
 * - Network Policies & RBAC
 * - Code Import/Export Gates
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Container,
  Shield,
  AlertTriangle,
  RefreshCw,
  Plus,
  Trash2,
  Play,
  Square,
  Upload,
  Download,
  Scan,
  Lock,
  Users,
  Crown,
  Star,
  Server,
  Network,
  Cpu,
  HardDrive,
  Box,
  CheckCircle,
  XCircle,
  AlertCircle,
  FileCode,
  GitBranch,
  Timer,
  Zap,
  Settings,
  Eye,
  FolderOpen,
  ArrowUpCircle,
  ShieldCheck,
  ShieldAlert,
  ShieldOff
} from 'lucide-react';
import { useVirtualSpacesStore, SpaceTier, ClusterStatus } from '../store/virtualSpacesStore';

// ========================================
// VIRTUAL SPACES VIEW COMPONENT
// ========================================

export default function VirtualSpacesView() {
  const {
    spaces,
    activeSpace,
    clusterInfo,
    tiers,
    isLoading,
    error,
    isScanning,
    isImporting,
    isExporting,
    lastScanResult,
    initializeCluster,
    destroyCluster,
    refreshClusterStatus,
    createSpace,
    destroySpace,
    selectSpace,
    refreshSpaces,
    extendSpace,
    importCode,
    exportArtifacts,
    scanActiveSpace,
    clearError
  } = useVirtualSpacesStore();

  const [activeTab, setActiveTab] = useState<'spaces' | 'active' | 'security' | 'settings'>('spaces');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [newSpaceName, setNewSpaceName] = useState('');
  const [newSpaceOwner, setNewSpaceOwner] = useState('');
  const [newSpaceTier, setNewSpaceTier] = useState<SpaceTier>('team');
  const [importType, setImportType] = useState<'git' | 'upload'>('git');
  const [importUrl, setImportUrl] = useState('');
  const [importPath, setImportPath] = useState('');

  // Refresh cluster status and spaces on mount
  useEffect(() => {
    refreshClusterStatus();
    refreshSpaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Get cluster status icon
  const getClusterStatusIcon = (status: ClusterStatus) => {
    switch (status) {
      case 'ready':
        return <CheckCircle className="text-green-500" size={20} />;
      case 'starting':
        return <RefreshCw className="text-yellow-500 animate-spin" size={20} />;
      case 'error':
        return <XCircle className="text-red-500" size={20} />;
      case 'not-installed':
        return <AlertCircle className="text-orange-500" size={20} />;
      default:
        return <Square className="text-gray-500" size={20} />;
    }
  };

  // Get tier icon
  const getTierIcon = (tier: SpaceTier) => {
    switch (tier) {
      case 'team':
        return <Users className="text-blue-500" size={18} />;
      case 'elevated':
        return <Star className="text-yellow-500" size={18} />;
      case 'admin':
        return <Crown className="text-purple-500" size={18} />;
    }
  };

  // Get tier badge color
  const getTierBadgeClass = (tier: SpaceTier) => {
    switch (tier) {
      case 'team':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'elevated':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'admin':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    }
  };

  // Get PSS icon
  const getPSSIcon = (level: string) => {
    switch (level) {
      case 'restricted':
        return <ShieldCheck className="text-green-500" size={16} />;
      case 'baseline':
        return <ShieldAlert className="text-yellow-500" size={16} />;
      case 'privileged':
        return <ShieldOff className="text-red-500" size={16} />;
      default:
        return <Shield className="text-gray-500" size={16} />;
    }
  };

  // Get time remaining
  const getTimeRemaining = (expiresAt: string) => {
    const now = new Date();
    const expires = new Date(expiresAt);
    const diff = expires.getTime() - now.getTime();

    if (diff <= 0) {return 'Expired';}

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  // Handle create space
  const handleCreateSpace = async () => {
    try {
      await createSpace({
        name: newSpaceName,
        owner: newSpaceOwner,
        tier: newSpaceTier,
        ttlMinutes: 60
      });
      setShowCreateModal(false);
      setNewSpaceName('');
      setNewSpaceOwner('');
      setNewSpaceTier('team');
    } catch {
      // Error handled by store
    }
  };

  // Handle import
  const handleImport = async () => {
    try {
      await importCode({
        type: importType,
        url: importType === 'git' ? importUrl : undefined,
        path: importType === 'upload' ? importPath : undefined
      });
      setShowImportModal(false);
      setImportUrl('');
      setImportPath('');
    } catch {
      // Error handled by store
    }
  };

  // Handle export
  const handleExport = async () => {
    try {
      await exportArtifacts(['*']); // Export all
      setShowExportModal(false);
    } catch {
      // Error handled by store
    }
  };

  // Handle select directory
  const handleSelectDirectory = async () => {
    const path = await window.electronAPI?.fs?.selectDirectory?.();
    if (path) {
      setImportPath(path);
    }
  };

  return (
    <div className="h-full bg-slate-900 text-white overflow-auto">
      {/* Header */}
      <div className="border-b border-slate-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Container className="text-cyan-500" size={28} />
            <div>
              <h1 className="text-xl font-bold">Virtual Spaces</h1>
              <p className="text-sm text-slate-400">DoD-Hardened Kubernetes Namespaces</p>
            </div>
          </div>

          {/* Cluster Status */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-slate-800 rounded-lg px-3 py-2">
              {getClusterStatusIcon(clusterInfo.status)}
              <span className="text-sm capitalize">{clusterInfo.status}</span>
              {clusterInfo.nodes > 0 && (
                <span className="text-xs text-slate-400">({clusterInfo.nodes} nodes)</span>
              )}
            </div>

            {clusterInfo.status === 'offline' || clusterInfo.status === 'not-installed' ? (
              <button
                onClick={initializeCluster}
                disabled={isLoading}
                className="flex items-center gap-2 bg-green-600 hover:bg-green-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
              >
                {isLoading ? (
                  <RefreshCw className="animate-spin" size={16} />
                ) : (
                  <Play size={16} />
                )}
                Start Cluster
              </button>
            ) : clusterInfo.status === 'ready' && (
              <button
                onClick={destroyCluster}
                disabled={isLoading}
                className="flex items-center gap-2 bg-red-600 hover:bg-red-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
              >
                <Square size={16} />
                Stop Cluster
              </button>
            )}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {[
            { id: 'spaces', label: 'Spaces', icon: Box },
            { id: 'active', label: 'Active Space', icon: Eye },
            { id: 'security', label: 'Security', icon: Shield },
            { id: 'settings', label: 'Settings', icon: Settings }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
            >
              <tab.icon size={16} />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="bg-red-500/20 border border-red-500/30 text-red-400 px-4 py-3 mx-6 mt-4 rounded-lg flex items-center justify-between"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle size={18} />
              {error}
            </div>
            <button onClick={clearError} className="text-red-300 hover:text-red-200">
              <XCircle size={18} />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="p-6">
        {/* Spaces Tab */}
        {activeTab === 'spaces' && (
          <div className="space-y-6">
            {/* Actions Bar */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setShowCreateModal(true)}
                  disabled={clusterInfo.status !== 'ready' || isLoading}
                  className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
                >
                  <Plus size={16} />
                  New Space
                </button>
                <button
                  onClick={refreshSpaces}
                  className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 rounded-lg px-3 py-2 transition-colors"
                >
                  <RefreshCw size={16} />
                </button>
              </div>

              <div className="text-sm text-slate-400">
                {spaces.length} space{spaces.length !== 1 ? 's' : ''} active
              </div>
            </div>

            {/* Space Tiers Overview */}
            <div className="grid grid-cols-3 gap-4">
              {(Object.entries(tiers) as [SpaceTier, typeof tiers.team][]).map(([tier, info]) => (
                <div
                  key={tier}
                  className={`bg-slate-800 rounded-lg p-4 border ${getTierBadgeClass(tier)}`}
                >
                  <div className="flex items-center gap-2 mb-3">
                    {getTierIcon(tier)}
                    <span className="font-semibold">{info.name}</span>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2 text-slate-400">
                      {getPSSIcon(info.pssLevel)}
                      <span>PSS: {info.pssLevel}</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Network size={14} />
                      <span>Network: {info.networkPolicy}</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Cpu size={14} />
                      <span>CPU: {info.resourceQuota.cpu}</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <HardDrive size={14} />
                      <span>Memory: {info.resourceQuota.memory}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Spaces List */}
            <div className="space-y-3">
              {spaces.length === 0 ? (
                <div className="bg-slate-800 rounded-lg p-8 text-center">
                  <Box className="mx-auto text-slate-600 mb-3" size={48} />
                  <p className="text-slate-400">No virtual spaces created yet</p>
                  <p className="text-sm text-slate-500 mt-1">
                    Click "New Space" to create an isolated workspace
                  </p>
                </div>
              ) : (
                spaces.map(space => (
                  <motion.div
                    key={space.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`bg-slate-800 rounded-lg p-4 border transition-colors cursor-pointer ${
                      activeSpace?.id === space.id
                        ? 'border-cyan-500'
                        : 'border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => selectSpace(space.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`p-2 rounded-lg ${getTierBadgeClass(space.tier)}`}>
                          {getTierIcon(space.tier)}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold">{space.name}</h3>
                            <span className={`text-xs px-2 py-0.5 rounded border ${getTierBadgeClass(space.tier)}`}>
                              {space.tier}
                            </span>
                          </div>
                          <p className="text-sm text-slate-400">
                            Owner: {space.owner} | NS: {space.namespace}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        {/* Time Remaining */}
                        <div className="flex items-center gap-2 text-sm">
                          <Timer size={14} className="text-slate-400" />
                          <span className={
                            new Date(space.expiresAt).getTime() - Date.now() < 10 * 60 * 1000
                              ? 'text-red-400'
                              : 'text-slate-400'
                          }>
                            {getTimeRemaining(space.expiresAt)}
                          </span>
                        </div>

                        {/* Status Badge */}
                        <span className={`text-xs px-2 py-1 rounded ${
                          space.status === 'ready'
                            ? 'bg-green-500/20 text-green-400'
                            : space.status === 'creating' || space.status === 'scanning'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}>
                          {space.status}
                        </span>

                        {/* Actions */}
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              extendSpace(space.id, 30);
                            }}
                            className="p-2 rounded hover:bg-slate-700 transition-colors"
                            title="Extend 30 minutes"
                          >
                            <ArrowUpCircle size={16} className="text-slate-400" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              destroySpace(space.id);
                            }}
                            className="p-2 rounded hover:bg-red-500/20 transition-colors"
                            title="Destroy Space"
                          >
                            <Trash2 size={16} className="text-red-400" />
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Scan Results Preview */}
                    {space.scanResults && (
                      <div className="mt-3 pt-3 border-t border-slate-700 flex items-center gap-4 text-sm">
                        <span className="text-slate-400">Last Scan:</span>
                        <span className="text-red-400">{space.scanResults.critical} Critical</span>
                        <span className="text-orange-400">{space.scanResults.high} High</span>
                        <span className="text-yellow-400">{space.scanResults.medium} Medium</span>
                        <span className="text-blue-400">{space.scanResults.low} Low</span>
                      </div>
                    )}
                  </motion.div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Active Space Tab */}
        {activeTab === 'active' && (
          <div className="space-y-6">
            {!activeSpace ? (
              <div className="bg-slate-800 rounded-lg p-8 text-center">
                <Eye className="mx-auto text-slate-600 mb-3" size={48} />
                <p className="text-slate-400">No space selected</p>
                <p className="text-sm text-slate-500 mt-1">
                  Select a space from the Spaces tab
                </p>
              </div>
            ) : (
              <>
                {/* Space Info Header */}
                <div className="bg-slate-800 rounded-lg p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`p-3 rounded-lg ${getTierBadgeClass(activeSpace.tier)}`}>
                        {getTierIcon(activeSpace.tier)}
                      </div>
                      <div>
                        <h2 className="text-xl font-bold">{activeSpace.name}</h2>
                        <p className="text-slate-400">
                          {tiers[activeSpace.tier].name} | {activeSpace.namespace}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => setShowImportModal(true)}
                        disabled={isImporting}
                        className="flex items-center gap-2 bg-green-600 hover:bg-green-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
                      >
                        {isImporting ? <RefreshCw className="animate-spin" size={16} /> : <Upload size={16} />}
                        Import Code
                      </button>
                      <button
                        onClick={scanActiveSpace}
                        disabled={isScanning}
                        className="flex items-center gap-2 bg-yellow-600 hover:bg-yellow-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
                      >
                        {isScanning ? <RefreshCw className="animate-spin" size={16} /> : <Scan size={16} />}
                        Scan
                      </button>
                      <button
                        onClick={() => setShowExportModal(true)}
                        disabled={isExporting}
                        className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
                      >
                        {isExporting ? <RefreshCw className="animate-spin" size={16} /> : <Download size={16} />}
                        Export
                      </button>
                    </div>
                  </div>

                  {/* Space Details Grid */}
                  <div className="grid grid-cols-4 gap-4 mt-6">
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                        <Timer size={14} />
                        Time Remaining
                      </div>
                      <div className="text-lg font-semibold">
                        {getTimeRemaining(activeSpace.expiresAt)}
                      </div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                        <Shield size={14} />
                        Pod Security
                      </div>
                      <div className="text-lg font-semibold capitalize">
                        {tiers[activeSpace.tier].pssLevel}
                      </div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                        <Network size={14} />
                        Network Policy
                      </div>
                      <div className="text-lg font-semibold">
                        {tiers[activeSpace.tier].networkPolicy}
                      </div>
                    </div>
                    <div className="bg-slate-700/50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                        <Cpu size={14} />
                        Resources
                      </div>
                      <div className="text-lg font-semibold">
                        {tiers[activeSpace.tier].resourceQuota.cpu} CPU / {tiers[activeSpace.tier].resourceQuota.memory}
                      </div>
                    </div>
                  </div>

                  {/* Code Source */}
                  {activeSpace.codeSource && (
                    <div className="mt-4 p-3 bg-slate-700/50 rounded-lg">
                      <div className="flex items-center gap-2 text-sm">
                        {activeSpace.codeSource.type === 'git' ? (
                          <GitBranch size={14} className="text-green-500" />
                        ) : (
                          <FolderOpen size={14} className="text-blue-500" />
                        )}
                        <span className="text-slate-400">Code Source:</span>
                        <span>{activeSpace.codeSource.url || activeSpace.codeSource.path}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Scan Results */}
                {lastScanResult && (
                  <div className="bg-slate-800 rounded-lg p-6">
                    <h3 className="font-semibold mb-4 flex items-center gap-2">
                      <Scan size={18} />
                      Security Scan Results
                    </h3>

                    <div className="grid grid-cols-5 gap-4 mb-6">
                      {[
                        { label: 'Critical', value: lastScanResult.summary.critical, color: 'red' },
                        { label: 'High', value: lastScanResult.summary.high, color: 'orange' },
                        { label: 'Medium', value: lastScanResult.summary.medium, color: 'yellow' },
                        { label: 'Low', value: lastScanResult.summary.low, color: 'blue' },
                        { label: 'Info', value: lastScanResult.summary.info, color: 'gray' }
                      ].map(item => (
                        <div key={item.label} className={`bg-${item.color}-500/20 rounded-lg p-3 text-center`}>
                          <div className={`text-2xl font-bold text-${item.color}-400`}>{item.value}</div>
                          <div className="text-sm text-slate-400">{item.label}</div>
                        </div>
                      ))}
                    </div>

                    {lastScanResult.vulnerabilities.length > 0 && (
                      <div className="space-y-2 max-h-64 overflow-auto">
                        {lastScanResult.vulnerabilities.slice(0, 10).map((vuln, idx) => (
                          <div
                            key={idx}
                            className="bg-slate-700/50 rounded-lg p-3 flex items-start justify-between"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                  vuln.severity === 'critical' ? 'bg-red-500/30 text-red-400' :
                                  vuln.severity === 'high' ? 'bg-orange-500/30 text-orange-400' :
                                  vuln.severity === 'medium' ? 'bg-yellow-500/30 text-yellow-400' :
                                  'bg-blue-500/30 text-blue-400'
                                }`}>
                                  {vuln.severity.toUpperCase()}
                                </span>
                                <span className="font-medium">{vuln.title}</span>
                              </div>
                              {vuln.file && (
                                <div className="text-sm text-slate-400 mt-1">
                                  <FileCode size={12} className="inline mr-1" />
                                  {vuln.file}{vuln.line && `:${vuln.line}`}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-lg p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <Shield size={18} />
                DoD Hardening Overview
              </h3>

              <div className="space-y-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Lock size={16} className="text-green-500" />
                    Pod Security Standards
                  </h4>
                  <p className="text-sm text-slate-400">
                    All spaces enforce Kubernetes Pod Security Standards (PSS) based on tier level.
                    Team spaces use "restricted" mode, elevated uses "baseline", and admin uses "privileged".
                  </p>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Network size={16} className="text-blue-500" />
                    Network Policies
                  </h4>
                  <p className="text-sm text-slate-400">
                    Default deny-all network policies are applied to team spaces. Elevated spaces
                    allow limited egress, while admin spaces have full network access.
                  </p>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Users size={16} className="text-purple-500" />
                    RBAC Controls
                  </h4>
                  <p className="text-sm text-slate-400">
                    Role-Based Access Control limits namespace access per tier. Each space owner
                    receives only the permissions necessary for their tier level.
                  </p>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <h4 className="font-medium mb-2 flex items-center gap-2">
                    <Zap size={16} className="text-yellow-500" />
                    Resource Quotas
                  </h4>
                  <p className="text-sm text-slate-400">
                    Each space has CPU, memory, and pod limits to prevent resource exhaustion.
                    Limit ranges ensure individual containers don't exceed their allocation.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Settings Tab */}
        {activeTab === 'settings' && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-lg p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <Server size={18} />
                Cluster Configuration
              </h3>

              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-slate-700/50 rounded-lg">
                  <div>
                    <h4 className="font-medium">Cluster Name</h4>
                    <p className="text-sm text-slate-400">{clusterInfo.name || 'joe-virtual-spaces'}</p>
                  </div>
                  <div className="text-right">
                    <h4 className="font-medium">Version</h4>
                    <p className="text-sm text-slate-400">{clusterInfo.version || 'Not running'}</p>
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 bg-slate-700/50 rounded-lg">
                  <div>
                    <h4 className="font-medium">Node Count</h4>
                    <p className="text-sm text-slate-400">{clusterInfo.nodes} nodes</p>
                  </div>
                  <div className="text-right">
                    <h4 className="font-medium">Status</h4>
                    <p className="text-sm text-slate-400 capitalize">{clusterInfo.status}</p>
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 bg-slate-700/50 rounded-lg">
                  <div>
                    <h4 className="font-medium">Air-Gapped Mode</h4>
                    <p className="text-sm text-slate-400">Works fully offline with pre-pulled images</p>
                  </div>
                  <CheckCircle className="text-green-500" size={20} />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Create Space Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
            onClick={() => setShowCreateModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="bg-slate-800 rounded-lg p-6 w-[500px] max-w-[90vw]"
              onClick={e => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Plus size={20} />
                Create Virtual Space
              </h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Space Name</label>
                  <input
                    type="text"
                    value={newSpaceName}
                    onChange={e => setNewSpaceName(e.target.value)}
                    placeholder="my-analysis-space"
                    className="w-full bg-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-sm text-slate-400 mb-1">Owner</label>
                  <input
                    type="text"
                    value={newSpaceOwner}
                    onChange={e => setNewSpaceOwner(e.target.value)}
                    placeholder="username"
                    className="w-full bg-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-sm text-slate-400 mb-1">Tier</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(['team', 'elevated', 'admin'] as SpaceTier[]).map(tier => (
                      <button
                        key={tier}
                        onClick={() => setNewSpaceTier(tier)}
                        className={`p-3 rounded-lg border transition-colors ${
                          newSpaceTier === tier
                            ? getTierBadgeClass(tier)
                            : 'bg-slate-700 border-slate-600 hover:border-slate-500'
                        }`}
                      >
                        <div className="flex items-center justify-center gap-2">
                          {getTierIcon(tier)}
                          <span className="capitalize">{tier}</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-3 text-sm">
                  <p className="text-slate-400">
                    {tiers[newSpaceTier].name}
                  </p>
                  <p className="text-slate-500 mt-1">
                    PSS: {tiers[newSpaceTier].pssLevel} | Network: {tiers[newSpaceTier].networkPolicy}
                  </p>
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateSpace}
                  disabled={!newSpaceName || !newSpaceOwner || isLoading}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors disabled:opacity-50"
                >
                  Create Space
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Import Modal */}
      <AnimatePresence>
        {showImportModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
            onClick={() => setShowImportModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="bg-slate-800 rounded-lg p-6 w-[500px] max-w-[90vw]"
              onClick={e => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Upload size={20} />
                Import Code
              </h3>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => setImportType('git')}
                    className={`p-3 rounded-lg border transition-colors ${
                      importType === 'git'
                        ? 'bg-green-500/20 border-green-500/30 text-green-400'
                        : 'bg-slate-700 border-slate-600 hover:border-slate-500'
                    }`}
                  >
                    <GitBranch size={20} className="mx-auto mb-1" />
                    Git Repository
                  </button>
                  <button
                    onClick={() => setImportType('upload')}
                    className={`p-3 rounded-lg border transition-colors ${
                      importType === 'upload'
                        ? 'bg-blue-500/20 border-blue-500/30 text-blue-400'
                        : 'bg-slate-700 border-slate-600 hover:border-slate-500'
                    }`}
                  >
                    <FolderOpen size={20} className="mx-auto mb-1" />
                    Local Directory
                  </button>
                </div>

                {importType === 'git' ? (
                  <div>
                    <label className="block text-sm text-slate-400 mb-1">Git URL</label>
                    <input
                      type="text"
                      value={importUrl}
                      onChange={e => setImportUrl(e.target.value)}
                      placeholder="https://github.com/user/repo.git"
                      className="w-full bg-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm text-slate-400 mb-1">Local Path</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={importPath}
                        onChange={e => setImportPath(e.target.value)}
                        placeholder="/path/to/code"
                        className="flex-1 bg-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      />
                      <button
                        onClick={handleSelectDirectory}
                        className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                      >
                        Browse
                      </button>
                    </div>
                  </div>
                )}

                <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-3 text-sm text-yellow-400">
                  <AlertTriangle size={16} className="inline mr-2" />
                  Code will be scanned for security vulnerabilities before import is complete.
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleImport}
                  disabled={isImporting || (importType === 'git' ? !importUrl : !importPath)}
                  className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded-lg transition-colors disabled:opacity-50"
                >
                  {isImporting ? 'Importing...' : 'Import'}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Export Modal */}
      <AnimatePresence>
        {showExportModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
            onClick={() => setShowExportModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="bg-slate-800 rounded-lg p-6 w-[500px] max-w-[90vw]"
              onClick={e => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Download size={20} />
                Export Artifacts
              </h3>

              <div className="space-y-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <p className="text-sm text-slate-400">
                    This will export all code and artifacts from the virtual space.
                    The export will be scanned and validated before completion.
                  </p>
                </div>

                <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-3 text-sm text-yellow-400">
                  <AlertTriangle size={16} className="inline mr-2" />
                  All exports are logged for security audit purposes.
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowExportModal(false)}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleExport}
                  disabled={isExporting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors disabled:opacity-50"
                >
                  {isExporting ? 'Exporting...' : 'Export All'}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
