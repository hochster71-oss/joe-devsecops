/**
 * J.O.E. Attack Surface Visualization
 *
 * Maps and visualizes potential attack vectors across the infrastructure
 * Integrates data from all security scanners
 */

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import MermaidDiagram from '../components/common/MermaidDiagram';
import {
  Shield,
  Globe,
  Server,
  Database,
  Container,
  Code,
  Key,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronRight,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Minus,
  Eye,
  Network,
  Layers,
  Target
} from 'lucide-react';

// ========================================
// INTERFACES
// ========================================

interface AttackVector {
  id: string;
  name: string;
  category: 'network' | 'application' | 'data' | 'identity' | 'infrastructure' | 'supply-chain';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'exposed' | 'protected' | 'monitoring';
  description: string;
  mitigation: string;
  findings: number;
  lastScanned?: string;
}

interface SurfaceMetrics {
  totalVectors: number;
  exposedVectors: number;
  protectedVectors: number;
  monitoringVectors: number;
  riskScore: number;
  trend: 'improving' | 'stable' | 'degrading';
}

// ========================================
// ATTACK SURFACE VIEW
// ========================================

export default function AttackSurfaceView() {
  const [metrics, setMetrics] = useState<SurfaceMetrics | null>(null);
  const [vectors, setVectors] = useState<AttackVector[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);

  // Simulated attack surface data - in production this would aggregate from all scanners
  useEffect(() => {
    const loadAttackSurface = async () => {
      setIsLoading(true);

      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const mockVectors: AttackVector[] = [
        {
          id: 'ASV-001',
          name: 'Public API Endpoints',
          category: 'network',
          severity: 'HIGH',
          status: 'monitoring',
          description: 'Externally exposed REST API endpoints',
          mitigation: 'Implement rate limiting, WAF, and API gateway',
          findings: 3,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-002',
          name: 'Container Registries',
          category: 'infrastructure',
          severity: 'CRITICAL',
          status: 'exposed',
          description: 'Private container registries with public access',
          mitigation: 'Restrict network access, enable authentication',
          findings: 2,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-003',
          name: 'Database Connections',
          category: 'data',
          severity: 'CRITICAL',
          status: 'protected',
          description: 'Database connection strings and credentials',
          mitigation: 'Use secrets manager, rotate credentials',
          findings: 0,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-004',
          name: 'CI/CD Pipelines',
          category: 'supply-chain',
          severity: 'HIGH',
          status: 'monitoring',
          description: 'Build and deployment pipeline access',
          mitigation: 'Enforce branch protection, signed commits',
          findings: 5,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-005',
          name: 'Service Accounts',
          category: 'identity',
          severity: 'HIGH',
          status: 'exposed',
          description: 'Over-privileged service accounts',
          mitigation: 'Apply least privilege, enable MFA',
          findings: 4,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-006',
          name: 'Third-Party Dependencies',
          category: 'supply-chain',
          severity: 'MEDIUM',
          status: 'monitoring',
          description: 'External libraries and packages',
          mitigation: 'Regular SBOM analysis, vulnerability scanning',
          findings: 12,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-007',
          name: 'Web Application Inputs',
          category: 'application',
          severity: 'HIGH',
          status: 'protected',
          description: 'User input validation points',
          mitigation: 'Input validation, sanitization, CSP headers',
          findings: 1,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-008',
          name: 'Cloud Storage Buckets',
          category: 'data',
          severity: 'CRITICAL',
          status: 'protected',
          description: 'Object storage access controls',
          mitigation: 'Block public access, enable encryption',
          findings: 0,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-009',
          name: 'Kubernetes Ingress',
          category: 'infrastructure',
          severity: 'MEDIUM',
          status: 'protected',
          description: 'Cluster ingress controllers',
          mitigation: 'Network policies, TLS termination',
          findings: 2,
          lastScanned: new Date().toISOString()
        },
        {
          id: 'ASV-010',
          name: 'SSH/RDP Access',
          category: 'network',
          severity: 'HIGH',
          status: 'protected',
          description: 'Remote access protocols',
          mitigation: 'Bastion hosts, MFA, session recording',
          findings: 0,
          lastScanned: new Date().toISOString()
        }
      ];

      const exposed = mockVectors.filter(v => v.status === 'exposed').length;
      const protectedCount = mockVectors.filter(v => v.status === 'protected').length;
      const monitoring = mockVectors.filter(v => v.status === 'monitoring').length;

      setMetrics({
        totalVectors: mockVectors.length,
        exposedVectors: exposed,
        protectedVectors: protectedCount,
        monitoringVectors: monitoring,
        riskScore: Math.round(100 - (exposed * 15) - (monitoring * 5)),
        trend: exposed > 2 ? 'degrading' : monitoring > 3 ? 'stable' : 'improving'
      });

      setVectors(mockVectors);
      setIsLoading(false);
    };

    loadAttackSurface();
  }, []);

  // ========================================
  // HELPERS
  // ========================================

  const categoryIcons: Record<string, typeof Shield> = {
    network: Globe,
    application: Code,
    data: Database,
    identity: Key,
    infrastructure: Server,
    'supply-chain': Container
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-alert-critical bg-alert-critical/10 border-alert-critical/30';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'MEDIUM': return 'text-alert-warning bg-alert-warning/10 border-alert-warning/30';
      case 'LOW': return 'text-dws-green bg-dws-green/10 border-dws-green/30';
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'exposed': return <XCircle className="text-alert-critical" size={16} />;
      case 'protected': return <CheckCircle className="text-dws-green" size={16} />;
      case 'monitoring': return <Eye className="text-alert-warning" size={16} />;
      default: return null;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'exposed': return 'bg-alert-critical/10 text-alert-critical border border-alert-critical/30';
      case 'protected': return 'bg-dws-green/10 text-dws-green border border-dws-green/30';
      case 'monitoring': return 'bg-alert-warning/10 text-alert-warning border border-alert-warning/30';
      default: return 'bg-gray-500/10 text-gray-400';
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'improving': return <TrendingDown className="text-dws-green" size={20} />;
      case 'degrading': return <TrendingUp className="text-alert-critical" size={20} />;
      default: return <Minus className="text-alert-warning" size={20} />;
    }
  };

  const filteredVectors = selectedCategory === 'all'
    ? vectors
    : vectors.filter(v => v.category === selectedCategory);

  const attackSurfaceDiagram = `
flowchart TB
    subgraph External["External Attack Surface"]
        API["API Endpoints"]
        Web["Web Applications"]
        DNS["DNS/Domain"]
    end

    subgraph Network["Network Layer"]
        FW["Firewall/WAF"]
        LB["Load Balancer"]
        VPN["VPN Gateway"]
    end

    subgraph Application["Application Layer"]
        App["Applications"]
        Micro["Microservices"]
        Queue["Message Queues"]
    end

    subgraph Data["Data Layer"]
        DB["Databases"]
        Cache["Cache Systems"]
        Storage["Object Storage"]
    end

    subgraph Identity["Identity & Access"]
        IAM["IAM/SSO"]
        Secrets["Secrets Manager"]
        Certs["Certificates"]
    end

    External --> Network
    Network --> Application
    Application --> Data
    Identity --> Application
    Identity --> Data

    style External fill:#dc2626,stroke:#dc2626,color:#fff
    style Network fill:#f97316,stroke:#f97316,color:#fff
    style Application fill:#eab308,stroke:#eab308,color:#000
    style Data fill:#22c55e,stroke:#22c55e,color:#fff
    style Identity fill:#00b4d8,stroke:#00b4d8,color:#fff
`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-alert-critical/20 to-orange-500/20 border border-alert-critical/30">
            <Target className="text-alert-critical" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">
              Attack Surface Analysis
            </h1>
            <p className="text-gray-400 mt-1">Map and monitor your exposure vectors</p>
          </div>
        </div>
        <button
          onClick={() => window.location.reload()}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw size={16} />
          Refresh Analysis
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <RefreshCw className="text-joe-blue animate-spin" size={40} />
        </div>
      ) : (
        <>
          {/* Metrics Overview */}
          {metrics && (
            <div className="grid grid-cols-5 gap-4">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass-card p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-joe-blue/10">
                    <Layers className="text-joe-blue" size={20} />
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Total Vectors</p>
                    <p className="text-2xl font-bold text-white">{metrics.totalVectors}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="glass-card p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-alert-critical/10">
                    <Unlock className="text-alert-critical" size={20} />
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Exposed</p>
                    <p className="text-2xl font-bold text-alert-critical">{metrics.exposedVectors}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="glass-card p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-dws-green/10">
                    <Lock className="text-dws-green" size={20} />
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Protected</p>
                    <p className="text-2xl font-bold text-dws-green">{metrics.protectedVectors}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="glass-card p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-alert-warning/10">
                    <Eye className="text-alert-warning" size={20} />
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Monitoring</p>
                    <p className="text-2xl font-bold text-alert-warning">{metrics.monitoringVectors}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="glass-card p-4"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    {getTrendIcon(metrics.trend)}
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Risk Score</p>
                    <p className={`text-2xl font-bold ${
                      metrics.riskScore >= 80 ? 'text-dws-green' :
                      metrics.riskScore >= 60 ? 'text-alert-warning' : 'text-alert-critical'
                    }`}>{metrics.riskScore}/100</p>
                  </div>
                </div>
              </motion.div>
            </div>
          )}

          {/* Attack Surface Diagram */}
          <div className="glass-card p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Network className="text-joe-blue" size={20} />
              Attack Surface Map
            </h2>
            <div className="bg-dws-dark p-6 rounded-lg">
              <MermaidDiagram
                chart={attackSurfaceDiagram}
                id="attack-surface-map"
                className="min-h-[350px]"
              />
            </div>
          </div>

          {/* Category Filter */}
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedCategory === 'all'
                  ? 'bg-joe-blue text-white'
                  : 'bg-dws-card text-gray-400 hover:text-white'
              }`}
            >
              All Categories
            </button>
            {['network', 'application', 'data', 'identity', 'infrastructure', 'supply-chain'].map(cat => {
              const Icon = categoryIcons[cat] || Shield;
              return (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${
                    selectedCategory === cat
                      ? 'bg-joe-blue text-white'
                      : 'bg-dws-card text-gray-400 hover:text-white'
                  }`}
                >
                  <Icon size={16} />
                  {cat.charAt(0).toUpperCase() + cat.slice(1).replace('-', ' ')}
                </button>
              );
            })}
          </div>

          {/* Attack Vectors List */}
          <div className="glass-card p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="text-alert-warning" size={20} />
              Attack Vectors ({filteredVectors.length})
            </h2>
            <div className="space-y-3">
              {filteredVectors.map((vector, i) => {
                const CategoryIcon = categoryIcons[vector.category] || Shield;
                return (
                  <motion.div
                    key={vector.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-4">
                        <div className={`p-2 rounded-lg ${getSeverityColor(vector.severity).split(' ').slice(1).join(' ')}`}>
                          <CategoryIcon className={getSeverityColor(vector.severity).split(' ')[0]} size={20} />
                        </div>
                        <div>
                          <div className="flex items-center gap-3 mb-1">
                            <h3 className="text-white font-medium">{vector.name}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(vector.severity)}`}>
                              {vector.severity}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1 ${getStatusBadge(vector.status)}`}>
                              {getStatusIcon(vector.status)}
                              {vector.status}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm">{vector.description}</p>
                          <div className="flex items-center gap-4 mt-2">
                            <span className="text-xs text-gray-500">
                              Category: <span className="text-gray-400">{vector.category}</span>
                            </span>
                            <span className="text-xs text-gray-500">
                              Findings: <span className={vector.findings > 0 ? 'text-alert-warning' : 'text-dws-green'}>{vector.findings}</span>
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-gray-500">Mitigation</p>
                        <p className="text-sm text-joe-blue flex items-center gap-1">
                          <ChevronRight size={14} />
                          {vector.mitigation}
                        </p>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
