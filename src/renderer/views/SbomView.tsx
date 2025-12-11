import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Package,
  Search,
  Download,
  RefreshCw,
  AlertTriangle,
  Shield,
  FileJson,
  ExternalLink,
  GitBranch,
  Scale,
  Clock,
  CheckCircle,
  XCircle,
  Info,
  Eye
} from 'lucide-react';
import Modal from '../components/common/Modal';

/**
 * SBOM Explorer View - J.O.E. DevSecOps Platform
 *
 * Software Bill of Materials management with:
 * - CycloneDX and SPDX format support
 * - Dependency vulnerability tracking
 * - License compliance analysis
 * - Component detail modals
 *
 * Reference: NTIA SBOM Minimum Elements
 * https://www.ntia.gov/page/software-bill-materials
 */

interface Component {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'tool' | 'runtime';
  license: string;
  vulnerabilities: number;
  description?: string;
  repository?: string;
  dependencies?: string[];
  cves?: { id: string; severity: string; description: string }[];
  lastUpdated?: string;
  maintainer?: string;
}

const mockComponents: Component[] = [
  {
    name: 'react',
    version: '18.2.0',
    type: 'library',
    license: 'MIT',
    vulnerabilities: 0,
    description: 'A JavaScript library for building user interfaces',
    repository: 'https://github.com/facebook/react',
    dependencies: ['react-dom', 'scheduler'],
    lastUpdated: '2023-06-14',
    maintainer: 'Meta'
  },
  {
    name: 'lodash',
    version: '4.17.15',
    type: 'library',
    license: 'MIT',
    vulnerabilities: 3,
    description: 'A modern JavaScript utility library delivering modularity, performance & extras',
    repository: 'https://github.com/lodash/lodash',
    dependencies: [],
    cves: [
      { id: 'CVE-2021-23337', severity: 'high', description: 'Prototype pollution via command method' },
      { id: 'CVE-2020-28500', severity: 'medium', description: 'ReDoS via toNumber, trim and trimEnd methods' },
      { id: 'CVE-2020-8203', severity: 'high', description: 'Prototype pollution via zipObjectDeep' }
    ],
    lastUpdated: '2020-01-12',
    maintainer: 'John-David Dalton'
  },
  {
    name: 'axios',
    version: '1.6.2',
    type: 'library',
    license: 'MIT',
    vulnerabilities: 0,
    description: 'Promise based HTTP client for the browser and node.js',
    repository: 'https://github.com/axios/axios',
    dependencies: ['follow-redirects', 'form-data'],
    lastUpdated: '2023-11-14',
    maintainer: 'Matt Zabriskie'
  },
  {
    name: 'express',
    version: '4.18.2',
    type: 'framework',
    license: 'MIT',
    vulnerabilities: 1,
    description: 'Fast, unopinionated, minimalist web framework for Node.js',
    repository: 'https://github.com/expressjs/express',
    dependencies: ['body-parser', 'cookie-parser', 'debug'],
    cves: [
      { id: 'CVE-2024-29041', severity: 'medium', description: 'URL redirection to untrusted site (Open Redirect)' }
    ],
    lastUpdated: '2022-10-08',
    maintainer: 'Express.js Team'
  },
  {
    name: 'typescript',
    version: '5.3.2',
    type: 'tool',
    license: 'Apache-2.0',
    vulnerabilities: 0,
    description: 'TypeScript is a typed superset of JavaScript that compiles to plain JavaScript',
    repository: 'https://github.com/microsoft/TypeScript',
    dependencies: [],
    lastUpdated: '2023-11-20',
    maintainer: 'Microsoft'
  },
  {
    name: 'electron',
    version: '28.0.0',
    type: 'framework',
    license: 'MIT',
    vulnerabilities: 0,
    description: 'Build cross-platform desktop apps with JavaScript, HTML, and CSS',
    repository: 'https://github.com/electron/electron',
    dependencies: ['chromium', 'node.js', 'v8'],
    lastUpdated: '2023-12-05',
    maintainer: 'Electron Team'
  },
  {
    name: 'tailwindcss',
    version: '3.3.6',
    type: 'library',
    license: 'MIT',
    vulnerabilities: 0,
    description: 'A utility-first CSS framework for rapidly building custom user interfaces',
    repository: 'https://github.com/tailwindlabs/tailwindcss',
    dependencies: ['postcss', 'autoprefixer'],
    lastUpdated: '2023-11-29',
    maintainer: 'Tailwind Labs'
  },
  {
    name: 'vite',
    version: '5.0.7',
    type: 'tool',
    license: 'MIT',
    vulnerabilities: 0,
    description: 'Next generation frontend tooling. It\'s fast!',
    repository: 'https://github.com/vitejs/vite',
    dependencies: ['esbuild', 'rollup'],
    lastUpdated: '2023-12-07',
    maintainer: 'Evan You'
  }
];

type StatModalType = 'components' | 'secure' | 'cves' | 'format' | null;

export default function SbomView() {
  const [searchQuery, setSearchQuery] = useState('');
  const [sbomFormat, setSbomFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');
  const [selectedComponent, setSelectedComponent] = useState<Component | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [isExporting, setIsExporting] = useState(false);
  const [activeStatModal, setActiveStatModal] = useState<StatModalType>(null);

  const filteredComponents = mockComponents.filter(c => {
    const matchesSearch = c.name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = filterType === 'all' || c.type === filterType;
    return matchesSearch && matchesType;
  });

  const vulnerableCount = mockComponents.filter(c => c.vulnerabilities > 0).length;
  const secureCount = mockComponents.length - vulnerableCount;
  const totalVulns = mockComponents.reduce((sum, c) => sum + c.vulnerabilities, 0);
  const vulnerableComponents = mockComponents.filter(c => c.vulnerabilities > 0);
  const secureComponents = mockComponents.filter(c => c.vulnerabilities === 0);

  // Component type breakdown
  const typeBreakdown = mockComponents.reduce((acc, c) => {
    acc[c.type] = (acc[c.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // License breakdown
  const licenseBreakdown = mockComponents.reduce((acc, c) => {
    acc[c.license] = (acc[c.license] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const handleExport = async () => {
    setIsExporting(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsExporting(false);
  };

  const getLicenseRisk = (license: string) => {
    const permissive = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'];
    const copyleft = ['GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'AGPL-3.0'];
    if (permissive.includes(license)) return { level: 'low', color: 'text-dws-green' };
    if (copyleft.includes(license)) return { level: 'medium', color: 'text-alert-warning' };
    return { level: 'unknown', color: 'text-gray-500' };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-3">
            <Package className="text-joe-blue" />
            SBOM Explorer
          </h1>
          <p className="text-gray-400 mt-1">Software Bill of Materials - Track all dependencies</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={sbomFormat}
            onChange={(e) => setSbomFormat(e.target.value as 'cyclonedx' | 'spdx')}
            className="input-field w-auto"
            aria-label="Select SBOM format"
          >
            <option value="cyclonedx">CycloneDX 1.5</option>
            <option value="spdx">SPDX 2.3</option>
          </select>
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="btn-secondary flex items-center gap-2"
            type="button"
          >
            <Download size={16} className={isExporting ? 'animate-bounce' : ''} />
            {isExporting ? 'Exporting...' : 'Export SBOM'}
          </button>
          <button className="btn-primary flex items-center gap-2" type="button">
            <RefreshCw size={16} />
            Regenerate
          </button>
        </div>
      </div>

      {/* Stats - All Clickable with Deep Dive Modals */}
      <div className="grid grid-cols-4 gap-4">
        <button
          onClick={() => setActiveStatModal('components')}
          className="glass-card p-4 text-left transition-all hover:scale-105 hover:ring-2 hover:ring-joe-blue/50 cursor-pointer group"
          type="button"
        >
          <Package className="text-joe-blue mb-2 group-hover:scale-110 transition-transform" size={24} />
          <p className="text-2xl font-bold text-white">{mockComponents.length}</p>
          <p className="text-gray-400 text-sm">Total Components</p>
          <p className="text-joe-blue text-xs mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveStatModal('secure')}
          className="glass-card p-4 text-left transition-all hover:scale-105 hover:ring-2 hover:ring-dws-green/50 cursor-pointer group"
          type="button"
        >
          <Shield className="text-dws-green mb-2 group-hover:scale-110 transition-transform" size={24} />
          <p className="text-2xl font-bold text-dws-green">{secureCount}</p>
          <p className="text-gray-400 text-sm">Secure Components</p>
          <p className="text-dws-green text-xs mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveStatModal('cves')}
          className="glass-card p-4 text-left transition-all hover:scale-105 bg-alert-warning/5 border border-alert-warning/20 hover:ring-2 hover:ring-alert-warning/50 cursor-pointer group"
          type="button"
        >
          <AlertTriangle className="text-alert-warning mb-2 group-hover:scale-110 transition-transform" size={24} />
          <p className="text-2xl font-bold text-alert-warning">{totalVulns}</p>
          <p className="text-gray-400 text-sm">Total CVEs ({vulnerableCount} packages)</p>
          <p className="text-alert-warning text-xs mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveStatModal('format')}
          className="glass-card p-4 text-left transition-all hover:scale-105 hover:ring-2 hover:ring-gray-500/50 cursor-pointer group"
          type="button"
        >
          <FileJson className="text-gray-400 mb-2 group-hover:scale-110 transition-transform" size={24} />
          <p className="text-2xl font-bold text-white uppercase">{sbomFormat}</p>
          <p className="text-gray-400 text-sm">Output Format</p>
          <p className="text-gray-500 text-xs mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
      </div>

      {/* Filters */}
      <div className="glass-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="relative flex-1 min-w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
            <input
              type="text"
              placeholder="Search components..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-field pl-10"
              aria-label="Search components"
            />
          </div>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="input-field w-auto"
            aria-label="Filter by component type"
          >
            <option value="all">All Types</option>
            <option value="library">Libraries</option>
            <option value="framework">Frameworks</option>
            <option value="tool">Tools</option>
            <option value="runtime">Runtimes</option>
          </select>
        </div>
      </div>

      {/* Components Table */}
      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-dws-card/50">
            <tr className="text-left text-sm text-gray-400">
              <th className="p-4">Component</th>
              <th className="p-4">Version</th>
              <th className="p-4">Type</th>
              <th className="p-4">License</th>
              <th className="p-4">Vulnerabilities</th>
              <th className="p-4">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredComponents.map((component, index) => {
              const licenseRisk = getLicenseRisk(component.license);
              return (
                <motion.tr
                  key={component.name}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: index * 0.03 }}
                  className="border-t border-dws-border hover:bg-dws-card/30 transition-colors"
                >
                  <td className="p-4">
                    <div className="flex items-center gap-3">
                      <Package size={18} className="text-joe-blue" />
                      <div>
                        <span className="text-white font-medium">{component.name}</span>
                        {component.maintainer && (
                          <p className="text-gray-600 text-xs">{component.maintainer}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="p-4 text-gray-400 font-mono">{component.version}</td>
                  <td className="p-4">
                    <span className="badge badge-info capitalize">{component.type}</span>
                  </td>
                  <td className="p-4">
                    <span className={`font-mono text-sm ${licenseRisk.color}`}>{component.license}</span>
                  </td>
                  <td className="p-4">
                    {component.vulnerabilities > 0 ? (
                      <span className="badge badge-critical">{component.vulnerabilities} CVEs</span>
                    ) : (
                      <span className="badge badge-low">
                        <CheckCircle size={12} className="inline mr-1" />
                        Secure
                      </span>
                    )}
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => setSelectedComponent(component)}
                      className="p-2 hover:bg-dws-card rounded transition-colors"
                      type="button"
                      aria-label={`View details for ${component.name}`}
                    >
                      <Eye size={16} className="text-joe-blue" />
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Component Detail Modal */}
      <Modal
        isOpen={!!selectedComponent}
        onClose={() => setSelectedComponent(null)}
        title={selectedComponent?.name}
        subtitle={`v${selectedComponent?.version} | ${selectedComponent?.license}`}
        size="xl"
        headerIcon={<Package size={24} />}
        variant={selectedComponent?.vulnerabilities ? 'warning' : 'success'}
        footer={
          <div className="flex justify-between items-center">
            {selectedComponent?.repository && (
              <a
                href={selectedComponent.repository}
                target="_blank"
                rel="noopener noreferrer"
                className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
              >
                <GitBranch size={14} />
                View Repository <ExternalLink size={12} />
              </a>
            )}
            <button className="btn-primary" type="button" onClick={() => setSelectedComponent(null)}>
              Close
            </button>
          </div>
        }
      >
        {selectedComponent && (
          <div className="space-y-6">
            {/* Stats Row */}
            <div className="grid grid-cols-4 gap-4">
              <div className="glass-card p-4">
                <Package className="text-joe-blue mb-2" size={20} />
                <p className="text-gray-400 text-sm">Type</p>
                <p className="text-white font-medium capitalize">{selectedComponent.type}</p>
              </div>
              <div className="glass-card p-4">
                <Scale className={getLicenseRisk(selectedComponent.license).color} size={20} />
                <p className="text-gray-400 text-sm">License</p>
                <p className={`font-medium ${getLicenseRisk(selectedComponent.license).color}`}>
                  {selectedComponent.license}
                </p>
              </div>
              <div className="glass-card p-4">
                <Clock className="text-gray-400 mb-2" size={20} />
                <p className="text-gray-400 text-sm">Last Updated</p>
                <p className="text-white font-medium">{selectedComponent.lastUpdated || 'Unknown'}</p>
              </div>
              <div className={`glass-card p-4 ${selectedComponent.vulnerabilities > 0 ? 'bg-alert-critical/10 border border-alert-critical/30' : 'bg-dws-green/10 border border-dws-green/30'}`}>
                {selectedComponent.vulnerabilities > 0 ? (
                  <XCircle className="text-alert-critical mb-2" size={20} />
                ) : (
                  <CheckCircle className="text-dws-green mb-2" size={20} />
                )}
                <p className="text-gray-400 text-sm">Security Status</p>
                <p className={`font-medium ${selectedComponent.vulnerabilities > 0 ? 'text-alert-critical' : 'text-dws-green'}`}>
                  {selectedComponent.vulnerabilities > 0 ? `${selectedComponent.vulnerabilities} Vulnerabilities` : 'Secure'}
                </p>
              </div>
            </div>

            {/* Description */}
            {selectedComponent.description && (
              <div>
                <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                  <Info size={16} className="text-joe-blue" />
                  Description
                </h4>
                <p className="text-gray-300">{selectedComponent.description}</p>
              </div>
            )}

            {/* Dependencies */}
            {selectedComponent.dependencies && selectedComponent.dependencies.length > 0 && (
              <div>
                <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                  <GitBranch size={16} className="text-joe-blue" />
                  Dependencies ({selectedComponent.dependencies.length})
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedComponent.dependencies.map(dep => (
                    <span
                      key={dep}
                      className="px-3 py-1 text-sm bg-dws-dark rounded-lg text-gray-300 font-mono"
                    >
                      {dep}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Vulnerabilities */}
            {selectedComponent.cves && selectedComponent.cves.length > 0 && (
              <div>
                <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                  <AlertTriangle size={16} className="text-alert-critical" />
                  Known Vulnerabilities ({selectedComponent.cves.length})
                </h4>
                <div className="space-y-3">
                  {selectedComponent.cves.map(cve => (
                    <div
                      key={cve.id}
                      className="p-4 bg-alert-critical/10 border border-alert-critical/30 rounded-lg"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-joe-blue font-mono text-sm flex items-center gap-1 hover:underline"
                        >
                          {cve.id} <ExternalLink size={12} />
                        </a>
                        <span className={`badge ${cve.severity === 'high' ? 'badge-critical' : 'badge-medium'}`}>
                          {cve.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-300 text-sm">{cve.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation */}
            {selectedComponent.vulnerabilities > 0 && (
              <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
                <h4 className="font-semibold text-dws-green mb-2 flex items-center gap-2">
                  <CheckCircle size={16} />
                  Recommended Action
                </h4>
                <p className="text-gray-300">
                  Upgrade {selectedComponent.name} to the latest stable version to address known vulnerabilities.
                  Run: <code className="bg-dws-dark px-2 py-1 rounded font-mono text-sm">npm update {selectedComponent.name}</code>
                </p>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Total Components Deep Dive Modal */}
      <Modal
        isOpen={activeStatModal === 'components'}
        onClose={() => setActiveStatModal(null)}
        title="Component Inventory"
        subtitle={`${mockComponents.length} total components tracked`}
        size="lg"
        headerIcon={<Package size={24} />}
        variant="info"
      >
        <div className="space-y-6">
          {/* Type Breakdown */}
          <div>
            <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
              <Package size={16} className="text-joe-blue" />
              Component Types
            </h4>
            <div className="grid grid-cols-2 gap-3">
              {Object.entries(typeBreakdown).map(([type, count]) => (
                <div key={type} className="glass-card p-3 flex items-center justify-between">
                  <span className="text-gray-300 capitalize">{type}s</span>
                  <span className="text-white font-bold">{count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* License Summary */}
          <div>
            <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
              <Scale size={16} className="text-joe-blue" />
              License Distribution
            </h4>
            <div className="space-y-2">
              {Object.entries(licenseBreakdown).map(([license, count]) => (
                <div key={license} className="flex items-center justify-between py-2 border-b border-dws-border/30">
                  <span className={`font-mono text-sm ${getLicenseRisk(license).color}`}>{license}</span>
                  <span className="text-gray-400">{count} packages</span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="glass-card p-4 text-center">
              <p className="text-2xl font-bold text-dws-green">{secureCount}</p>
              <p className="text-gray-400 text-xs">Secure</p>
            </div>
            <div className="glass-card p-4 text-center">
              <p className="text-2xl font-bold text-alert-warning">{vulnerableCount}</p>
              <p className="text-gray-400 text-xs">Vulnerable</p>
            </div>
            <div className="glass-card p-4 text-center">
              <p className="text-2xl font-bold text-joe-blue">{Object.keys(licenseBreakdown).length}</p>
              <p className="text-gray-400 text-xs">Licenses</p>
            </div>
          </div>
        </div>
      </Modal>

      {/* Secure Components Deep Dive Modal */}
      <Modal
        isOpen={activeStatModal === 'secure'}
        onClose={() => setActiveStatModal(null)}
        title="Secure Components"
        subtitle={`${secureCount} components with no known vulnerabilities`}
        size="lg"
        headerIcon={<Shield size={24} />}
        variant="success"
      >
        <div className="space-y-4">
          <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
            <p className="text-dws-green flex items-center gap-2">
              <CheckCircle size={16} />
              All listed components have passed vulnerability scans
            </p>
          </div>
          <div className="space-y-2">
            {secureComponents.map(c => (
              <button
                key={c.name}
                onClick={() => { setActiveStatModal(null); setSelectedComponent(c); }}
                className="w-full glass-card p-4 flex items-center justify-between hover:bg-dws-card/50 transition-colors text-left"
                type="button"
              >
                <div className="flex items-center gap-3">
                  <Package size={18} className="text-dws-green" />
                  <div>
                    <span className="text-white font-medium">{c.name}</span>
                    <span className="text-gray-500 text-sm ml-2">v{c.version}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-sm ${getLicenseRisk(c.license).color}`}>{c.license}</span>
                  <Eye size={16} className="text-gray-500" />
                </div>
              </button>
            ))}
          </div>
        </div>
      </Modal>

      {/* CVE Deep Dive Modal */}
      <Modal
        isOpen={activeStatModal === 'cves'}
        onClose={() => setActiveStatModal(null)}
        title="Vulnerability Analysis"
        subtitle={`${totalVulns} CVEs across ${vulnerableCount} packages`}
        size="xl"
        headerIcon={<AlertTriangle size={24} />}
        variant="warning"
      >
        <div className="space-y-6">
          {/* Severity Breakdown */}
          <div className="grid grid-cols-3 gap-4">
            <div className="glass-card p-4 bg-alert-critical/10 border border-alert-critical/30">
              <p className="text-2xl font-bold text-alert-critical">
                {vulnerableComponents.reduce((sum, c) => sum + (c.cves?.filter(cve => cve.severity === 'high').length || 0), 0)}
              </p>
              <p className="text-gray-400 text-sm">High Severity</p>
            </div>
            <div className="glass-card p-4 bg-alert-warning/10 border border-alert-warning/30">
              <p className="text-2xl font-bold text-alert-warning">
                {vulnerableComponents.reduce((sum, c) => sum + (c.cves?.filter(cve => cve.severity === 'medium').length || 0), 0)}
              </p>
              <p className="text-gray-400 text-sm">Medium Severity</p>
            </div>
            <div className="glass-card p-4">
              <p className="text-2xl font-bold text-gray-400">
                {vulnerableComponents.reduce((sum, c) => sum + (c.cves?.filter(cve => cve.severity === 'low').length || 0), 0)}
              </p>
              <p className="text-gray-400 text-sm">Low Severity</p>
            </div>
          </div>

          {/* Vulnerable Packages */}
          <div>
            <h4 className="font-semibold text-white mb-3">Affected Packages</h4>
            <div className="space-y-4">
              {vulnerableComponents.map(c => (
                <div key={c.name} className="glass-card p-4 bg-alert-critical/5 border border-alert-critical/20">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Package size={18} className="text-alert-warning" />
                      <span className="text-white font-medium">{c.name}@{c.version}</span>
                    </div>
                    <span className="badge badge-critical">{c.vulnerabilities} CVEs</span>
                  </div>
                  {c.cves && (
                    <div className="space-y-2">
                      {c.cves.map(cve => (
                        <div key={cve.id} className="flex items-center justify-between py-2 border-t border-dws-border/30">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-joe-blue text-sm font-mono hover:underline flex items-center gap-1"
                          >
                            {cve.id} <ExternalLink size={10} />
                          </a>
                          <span className={`text-xs ${cve.severity === 'high' ? 'text-alert-critical' : 'text-alert-warning'}`}>
                            {cve.severity.toUpperCase()}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="mt-3 pt-3 border-t border-dws-border/30">
                    <p className="text-dws-green text-sm flex items-center gap-2">
                      <CheckCircle size={14} />
                      Fix: <code className="bg-dws-dark px-2 py-0.5 rounded">npm update {c.name}</code>
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      {/* SBOM Format Deep Dive Modal */}
      <Modal
        isOpen={activeStatModal === 'format'}
        onClose={() => setActiveStatModal(null)}
        title="SBOM Format Details"
        subtitle={`Current format: ${sbomFormat.toUpperCase()}`}
        size="lg"
        headerIcon={<FileJson size={24} />}
        variant="info"
      >
        <div className="space-y-6">
          {/* Format Comparison */}
          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={() => setSbomFormat('cyclonedx')}
              className={`glass-card p-4 text-left transition-all ${sbomFormat === 'cyclonedx' ? 'ring-2 ring-joe-blue bg-joe-blue/10' : 'hover:bg-dws-card/50'}`}
              type="button"
            >
              <h4 className="text-white font-semibold mb-2">CycloneDX 1.5</h4>
              <ul className="text-gray-400 text-sm space-y-1">
                <li>• OWASP Standard</li>
                <li>• Vulnerability tracking</li>
                <li>• Service definitions</li>
                <li>• Full dependency graph</li>
              </ul>
              {sbomFormat === 'cyclonedx' && (
                <p className="text-joe-blue text-xs mt-3 flex items-center gap-1">
                  <CheckCircle size={12} /> Currently selected
                </p>
              )}
            </button>
            <button
              onClick={() => setSbomFormat('spdx')}
              className={`glass-card p-4 text-left transition-all ${sbomFormat === 'spdx' ? 'ring-2 ring-joe-blue bg-joe-blue/10' : 'hover:bg-dws-card/50'}`}
              type="button"
            >
              <h4 className="text-white font-semibold mb-2">SPDX 2.3</h4>
              <ul className="text-gray-400 text-sm space-y-1">
                <li>• Linux Foundation</li>
                <li>• ISO/IEC 5962:2021</li>
                <li>• License compliance</li>
                <li>• Wide adoption</li>
              </ul>
              {sbomFormat === 'spdx' && (
                <p className="text-joe-blue text-xs mt-3 flex items-center gap-1">
                  <CheckCircle size={12} /> Currently selected
                </p>
              )}
            </button>
          </div>

          {/* Compliance Info */}
          <div className="p-4 bg-joe-blue/10 border border-joe-blue/30 rounded-lg">
            <h4 className="text-joe-blue font-semibold mb-2 flex items-center gap-2">
              <Info size={16} />
              Executive Order 14028 Compliance
            </h4>
            <p className="text-gray-300 text-sm">
              Both CycloneDX and SPDX formats meet the NTIA minimum elements for SBOM as required by
              Executive Order 14028 on Improving the Nation's Cybersecurity.
            </p>
          </div>

          {/* Export Options */}
          <div>
            <h4 className="text-white font-semibold mb-3">Export Options</h4>
            <div className="flex gap-3">
              <button
                onClick={() => { handleExport(); setActiveStatModal(null); }}
                className="btn-primary flex items-center gap-2"
                type="button"
              >
                <Download size={16} />
                Export {sbomFormat.toUpperCase()}
              </button>
              <button className="btn-secondary flex items-center gap-2" type="button">
                <RefreshCw size={16} />
                Regenerate SBOM
              </button>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
}
