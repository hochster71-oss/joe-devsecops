import { useState } from 'react';
import { motion } from 'framer-motion';
import Modal from '../common/Modal';
import {
  AlertTriangle,
  AlertCircle,
  Shield,
  Bug,
  Lock,
  Clock,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

/**
 * Threat Timeline Component
 *
 * Visualizes security events over time with interactive details.
 * Follows NIST SP 800-61 incident handling guidelines for event categorization.
 *
 * Reference: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
 */

interface ThreatEvent {
  id: string;
  timestamp: Date;
  type: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'vulnerability' | 'secret' | 'compliance' | 'malware' | 'access';
  title: string;
  description: string;
  source: string;
  affectedAssets: string[];
  status: 'open' | 'investigating' | 'resolved';
  remediation?: string;
  cveId?: string;
}

// Sample threat events data
const threatEvents: ThreatEvent[] = [
  {
    id: '1',
    timestamp: new Date(Date.now() - 1800000), // 30 min ago
    type: 'critical',
    category: 'vulnerability',
    title: 'SQL Injection Detected',
    description: 'Critical SQL injection vulnerability detected in user authentication endpoint. Immediate remediation required.',
    source: 'Semgrep',
    affectedAssets: ['src/api/auth.ts', 'src/api/users.ts'],
    status: 'open',
    remediation: 'Use parameterized queries or ORM with prepared statements. Apply input validation.',
    cveId: 'CWE-89'
  },
  {
    id: '2',
    timestamp: new Date(Date.now() - 3600000), // 1 hour ago
    type: 'critical',
    category: 'secret',
    title: 'API Key Exposed',
    description: 'Hardcoded AWS API key detected in source code. Key should be rotated immediately.',
    source: 'GitGuardian',
    affectedAssets: ['src/config/aws.ts'],
    status: 'investigating',
    remediation: 'Rotate the exposed key immediately. Move secrets to environment variables or secrets manager.'
  },
  {
    id: '3',
    timestamp: new Date(Date.now() - 7200000), // 2 hours ago
    type: 'high',
    category: 'vulnerability',
    title: 'Outdated Dependency',
    description: 'Critical vulnerability CVE-2021-23337 found in lodash@4.17.15. Prototype pollution possible.',
    source: 'Snyk',
    affectedAssets: ['package.json', 'package-lock.json'],
    status: 'open',
    remediation: 'Upgrade lodash to version 4.17.21 or later.',
    cveId: 'CVE-2021-23337'
  },
  {
    id: '4',
    timestamp: new Date(Date.now() - 14400000), // 4 hours ago
    type: 'medium',
    category: 'compliance',
    title: 'CMMC Control Deviation',
    description: 'Authentication policy does not meet CMMC Level 2 requirements for IA.L2-3.5.3.',
    source: 'Compliance Scanner',
    affectedAssets: ['Authentication System'],
    status: 'open',
    remediation: 'Implement multi-factor authentication for all privileged accounts.'
  },
  {
    id: '5',
    timestamp: new Date(Date.now() - 28800000), // 8 hours ago
    type: 'high',
    category: 'malware',
    title: 'Suspicious Container Image',
    description: 'Container image contains known vulnerable packages and potential crypto miner signatures.',
    source: 'Trivy',
    affectedAssets: ['Dockerfile', 'docker-compose.yml'],
    status: 'resolved',
    remediation: 'Rebuild container from verified base image. Remove suspicious packages.'
  },
  {
    id: '6',
    timestamp: new Date(Date.now() - 43200000), // 12 hours ago
    type: 'low',
    category: 'access',
    title: 'Failed Login Attempts',
    description: 'Multiple failed login attempts detected from unusual IP address.',
    source: 'SIEM',
    affectedAssets: ['Authentication Logs'],
    status: 'resolved',
    remediation: 'IP address blocked. User notified and password reset initiated.'
  }
];

const categoryIcons = {
  vulnerability: Bug,
  secret: Lock,
  compliance: Shield,
  malware: AlertTriangle,
  access: AlertCircle
};

const typeColors = {
  critical: { bg: 'bg-alert-critical', text: 'text-alert-critical', border: 'border-alert-critical' },
  high: { bg: 'bg-alert-high', text: 'text-alert-high', border: 'border-alert-high' },
  medium: { bg: 'bg-alert-warning', text: 'text-alert-warning', border: 'border-alert-warning' },
  low: { bg: 'bg-dws-green', text: 'text-dws-green', border: 'border-dws-green' },
  info: { bg: 'bg-joe-blue', text: 'text-joe-blue', border: 'border-joe-blue' }
};

const statusColors = {
  open: 'bg-alert-critical/10 text-alert-critical border-alert-critical/30',
  investigating: 'bg-alert-warning/10 text-alert-warning border-alert-warning/30',
  resolved: 'bg-dws-green/10 text-dws-green border-dws-green/30'
};

export default function ThreatTimeline() {
  const [selectedEvent, setSelectedEvent] = useState<ThreatEvent | null>(null);
  const [filter, setFilter] = useState<'all' | 'open' | 'critical'>('all');

  const filteredEvents = threatEvents.filter(event => {
    if (filter === 'open') {return event.status !== 'resolved';}
    if (filter === 'critical') {return event.type === 'critical' || event.type === 'high';}
    return true;
  });

  const formatTimeAgo = (date: Date) => {
    const diff = Date.now() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    if (hours > 0) {return `${hours}h ago`;}
    return `${minutes}m ago`;
  };

  return (
    <div className="space-y-4">
      {/* Header with filters */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="text-joe-blue" size={20} />
          <span className="font-medium text-white">Threat Timeline</span>
        </div>
        <div className="flex gap-2">
          {(['all', 'open', 'critical'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 text-xs rounded-full transition-colors ${
                filter === f
                  ? 'bg-joe-blue text-white'
                  : 'bg-dws-card text-gray-400 hover:bg-dws-elevated'
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Timeline */}
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-dws-border" />

        {/* Events */}
        <div className="space-y-4">
          {filteredEvents.map((event, index) => {
            const colors = typeColors[event.type];
            const Icon = categoryIcons[event.category];

            return (
              <motion.div
                key={event.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="relative pl-10"
              >
                {/* Timeline dot */}
                <motion.div
                  className={`absolute left-2 w-5 h-5 rounded-full ${colors.bg} flex items-center justify-center`}
                  animate={event.status === 'open' && event.type === 'critical' ? {
                    scale: [1, 1.2, 1],
                    boxShadow: ['0 0 0 0 rgba(255,51,102,0.4)', '0 0 0 8px rgba(255,51,102,0)', '0 0 0 0 rgba(255,51,102,0)']
                  } : {}}
                  transition={{ duration: 2, repeat: event.status === 'open' ? Infinity : 0 }}
                >
                  <Icon size={12} className="text-white" />
                </motion.div>

                {/* Event Card */}
                <button
                  onClick={() => setSelectedEvent(event)}
                  className={`
                    w-full text-left p-4 rounded-lg
                    bg-dws-card/50 border ${colors.border}/30
                    hover:bg-dws-card hover:border-${colors.border}
                    transition-all duration-200 group
                  `}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-medium uppercase ${colors.text}`}>
                          {event.type}
                        </span>
                        <span className="text-gray-600">|</span>
                        <span className="text-xs text-gray-500">{event.source}</span>
                      </div>
                      <p className="text-white font-medium truncate">{event.title}</p>
                      <p className="text-gray-500 text-xs mt-1">{formatTimeAgo(event.timestamp)}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs rounded-full border ${statusColors[event.status]}`}>
                        {event.status}
                      </span>
                      <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={16} />
                    </div>
                  </div>
                </button>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Event Detail Modal */}
      <Modal
        isOpen={!!selectedEvent}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent?.title}
        subtitle={`${selectedEvent?.source} | ${selectedEvent?.timestamp.toLocaleString()}`}
        size="lg"
        headerIcon={selectedEvent && <Icon component={categoryIcons[selectedEvent.category]} size={24} />}
        variant={selectedEvent?.type === 'critical' ? 'critical' : selectedEvent?.type === 'high' ? 'warning' : 'info'}
        footer={
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {selectedEvent?.cveId && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${selectedEvent.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
                >
                  {selectedEvent.cveId} <ExternalLink size={14} />
                </a>
              )}
            </div>
            <div className="flex items-center gap-3">
              {selectedEvent?.status === 'open' && (
                <button className="btn-secondary">Mark Investigating</button>
              )}
              {selectedEvent?.status !== 'resolved' && (
                <button className="btn-primary">Mark Resolved</button>
              )}
            </div>
          </div>
        }
      >
        {selectedEvent && (
          <div className="space-y-6">
            {/* Status and Type */}
            <div className="flex items-center gap-4">
              <span className={`px-3 py-1 text-sm rounded-full border ${statusColors[selectedEvent.status]}`}>
                Status: {selectedEvent.status.charAt(0).toUpperCase() + selectedEvent.status.slice(1)}
              </span>
              <span className={`px-3 py-1 text-sm rounded-full ${typeColors[selectedEvent.type].bg}/20 ${typeColors[selectedEvent.type].text} border ${typeColors[selectedEvent.type].border}/30`}>
                Severity: {selectedEvent.type.toUpperCase()}
              </span>
            </div>

            {/* Description */}
            <div>
              <h4 className="font-semibold text-white mb-2">Description</h4>
              <p className="text-gray-300">{selectedEvent.description}</p>
            </div>

            {/* Affected Assets */}
            <div>
              <h4 className="font-semibold text-white mb-2">Affected Assets</h4>
              <div className="space-y-2">
                {selectedEvent.affectedAssets.map(asset => (
                  <div
                    key={asset}
                    className="px-3 py-2 bg-dws-dark rounded-lg font-mono text-sm text-gray-300"
                  >
                    {asset}
                  </div>
                ))}
              </div>
            </div>

            {/* Remediation */}
            {selectedEvent.remediation && (
              <div>
                <h4 className="font-semibold text-white mb-2">Recommended Remediation</h4>
                <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
                  <p className="text-gray-300">{selectedEvent.remediation}</p>
                </div>
              </div>
            )}

            {/* Timeline */}
            <div>
              <h4 className="font-semibold text-white mb-2">Event Timeline</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-3 text-gray-400">
                  <div className="w-2 h-2 rounded-full bg-joe-blue" />
                  <span>Detected: {selectedEvent.timestamp.toLocaleString()}</span>
                </div>
                {selectedEvent.status !== 'open' && (
                  <div className="flex items-center gap-3 text-gray-400">
                    <div className="w-2 h-2 rounded-full bg-alert-warning" />
                    <span>Investigation started</span>
                  </div>
                )}
                {selectedEvent.status === 'resolved' && (
                  <div className="flex items-center gap-3 text-gray-400">
                    <div className="w-2 h-2 rounded-full bg-dws-green" />
                    <span>Resolved</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

// Helper component for dynamic icons
function Icon({ component: IconComponent, size }: { component: typeof AlertTriangle; size: number }) {
  return <IconComponent size={size} />;
}
