import { useState } from 'react';
import { motion } from 'framer-motion';
import Modal, { ConfirmModal } from '../components/common/Modal';
import {
  FileText,
  Download,
  Calendar,
  Filter,
  Plus,
  Eye,
  Trash2,
  Shield,
  Package,
  ClipboardCheck,
  BarChart3,
  CheckCircle,
  AlertTriangle,
  Clock,
  FileCode,
  Printer,
  Mail,
  ExternalLink
} from 'lucide-react';

interface Report {
  id: string;
  name: string;
  type: 'vulnerability' | 'compliance' | 'sbom' | 'executive';
  date: string;
  size: string;
  status: 'complete' | 'generating' | 'failed';
  summary: {
    totalFindings?: number;
    criticalFindings?: number;
    complianceScore?: number;
    componentsScanned?: number;
    riskLevel?: string;
  };
  sections: string[];
  generatedBy: string;
}

const mockReports: Report[] = [
  {
    id: '1',
    name: 'Security Scan Report',
    type: 'vulnerability',
    date: '2024-12-10',
    size: '2.4 MB',
    status: 'complete',
    summary: { totalFindings: 8, criticalFindings: 1, riskLevel: 'Medium' },
    sections: ['Executive Summary', 'Critical Findings', 'High Findings', 'Remediation Plan', 'Appendix'],
    generatedBy: 'Michael Hoch'
  },
  {
    id: '2',
    name: 'CMMC Compliance Audit',
    type: 'compliance',
    date: '2024-12-09',
    size: '1.8 MB',
    status: 'complete',
    summary: { complianceScore: 75, totalFindings: 12 },
    sections: ['Compliance Score', 'Control Assessment', 'Gap Analysis', 'Remediation Roadmap'],
    generatedBy: 'Michael Hoch'
  },
  {
    id: '3',
    name: 'SBOM Export - CycloneDX',
    type: 'sbom',
    date: '2024-12-08',
    size: '856 KB',
    status: 'complete',
    summary: { componentsScanned: 847 },
    sections: ['Component List', 'License Summary', 'Vulnerability Mapping', 'Dependency Graph'],
    generatedBy: 'J.O.E. Auto-Generate'
  },
  {
    id: '4',
    name: 'Executive Risk Summary',
    type: 'executive',
    date: '2024-12-07',
    size: '542 KB',
    status: 'complete',
    summary: { riskLevel: 'Medium', complianceScore: 75, criticalFindings: 1 },
    sections: ['Risk Overview', 'Key Metrics', 'Trend Analysis', 'Recommendations'],
    generatedBy: 'Michael Hoch'
  },
  {
    id: '5',
    name: 'Container Security Report',
    type: 'vulnerability',
    date: '2024-12-05',
    size: '1.2 MB',
    status: 'complete',
    summary: { totalFindings: 3, criticalFindings: 0, riskLevel: 'Low' },
    sections: ['Image Analysis', 'Layer Vulnerabilities', 'Base Image Assessment', 'Recommendations'],
    generatedBy: 'Joseph Scholer'
  }
];

// Report generation templates
const reportTemplates = {
  'Executive Summary': {
    icon: BarChart3,
    description: 'High-level overview for leadership with key metrics and recommendations',
    estimatedTime: '30 seconds',
    sections: ['Risk Overview', 'Key Metrics', 'Trend Analysis', 'Recommendations']
  },
  'Vulnerability Report': {
    icon: Shield,
    description: 'Detailed security findings from all scanners with remediation guidance',
    estimatedTime: '1-2 minutes',
    sections: ['Executive Summary', 'Critical Findings', 'Detailed Analysis', 'Remediation Plan']
  },
  'Compliance Audit': {
    icon: ClipboardCheck,
    description: 'CMMC 2.0 compliance assessment with evidence and gap analysis',
    estimatedTime: '2-3 minutes',
    sections: ['Compliance Score', 'Control Assessment', 'Evidence Documentation', 'Remediation Roadmap']
  },
  'SBOM Export': {
    icon: Package,
    description: 'Software Bill of Materials in CycloneDX or SPDX format',
    estimatedTime: '15 seconds',
    sections: ['Component Inventory', 'License Summary', 'Vulnerability Correlation', 'Dependency Tree']
  }
};

export default function ReportsView() {
  const [selectedType, setSelectedType] = useState('all');
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [reportToDelete, setReportToDelete] = useState<Report | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportMessage, setExportMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Handle download/export
  const handleDownloadReport = async (report: Report) => {
    if (!window.electronAPI?.export) {
      setExportMessage({ type: 'error', text: 'Export not available in browser mode' });
      setTimeout(() => setExportMessage(null), 3000);
      return;
    }

    setIsExporting(true);
    setExportMessage(null);

    try {
      const result = await window.electronAPI.export.savePDF({
        title: `Save ${report.name}`,
        defaultPath: `${report.name.replace(/\s+/g, '-')}-${report.date}.pdf`,
        reportData: {
          reportType: report.type,
          reportName: report.name,
          sections: report.sections,
          summary: report.summary,
          generatedBy: report.generatedBy,
          date: report.date
        }
      });

      if (result.success) {
        setExportMessage({ type: 'success', text: `Report saved successfully!` });
      } else if (result.error !== 'Export cancelled') {
        setExportMessage({ type: 'error', text: result.error || 'Export failed' });
      }
    } catch (error) {
      setExportMessage({
        type: 'error',
        text: error instanceof Error ? error.message : 'Export failed'
      });
    } finally {
      setIsExporting(false);
      setTimeout(() => setExportMessage(null), 5000);
    }
  };

  const filteredReports = selectedType === 'all'
    ? mockReports
    : mockReports.filter(r => r.type === selectedType);

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'vulnerability': return 'bg-alert-critical/10 text-alert-critical border-alert-critical/30';
      case 'compliance': return 'bg-joe-blue/10 text-joe-blue border-joe-blue/30';
      case 'sbom': return 'bg-dws-green/10 text-dws-green border-dws-green/30';
      case 'executive': return 'bg-alert-warning/10 text-alert-warning border-alert-warning/30';
      default: return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'vulnerability': return Shield;
      case 'compliance': return ClipboardCheck;
      case 'sbom': return Package;
      case 'executive': return BarChart3;
      default: return FileText;
    }
  };

  const handleGenerateReport = () => {
    setIsGenerating(true);
    setTimeout(() => {
      setIsGenerating(false);
      setSelectedTemplate(null);
    }, 2000);
  };

  // Stats
  const stats = {
    total: mockReports.length,
    vulnerability: mockReports.filter(r => r.type === 'vulnerability').length,
    compliance: mockReports.filter(r => r.type === 'compliance').length,
    sbom: mockReports.filter(r => r.type === 'sbom').length
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-joe-blue/10 border border-joe-blue/30">
            <FileText className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">Reports</h1>
            <p className="text-gray-400 mt-1">Generate and manage security reports</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setSelectedTemplate('Executive Summary')}
          className="btn-primary flex items-center gap-2"
        >
          <Plus size={16} />
          Generate Report
        </button>
      </div>

      {/* Export Message Banner */}
      {exportMessage && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-lg flex items-center gap-3 ${
            exportMessage.type === 'success'
              ? 'bg-dws-green/20 border border-dws-green/30'
              : 'bg-alert-critical/20 border border-alert-critical/30'
          }`}
        >
          {exportMessage.type === 'success' ? (
            <CheckCircle className="text-dws-green" size={20} />
          ) : (
            <AlertTriangle className="text-alert-critical" size={20} />
          )}
          <span className={exportMessage.type === 'success' ? 'text-dws-green' : 'text-alert-critical'}>
            {exportMessage.text}
          </span>
        </motion.div>
      )}

      {/* Stats Cards - Clickable */}
      <div className="grid grid-cols-4 gap-4">
        <motion.button
          type="button"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          onClick={() => setSelectedType('all')}
          className={`glass-card p-4 text-left transition-all ${selectedType === 'all' ? 'ring-2 ring-joe-blue' : ''}`}
        >
          <div className="flex items-center gap-3">
            <FileText className="text-joe-blue" size={20} />
            <div>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
              <p className="text-gray-500 text-sm">Total Reports</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          type="button"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          onClick={() => setSelectedType('vulnerability')}
          className={`glass-card p-4 text-left transition-all bg-alert-critical/5 ${selectedType === 'vulnerability' ? 'ring-2 ring-alert-critical' : ''}`}
        >
          <div className="flex items-center gap-3">
            <Shield className="text-alert-critical" size={20} />
            <div>
              <p className="text-2xl font-bold text-alert-critical">{stats.vulnerability}</p>
              <p className="text-gray-500 text-sm">Vulnerability</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          type="button"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          onClick={() => setSelectedType('compliance')}
          className={`glass-card p-4 text-left transition-all bg-joe-blue/5 ${selectedType === 'compliance' ? 'ring-2 ring-joe-blue' : ''}`}
        >
          <div className="flex items-center gap-3">
            <ClipboardCheck className="text-joe-blue" size={20} />
            <div>
              <p className="text-2xl font-bold text-joe-blue">{stats.compliance}</p>
              <p className="text-gray-500 text-sm">Compliance</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          type="button"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          onClick={() => setSelectedType('sbom')}
          className={`glass-card p-4 text-left transition-all bg-dws-green/5 ${selectedType === 'sbom' ? 'ring-2 ring-dws-green' : ''}`}
        >
          <div className="flex items-center gap-3">
            <Package className="text-dws-green" size={20} />
            <div>
              <p className="text-2xl font-bold text-dws-green">{stats.sbom}</p>
              <p className="text-gray-500 text-sm">SBOM</p>
            </div>
          </div>
        </motion.button>
      </div>

      {/* Quick Generate - Clickable */}
      <div className="glass-card p-6">
        <h3 className="font-heading font-semibold text-white mb-4 flex items-center gap-2">
          <Plus className="text-joe-blue" size={20} />
          Quick Generate
        </h3>
        <p className="text-gray-500 text-sm mb-4">Click a report type to configure and generate</p>
        <div className="grid grid-cols-4 gap-4">
          {Object.entries(reportTemplates).map(([name, template]) => {
            const Icon = template.icon;
            return (
              <button
                key={name}
                type="button"
                onClick={() => setSelectedTemplate(name)}
                className="btn-secondary flex flex-col items-center gap-2 py-4 hover:border-joe-blue/50 hover:bg-joe-blue/10 transition-colors"
              >
                <Icon size={24} className="text-joe-blue" />
                <span className="text-sm">{name}</span>
                <span className="text-xs text-gray-500">{template.estimatedTime}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex items-center gap-4">
        <Filter size={18} className="text-gray-500" />
        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
          className="input-field w-auto"
          aria-label="Filter reports by type"
        >
          <option value="all">All Types</option>
          <option value="vulnerability">Vulnerability ({stats.vulnerability})</option>
          <option value="compliance">Compliance ({stats.compliance})</option>
          <option value="sbom">SBOM ({stats.sbom})</option>
          <option value="executive">Executive</option>
        </select>
      </div>

      {/* Reports Table - Clickable rows */}
      <div className="glass-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-dws-card/50">
            <tr className="text-left text-sm text-gray-400">
              <th className="p-4">Report Name</th>
              <th className="p-4">Type</th>
              <th className="p-4">Date</th>
              <th className="p-4">Size</th>
              <th className="p-4">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredReports.map((report, index) => {
              const TypeIcon = getTypeIcon(report.type);
              return (
                <motion.tr
                  key={report.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: index * 0.05 }}
                  onClick={() => setSelectedReport(report)}
                  className="border-t border-dws-border hover:bg-dws-card/30 transition-colors cursor-pointer"
                >
                  <td className="p-4">
                    <div className="flex items-center gap-3">
                      <TypeIcon size={18} className="text-joe-blue" />
                      <span className="text-white">{report.name}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className={`badge border ${getTypeColor(report.type)} capitalize`}>
                      {report.type}
                    </span>
                  </td>
                  <td className="p-4 text-gray-400">
                    <div className="flex items-center gap-2">
                      <Calendar size={14} />
                      {report.date}
                    </div>
                  </td>
                  <td className="p-4 text-gray-400">{report.size}</td>
                  <td className="p-4">
                    <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => setSelectedReport(report)}
                        className="p-2 hover:bg-dws-card rounded transition-colors"
                        title="View"
                      >
                        <Eye size={16} className="text-gray-400 hover:text-joe-blue" />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDownloadReport(report)}
                        disabled={isExporting}
                        className="p-2 hover:bg-dws-card rounded transition-colors disabled:opacity-50"
                        title="Download"
                      >
                        <Download size={16} className={isExporting ? "text-gray-500 animate-pulse" : "text-joe-blue"} />
                      </button>
                      <button
                        type="button"
                        onClick={() => setReportToDelete(report)}
                        className="p-2 hover:bg-dws-card rounded transition-colors"
                        title="Delete"
                      >
                        <Trash2 size={16} className="text-alert-critical" />
                      </button>
                    </div>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Report Preview Modal */}
      <Modal
        isOpen={!!selectedReport}
        onClose={() => setSelectedReport(null)}
        title={selectedReport?.name}
        subtitle={`Generated on ${selectedReport?.date} by ${selectedReport?.generatedBy}`}
        size="xl"
        headerIcon={selectedReport && <FileText size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button type="button" className="btn-secondary flex items-center gap-2">
                <Printer size={16} />
                Print
              </button>
              <button type="button" className="btn-secondary flex items-center gap-2">
                <Mail size={16} />
                Email
              </button>
            </div>
            <div className="flex items-center gap-3">
              <button type="button" onClick={() => setSelectedReport(null)} className="btn-secondary">
                Close
              </button>
              <button
                type="button"
                onClick={() => selectedReport && handleDownloadReport(selectedReport)}
                disabled={isExporting}
                className="btn-primary flex items-center gap-2"
              >
                {isExporting ? (
                  <>
                    <Download size={16} className="animate-pulse" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Download size={16} />
                    Download PDF
                  </>
                )}
              </button>
            </div>
          </div>
        }
      >
        {selectedReport && (
          <div className="space-y-6">
            {/* Report Summary */}
            <div className="grid grid-cols-4 gap-4">
              {selectedReport.summary.totalFindings !== undefined && (
                <div className="glass-card p-4">
                  <AlertTriangle className="text-alert-warning mb-2" size={20} />
                  <p className="text-2xl font-bold text-white">{selectedReport.summary.totalFindings}</p>
                  <p className="text-gray-500 text-sm">Total Findings</p>
                </div>
              )}
              {selectedReport.summary.criticalFindings !== undefined && (
                <div className="glass-card p-4">
                  <Shield className={selectedReport.summary.criticalFindings > 0 ? 'text-alert-critical' : 'text-dws-green'} size={20} />
                  <p className={`text-2xl font-bold ${selectedReport.summary.criticalFindings > 0 ? 'text-alert-critical' : 'text-dws-green'}`}>
                    {selectedReport.summary.criticalFindings}
                  </p>
                  <p className="text-gray-500 text-sm">Critical</p>
                </div>
              )}
              {selectedReport.summary.complianceScore !== undefined && (
                <div className="glass-card p-4">
                  <ClipboardCheck className="text-joe-blue mb-2" size={20} />
                  <p className="text-2xl font-bold text-joe-blue">{selectedReport.summary.complianceScore}%</p>
                  <p className="text-gray-500 text-sm">Compliance</p>
                </div>
              )}
              {selectedReport.summary.componentsScanned !== undefined && (
                <div className="glass-card p-4">
                  <Package className="text-dws-green mb-2" size={20} />
                  <p className="text-2xl font-bold text-dws-green">{selectedReport.summary.componentsScanned}</p>
                  <p className="text-gray-500 text-sm">Components</p>
                </div>
              )}
              {selectedReport.summary.riskLevel && (
                <div className="glass-card p-4">
                  <BarChart3 className="text-alert-warning mb-2" size={20} />
                  <p className={`text-2xl font-bold ${
                    selectedReport.summary.riskLevel === 'High' ? 'text-alert-critical' :
                    selectedReport.summary.riskLevel === 'Medium' ? 'text-alert-warning' : 'text-dws-green'
                  }`}>
                    {selectedReport.summary.riskLevel}
                  </p>
                  <p className="text-gray-500 text-sm">Risk Level</p>
                </div>
              )}
            </div>

            {/* Report Sections */}
            <div>
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <FileCode size={16} className="text-joe-blue" />
                Report Sections
              </h4>
              <div className="space-y-2">
                {selectedReport.sections.map((section, i) => (
                  <div key={section} className="flex items-center gap-3 p-3 bg-dws-dark rounded-lg hover:bg-dws-elevated transition-colors cursor-pointer">
                    <span className="w-6 h-6 rounded-full bg-joe-blue/20 flex items-center justify-center text-xs font-bold text-joe-blue">
                      {i + 1}
                    </span>
                    <span className="text-gray-300">{section}</span>
                    <ExternalLink size={14} className="text-gray-600 ml-auto" />
                  </div>
                ))}
              </div>
            </div>

            {/* Report Info */}
            <div className="grid grid-cols-3 gap-4 pt-4 border-t border-dws-border">
              <div>
                <p className="text-gray-500 text-sm">File Size</p>
                <p className="text-white font-medium">{selectedReport.size}</p>
              </div>
              <div>
                <p className="text-gray-500 text-sm">Format</p>
                <p className="text-white font-medium">PDF</p>
              </div>
              <div>
                <p className="text-gray-500 text-sm">Generated By</p>
                <p className="text-white font-medium">{selectedReport.generatedBy}</p>
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Generate Report Modal */}
      <Modal
        isOpen={!!selectedTemplate}
        onClose={() => setSelectedTemplate(null)}
        title={`Generate ${selectedTemplate}`}
        subtitle="Configure and generate a new report"
        size="lg"
        headerIcon={selectedTemplate && reportTemplates[selectedTemplate as keyof typeof reportTemplates] &&
          (() => { const Icon = reportTemplates[selectedTemplate as keyof typeof reportTemplates].icon; return <Icon size={24} />; })()
        }
        variant="info"
        footer={
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-sm flex items-center gap-2">
              <Clock size={14} />
              Est. time: {selectedTemplate && reportTemplates[selectedTemplate as keyof typeof reportTemplates]?.estimatedTime}
            </span>
            <div className="flex items-center gap-3">
              <button type="button" onClick={() => setSelectedTemplate(null)} className="btn-secondary">
                Cancel
              </button>
              <button
                type="button"
                onClick={handleGenerateReport}
                disabled={isGenerating}
                className="btn-primary flex items-center gap-2"
              >
                {isGenerating ? (
                  <>
                    <Clock size={16} className="animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Plus size={16} />
                    Generate Report
                  </>
                )}
              </button>
            </div>
          </div>
        }
      >
        {selectedTemplate && reportTemplates[selectedTemplate as keyof typeof reportTemplates] && (
          <div className="space-y-6">
            {/* Description */}
            <div className="p-4 bg-joe-blue/10 border border-joe-blue/30 rounded-lg">
              <p className="text-gray-300">
                {reportTemplates[selectedTemplate as keyof typeof reportTemplates].description}
              </p>
            </div>

            {/* Sections to Include */}
            <div>
              <h4 className="font-semibold text-white mb-3">Sections Included</h4>
              <div className="grid grid-cols-2 gap-2">
                {reportTemplates[selectedTemplate as keyof typeof reportTemplates].sections.map(section => (
                  <div key={section} className="flex items-center gap-2 p-2 bg-dws-dark rounded">
                    <CheckCircle size={14} className="text-dws-green" />
                    <span className="text-gray-300 text-sm">{section}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Options */}
            <div>
              <h4 className="font-semibold text-white mb-3">Export Options</h4>
              <div className="grid grid-cols-3 gap-3">
                {['PDF', 'HTML', 'JSON'].map(format => (
                  <label key={format} className="flex items-center gap-2 p-3 bg-dws-dark rounded-lg cursor-pointer hover:bg-dws-elevated transition-colors">
                    <input
                      type="radio"
                      name="format"
                      defaultChecked={format === 'PDF'}
                      className="text-joe-blue"
                    />
                    <span className="text-gray-300">{format}</span>
                  </label>
                ))}
              </div>
            </div>

            {isGenerating && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg text-center"
              >
                <div className="w-8 h-8 border-2 border-dws-green border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                <p className="text-dws-green font-medium">Generating report...</p>
                <p className="text-gray-500 text-sm">This may take a moment</p>
              </motion.div>
            )}
          </div>
        )}
      </Modal>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={!!reportToDelete}
        onClose={() => setReportToDelete(null)}
        onConfirm={() => setReportToDelete(null)}
        title="Delete Report"
        message={`Are you sure you want to delete "${reportToDelete?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        variant="danger"
      />
    </div>
  );
}
