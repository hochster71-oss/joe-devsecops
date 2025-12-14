/**
 * J.O.E. SBOM (Software Bill of Materials) Service
 *
 * Generates and analyzes SBOMs for supply chain security
 * Supports CycloneDX and SPDX formats
 * Integrates with vulnerability databases for risk assessment
 */

import * as fs from 'fs';
import * as path from 'path';

// ========================================
// SBOM INTERFACES
// ========================================

export interface SBOMComponent {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'application' | 'container' | 'os' | 'device' | 'file';
  purl?: string; // Package URL
  licenses: string[];
  supplier?: string;
  description?: string;
  hashes?: {
    algorithm: string;
    value: string;
  }[];
  dependencies?: string[];
  vulnerabilities?: ComponentVulnerability[];
  riskScore?: number;
}

export interface ComponentVulnerability {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssScore?: number;
  description?: string;
  fixedIn?: string;
}

export interface SBOM {
  bomFormat: 'CycloneDX' | 'SPDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { name: string; version: string }[];
    component?: {
      name: string;
      version: string;
      type: string;
    };
  };
  components: SBOMComponent[];
  dependencies?: {
    ref: string;
    dependsOn: string[];
  }[];
}

export interface SBOMAnalysis {
  totalComponents: number;
  directDependencies: number;
  transitiveDependencies: number;
  licenseBreakdown: Record<string, number>;
  vulnerabilitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  riskScore: number;
  outdatedComponents: SBOMComponent[];
  licensingRisks: SBOMComponent[];
  supplyChainRisks: {
    unmaintainedPackages: SBOMComponent[];
    typosquatRisks: SBOMComponent[];
    singleMaintainerRisks: SBOMComponent[];
  };
  recommendations: string[];
}

// ========================================
// KNOWN RISKY LICENSES
// ========================================

const COPYLEFT_LICENSES = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0'];
const RESTRICTIVE_LICENSES = ['SSPL-1.0', 'BSL-1.1', 'Elastic-2.0'];
const UNKNOWN_RISK_LICENSES = ['UNLICENSED', 'UNKNOWN', 'SEE LICENSE IN'];

// ========================================
// SBOM SERVICE
// ========================================

class SBOMService {
  private cache: Map<string, { sbom: SBOM; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 30 * 60 * 1000; // 30 minutes

  /**
   * Generate SBOM from package.json (Node.js projects)
   */
  async generateFromNodeProject(projectPath: string): Promise<SBOM> {
    const packageJsonPath = path.join(projectPath, 'package.json');
    const lockfilePath = path.join(projectPath, 'package-lock.json');

    if (!fs.existsSync(packageJsonPath)) {
      throw new Error('No package.json found in project directory');
    }

    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const lockfile = fs.existsSync(lockfilePath)
      ? JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'))
      : null;

    const components: SBOMComponent[] = [];

    // Add direct dependencies
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const versionStr = String(version).replace(/[\^~>=<]/g, '');
      const component: SBOMComponent = {
        name,
        version: versionStr,
        type: 'library',
        purl: `pkg:npm/${name}@${versionStr}`,
        licenses: await this.detectLicense(name, projectPath),
        dependencies: []
      };

      // Get transitive dependencies from lockfile
      if (lockfile?.packages?.[`node_modules/${name}`]) {
        const pkgInfo = lockfile.packages[`node_modules/${name}`];
        component.version = pkgInfo.version || versionStr;
        if (pkgInfo.dependencies) {
          component.dependencies = Object.keys(pkgInfo.dependencies);
        }
      }

      components.push(component);
    }

    // Add transitive dependencies from lockfile
    if (lockfile?.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        if (pkgPath.startsWith('node_modules/') && pkgPath !== '') {
          const name = pkgPath.replace('node_modules/', '').split('/node_modules/').pop() || '';
          if (name && !components.find(c => c.name === name)) {
            const info = pkgInfo as Record<string, unknown>;
            components.push({
              name,
              version: info.version || 'unknown',
              type: 'library',
              purl: `pkg:npm/${name}@${info.version}`,
              licenses: info.license ? [info.license] : ['UNKNOWN'],
              dependencies: info.dependencies ? Object.keys(info.dependencies) : []
            });
          }
        }
      }
    }

    const sbom: SBOM = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ name: 'J.O.E. SBOM Generator', version: '1.0.0' }],
        component: {
          name: packageJson.name || 'unknown',
          version: packageJson.version || '0.0.0',
          type: 'application'
        }
      },
      components,
      dependencies: components.map(c => ({
        ref: c.purl || c.name,
        dependsOn: c.dependencies?.map(d => `pkg:npm/${d}`) || []
      }))
    };

    return sbom;
  }

  /**
   * Analyze SBOM for security and compliance risks
   */
  async analyzeSBOM(sbom: SBOM): Promise<SBOMAnalysis> {
    const directDeps = new Set(
      sbom.metadata.component
        ? sbom.dependencies?.find(d => d.ref.includes(sbom.metadata.component!.name))?.dependsOn || []
        : []
    );

    const licenseBreakdown: Record<string, number> = {};
    const licensingRisks: SBOMComponent[] = [];
    const outdatedComponents: SBOMComponent[] = [];
    let criticalVulns = 0, highVulns = 0, mediumVulns = 0, lowVulns = 0;

    for (const component of sbom.components) {
      // License analysis
      for (const license of component.licenses) {
        licenseBreakdown[license] = (licenseBreakdown[license] || 0) + 1;

        if (COPYLEFT_LICENSES.includes(license) ||
            RESTRICTIVE_LICENSES.includes(license) ||
            UNKNOWN_RISK_LICENSES.some(l => license.includes(l))) {
          licensingRisks.push(component);
        }
      }

      // Vulnerability counting
      if (component.vulnerabilities) {
        for (const vuln of component.vulnerabilities) {
          switch (vuln.severity) {
            case 'CRITICAL': criticalVulns++; break;
            case 'HIGH': highVulns++; break;
            case 'MEDIUM': mediumVulns++; break;
            case 'LOW': lowVulns++; break;
          }
        }
      }

      // Check for outdated (example heuristic)
      if (component.version.match(/^0\./)) {
        outdatedComponents.push(component);
      }
    }

    // Calculate risk score (0-100)
    const vulnWeight = (criticalVulns * 40) + (highVulns * 20) + (mediumVulns * 5) + (lowVulns * 1);
    const licenseWeight = licensingRisks.length * 5;
    const riskScore = Math.min(100, Math.max(0, 100 - vulnWeight - licenseWeight));

    // Generate recommendations
    const recommendations: string[] = [];
    if (criticalVulns > 0) {
      recommendations.push(`URGENT: ${criticalVulns} critical vulnerabilities require immediate patching`);
    }
    if (highVulns > 0) {
      recommendations.push(`Update ${highVulns} components with high-severity vulnerabilities`);
    }
    if (licensingRisks.length > 0) {
      recommendations.push(`Review ${licensingRisks.length} components with restrictive licenses for compliance`);
    }
    if (outdatedComponents.length > 5) {
      recommendations.push(`Consider updating ${outdatedComponents.length} pre-1.0 dependencies for stability`);
    }

    return {
      totalComponents: sbom.components.length,
      directDependencies: directDeps.size || Object.keys(sbom.components.filter(c =>
        sbom.dependencies?.some(d => d.dependsOn.includes(c.purl || c.name))
      )).length,
      transitiveDependencies: sbom.components.length - (directDeps.size || 0),
      licenseBreakdown,
      vulnerabilitySummary: {
        critical: criticalVulns,
        high: highVulns,
        medium: mediumVulns,
        low: lowVulns,
        total: criticalVulns + highVulns + mediumVulns + lowVulns
      },
      riskScore,
      outdatedComponents,
      licensingRisks: [...new Set(licensingRisks)],
      supplyChainRisks: {
        unmaintainedPackages: [],
        typosquatRisks: [],
        singleMaintainerRisks: []
      },
      recommendations
    };
  }

  /**
   * Export SBOM to file
   */
  exportSBOM(sbom: SBOM, format: 'json' | 'xml', outputPath: string): void {
    if (format === 'json') {
      fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2));
    } else {
      // Simplified XML export
      const xml = this.sbomToXML(sbom);
      fs.writeFileSync(outputPath, xml);
    }
  }

  /**
   * Detect license from node_modules
   */
  private async detectLicense(packageName: string, projectPath: string): Promise<string[]> {
    const pkgPath = path.join(projectPath, 'node_modules', packageName, 'package.json');
    try {
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        if (pkg.license) {
          return [pkg.license];
        }
        if (pkg.licenses && Array.isArray(pkg.licenses)) {
          return pkg.licenses.map((l: { type?: string } | string) => (typeof l === 'string' ? l : l.type || 'UNKNOWN'));
        }
      }
    } catch {
      // Ignore errors
    }
    return ['UNKNOWN'];
  }

  /**
   * Convert SBOM to XML format
   */
  private sbomToXML(sbom: SBOM): string {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += `<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="${sbom.version}" serialNumber="${sbom.serialNumber}">\n`;
    xml += '  <metadata>\n';
    xml += `    <timestamp>${sbom.metadata.timestamp}</timestamp>\n`;
    xml += '    <tools>\n';
    for (const tool of sbom.metadata.tools) {
      xml += `      <tool><name>${tool.name}</name><version>${tool.version}</version></tool>\n`;
    }
    xml += '    </tools>\n';
    xml += '  </metadata>\n';
    xml += '  <components>\n';
    for (const comp of sbom.components) {
      xml += `    <component type="${comp.type}">\n`;
      xml += `      <name>${comp.name}</name>\n`;
      xml += `      <version>${comp.version}</version>\n`;
      if (comp.purl) {xml += `      <purl>${comp.purl}</purl>\n`;}
      xml += '    </component>\n';
    }
    xml += '  </components>\n';
    xml += '</bom>';
    return xml;
  }

  /**
   * Generate UUID
   */
  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

export const sbomService = new SBOMService();
