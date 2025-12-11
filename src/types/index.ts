export interface SecurityFinding {
    id: string;
    title: string;
    severity: Severity;
    tool: string;
    filePath?: string;
    line?: number;
    description: string;
    recommendation?: string;
    cveId?: string;
    cweId?: string;
    timestamp: Date;
}

export enum Severity {
    critical = 'critical',
    high = 'high',
    medium = 'medium',
    low = 'low',
    info = 'info'
}

export interface SbomComponent {
    name: string;
    version: string;
    type: ComponentType;
    purl?: string;
    licenses?: string[];
    vulnerabilities?: VulnerabilityInfo[];
}

export enum ComponentType {
    library = 'library',
    framework = 'framework',
    application = 'application',
    container = 'container',
    operatingSystem = 'operating-system'
}

export interface VulnerabilityInfo {
    id: string;
    severity: Severity;
    description: string;
    fixedIn?: string;
}

export interface ComplianceControl {
    id: string;
    framework: ComplianceFramework;
    title: string;
    description: string;
    status: ComplianceStatus;
    evidence?: string[];
}

export enum ComplianceFramework {
    cmmc2 = 'cmmc-2',
    nist80053 = 'nist-800-53',
    iso27001 = 'iso-27001',
    soc2 = 'soc2'
}

export enum ComplianceStatus {
    compliant = 'compliant',
    partiallyCompliant = 'partially-compliant',
    nonCompliant = 'non-compliant',
    notAssessed = 'not-assessed'
}

export interface ScanResult {
    tool: string;
    timestamp: Date;
    findings: SecurityFinding[];
    success: boolean;
    error?: string;
}

export interface RiskScore {
    overall: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    cmmcLevel: number;
}

export interface ToolInfo {
    name: string;
    description: string;
    installed: boolean;
    version?: string;
    enabled: boolean;
}
