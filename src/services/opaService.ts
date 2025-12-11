import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { Logger } from '../utils/logger';

const execAsync = promisify(exec);

export interface PolicyResult {
    name: string;
    passed: boolean;
    message?: string;
    severity: 'error' | 'warning' | 'info';
    resource?: string;
}

export interface OPAViolation {
    rule?: string;
    msg?: string;
    message?: string;
    severity?: string;
    resource?: string;
}

export interface SBOMComponent {
    vulnerabilities?: Array<{
        severity: string;
    }>;
    licenses?: unknown[];
}

export interface ContainerInfo {
    user?: string;
    image?: string;
}

export interface PolicyBundle {
    name: string;
    path: string;
    description: string;
}

export class OpaService {
    private context: vscode.ExtensionContext;
    private opaAvailable: boolean = false;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async initialize(): Promise<boolean> {
        try {
            await execAsync('opa version');
            this.opaAvailable = true;
            Logger.info('OPA CLI found');
            return true;
        } catch {
            Logger.warn('OPA CLI not found - using built-in policy evaluation');
            return false;
        }
    }

    async evaluatePolicy(policyPath: string, inputData: object): Promise<PolicyResult[]> {
        if (this.opaAvailable) {
            return await this.evaluateWithCli(policyPath, inputData);
        } else {
            return await this.evaluateBuiltIn(inputData);
        }
    }

    private async evaluateWithCli(policyPath: string, inputData: object): Promise<PolicyResult[]> {
        const fs = await import('fs').then(m => m.promises);
        const os = await import('os');

        // Write input to temp file
        const inputFile = path.join(os.tmpdir(), 'opa-input.json');
        await fs.writeFile(inputFile, JSON.stringify(inputData), 'utf-8');

        try {
            const { stdout } = await execAsync(
                `opa eval -i "${inputFile}" -d "${policyPath}" "data.joe.deny" --format json`,
                { maxBuffer: 10 * 1024 * 1024 }
            );

            const result = JSON.parse(stdout);
            const violations = result.result?.[0]?.expressions?.[0]?.value || [];

            return violations.map((v: OPAViolation) => ({
                name: v.rule || 'policy-violation',
                passed: false,
                message: v.msg || v.message || 'Policy violation',
                severity: v.severity || 'error',
                resource: v.resource
            }));
        } catch (error) {
            Logger.error('OPA evaluation failed', error);
            throw error;
        } finally {
            await fs.unlink(inputFile).catch(() => {});
        }
    }

    private async evaluateBuiltIn(inputData: object): Promise<PolicyResult[]> {
        // Built-in policy checks when OPA is not available
        const results: PolicyResult[] = [];
        const data = inputData as Record<string, unknown>;

        // Security policies
        if (data.sbom) {
            // Check for vulnerable dependencies
            const vulnComponents = (data.sbom as { components?: SBOMComponent[] }).components?.filter((c: SBOMComponent) =>
                c.vulnerabilities?.some((v) => v.severity === 'critical' || v.severity === 'high')
            ) || [];

            if (vulnComponents.length > 0) {
                results.push({
                    name: 'vulnerable-dependencies',
                    passed: false,
                    message: `Found ${vulnComponents.length} components with critical/high vulnerabilities`,
                    severity: 'error'
                });
            }

            // Check for components without licenses
            const noLicense = (data.sbom as { components?: SBOMComponent[] }).components?.filter((c: SBOMComponent) =>
                !c.licenses || c.licenses.length === 0
            ) || [];

            if (noLicense.length > 0) {
                results.push({
                    name: 'missing-licenses',
                    passed: false,
                    message: `Found ${noLicense.length} components without license information`,
                    severity: 'warning'
                });
            }
        }

        // Container policies
        if (data.container) {
            const container = data.container as ContainerInfo;
            // Check for root user
            if (container.user === 'root' || container.user === '0') {
                results.push({
                    name: 'container-root-user',
                    passed: false,
                    message: 'Container runs as root user',
                    severity: 'error'
                });
            }

            // Check for latest tag
            if (container.image?.includes(':latest')) {
                results.push({
                    name: 'container-latest-tag',
                    passed: false,
                    message: 'Container uses :latest tag instead of specific version',
                    severity: 'warning'
                });
            }
        }

        // Secrets policies
        if (data.secrets) {
            const secrets = data.secrets as { count?: number };
            if (secrets.count && secrets.count > 0) {
                results.push({
                    name: 'secrets-detected',
                    passed: false,
                    message: `Found ${secrets.count} potential secrets in code`,
                    severity: 'error'
                });
            }
        }

        // Compliance policies
        if (data.compliance) {
            const compliance = data.compliance as { controls?: Record<string, unknown> };
            const nonCompliant = Object.entries(compliance.controls || {})
                .filter(([, status]) => status === 'non-compliant');

            if (nonCompliant.length > 0) {
                results.push({
                    name: 'compliance-gaps',
                    passed: false,
                    message: `${nonCompliant.length} compliance controls are non-compliant`,
                    severity: 'error',
                    resource: nonCompliant.map(([id]) => id).join(', ')
                });
            }
        }

        // If no violations found, add a passing result
        if (results.length === 0) {
            results.push({
                name: 'all-policies',
                passed: true,
                message: 'All built-in policies passed',
                severity: 'info'
            });
        }

        return results;
    }

    async createPolicyBundle(workspacePath: string): Promise<string> {
        const fs = await import('fs').then(m => m.promises);
        const policiesDir = path.join(workspacePath, '.joe', 'policies');
        await fs.mkdir(policiesDir, { recursive: true });

        // Create main.rego
        const mainPolicy = `# J.O.E. Security Policies
# CMMC 2.0 / NIST 800-53 aligned policy bundle

package joe

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny if critical vulnerabilities exist
deny contains msg if {
    some vuln in input.vulnerabilities
    vuln.severity == "critical"
    msg := sprintf("Critical vulnerability found: %s in %s", [vuln.id, vuln.package])
}

# Deny if high vulnerabilities exceed threshold
deny contains msg if {
    high_count := count([v | some v in input.vulnerabilities; v.severity == "high"])
    high_count > 5
    msg := sprintf("Too many high vulnerabilities: %d (max: 5)", [high_count])
}

# Deny if secrets are detected
deny contains msg if {
    some secret in input.secrets
    secret.severity == "critical"
    msg := sprintf("Secret detected: %s in %s:%d", [secret.type, secret.file, secret.line])
}

# Deny if container runs as root
deny contains msg if {
    input.container.user == "root"
    msg := "Container must not run as root user"
}

# Deny if container uses latest tag
deny contains msg if {
    contains(input.container.image, ":latest")
    msg := "Container images must use specific version tags, not :latest"
}

# Deny if SBOM is missing required fields
deny contains msg if {
    not input.sbom.metadata.timestamp
    msg := "SBOM must include timestamp metadata"
}

# Deny if no SBOM signature
deny contains msg if {
    not input.sbom.signature
    input.config.require_signed_sbom == true
    msg := "SBOM must be cryptographically signed"
}

# Warn if dependencies have no license
warn contains msg if {
    some comp in input.sbom.components
    not comp.licenses
    msg := sprintf("Component %s@%s has no license information", [comp.name, comp.version])
}

# CMMC Level 2 - Access Control
deny contains msg if {
    input.compliance.framework == "cmmc-2"
    some control in input.compliance.controls
    control.domain == "AC"
    control.status == "non-compliant"
    msg := sprintf("CMMC AC control %s is non-compliant: %s", [control.id, control.title])
}

# NIST 800-53 - RA-5 Vulnerability Scanning
deny contains msg if {
    input.compliance.framework == "nist-800-53"
    not input.scans.vulnerability.last_scan
    msg := "RA-5: Vulnerability scanning has not been performed"
}

deny contains msg if {
    input.compliance.framework == "nist-800-53"
    input.scans.vulnerability.age_days > 7
    msg := sprintf("RA-5: Vulnerability scan is %d days old (max: 7)", [input.scans.vulnerability.age_days])
}
`;

        await fs.writeFile(path.join(policiesDir, 'main.rego'), mainPolicy, 'utf-8');

        // Create container.rego
        const containerPolicy = `# Container Security Policies
package joe.container

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Deny privileged containers
deny contains msg if {
    input.securityContext.privileged == true
    msg := "Privileged containers are not allowed"
}

# Deny containers with host network
deny contains msg if {
    input.hostNetwork == true
    msg := "Host network mode is not allowed"
}

# Deny containers without resource limits
deny contains msg if {
    not input.resources.limits.memory
    msg := "Container must have memory limits defined"
}

deny contains msg if {
    not input.resources.limits.cpu
    msg := "Container must have CPU limits defined"
}

# Deny containers with writable root filesystem
deny contains msg if {
    not input.securityContext.readOnlyRootFilesystem
    msg := "Container root filesystem must be read-only"
}

# Deny containers that can escalate privileges
deny contains msg if {
    input.securityContext.allowPrivilegeEscalation == true
    msg := "Privilege escalation must be disabled"
}

# Require specific capabilities to be dropped
deny contains msg if {
    not "ALL" in input.securityContext.capabilities.drop
    msg := "All capabilities must be dropped by default"
}
`;

        await fs.writeFile(path.join(policiesDir, 'container.rego'), containerPolicy, 'utf-8');

        // Create iac.rego
        const iacPolicy = `# Infrastructure as Code Policies
package joe.iac

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Terraform - Deny unencrypted S3 buckets
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_s3_bucket"
    not resource.values.server_side_encryption_configuration
    msg := sprintf("S3 bucket %s must have encryption enabled", [resource.name])
}

# Terraform - Deny public S3 buckets
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_s3_bucket_public_access_block"
    resource.values.block_public_acls != true
    msg := sprintf("S3 bucket %s must block public ACLs", [resource.name])
}

# Terraform - Require encryption for RDS
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_db_instance"
    resource.values.storage_encrypted != true
    msg := sprintf("RDS instance %s must have storage encryption", [resource.name])
}

# Terraform - Deny default VPC usage
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_default_vpc"
    msg := "Default VPC should not be used"
}

# Kubernetes - Deny pods without security context
deny contains msg if {
    input.kind == "Pod"
    not input.spec.securityContext
    msg := sprintf("Pod %s must define a security context", [input.metadata.name])
}

# Kubernetes - Deny services with NodePort
deny contains msg if {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := sprintf("Service %s should not use NodePort", [input.metadata.name])
}
`;

        await fs.writeFile(path.join(policiesDir, 'iac.rego'), iacPolicy, 'utf-8');

        Logger.info(`Policy bundle created at ${policiesDir}`);
        return policiesDir;
    }

    async runPolicyCheck(workspacePath: string): Promise<PolicyResult[]> {
        // Gather input data from various sources
        const inputData = await this.gatherPolicyInput(workspacePath);

        // Create policies if they don't exist
        const fs = await import('fs').then(m => m.promises);
        const policiesDir = path.join(workspacePath, '.joe', 'policies');

        try {
            await fs.access(policiesDir);
        } catch {
            await this.createPolicyBundle(workspacePath);
        }

        // Run evaluation
        return await this.evaluatePolicy(policiesDir, inputData);
    }

    private async gatherPolicyInput(workspacePath: string): Promise<Record<string, unknown>> {
        const fs = await import('fs').then(m => m.promises);

        const input: Record<string, unknown> = {
            config: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                require_signed_sbom: false
            },
            vulnerabilities: [],
            secrets: [],
            sbom: { components: [], metadata: {} },
            container: {} as ContainerInfo,
            compliance: { framework: 'cmmc-2', controls: [] },
            scans: { vulnerability: {} }
        };

        // Try to load SBOM
        try {
            const sbomPath = path.join(workspacePath, 'sbom.cyclonedx.json');
            const sbomContent = await fs.readFile(sbomPath, 'utf-8');
            input.sbom = JSON.parse(sbomContent);
        } catch { /* SBOM not found */ }

        // Try to load Dockerfile for container config
        try {
            const dockerfile = await fs.readFile(path.join(workspacePath, 'Dockerfile'), 'utf-8');
            input.container = this.parseDockerfile(dockerfile);
        } catch { /* No Dockerfile */ }

        return input;
    }

    private parseDockerfile(content: string): ContainerInfo {
        const lines = content.split('\n');
        const config: Record<string, unknown> = {};

        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('FROM ')) {
                config.image = trimmed.substring(5).trim();
            } else if (trimmed.startsWith('USER ')) {
                config.user = trimmed.substring(5).trim();
            }
        }

        return config;
    }

    getBuiltInPolicies(): PolicyBundle[] {
        return [
            { name: 'CMMC 2.0', path: 'cmmc-2', description: 'CMMC Level 2 compliance policies' },
            { name: 'NIST 800-53', path: 'nist-800-53', description: 'NIST 800-53 Rev 5 controls' },
            { name: 'Container Security', path: 'container', description: 'Container/K8s security policies' },
            { name: 'IaC Security', path: 'iac', description: 'Terraform/CloudFormation policies' },
            { name: 'Secret Detection', path: 'secrets', description: 'Secret/credential policies' }
        ];
    }
}
