/**
 * J.O.E. DevSecOps Arsenal - Infrastructure as Code (IaC) Scanner
 * Security scanning for Terraform, CloudFormation, Kubernetes, Dockerfiles, and Ansible
 *
 * @module electron/iac-scanner
 * @version 1.0.0
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export type IaCType = 'terraform' | 'cloudformation' | 'kubernetes' | 'dockerfile' | 'ansible' | 'helm';

export interface IaCFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  iacType: IaCType;
  file: string;
  line?: number;
  endLine?: number;
  resource?: string;
  resourceType?: string;
  checkId: string;
  remediation: string;
  documentation?: string;
  framework?: string;
  controlId?: string;
}

export interface IaCScanResult {
  iacType: IaCType;
  scanTime: string;
  filesScanned: number;
  findings: IaCFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: number;
  failed: number;
  skipped: number;
}

export interface IaCRuleSet {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: IaCFinding['severity'];
  iacTypes: IaCType[];
  pattern?: RegExp;
  check: (content: string, filePath: string) => IaCFinding[];
}

// =============================================================================
// TERRAFORM RULES
// =============================================================================

const TERRAFORM_RULES: IaCRuleSet[] = [
  {
    id: 'TF001',
    name: 'S3 Bucket Public Access',
    description: 'S3 buckets should not be publicly accessible',
    enabled: true,
    severity: 'critical',
    iacTypes: ['terraform'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      let inS3Bucket = false;
      let resourceName = '';
      let startLine = 0;

      lines.forEach((line, idx) => {
        if (line.includes('resource "aws_s3_bucket"')) {
          inS3Bucket = true;
          resourceName = line.match(/"([^"]+)"\s*{/)?.[1] || 'unknown';
          startLine = idx + 1;
        }
        if (inS3Bucket && line.includes('acl') && (line.includes('"public-read"') || line.includes('"public-read-write"'))) {
          findings.push({
            id: `TF001-${idx}`,
            title: 'S3 Bucket with Public ACL',
            description: `S3 bucket "${resourceName}" has public ACL which allows unauthorized access`,
            severity: 'critical',
            iacType: 'terraform',
            file: filePath,
            line: idx + 1,
            resource: resourceName,
            resourceType: 'aws_s3_bucket',
            checkId: 'TF001',
            remediation: 'Set acl = "private" or use aws_s3_bucket_public_access_block to block public access',
            framework: 'CIS-AWS',
            controlId: '2.1.5'
          });
        }
        if (inS3Bucket && line.includes('}') && !line.includes('{')) {
          inS3Bucket = false;
        }
      });
      return findings;
    }
  },
  {
    id: 'TF002',
    name: 'Unencrypted EBS Volume',
    description: 'EBS volumes should be encrypted at rest',
    enabled: true,
    severity: 'high',
    iacTypes: ['terraform'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      let inEBSVolume = false;
      let hasEncryption = false;
      let resourceName = '';
      let startLine = 0;

      lines.forEach((line, idx) => {
        if (line.includes('resource "aws_ebs_volume"')) {
          inEBSVolume = true;
          hasEncryption = false;
          resourceName = line.match(/"([^"]+)"\s*{/)?.[1] || 'unknown';
          startLine = idx + 1;
        }
        if (inEBSVolume && line.includes('encrypted') && line.includes('true')) {
          hasEncryption = true;
        }
        if (inEBSVolume && line.match(/^\s*}\s*$/) && !line.includes('{')) {
          if (!hasEncryption) {
            findings.push({
              id: `TF002-${startLine}`,
              title: 'Unencrypted EBS Volume',
              description: `EBS volume "${resourceName}" is not encrypted at rest`,
              severity: 'high',
              iacType: 'terraform',
              file: filePath,
              line: startLine,
              resource: resourceName,
              resourceType: 'aws_ebs_volume',
              checkId: 'TF002',
              remediation: 'Add encrypted = true to the aws_ebs_volume resource',
              framework: 'CIS-AWS',
              controlId: '2.2.1'
            });
          }
          inEBSVolume = false;
        }
      });
      return findings;
    }
  },
  {
    id: 'TF003',
    name: 'Security Group Open to World',
    description: 'Security groups should not allow unrestricted access from 0.0.0.0/0',
    enabled: true,
    severity: 'critical',
    iacTypes: ['terraform'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('cidr_blocks') && (line.includes('"0.0.0.0/0"') || line.includes('["0.0.0.0/0"]'))) {
          // Check if it's in an ingress block
          let isIngress = false;
          for (let i = idx; i >= 0 && i > idx - 10; i--) {
            if (lines[i].includes('ingress')) {
              isIngress = true;
              break;
            }
          }
          if (isIngress) {
            findings.push({
              id: `TF003-${idx}`,
              title: 'Security Group Open to World',
              description: 'Security group ingress rule allows traffic from 0.0.0.0/0 (any IP)',
              severity: 'critical',
              iacType: 'terraform',
              file: filePath,
              line: idx + 1,
              resourceType: 'aws_security_group',
              checkId: 'TF003',
              remediation: 'Restrict cidr_blocks to specific IP ranges instead of 0.0.0.0/0',
              framework: 'CIS-AWS',
              controlId: '5.2'
            });
          }
        }
      });
      return findings;
    }
  },
  {
    id: 'TF004',
    name: 'Hardcoded AWS Credentials',
    description: 'AWS credentials should not be hardcoded in Terraform files',
    enabled: true,
    severity: 'critical',
    iacTypes: ['terraform'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      const accessKeyPattern = /access_key\s*=\s*"[A-Z0-9]{20}"/i;
      const secretKeyPattern = /secret_key\s*=\s*"[A-Za-z0-9/+=]{40}"/i;

      lines.forEach((line, idx) => {
        if (accessKeyPattern.test(line) || secretKeyPattern.test(line)) {
          findings.push({
            id: `TF004-${idx}`,
            title: 'Hardcoded AWS Credentials',
            description: 'AWS credentials are hardcoded in Terraform configuration',
            severity: 'critical',
            iacType: 'terraform',
            file: filePath,
            line: idx + 1,
            checkId: 'TF004',
            remediation: 'Use environment variables, AWS profiles, or a secrets manager instead of hardcoding credentials',
            framework: 'OWASP',
            controlId: 'A07:2021'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'TF005',
    name: 'RDS Instance Not Encrypted',
    description: 'RDS instances should have encryption enabled',
    enabled: true,
    severity: 'high',
    iacTypes: ['terraform'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      let inRDS = false;
      let hasEncryption = false;
      let resourceName = '';
      let startLine = 0;

      lines.forEach((line, idx) => {
        if (line.includes('resource "aws_db_instance"')) {
          inRDS = true;
          hasEncryption = false;
          resourceName = line.match(/"([^"]+)"\s*{/)?.[1] || 'unknown';
          startLine = idx + 1;
        }
        if (inRDS && line.includes('storage_encrypted') && line.includes('true')) {
          hasEncryption = true;
        }
        if (inRDS && line.match(/^\s*}\s*$/) && !line.includes('{')) {
          if (!hasEncryption) {
            findings.push({
              id: `TF005-${startLine}`,
              title: 'RDS Instance Not Encrypted',
              description: `RDS instance "${resourceName}" does not have storage encryption enabled`,
              severity: 'high',
              iacType: 'terraform',
              file: filePath,
              line: startLine,
              resource: resourceName,
              resourceType: 'aws_db_instance',
              checkId: 'TF005',
              remediation: 'Add storage_encrypted = true to the aws_db_instance resource',
              framework: 'CIS-AWS',
              controlId: '2.3.1'
            });
          }
          inRDS = false;
        }
      });
      return findings;
    }
  }
];

// =============================================================================
// KUBERNETES RULES
// =============================================================================

const KUBERNETES_RULES: IaCRuleSet[] = [
  {
    id: 'K8S001',
    name: 'Container Running as Root',
    description: 'Containers should not run as root user',
    enabled: true,
    severity: 'high',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('runAsUser:') && line.includes('0')) {
          findings.push({
            id: `K8S001-${idx}`,
            title: 'Container Running as Root',
            description: 'Container is configured to run as root user (UID 0)',
            severity: 'high',
            iacType: 'kubernetes',
            file: filePath,
            line: idx + 1,
            checkId: 'K8S001',
            remediation: 'Set runAsUser to a non-zero value and runAsNonRoot: true in securityContext',
            framework: 'CIS-Kubernetes',
            controlId: '5.2.6'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'K8S002',
    name: 'Privileged Container',
    description: 'Containers should not run in privileged mode',
    enabled: true,
    severity: 'critical',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('privileged:') && line.includes('true')) {
          findings.push({
            id: `K8S002-${idx}`,
            title: 'Privileged Container',
            description: 'Container is running in privileged mode with full host access',
            severity: 'critical',
            iacType: 'kubernetes',
            file: filePath,
            line: idx + 1,
            checkId: 'K8S002',
            remediation: 'Set privileged: false in the container securityContext',
            framework: 'CIS-Kubernetes',
            controlId: '5.2.1'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'K8S003',
    name: 'Host Network Enabled',
    description: 'Pods should not use host network namespace',
    enabled: true,
    severity: 'high',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('hostNetwork:') && line.includes('true')) {
          findings.push({
            id: `K8S003-${idx}`,
            title: 'Host Network Enabled',
            description: 'Pod is using the host network namespace',
            severity: 'high',
            iacType: 'kubernetes',
            file: filePath,
            line: idx + 1,
            checkId: 'K8S003',
            remediation: 'Remove hostNetwork: true or set it to false',
            framework: 'CIS-Kubernetes',
            controlId: '5.2.4'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'K8S004',
    name: 'Missing Resource Limits',
    description: 'Containers should have resource limits defined',
    enabled: true,
    severity: 'medium',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const hasLimits = content.includes('limits:') && (content.includes('cpu:') || content.includes('memory:'));

      if (content.includes('containers:') && !hasLimits) {
        findings.push({
          id: `K8S004-1`,
          title: 'Missing Resource Limits',
          description: 'Container does not have CPU/memory limits defined',
          severity: 'medium',
          iacType: 'kubernetes',
          file: filePath,
          line: 1,
          checkId: 'K8S004',
          remediation: 'Add resources.limits with cpu and memory values to container spec',
          framework: 'CIS-Kubernetes',
          controlId: '5.4.1'
        });
      }
      return findings;
    }
  },
  {
    id: 'K8S005',
    name: 'Latest Image Tag',
    description: 'Container images should use specific tags instead of latest',
    enabled: true,
    severity: 'medium',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('image:') && (line.includes(':latest') || !line.includes(':'))) {
          findings.push({
            id: `K8S005-${idx}`,
            title: 'Latest Image Tag Used',
            description: 'Container image uses latest tag or no tag, making deployments unpredictable',
            severity: 'medium',
            iacType: 'kubernetes',
            file: filePath,
            line: idx + 1,
            checkId: 'K8S005',
            remediation: 'Use a specific image tag or digest instead of latest',
            framework: 'CIS-Kubernetes',
            controlId: '5.5.1'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'K8S006',
    name: 'Missing Network Policy',
    description: 'Pods should have network policies to restrict traffic',
    enabled: true,
    severity: 'medium',
    iacTypes: ['kubernetes'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];

      if (content.includes('kind: Deployment') || content.includes('kind: Pod')) {
        if (!content.includes('kind: NetworkPolicy') && !filePath.includes('network')) {
          findings.push({
            id: `K8S006-1`,
            title: 'Consider Network Policy',
            description: 'No NetworkPolicy found - consider adding network segmentation',
            severity: 'info',
            iacType: 'kubernetes',
            file: filePath,
            line: 1,
            checkId: 'K8S006',
            remediation: 'Create NetworkPolicy resources to restrict pod-to-pod communication',
            framework: 'CIS-Kubernetes',
            controlId: '5.3.2'
          });
        }
      }
      return findings;
    }
  }
];

// =============================================================================
// DOCKERFILE RULES
// =============================================================================

const DOCKERFILE_RULES: IaCRuleSet[] = [
  {
    id: 'DF001',
    name: 'Running as Root',
    description: 'Dockerfile should specify a non-root USER',
    enabled: true,
    severity: 'high',
    iacTypes: ['dockerfile'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const hasUser = content.includes('USER ') && !content.match(/USER\s+(root|0)/i);

      if (!hasUser) {
        findings.push({
          id: 'DF001-1',
          title: 'Container May Run as Root',
          description: 'Dockerfile does not specify a non-root USER directive',
          severity: 'high',
          iacType: 'dockerfile',
          file: filePath,
          checkId: 'DF001',
          remediation: 'Add USER directive with a non-root user (e.g., USER 1000:1000)',
          framework: 'CIS-Docker',
          controlId: '4.1'
        });
      }
      return findings;
    }
  },
  {
    id: 'DF002',
    name: 'Using Latest Tag',
    description: 'Base images should use specific version tags',
    enabled: true,
    severity: 'medium',
    iacTypes: ['dockerfile'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.startsWith('FROM ') && (line.includes(':latest') || !line.includes(':'))) {
          findings.push({
            id: `DF002-${idx}`,
            title: 'Using Latest Tag in FROM',
            description: 'Base image uses latest tag or no tag, causing unpredictable builds',
            severity: 'medium',
            iacType: 'dockerfile',
            file: filePath,
            line: idx + 1,
            checkId: 'DF002',
            remediation: 'Use a specific version tag (e.g., FROM node:18.17.0-alpine)',
            framework: 'CIS-Docker',
            controlId: '4.2'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'DF003',
    name: 'ADD Instead of COPY',
    description: 'Use COPY instead of ADD when not extracting archives',
    enabled: true,
    severity: 'low',
    iacTypes: ['dockerfile'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.startsWith('ADD ') && !line.match(/\.(tar|gz|bz2|xz|zip)/i) && !line.includes('http')) {
          findings.push({
            id: `DF003-${idx}`,
            title: 'ADD Used Instead of COPY',
            description: 'ADD has unexpected behaviors; use COPY for simple file copying',
            severity: 'low',
            iacType: 'dockerfile',
            file: filePath,
            line: idx + 1,
            checkId: 'DF003',
            remediation: 'Replace ADD with COPY unless extracting archives or fetching URLs',
            framework: 'CIS-Docker',
            controlId: '4.9'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'DF004',
    name: 'Hardcoded Secrets',
    description: 'Secrets should not be hardcoded in Dockerfile',
    enabled: true,
    severity: 'critical',
    iacTypes: ['dockerfile'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      const secretPatterns = [
        /password\s*[=:]\s*["'][^"']+["']/i,
        /api[_-]?key\s*[=:]\s*["'][^"']+["']/i,
        /secret\s*[=:]\s*["'][^"']+["']/i,
        /token\s*[=:]\s*["'][^"']+["']/i
      ];

      lines.forEach((line, idx) => {
        for (const pattern of secretPatterns) {
          if (pattern.test(line) && line.includes('ENV ')) {
            findings.push({
              id: `DF004-${idx}`,
              title: 'Hardcoded Secret in Dockerfile',
              description: 'Sensitive value appears to be hardcoded in ENV instruction',
              severity: 'critical',
              iacType: 'dockerfile',
              file: filePath,
              line: idx + 1,
              checkId: 'DF004',
              remediation: 'Use build arguments or secrets management instead of hardcoding values',
              framework: 'OWASP',
              controlId: 'A07:2021'
            });
            break;
          }
        }
      });
      return findings;
    }
  },
  {
    id: 'DF005',
    name: 'HEALTHCHECK Missing',
    description: 'Dockerfile should include a HEALTHCHECK instruction',
    enabled: true,
    severity: 'low',
    iacTypes: ['dockerfile'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];

      if (!content.includes('HEALTHCHECK ')) {
        findings.push({
          id: 'DF005-1',
          title: 'Missing HEALTHCHECK',
          description: 'Dockerfile does not include a HEALTHCHECK instruction',
          severity: 'low',
          iacType: 'dockerfile',
          file: filePath,
          checkId: 'DF005',
          remediation: 'Add HEALTHCHECK instruction to monitor container health',
          framework: 'CIS-Docker',
          controlId: '4.6'
        });
      }
      return findings;
    }
  }
];

// =============================================================================
// CLOUDFORMATION RULES
// =============================================================================

const CLOUDFORMATION_RULES: IaCRuleSet[] = [
  {
    id: 'CFN001',
    name: 'S3 Bucket Without Encryption',
    description: 'S3 buckets should have server-side encryption enabled',
    enabled: true,
    severity: 'high',
    iacTypes: ['cloudformation'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];

      if (content.includes('AWS::S3::Bucket') && !content.includes('BucketEncryption')) {
        findings.push({
          id: 'CFN001-1',
          title: 'S3 Bucket Without Encryption',
          description: 'S3 bucket does not have server-side encryption configured',
          severity: 'high',
          iacType: 'cloudformation',
          file: filePath,
          checkId: 'CFN001',
          remediation: 'Add BucketEncryption property with SSEAlgorithm',
          framework: 'CIS-AWS',
          controlId: '2.1.1'
        });
      }
      return findings;
    }
  },
  {
    id: 'CFN002',
    name: 'Security Group Ingress from Anywhere',
    description: 'Security groups should not allow 0.0.0.0/0 ingress',
    enabled: true,
    severity: 'critical',
    iacTypes: ['cloudformation'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('CidrIp:') && line.includes('0.0.0.0/0')) {
          findings.push({
            id: `CFN002-${idx}`,
            title: 'Security Group Open to Internet',
            description: 'Security group allows ingress from any IP address (0.0.0.0/0)',
            severity: 'critical',
            iacType: 'cloudformation',
            file: filePath,
            line: idx + 1,
            checkId: 'CFN002',
            remediation: 'Restrict CidrIp to specific IP ranges',
            framework: 'CIS-AWS',
            controlId: '5.2'
          });
        }
      });
      return findings;
    }
  },
  {
    id: 'CFN003',
    name: 'RDS Without Encryption',
    description: 'RDS instances should have storage encryption enabled',
    enabled: true,
    severity: 'high',
    iacTypes: ['cloudformation'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];

      if (content.includes('AWS::RDS::DBInstance')) {
        if (!content.includes('StorageEncrypted: true') && !content.includes("StorageEncrypted: 'true'")) {
          findings.push({
            id: 'CFN003-1',
            title: 'RDS Without Storage Encryption',
            description: 'RDS instance does not have storage encryption enabled',
            severity: 'high',
            iacType: 'cloudformation',
            file: filePath,
            checkId: 'CFN003',
            remediation: 'Add StorageEncrypted: true to the RDS resource',
            framework: 'CIS-AWS',
            controlId: '2.3.1'
          });
        }
      }
      return findings;
    }
  }
];

// =============================================================================
// ANSIBLE RULES
// =============================================================================

const ANSIBLE_RULES: IaCRuleSet[] = [
  {
    id: 'ANS001',
    name: 'Plaintext Password',
    description: 'Passwords should not be in plaintext in Ansible playbooks',
    enabled: true,
    severity: 'critical',
    iacTypes: ['ansible'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');

      lines.forEach((line, idx) => {
        if (line.includes('password:') && !line.includes('{{ ') && !line.includes('vault_')) {
          const value = line.split(':')[1]?.trim();
          if (value && value.length > 0 && !value.startsWith('!vault')) {
            findings.push({
              id: `ANS001-${idx}`,
              title: 'Plaintext Password in Playbook',
              description: 'Password appears to be stored in plaintext',
              severity: 'critical',
              iacType: 'ansible',
              file: filePath,
              line: idx + 1,
              checkId: 'ANS001',
              remediation: 'Use ansible-vault to encrypt sensitive values or reference variables',
              framework: 'OWASP',
              controlId: 'A07:2021'
            });
          }
        }
      });
      return findings;
    }
  },
  {
    id: 'ANS002',
    name: 'Become Without Password',
    description: 'Privilege escalation should require password verification',
    enabled: true,
    severity: 'medium',
    iacTypes: ['ansible'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];

      if (content.includes('become: true') || content.includes('become: yes')) {
        if (content.includes('become_method: sudo') && !content.includes('become_flags')) {
          findings.push({
            id: 'ANS002-1',
            title: 'Become Without Password Verification',
            description: 'Privilege escalation does not appear to require password',
            severity: 'medium',
            iacType: 'ansible',
            file: filePath,
            checkId: 'ANS002',
            remediation: 'Configure proper sudo authentication or use become_flags',
            framework: 'CIS',
            controlId: '5.3'
          });
        }
      }
      return findings;
    }
  },
  {
    id: 'ANS003',
    name: 'Shell/Command Module Without Changed_When',
    description: 'Shell and command modules should use changed_when for idempotency',
    enabled: true,
    severity: 'low',
    iacTypes: ['ansible'],
    check: (content, filePath) => {
      const findings: IaCFinding[] = [];
      const lines = content.split('\n');
      let inShellCommand = false;
      let hasChangedWhen = false;
      let startLine = 0;

      lines.forEach((line, idx) => {
        if (line.match(/^\s*-?\s*(shell|command):/)) {
          inShellCommand = true;
          hasChangedWhen = false;
          startLine = idx + 1;
        }
        if (inShellCommand && line.includes('changed_when:')) {
          hasChangedWhen = true;
        }
        if (inShellCommand && line.match(/^\s*-\s+\w+:/) && !line.includes('name:')) {
          if (!hasChangedWhen) {
            findings.push({
              id: `ANS003-${startLine}`,
              title: 'Missing changed_when',
              description: 'Shell/command task should include changed_when for idempotency',
              severity: 'low',
              iacType: 'ansible',
              file: filePath,
              line: startLine,
              checkId: 'ANS003',
              remediation: 'Add changed_when: false or appropriate condition to the task',
              framework: 'Ansible Best Practices'
            });
          }
          inShellCommand = false;
        }
      });
      return findings;
    }
  }
];

// =============================================================================
// IAC SCANNER SERVICE
// =============================================================================

class IaCScanner {
  private rules: IaCRuleSet[];

  constructor() {
    this.rules = [
      ...TERRAFORM_RULES,
      ...KUBERNETES_RULES,
      ...DOCKERFILE_RULES,
      ...CLOUDFORMATION_RULES,
      ...ANSIBLE_RULES
    ];
  }

  detectIaCType(filePath: string, content: string): IaCType | null {
    const fileName = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();

    // Dockerfile
    if (fileName === 'dockerfile' || fileName.startsWith('dockerfile.')) {
      return 'dockerfile';
    }

    // Terraform
    if (ext === '.tf' || ext === '.tfvars') {
      return 'terraform';
    }

    // Kubernetes
    if ((ext === '.yaml' || ext === '.yml') &&
        (content.includes('apiVersion:') && content.includes('kind:'))) {
      return 'kubernetes';
    }

    // Helm
    if (fileName === 'chart.yaml' || fileName === 'values.yaml' ||
        filePath.includes('/templates/')) {
      return 'helm';
    }

    // CloudFormation
    if ((ext === '.yaml' || ext === '.yml' || ext === '.json') &&
        (content.includes('AWSTemplateFormatVersion') || content.includes('AWS::'))) {
      return 'cloudformation';
    }

    // Ansible
    if ((ext === '.yaml' || ext === '.yml') &&
        (content.includes('hosts:') || content.includes('tasks:') ||
         content.includes('ansible.builtin') || filePath.includes('playbook'))) {
      return 'ansible';
    }

    return null;
  }

  async scanFile(filePath: string): Promise<IaCFinding[]> {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const iacType = this.detectIaCType(filePath, content);

      if (!iacType) {
        return [];
      }

      const findings: IaCFinding[] = [];
      const applicableRules = this.rules.filter(r => r.enabled && r.iacTypes.includes(iacType));

      for (const rule of applicableRules) {
        const ruleFindings = rule.check(content, filePath);
        findings.push(...ruleFindings);
      }

      return findings;
    } catch (error) {
      console.error(`[J.O.E. IaC Scanner] Error scanning file ${filePath}:`, error);
      return [];
    }
  }

  async scanDirectory(dirPath: string): Promise<IaCScanResult> {
    const startTime = Date.now();
    const allFindings: IaCFinding[] = [];
    let filesScanned = 0;
    const iacTypesFound = new Set<IaCType>();

    const scanRecursive = (dir: string) => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          // Skip common non-IaC directories
          if (entry.isDirectory()) {
            if (!['node_modules', '.git', 'vendor', '.terraform', '__pycache__'].includes(entry.name)) {
              scanRecursive(fullPath);
            }
            continue;
          }

          // Check supported extensions
          const ext = path.extname(entry.name).toLowerCase();
          if (['.tf', '.tfvars', '.yaml', '.yml', '.json'].includes(ext) ||
              entry.name.toLowerCase().startsWith('dockerfile')) {
            try {
              const content = fs.readFileSync(fullPath, 'utf-8');
              const iacType = this.detectIaCType(fullPath, content);

              if (iacType) {
                iacTypesFound.add(iacType);
                filesScanned++;
                const findings = this.rules
                  .filter(r => r.enabled && r.iacTypes.includes(iacType))
                  .flatMap(r => r.check(content, fullPath));
                allFindings.push(...findings);
              }
            } catch {
              // Skip files that can't be read
            }
          }
        }
      } catch {
        // Skip directories that can't be read
      }
    };

    scanRecursive(dirPath);

    const summary = {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length,
      total: allFindings.length
    };

    return {
      iacType: iacTypesFound.size === 1 ? Array.from(iacTypesFound)[0] : 'terraform', // Default to terraform for mixed
      scanTime: new Date().toISOString(),
      filesScanned,
      findings: allFindings,
      summary,
      passed: filesScanned - allFindings.length,
      failed: allFindings.length,
      skipped: 0
    };
  }

  async runExternalTool(tool: 'tfsec' | 'checkov' | 'kubesec' | 'hadolint', targetPath: string): Promise<IaCFinding[]> {
    return new Promise((resolve) => {
      const findings: IaCFinding[] = [];

      const toolCommands: Record<string, { cmd: string; args: string[] }> = {
        tfsec: { cmd: 'tfsec', args: [targetPath, '--format', 'json'] },
        checkov: { cmd: 'checkov', args: ['-d', targetPath, '-o', 'json'] },
        kubesec: { cmd: 'kubesec', args: ['scan', targetPath] },
        hadolint: { cmd: 'hadolint', args: [targetPath, '-f', 'json'] }
      };

      const toolConfig = toolCommands[tool];
      if (!toolConfig) {
        resolve([]);
        return;
      }

      try {
        const proc = spawn(toolConfig.cmd, toolConfig.args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          shell: true
        });

        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', (data) => { stdout += data.toString(); });
        proc.stderr.on('data', (data) => { stderr += data.toString(); });

        proc.on('close', (code) => {
          if (stdout) {
            try {
              const results = JSON.parse(stdout);
              // Parse based on tool format
              if (tool === 'tfsec' && results.results) {
                for (const r of results.results) {
                  findings.push({
                    id: r.rule_id,
                    title: r.rule_description,
                    description: r.description,
                    severity: r.severity?.toLowerCase() || 'medium',
                    iacType: 'terraform',
                    file: r.location?.filename || targetPath,
                    line: r.location?.start_line,
                    endLine: r.location?.end_line,
                    resource: r.resource,
                    checkId: r.rule_id,
                    remediation: r.resolution || 'See documentation',
                    documentation: r.links?.[0]
                  });
                }
              }
            } catch {
              console.log(`[J.O.E. IaC Scanner] Could not parse ${tool} output`);
            }
          }
          resolve(findings);
        });

        proc.on('error', () => {
          console.log(`[J.O.E. IaC Scanner] ${tool} not available, using built-in rules`);
          resolve([]);
        });
      } catch {
        resolve([]);
      }
    });
  }

  getRules(): IaCRuleSet[] {
    return this.rules;
  }

  enableRule(ruleId: string): void {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) rule.enabled = true;
  }

  disableRule(ruleId: string): void {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) rule.enabled = false;
  }
}

// Export singleton instance
export const iacScanner = new IaCScanner();
