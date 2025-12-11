import * as vscode from 'vscode';
import * as path from 'path';
import { Logger } from '../utils/logger';

export type PipelineType = 'github-actions' | 'azure-pipelines' | 'gitlab-ci' | 'jenkins';

export interface PipelineOptions {
    includeSast: boolean;
    includeSca: boolean;
    includeSbom: boolean;
    includeContainerScan: boolean;
    includeSecretScan: boolean;
    includePolicyCheck: boolean;
    includeCompliance: boolean;
    languages: string[];
    containerRegistry?: string;
}

export class PipelineService {
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async generatePipeline(type: PipelineType, options: PipelineOptions): Promise<string> {
        switch (type) {
            case 'github-actions':
                return this.generateGitHubActions(options);
            case 'azure-pipelines':
                return this.generateAzurePipelines(options);
            case 'gitlab-ci':
                return this.generateGitLabCI(options);
            case 'jenkins':
                return this.generateJenkinsfile(options);
            default:
                throw new Error(`Unsupported pipeline type: ${type}`);
        }
    }

    private generateGitHubActions(options: PipelineOptions): string {
        const jobs: string[] = [];

        // Security scanning job
        if (options.includeSast || options.includeSca || options.includeSecretScan) {
            jobs.push(`
  security-scan:
    name: Security Scanning
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

${options.includeSecretScan ? `      - name: GitGuardian Scan
        uses: GitGuardian/ggshield-action@v1
        env:
          GITHUB_PUSH_BEFORE_SHA: \${{ github.event.before }}
          GITHUB_PUSH_BASE_SHA: \${{ github.event.base_ref }}
          GITHUB_PULL_BASE_SHA: \${{ github.event.pull_request.base.sha }}
          GITHUB_DEFAULT_BRANCH: \${{ github.event.repository.default_branch }}
          GITGUARDIAN_API_KEY: \${{ secrets.GITGUARDIAN_API_KEY }}
` : ''}
${options.includeSast ? `      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${options.languages.join(', ')}

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:\${{ matrix.language }}"

      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: p/security-audit p/owasp-top-ten
        env:
          SEMGREP_APP_TOKEN: \${{ secrets.SEMGREP_APP_TOKEN }}
` : ''}
${options.includeSca ? `      - name: Run Snyk SCA
        uses: snyk/actions/node@master
        continue-on-error: true
        env:
          SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
` : ''}`);
        }

        // SBOM generation job
        if (options.includeSbom) {
            jobs.push(`
  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    needs: [security-scan]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cyclonedx.json

      - name: Upload to Dependency-Track
        if: \${{ vars.DEPENDENCY_TRACK_URL }}
        run: |
          curl -X PUT "\${{ vars.DEPENDENCY_TRACK_URL }}/api/v1/bom" \\
            -H "X-Api-Key: \${{ secrets.DEPENDENCY_TRACK_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d "{
              \\"projectName\\": \\"\${{ github.repository }}\\",
              \\"projectVersion\\": \\"\${{ github.sha }}\\",
              \\"bom\\": \\"$(base64 -w 0 sbom.cyclonedx.json)\\"
            }"

      - name: Scan SBOM with Grype
        uses: anchore/scan-action@v3
        with:
          sbom: sbom.cyclonedx.json
          fail-build: true
          severity-cutoff: high`);
        }

        // Container scanning job
        if (options.includeContainerScan) {
            jobs.push(`
  container-scan:
    name: Container Security
    runs-on: ubuntu-latest
    needs: [sbom]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Build container image
        run: docker build -t \${{ github.repository }}:\${{ github.sha }} .

      - name: Run Trivy container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: '\${{ github.repository }}:\${{ github.sha }}'
          format: 'sarif'
          output: 'container-trivy.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload container scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'container-trivy.sarif'
          category: 'container-security'`);
        }

        // Policy check job
        if (options.includePolicyCheck) {
            jobs.push(`
  policy-check:
    name: Policy Compliance
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: all
          output_format: sarif
          output_file_path: checkov-results.sarif

      - name: Upload Checkov results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'checkov-results.sarif'
          category: 'iac-security'

      - name: Run OPA Policy Check
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa
          ./opa eval -i policy-input.json -d policies/ "data.main.deny"`);
        }

        // Compliance report job
        if (options.includeCompliance) {
            jobs.push(`
  compliance-report:
    name: Compliance Report
    runs-on: ubuntu-latest
    needs: [security-scan, sbom, policy-check]
    if: always()
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4

      - name: Generate compliance report
        run: |
          echo "# Compliance Report" > compliance-report.md
          echo "Generated: $(date -u)" >> compliance-report.md
          echo "" >> compliance-report.md
          echo "## Security Scan Summary" >> compliance-report.md
          echo "- SAST: \${{ needs.security-scan.result }}" >> compliance-report.md
          echo "- SBOM: \${{ needs.sbom.result }}" >> compliance-report.md
          echo "- Policy: \${{ needs.policy-check.result }}" >> compliance-report.md

      - name: Upload compliance report
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: compliance-report.md`);
        }

        return `# J.O.E. DevSecOps Pipeline - GitHub Actions
# Generated by J.O.E. (Joint-Ops-Engine)
# Aligned with CMMC 2.0, NIST 800-53, and SLSA requirements

name: J.O.E. Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly scan on Monday at 6 AM UTC

permissions:
  contents: read
  security-events: write
  packages: write

jobs:${jobs.join('\n')}
`;
    }

    private generateAzurePipelines(options: PipelineOptions): string {
        const stages: string[] = [];

        if (options.includeSast || options.includeSca) {
            stages.push(`
- stage: SecurityScan
  displayName: 'Security Scanning'
  jobs:
  - job: SAST
    displayName: 'Static Analysis'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - checkout: self
      fetchDepth: 0

${options.includeSecretScan ? `    - task: Bash@3
      displayName: 'GitGuardian Scan'
      inputs:
        targetType: 'inline'
        script: |
          pip install ggshield
          ggshield secret scan repo .
      env:
        GITGUARDIAN_API_KEY: $(GITGUARDIAN_API_KEY)
` : ''}
${options.includeSast ? `    - task: UseDotNet@2
      displayName: 'Use .NET SDK'
      inputs:
        version: '8.x'

    - task: Bash@3
      displayName: 'Run Semgrep'
      inputs:
        targetType: 'inline'
        script: |
          pip install semgrep
          semgrep scan --config auto --sarif --output semgrep-results.sarif .

    - task: PublishBuildArtifacts@1
      displayName: 'Publish SARIF results'
      inputs:
        PathtoPublish: 'semgrep-results.sarif'
        ArtifactName: 'CodeAnalysisLogs'
` : ''}
${options.includeSca ? `    - task: SnykSecurityScan@1
      displayName: 'Snyk SCA Scan'
      inputs:
        serviceConnectionEndpoint: 'SnykConnection'
        testType: 'app'
        severityThreshold: 'high'
        failOnIssues: true
` : ''}`);
        }

        if (options.includeSbom) {
            stages.push(`
- stage: SBOM
  displayName: 'SBOM Generation'
  dependsOn: SecurityScan
  jobs:
  - job: GenerateSBOM
    displayName: 'Generate SBOM'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - checkout: self

    - task: Bash@3
      displayName: 'Install Syft'
      inputs:
        targetType: 'inline'
        script: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

    - task: Bash@3
      displayName: 'Generate CycloneDX SBOM'
      inputs:
        targetType: 'inline'
        script: |
          syft . -o cyclonedx-json > sbom.cyclonedx.json

    - task: PublishBuildArtifacts@1
      displayName: 'Publish SBOM'
      inputs:
        PathtoPublish: 'sbom.cyclonedx.json'
        ArtifactName: 'SBOM'`);
        }

        if (options.includeContainerScan) {
            stages.push(`
- stage: ContainerSecurity
  displayName: 'Container Security'
  dependsOn: SBOM
  jobs:
  - job: ContainerScan
    displayName: 'Scan Container Image'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - checkout: self

    - task: Docker@2
      displayName: 'Build container'
      inputs:
        command: 'build'
        Dockerfile: '**/Dockerfile'
        tags: '$(Build.BuildId)'

    - task: Bash@3
      displayName: 'Trivy Container Scan'
      inputs:
        targetType: 'inline'
        script: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy image --severity HIGH,CRITICAL --exit-code 1 $(containerRegistry)/$(imageRepository):$(Build.BuildId)`);
        }

        return `# J.O.E. DevSecOps Pipeline - Azure Pipelines
# Generated by J.O.E. (Joint-Ops-Engine)

trigger:
  branches:
    include:
    - main
    - develop

pr:
  branches:
    include:
    - main

variables:
  - group: joe-security-variables

stages:${stages.join('\n')}
`;
    }

    private generateGitLabCI(options: PipelineOptions): string {
        const stages: string[] = ['stages:', '  - security', '  - sbom', '  - compliance'];
        const jobs: string[] = [];

        if (options.includeSast) {
            jobs.push(`
semgrep:
  stage: security
  image: semgrep/semgrep
  script:
    - semgrep scan --config auto --sarif --output gl-sast-report.sarif .
  artifacts:
    reports:
      sast: gl-sast-report.sarif`);
        }

        if (options.includeSca) {
            jobs.push(`
dependency-scan:
  stage: security
  image: aquasec/trivy
  script:
    - trivy fs --format sarif --output gl-dependency-report.sarif .
  artifacts:
    reports:
      dependency_scanning: gl-dependency-report.sarif`);
        }

        if (options.includeSecretScan) {
            jobs.push(`
secret-detection:
  stage: security
  image: gitguardian/ggshield
  script:
    - ggshield secret scan repo .
  variables:
    GITGUARDIAN_API_KEY: $GITGUARDIAN_API_KEY`);
        }

        if (options.includeSbom) {
            jobs.push(`
sbom-generation:
  stage: sbom
  image: anchore/syft
  script:
    - syft . -o cyclonedx-json > sbom.cyclonedx.json
  artifacts:
    paths:
      - sbom.cyclonedx.json`);
        }

        return `# J.O.E. DevSecOps Pipeline - GitLab CI
# Generated by J.O.E. (Joint-Ops-Engine)

${stages.join('\n')}

variables:
  SECURE_LOG_LEVEL: debug

${jobs.join('\n')}
`;
    }

    private generateJenkinsfile(options: PipelineOptions): string {
        const stages: string[] = [];

        if (options.includeSast) {
            stages.push(`
        stage('SAST') {
            steps {
                sh 'semgrep scan --config auto --sarif --output semgrep-results.sarif .'
                recordIssues(tools: [sarif(pattern: 'semgrep-results.sarif')])
            }
        }`);
        }

        if (options.includeSca) {
            stages.push(`
        stage('SCA') {
            steps {
                sh 'trivy fs --format sarif --output trivy-results.sarif .'
                recordIssues(tools: [sarif(pattern: 'trivy-results.sarif')])
            }
        }`);
        }

        if (options.includeSbom) {
            stages.push(`
        stage('SBOM') {
            steps {
                sh 'syft . -o cyclonedx-json > sbom.cyclonedx.json'
                archiveArtifacts artifacts: 'sbom.cyclonedx.json'
            }
        }`);
        }

        return `// J.O.E. DevSecOps Pipeline - Jenkinsfile
// Generated by J.O.E. (Joint-Ops-Engine)

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
    }

    environment {
        GITGUARDIAN_API_KEY = credentials('gitguardian-api-key')
        SNYK_TOKEN = credentials('snyk-token')
    }

    stages {${stages.join('\n')}
    }

    post {
        always {
            cleanWs()
        }
        failure {
            emailext(
                subject: "Pipeline Failed: \${env.JOB_NAME} #\${env.BUILD_NUMBER}",
                body: "Check console output at \${env.BUILD_URL}",
                recipientProviders: [requestor()]
            )
        }
    }
}
`;
    }

    async savePipeline(type: PipelineType, content: string): Promise<string> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }

        const fs = await import('fs').then(m => m.promises);
        let filePath: string;

        switch (type) {
            case 'github-actions': {
                const ghDir = path.join(workspaceFolder, '.github', 'workflows');
                await fs.mkdir(ghDir, { recursive: true });
                filePath = path.join(ghDir, 'joe-security.yml');
                break;
            }
            case 'azure-pipelines':
                filePath = path.join(workspaceFolder, 'azure-pipelines.yml');
                break;
            case 'gitlab-ci':
                filePath = path.join(workspaceFolder, '.gitlab-ci.yml');
                break;
            case 'jenkins':
                filePath = path.join(workspaceFolder, 'Jenkinsfile');
                break;
            default:
                throw new Error(`Unsupported pipeline type: ${type}`);
        }

        await fs.writeFile(filePath, content, 'utf-8');
        Logger.info(`Pipeline saved to ${filePath}`);

        // Open the file
        const doc = await vscode.workspace.openTextDocument(filePath);
        await vscode.window.showTextDocument(doc);

        return filePath;
    }

    async showPipelineWizard(): Promise<void> {
        // Step 1: Select pipeline type
        const pipelineType = await vscode.window.showQuickPick(
            [
                { label: 'GitHub Actions', value: 'github-actions' as PipelineType, description: 'CI/CD for GitHub repositories' },
                { label: 'Azure Pipelines', value: 'azure-pipelines' as PipelineType, description: 'Azure DevOps pipelines' },
                { label: 'GitLab CI', value: 'gitlab-ci' as PipelineType, description: 'GitLab CI/CD' },
                { label: 'Jenkins', value: 'jenkins' as PipelineType, description: 'Jenkinsfile pipeline' }
            ],
            { placeHolder: 'Select CI/CD platform' }
        );

        if (!pipelineType) {return;}

        // Step 2: Select security features
        const features = await vscode.window.showQuickPick(
            [
                { label: 'SAST (Static Analysis)', picked: true, value: 'sast' },
                { label: 'SCA (Dependency Scanning)', picked: true, value: 'sca' },
                { label: 'Secret Detection', picked: true, value: 'secrets' },
                { label: 'SBOM Generation', picked: true, value: 'sbom' },
                { label: 'Container Scanning', picked: false, value: 'container' },
                { label: 'Policy Checks (IaC)', picked: false, value: 'policy' },
                { label: 'Compliance Reporting', picked: false, value: 'compliance' }
            ],
            { placeHolder: 'Select security features', canPickMany: true }
        );

        if (!features || features.length === 0) {return;}

        const options: PipelineOptions = {
            includeSast: features.some(f => f.value === 'sast'),
            includeSca: features.some(f => f.value === 'sca'),
            includeSbom: features.some(f => f.value === 'sbom'),
            includeContainerScan: features.some(f => f.value === 'container'),
            includeSecretScan: features.some(f => f.value === 'secrets'),
            includePolicyCheck: features.some(f => f.value === 'policy'),
            includeCompliance: features.some(f => f.value === 'compliance'),
            languages: ['javascript', 'typescript']
        };

        // Generate and save
        const content = await this.generatePipeline(pipelineType.value, options);
        const filePath = await this.savePipeline(pipelineType.value, content);

        vscode.window.showInformationMessage(`Pipeline created: ${path.basename(filePath)}`);
    }
}
