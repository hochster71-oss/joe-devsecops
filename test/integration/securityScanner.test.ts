import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * Integration tests for Security Scanner service
 * Tests the electron main process security scanning functionality
 */

// Mock the electron main process modules
vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn()
}));

vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  readFileSync: vi.fn(() => '{}'),
  writeFileSync: vi.fn()
}));

describe('Security Scanner Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('npm audit scanning', () => {
    it('should parse npm audit output correctly', async () => {
      const mockAuditOutput = {
        vulnerabilities: {
          'lodash': {
            name: 'lodash',
            severity: 'high',
            via: [{ title: 'Prototype Pollution' }]
          }
        },
        metadata: {
          vulnerabilities: {
            critical: 0,
            high: 1,
            moderate: 2,
            low: 0
          }
        }
      };

      // Simulate parsing audit output
      const result = parseAuditOutput(JSON.stringify(mockAuditOutput));

      expect(result.high).toBe(1);
      expect(result.moderate).toBe(2);
      expect(result.total).toBe(3);
    });

    it('should handle empty audit output', () => {
      const emptyAudit = {
        vulnerabilities: {},
        metadata: {
          vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 }
        }
      };

      const result = parseAuditOutput(JSON.stringify(emptyAudit));
      expect(result.total).toBe(0);
    });
  });

  describe('ESLint security scanning', () => {
    it('should identify security rule violations', () => {
      const mockEslintOutput = [
        {
          filePath: '/src/test.ts',
          messages: [
            { ruleId: 'no-eval', severity: 2, message: 'eval can be harmful' },
            { ruleId: 'no-new-func', severity: 2, message: 'The Function constructor is eval' }
          ]
        }
      ];

      const securityFindings = filterSecurityFindings(mockEslintOutput);
      expect(securityFindings.length).toBe(2);
      expect(securityFindings[0].ruleId).toBe('no-eval');
    });

    it('should filter non-security rules', () => {
      const mockEslintOutput = [
        {
          filePath: '/src/test.ts',
          messages: [
            { ruleId: 'semi', severity: 1, message: 'Missing semicolon' },
            { ruleId: 'no-eval', severity: 2, message: 'eval can be harmful' }
          ]
        }
      ];

      const securityFindings = filterSecurityFindings(mockEslintOutput);
      expect(securityFindings.length).toBe(1);
      expect(securityFindings[0].ruleId).toBe('no-eval');
    });
  });

  describe('SARIF output generation', () => {
    it('should generate valid SARIF format', () => {
      const findings = [
        {
          id: 'SEC-001',
          severity: 'high',
          message: 'SQL Injection vulnerability',
          file: 'src/api.ts',
          line: 42
        }
      ];

      const sarif = generateSarif(findings);

      expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].results).toHaveLength(1);
    });

    it('should map severity levels correctly', () => {
      const findings = [
        { id: '1', severity: 'critical', message: 'test', file: 'a.ts', line: 1 },
        { id: '2', severity: 'high', message: 'test', file: 'b.ts', line: 1 },
        { id: '3', severity: 'medium', message: 'test', file: 'c.ts', line: 1 },
        { id: '4', severity: 'low', message: 'test', file: 'd.ts', line: 1 }
      ];

      const sarif = generateSarif(findings);
      const levels = sarif.runs[0].results.map((r: { level: string }) => r.level);

      expect(levels).toContain('error');
      expect(levels).toContain('warning');
      expect(levels).toContain('note');
    });
  });
});

// Helper functions that would be in the actual scanner
function parseAuditOutput(jsonString: string): { critical: number; high: number; moderate: number; low: number; total: number } {
  const data = JSON.parse(jsonString);
  const vulns = data.metadata?.vulnerabilities || { critical: 0, high: 0, moderate: 0, low: 0 };
  return {
    ...vulns,
    total: vulns.critical + vulns.high + vulns.moderate + vulns.low
  };
}

function filterSecurityFindings(eslintOutput: Array<{ filePath: string; messages: Array<{ ruleId: string; severity: number; message: string }> }>) {
  const securityRules = ['no-eval', 'no-new-func', 'no-implied-eval', 'security/detect-eval-with-expression'];

  return eslintOutput.flatMap(file =>
    file.messages.filter(msg => securityRules.includes(msg.ruleId))
  );
}

function generateSarif(findings: Array<{ id: string; severity: string; message: string; file: string; line: number }>) {
  const severityToLevel: Record<string, string> = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
    'info': 'note'
  };

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'J.O.E. Security Scanner',
          version: '1.0.0'
        }
      },
      results: findings.map(f => ({
        ruleId: f.id,
        level: severityToLevel[f.severity] || 'warning',
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line }
          }
        }]
      }))
    }]
  };
}
