#!/usr/bin/env npx ts-node
/**
 * data-testid Coverage Enforcement Script
 * DoD DevSecOps Compliance - E2E Test Coverage Gate
 *
 * Ensures all interactive UI elements have data-testid attributes
 * for reliable E2E testing with Playwright.
 *
 * Usage: npx ts-node scripts/check-testid-coverage.ts
 */

import * as fs from 'fs';
import * as path from 'path';

interface CoverageResult {
  file: string;
  missing: string[];
  line: number;
}

interface CoverageSummary {
  totalFiles: number;
  filesWithMissing: number;
  totalMissing: number;
  results: CoverageResult[];
  coverage: number;
}

// Interactive elements that MUST have data-testid
const INTERACTIVE_PATTERNS = [
  /<button(?![^>]*data-testid)[^>]*>/gi,
  /<input(?![^>]*data-testid)[^>]*>/gi,
  /<select(?![^>]*data-testid)[^>]*>/gi,
  /<textarea(?![^>]*data-testid)[^>]*>/gi,
  /<a(?![^>]*data-testid)[^>]*href[^>]*>/gi,
  /onClick\s*=\s*\{[^}]+\}(?![^>]*data-testid)/gi,
  /onSubmit\s*=\s*\{[^}]+\}(?![^>]*data-testid)/gi,
];

// Elements that should have data-testid for assertions
const ASSERTION_PATTERNS = [
  /<form(?![^>]*data-testid)[^>]*>/gi,
  /<table(?![^>]*data-testid)[^>]*>/gi,
  /<nav(?![^>]*data-testid)[^>]*>/gi,
];

const EXCLUDED_DIRS = ['node_modules', '.vite', 'dist', 'out', 'coverage', '.git'];
const INCLUDED_EXTENSIONS = ['.tsx', '.jsx'];

function findTsxFiles(dir: string): string[] {
  const files: string[] = [];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.includes(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        if (INCLUDED_EXTENSIONS.some(ext => entry.name.endsWith(ext))) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(dir);
  return files;
}

function checkFile(filePath: string): CoverageResult | null {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const missing: string[] = [];

  // Check each line for interactive elements without data-testid
  lines.forEach((line, index) => {
    for (const pattern of [...INTERACTIVE_PATTERNS, ...ASSERTION_PATTERNS]) {
      const matches = line.match(pattern);
      if (matches) {
        matches.forEach(match => {
          // Skip if it's a component import or type definition
          if (!match.includes('import') && !match.includes('type ')) {
            missing.push(`Line ${index + 1}: ${match.substring(0, 80)}${match.length > 80 ? '...' : ''}`);
          }
        });
      }
    }
  });

  if (missing.length > 0) {
    return {
      file: filePath,
      missing,
      line: 0
    };
  }

  return null;
}

function checkCoverage(srcDir: string): CoverageSummary {
  const files = findTsxFiles(srcDir);
  const results: CoverageResult[] = [];
  let totalMissing = 0;

  for (const file of files) {
    const result = checkFile(file);
    if (result) {
      results.push(result);
      totalMissing += result.missing.length;
    }
  }

  const filesWithMissing = results.length;
  const coverage = files.length > 0
    ? Math.round(((files.length - filesWithMissing) / files.length) * 100)
    : 100;

  return {
    totalFiles: files.length,
    filesWithMissing,
    totalMissing,
    results,
    coverage
  };
}

function generateReport(summary: CoverageSummary): string {
  const lines: string[] = [
    '═══════════════════════════════════════════════════════════════',
    '  J.O.E. DevSecOps Arsenal - data-testid Coverage Report',
    '  DoD Enterprise DevSecOps Compliance Gate',
    '═══════════════════════════════════════════════════════════════',
    '',
    `📊 Coverage: ${summary.coverage}%`,
    `📁 Total Files Scanned: ${summary.totalFiles}`,
    `⚠️  Files with Missing data-testid: ${summary.filesWithMissing}`,
    `🔍 Total Missing Attributes: ${summary.totalMissing}`,
    '',
  ];

  if (summary.results.length > 0) {
    lines.push('───────────────────────────────────────────────────────────────');
    lines.push('  MISSING data-testid ATTRIBUTES');
    lines.push('───────────────────────────────────────────────────────────────');

    for (const result of summary.results) {
      lines.push('');
      lines.push(`📄 ${result.file}`);
      for (const missing of result.missing) {
        lines.push(`   └─ ${missing}`);
      }
    }
  }

  lines.push('');
  lines.push('═══════════════════════════════════════════════════════════════');

  if (summary.coverage >= 100) {
    lines.push('✅ PASS: All interactive elements have data-testid attributes');
  } else if (summary.coverage >= 80) {
    lines.push('⚠️  WARNING: Coverage below 100% - Add missing data-testid attributes');
  } else {
    lines.push('❌ FAIL: Coverage below 80% - Critical gap in E2E test coverage');
  }

  lines.push('═══════════════════════════════════════════════════════════════');

  return lines.join('\n');
}

function saveEvidenceReport(summary: CoverageSummary, evidencePath: string): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportPath = path.join(evidencePath, `testid-coverage-${timestamp}.json`);

  const evidence = {
    timestamp: new Date().toISOString(),
    tool: 'check-testid-coverage.ts',
    standard: 'DoD Enterprise DevSecOps Reference Design',
    summary: {
      coverage: summary.coverage,
      totalFiles: summary.totalFiles,
      filesWithMissing: summary.filesWithMissing,
      totalMissing: summary.totalMissing,
      pass: summary.coverage >= 100
    },
    details: summary.results.map(r => ({
      file: r.file,
      missingCount: r.missing.length,
      items: r.missing
    }))
  };

  fs.mkdirSync(evidencePath, { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify(evidence, null, 2));
  console.log(`\n📋 Evidence saved to: ${reportPath}`);
}

// Main execution
const args = process.argv.slice(2);
const strictMode = args.includes('--strict');
const threshold = strictMode ? 100 : 80;

const projectRoot = path.resolve(__dirname, '..');
const srcDir = path.join(projectRoot, 'src');
const evidenceDir = path.join(projectRoot, 'evidence', 'tests', 'e2e');

console.log('🔍 Scanning for data-testid coverage...\n');
if (strictMode) {
  console.log('⚠️  STRICT MODE: Requiring 100% coverage\n');
}

const summary = checkCoverage(srcDir);
const report = generateReport(summary);

console.log(report);
saveEvidenceReport(summary, evidenceDir);

// Exit with error code if coverage is below threshold
if (summary.coverage < threshold) {
  console.log(`\n❌ Coverage ${summary.coverage}% is below required threshold of ${threshold}%`);
  process.exit(1);
}

console.log(`\n✅ Coverage ${summary.coverage}% meets threshold of ${threshold}%`);
process.exit(0);
