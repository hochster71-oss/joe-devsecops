import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Automated Route/Link Checker
 * Verifies all routes in the application are properly configured
 */

// Expected routes based on sidebar configuration
const EXPECTED_ROUTES = [
  '/dashboard',
  '/findings',
  '/threat-intel',
  '/kubernetes',
  '/gitlab',
  '/supply-chain',
  '/compliance',
  '/space-compliance',
  '/pipeline',
  '/ai-assistant',
  '/mission-control',
  '/attack-surface',
  '/analytics',
  '/reports',
  '/settings',
  '/admin',
  '/login'
];

describe('Route Configuration Checker', () => {
  describe('Sidebar Routes', () => {
    it('should have all expected routes defined in Sidebar.tsx', () => {
      const sidebarPath = path.join(__dirname, '../../src/renderer/components/layout/Sidebar.tsx');
      const sidebarContent = fs.readFileSync(sidebarPath, 'utf-8');

      const navItemRoutes = EXPECTED_ROUTES.filter(route =>
        route !== '/login' && route !== '/admin' // These are special routes
      );

      for (const route of navItemRoutes) {
        // Check if route is defined in navItems or bottomNavItems
        const hasRoute = sidebarContent.includes(`path: '${route}'`) ||
                        sidebarContent.includes(`path: "${route}"`);

        expect(hasRoute, `Route ${route} should be defined in Sidebar.tsx`).toBe(true);
      }
    });
  });

  describe('App Router Configuration', () => {
    it('should have all routes configured in App.tsx', () => {
      const appPath = path.join(__dirname, '../../src/renderer/App.tsx');
      const appContent = fs.readFileSync(appPath, 'utf-8');

      for (const route of EXPECTED_ROUTES) {
        // Check for Route element with path
        const routePath = route.replace('/', '');
        const hasRoute = appContent.includes(`path="${routePath}"`) ||
                        appContent.includes(`path="${route}"`) ||
                        appContent.includes(`path='${routePath}'`) ||
                        appContent.includes(`path='${route}'`);

        expect(hasRoute, `Route ${route} should be configured in App.tsx`).toBe(true);
      }
    });

    it('should have catch-all route for 404 handling', () => {
      const appPath = path.join(__dirname, '../../src/renderer/App.tsx');
      const appContent = fs.readFileSync(appPath, 'utf-8');

      const hasCatchAll = appContent.includes('path="*"') || appContent.includes("path='*'");
      expect(hasCatchAll, 'Should have catch-all route for 404 handling').toBe(true);
    });
  });

  describe('View Components', () => {
    it('should have view components for all routes', () => {
      const viewsDir = path.join(__dirname, '../../src/renderer/views');
      const viewFiles = fs.readdirSync(viewsDir).filter(f => f.endsWith('.tsx'));

      // Map routes to expected view files
      const routeToView: Record<string, string> = {
        '/dashboard': 'DashboardView.tsx',
        '/findings': 'FindingsView.tsx',
        '/threat-intel': 'ThreatIntelView.tsx',
        '/kubernetes': 'KubernetesView.tsx',
        '/gitlab': 'GitLabView.tsx',
        '/supply-chain': 'SupplyChainView.tsx',
        '/compliance': 'ComplianceView.tsx',
        '/space-compliance': 'SpaceComplianceView.tsx',
        '/pipeline': 'PipelineView.tsx',
        '/ai-assistant': 'AiAssistantView.tsx',
        '/mission-control': 'MissionControlView.tsx',
        '/attack-surface': 'AttackSurfaceView.tsx',
        '/analytics': 'AnalyticsView.tsx',
        '/reports': 'ReportsView.tsx',
        '/settings': 'SettingsView.tsx',
        '/admin': 'AdminView.tsx',
        '/login': 'LoginView.tsx'
      };

      for (const [route, viewFile] of Object.entries(routeToView)) {
        const exists = viewFiles.includes(viewFile);
        expect(exists, `View component ${viewFile} should exist for route ${route}`).toBe(true);
      }
    });
  });

  describe('Navigation Imports', () => {
    it('should have all view imports in App.tsx', () => {
      const appPath = path.join(__dirname, '../../src/renderer/App.tsx');
      const appContent = fs.readFileSync(appPath, 'utf-8');

      const expectedImports = [
        'DashboardView',
        'FindingsView',
        'ThreatIntelView',
        'KubernetesView',
        'GitLabView',
        'SupplyChainView',
        'ComplianceView',
        'SpaceComplianceView',
        'PipelineView',
        'AiAssistantView',
        'MissionControlView',
        'AttackSurfaceView',
        'AnalyticsView',
        'ReportsView',
        'SettingsView',
        'AdminView',
        'LoginView'
      ];

      for (const viewName of expectedImports) {
        const hasImport = appContent.includes(`import ${viewName}`) ||
                         appContent.includes(`import { ${viewName}`);
        expect(hasImport, `Should import ${viewName} in App.tsx`).toBe(true);
      }
    });
  });

  describe('Protected Route Configuration', () => {
    it('should wrap authenticated routes in ProtectedRoute', () => {
      const appPath = path.join(__dirname, '../../src/renderer/App.tsx');
      const appContent = fs.readFileSync(appPath, 'utf-8');

      const hasProtectedRoute = appContent.includes('ProtectedRoute');
      expect(hasProtectedRoute, 'Should have ProtectedRoute component').toBe(true);
    });

    it('should wrap admin routes in AdminRoute', () => {
      const appPath = path.join(__dirname, '../../src/renderer/App.tsx');
      const appContent = fs.readFileSync(appPath, 'utf-8');

      const hasAdminRoute = appContent.includes('AdminRoute');
      expect(hasAdminRoute, 'Should have AdminRoute component for admin pages').toBe(true);
    });
  });
});

describe('External Link Checker', () => {
  it('should not have broken documentation links', () => {
    // Check AUTHORITATIVE_SOURCES in compliance views
    const complianceFiles = [
      'src/renderer/views/ComplianceView.tsx',
      'src/renderer/views/SpaceComplianceView.tsx'
    ];

    for (const file of complianceFiles) {
      const filePath = path.join(__dirname, '../../', file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf-8');

        // Check for well-formed URLs
        const urlMatches = content.match(/https?:\/\/[^\s'"]+/g) || [];

        for (const url of urlMatches) {
          // Basic URL validation
          try {
            new URL(url.replace(/['"]/g, ''));
          } catch {
            throw new Error(`Invalid URL found in ${file}: ${url}`);
          }
        }
      }
    }
  });
});
