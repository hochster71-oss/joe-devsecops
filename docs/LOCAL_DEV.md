# J.O.E. DevSecOps Arsenal - Local Development Guide

## Stack Overview

| Component | Technology |
|-----------|------------|
| Frontend | React 18 + TypeScript + Vite |
| UI Framework | Tailwind CSS |
| State Management | Zustand (with persist middleware) |
| Routing | React Router DOM v6 |
| Backend | Electron 35 (Node.js main process) |
| Database | SQLite (better-sqlite3) |
| Build Tool | Electron Forge + Vite |
| Auth | Custom session-based + 2FA (TOTP) |

## Prerequisites

- **Node.js**: v18.x or v20.x (LTS recommended)
- **npm**: v9.x or higher
- **Git**: v2.x
- **Windows**: Windows 10/11 (primary development platform)
- **Optional**: Ollama (for AI features) - https://ollama.ai

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
cd joe-devsecops

# 2. Install dependencies
npm install

# 3. Start development server
npm start

# 4. (Optional) Run type checking
npm run typecheck

# 5. (Optional) Run linting
npm run lint
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm start` | Start Electron app in development mode |
| `npm run package` | Package app for distribution |
| `npm run make` | Build distributable installers |
| `npm run lint` | Run ESLint on source files |
| `npm run typecheck` | Run TypeScript type checking |

## Project Structure

```
joe-devsecops/
├── electron/           # Electron main process code
│   ├── main.ts        # Main entry point
│   ├── preload.ts     # Context bridge (IPC)
│   ├── security-scanner.ts
│   ├── kubernetes-scanner.ts
│   ├── gitlab-scanner.ts
│   ├── threat-intel.ts
│   ├── sbom-service.ts
│   ├── secret-scanner.ts
│   ├── secure-vault.ts
│   ├── analytics-service.ts
│   └── space-compliance-service.ts
├── src/
│   ├── renderer/      # React frontend
│   │   ├── App.tsx    # Root component
│   │   ├── main.tsx   # React entry point
│   │   ├── components/
│   │   ├── views/     # Page components
│   │   └── store/     # Zustand stores
│   ├── services/      # Shared services
│   └── types/         # TypeScript definitions
├── test/              # Test files
│   ├── unit/
│   └── integration/
├── docs/              # Documentation
├── scripts/           # Build/utility scripts
└── resources/         # Static assets
```

## Authentication

The app implements DoD STIG/NIST 800-53 compliant authentication:

- **Session Timeout**: 15 minutes of inactivity
- **Token Expiration**: 24 hours
- **Account Lockout**: 5 failed attempts = 30 minute lockout
- **Password Requirements**: 15+ characters (DoD privileged account standard)
- **2FA**: TOTP-based (Google Authenticator compatible)

### Default Development Credentials

When running without Electron IPC (browser mode):
- Username: `mhoch` | Password: `darkwolf`
- Username: `jscholer` | Password: `darkwolf`

**Note**: First login will require password change (DoD compliance).

## Security Note: Auth State Persistence

**IMPORTANT**: Authentication state is intentionally NOT persisted between app restarts. This is a security feature per DoD STIG requirements. Users must re-authenticate each time the app starts.

This behavior is controlled in `src/renderer/store/authStore.ts`:
- Lines 6-23: Clear auth state on app load
- Lines 550-558: `partialize` returns empty object (no persistence)

## Environment Variables

This application uses minimal environment variables. Most configuration is handled through Electron's secure storage mechanisms.

See `.env.example` for available options.

## Troubleshooting

### App won't start
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Type errors
```bash
npm run typecheck
```

### Lint errors
```bash
npm run lint
```

### Electron window doesn't appear
- Check console for errors
- Ensure no other Electron instances are running
- Try: `taskkill /f /im electron.exe` (Windows)

## API Endpoints (IPC Channels)

The app uses Electron IPC for all backend communication. Key channels:

| Channel | Description |
|---------|-------------|
| `auth-login` | User authentication |
| `auth-logout` | Session termination |
| `security-run-audit` | Run security scans |
| `kubernetes-*` | Kubernetes security operations |
| `gitlab-*` | GitLab security operations |
| `threatIntel-*` | Threat intelligence queries |

See `electron/preload.ts` for complete API surface.
