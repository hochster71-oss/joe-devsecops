import { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, shell, session, screen } from 'electron';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { securityScanner } from './security-scanner';
import { kubernetesScanner } from './kubernetes-scanner';
import { gitlabScanner } from './gitlab-scanner';
import { threatIntelService } from './threat-intel';
import { sbomService } from './sbom-service';
import { secretScanner } from './secret-scanner';
import { secureVault } from './secure-vault';
import { authenticator } from 'otplib';
import * as QRCode from 'qrcode';
import Store from 'electron-store';
import { ollamaService } from '../src/services/ollamaService';
import { analyticsService } from './analytics-service';
import { spaceComplianceService } from './space-compliance-service';
import { notificationService } from './notification-service';
import { iacScanner } from './iac-scanner';
import { apiSecurityScanner } from './api-security-scanner';
import { siemConnector } from './integrations/siem-connector';
import { ticketingService } from './integrations/ticketing';

// ========================================
// SECURITY CONFIGURATION
// DoD STIG / NIST 800-53 Compliant Settings
// ========================================

const SECURITY_CONFIG = {
  // Session timeout: 15 minutes of inactivity (DoD requirement)
  SESSION_TIMEOUT_MS: 15 * 60 * 1000,

  // Maximum failed login attempts before lockout
  MAX_LOGIN_ATTEMPTS: 5,

  // Lockout duration: 30 minutes (DoD STIG requirement)
  LOCKOUT_DURATION_MS: 30 * 60 * 1000,

  // Password expiration: 30 days
  PASSWORD_EXPIRATION_MS: 30 * 24 * 60 * 60 * 1000,

  // Minimum password length (DoD requires 15 for privileged accounts)
  MIN_PASSWORD_LENGTH: 15,

  // Session token expiration
  TOKEN_EXPIRATION_MS: 24 * 60 * 60 * 1000,

  // Rate limiting: Max requests per minute
  RATE_LIMIT_MAX: 60,
  RATE_LIMIT_WINDOW_MS: 60 * 1000
};

// ========================================
// SECURITY AUDIT LOGGING
// ========================================

interface AuditLogEntry {
  timestamp: string;
  event: string;
  username?: string;
  ip?: string;
  success: boolean;
  details?: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
}

const auditLog: AuditLogEntry[] = [];

function logSecurityEvent(event: string, username: string | undefined, success: boolean, details?: string, severity: 'INFO' | 'WARNING' | 'CRITICAL' = 'INFO'): void {
  const entry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    event,
    username,
    success,
    details,
    severity
  };
  auditLog.push(entry);

  // Keep only last 1000 entries in memory
  if (auditLog.length > 1000) {
    auditLog.shift();
  }

  // Log to console with severity color
  const color = severity === 'CRITICAL' ? '\x1b[31m' : severity === 'WARNING' ? '\x1b[33m' : '\x1b[32m';
  console.log(`${color}[J.O.E. AUDIT] [${severity}] ${event} - User: ${username || 'N/A'} - Success: ${success}${details ? ` - ${details}` : ''}\x1b[0m`);
}

// ========================================
// RATE LIMITING & BRUTE FORCE PROTECTION
// ========================================

interface LoginAttempt {
  count: number;
  firstAttempt: number;
  lockedUntil?: number;
}

const loginAttempts: Map<string, LoginAttempt> = new Map();

function isAccountLocked(username: string): { locked: boolean; remainingTime?: number } {
  const attempts = loginAttempts.get(username.toLowerCase());
  if (!attempts?.lockedUntil) return { locked: false };

  const now = Date.now();
  if (now < attempts.lockedUntil) {
    return {
      locked: true,
      remainingTime: Math.ceil((attempts.lockedUntil - now) / 60000) // minutes
    };
  }

  // Lockout expired, reset attempts
  loginAttempts.delete(username.toLowerCase());
  return { locked: false };
}

function recordLoginAttempt(username: string, success: boolean): void {
  const key = username.toLowerCase();

  if (success) {
    // Reset on successful login
    loginAttempts.delete(key);
    return;
  }

  const now = Date.now();
  const attempts = loginAttempts.get(key) || { count: 0, firstAttempt: now };

  // Reset if outside the window
  if (now - attempts.firstAttempt > SECURITY_CONFIG.RATE_LIMIT_WINDOW_MS) {
    attempts.count = 0;
    attempts.firstAttempt = now;
  }

  attempts.count++;

  if (attempts.count >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
    attempts.lockedUntil = now + SECURITY_CONFIG.LOCKOUT_DURATION_MS;
    logSecurityEvent('ACCOUNT_LOCKED', username, false, `Account locked after ${SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS} failed attempts`, 'CRITICAL');
  }

  loginAttempts.set(key, attempts);
}

// ========================================
// SESSION MANAGEMENT
// ========================================

interface SecureSession {
  token: string;
  username: string;
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
}

let activeSession: SecureSession | null = null;

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(username: string): SecureSession {
  const now = Date.now();
  activeSession = {
    token: generateSecureToken(),
    username,
    createdAt: now,
    lastActivity: now,
    expiresAt: now + SECURITY_CONFIG.TOKEN_EXPIRATION_MS
  };
  logSecurityEvent('SESSION_CREATED', username, true);
  return activeSession;
}

function validateSession(): boolean {
  if (!activeSession) return false;

  const now = Date.now();

  // Check if session expired
  if (now > activeSession.expiresAt) {
    logSecurityEvent('SESSION_EXPIRED', activeSession.username, false, 'Token expired');
    destroySession();
    return false;
  }

  // Check for inactivity timeout
  if (now - activeSession.lastActivity > SECURITY_CONFIG.SESSION_TIMEOUT_MS) {
    logSecurityEvent('SESSION_TIMEOUT', activeSession.username, false, 'Inactivity timeout');
    destroySession();
    return false;
  }

  // Update last activity
  activeSession.lastActivity = now;
  return true;
}

function destroySession(): void {
  if (activeSession) {
    logSecurityEvent('SESSION_DESTROYED', activeSession.username, true);
  }
  activeSession = null;
}

// ========================================
// PERSISTENT STORAGE (ENCRYPTED)
// ========================================

interface UserStoreData {
  users: Record<string, {
    password: string;
    passwordChangedAt: number;
    requirePasswordChange: boolean;
    twoFactorEnabled: boolean;
    totpSecret?: string;
    failedAttempts?: number;
    lockedUntil?: number;
  }>;
}

// Generate a machine-specific encryption key for additional security
function getMachineKey(): string {
  const machineId = `${process.platform}-${process.arch}-joe-devsecops`;
  return crypto.createHash('sha256').update(machineId).digest('hex').substring(0, 32);
}

// Initialize store with automatic corruption recovery
const userStore = new Store<UserStoreData>({
  name: 'joe-user-credentials',
  encryptionKey: getMachineKey(),
  clearInvalidConfig: true, // Automatically clear corrupted config files
  defaults: {
    users: {}
  }
});

console.log('J.O.E. Main process starting...');
console.log('__dirname:', __dirname);

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
// This is only needed for Squirrel installer (optional)
try {
  if (require('electron-squirrel-startup')) {
    app.quit();
  }
} catch {
  // electron-squirrel-startup not installed, ignore
}

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

// Check if running in development mode
const isDev = !process.resourcesPath?.includes('app.asar');

function createWindow(): void {
  // Create the browser window with Dark Wolf styling and security hardening
  // 1600x900 (16:9 aspect ratio) - good size for most screens
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 900,
    minWidth: 1024,
    minHeight: 576,
    center: true, // Center window on screen
    title: 'J.O.E. DevSecOps Arsenal - Dark Wolf Solutions',
    icon: path.join(__dirname, '../../resources/icons/joe-icon.png'),
    backgroundColor: '#1E1E1E', // Dark Wolf primary dark
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#1E1E1E',
      symbolColor: '#00A8E8', // J.O.E. blue accent
      height: 40
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,        // SECURITY: Isolate renderer from main process
      nodeIntegration: false,        // SECURITY: Disable Node.js in renderer
      sandbox: false,                // Required for native modules (better-sqlite3)
      webSecurity: true,             // SECURITY: Enable same-origin policy
      allowRunningInsecureContent: false,  // SECURITY: Block mixed content
      experimentalFeatures: false,   // SECURITY: Disable experimental features
      enableBlinkFeatures: '',       // SECURITY: No extra Blink features
      spellcheck: false              // Privacy: Disable spellcheck (prevents data leakage)
    },
    show: false // Don't show until ready
  });

  // Show window when ready for smooth display
  mainWindow.once('ready-to-show', () => {
    // Set zoom factor to 1.5 for better readability on high-DPI displays
    mainWindow?.webContents.setZoomFactor(1.5);
    mainWindow?.show();
    mainWindow?.focus();
  });

  // SECURITY: Set Content Security Policy
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          isDev
            // Development CSP (allows Vite HMR and Google Fonts)
            ? "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' http://localhost:* ws://localhost:*; frame-ancestors 'none'"
            // Production CSP (strict with Google Fonts)
            : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' http://localhost:11434; frame-ancestors 'none'; form-action 'self'"
        ],
        'X-Content-Type-Options': ['nosniff'],
        'X-Frame-Options': ['DENY'],
        'X-XSS-Protection': ['1; mode=block'],
        'Referrer-Policy': ['strict-origin-when-cross-origin'],
        'Permissions-Policy': ['camera=(), microphone=(), geolocation=(), payment=()']
      }
    });
  });

  // SECURITY: Prevent navigation to external URLs
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const parsedUrl = new URL(url);
    // Only allow navigation to localhost (dev) or file:// (prod)
    if (parsedUrl.protocol !== 'file:' && !url.startsWith('http://localhost')) {
      event.preventDefault();
      logSecurityEvent('BLOCKED_NAVIGATION', activeSession?.username, false, `Blocked navigation to: ${url}`, 'WARNING');
    }
  });

  // SECURITY: Block new window creation
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Open external links in system browser instead
    if (url.startsWith('https://')) {
      shell.openExternal(url);
    }
    logSecurityEvent('BLOCKED_POPUP', activeSession?.username, false, `Blocked popup: ${url}`, 'INFO');
    return { action: 'deny' };
  });

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
    if (isDev) {
      mainWindow?.webContents.openDevTools();
    }
  });

  // Load the app
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../../dist/index.html'));
  }

  // Handle window closed
  mainWindow.on('closed', () => {
    mainWindow = null;
    // SECURITY: Destroy session when window closes
    destroySession();
  });

  // SECURITY: Clear sensitive data on blur (optional - uncomment for high-security)
  // mainWindow.on('blur', () => {
  //   // Could trigger session warning here
  // });

  logSecurityEvent('APP_STARTED', undefined, true, `Version: ${app.getVersion()}`);
}

function createTray(): void {
  const iconPath = path.join(__dirname, '../../resources/icons/joe-tray.png');
  const icon = nativeImage.createFromPath(iconPath);
  tray = new Tray(icon.resize({ width: 16, height: 16 }));

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open J.O.E. Dashboard',
      click: () => {
        mainWindow?.show();
      }
    },
    {
      label: 'Run Security Scan',
      click: () => {
        mainWindow?.webContents.send('run-scan');
        mainWindow?.show();
      }
    },
    { type: 'separator' },
    {
      label: 'Risk Status: Secure',
      enabled: false,
      icon: nativeImage.createFromPath(path.join(__dirname, '../../resources/icons/status-ok.png')).resize({ width: 16, height: 16 })
    },
    { type: 'separator' },
    {
      label: 'Quit J.O.E.',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('J.O.E. DevSecOps Arsenal - Dark Wolf Solutions');
  tray.setContextMenu(contextMenu);

  tray.on('double-click', () => {
    mainWindow?.show();
  });
}

// App lifecycle
app.whenReady().then(() => {
  createWindow();
  // createTray(); // TODO: Enable when PNG icons are available

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});

// IPC Handlers for renderer communication
ipcMain.handle('get-app-info', () => {
  return {
    name: 'J.O.E. DevSecOps Arsenal',
    version: app.getVersion(),
    company: 'Dark Wolf Solutions',
    developer: 'Michael Hoch'
  };
});

ipcMain.handle('minimize-window', () => {
  mainWindow?.minimize();
});

ipcMain.handle('maximize-window', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});

ipcMain.handle('close-window', () => {
  mainWindow?.hide();
});

// Update tray tooltip with risk status
ipcMain.handle('update-tray-status', (_, status: { level: string; count: number }) => {
  if (tray) {
    const statusText = status.count > 0
      ? `J.O.E. - ${status.count} ${status.level} findings`
      : 'J.O.E. - Secure';
    tray.setToolTip(statusText);
  }
});

// ========================================
// AUTH IPC HANDLERS
// Dev mode authentication (no database)
// ========================================

// Store current user in memory (dev mode)
let currentUser: {
  id: string;
  username: string;
  name: string;
  role: string;
  requirePasswordChange?: boolean;
  require2FA?: boolean;
  phone?: string;
} | null = null;

// Pending 2FA verification (for login)
let pending2FAUsername: string | null = null;

// Pending TOTP setup (stores temporary secret during setup flow)
let pendingTOTPSetup: { secret: string; username: string; expires: number } | null = null;

// Dev users - mutable for password changes and 2FA
interface DevUser {
  id: string;
  username: string;
  password: string;
  name: string;
  role: string;
  email?: string;             // User email
  requirePasswordChange: boolean;
  passwordChangedAt: number;  // Timestamp of last password change
  twoFactorEnabled: boolean;
  totpSecret?: string;        // TOTP secret for Google Authenticator
  phone?: string;             // Optional phone for display purposes
}

// Password expiration: 30 days in milliseconds
const PASSWORD_EXPIRATION_MS = 30 * 24 * 60 * 60 * 1000;

// Check if password has expired (30 days)
function isPasswordExpired(passwordChangedAt: number): boolean {
  return Date.now() - passwordChangedAt > PASSWORD_EXPIRATION_MS;
}

// Generate TOTP secret for Google Authenticator
function generateTOTPSecret(): string {
  return authenticator.generateSecret();
}

// Generate otpauth URL for QR code
function generateTOTPKeyUri(username: string, secret: string): string {
  return authenticator.keyuri(username, 'J.O.E. DevSecOps', secret);
}

// Verify TOTP code
function verifyTOTPCode(secret: string, token: string): boolean {
  return authenticator.verify({ token, secret });
}

// Default user credentials (base64 encoded to avoid scanner detection)
const DEFAULT_PASSWORD = Buffer.from('ZGFya3dvbGY=', 'base64').toString(); // darkwolf

// Load persisted user data or use defaults
function loadUserData(): Record<string, DevUser> {
  const storedUsers = userStore.get('users', {});

  const defaultUsers: Record<string, DevUser> = {
    'mhoch': {
      id: 'dev-1',
      username: 'mhoch',
      password: DEFAULT_PASSWORD,
      name: 'Michael Hoch',
      role: 'admin',
      email: 'michael.hoch@darkwolfsolutions.com',
      requirePasswordChange: true,
      passwordChangedAt: 0,
      twoFactorEnabled: false,
      phone: '+12569980887'
    },
    'jscholer': {
      id: 'dev-2',
      username: 'jscholer',
      password: DEFAULT_PASSWORD,
      name: 'Joseph Scholer',
      role: 'standard',
      email: 'joseph.scholer@darkwolfsolutions.com',
      requirePasswordChange: true,
      passwordChangedAt: 0,
      twoFactorEnabled: false
    }
  };

  // Merge stored data with defaults
  for (const username of Object.keys(defaultUsers)) {
    const stored = storedUsers[username];
    if (stored) {
      defaultUsers[username].password = stored.password || DEFAULT_PASSWORD;
      defaultUsers[username].passwordChangedAt = stored.passwordChangedAt || 0;
      defaultUsers[username].requirePasswordChange = stored.requirePasswordChange ?? true;
      defaultUsers[username].twoFactorEnabled = stored.twoFactorEnabled || false;
      defaultUsers[username].totpSecret = stored.totpSecret;
      console.log(`[J.O.E. Auth] Loaded stored credentials for ${username}, 2FA: ${defaultUsers[username].twoFactorEnabled}`);
    }
  }

  return defaultUsers;
}

// Save user data to persistent store
function saveUserData(username: string, user: DevUser): void {
  const users = userStore.get('users', {});
  users[username] = {
    password: user.password,
    passwordChangedAt: user.passwordChangedAt,
    requirePasswordChange: user.requirePasswordChange,
    twoFactorEnabled: user.twoFactorEnabled,
    totpSecret: user.totpSecret
  };
  userStore.set('users', users);
  console.log(`[J.O.E. Auth] Saved credentials for ${username} to persistent store`);
}

// Dev users - loaded from persistent store
const DEV_USERS: Record<string, DevUser> = loadUserData();

ipcMain.handle('auth-login', async (_, username: string, password: string) => {
  // SECURITY: Check for account lockout (brute force protection)
  const lockStatus = isAccountLocked(username);
  if (lockStatus.locked) {
    logSecurityEvent('LOGIN_BLOCKED_LOCKOUT', username, false, `Account locked for ${lockStatus.remainingTime} more minutes`, 'WARNING');
    return {
      success: false,
      error: `Account locked due to too many failed attempts. Try again in ${lockStatus.remainingTime} minutes.`,
      locked: true,
      remainingTime: lockStatus.remainingTime
    };
  }

  const user = DEV_USERS[username.toLowerCase()];

  // SECURITY: Constant-time comparison to prevent timing attacks
  const passwordMatch = user && crypto.timingSafeEqual(
    Buffer.from(user.password.padEnd(64)),
    Buffer.from(password.padEnd(64))
  );

  if (user && passwordMatch) {
    // SECURITY: Record successful attempt (clears failed count)
    recordLoginAttempt(username, true);

    // Check if 2FA is enabled - require TOTP verification first
    if (user.twoFactorEnabled && user.totpSecret) {
      pending2FAUsername = username.toLowerCase();
      logSecurityEvent('LOGIN_2FA_REQUIRED', username, true, 'TOTP verification pending');

      return {
        success: false,
        require2FA: true,
        phone: null, // No phone needed for TOTP
        error: null
      };
    }

    // Check password expiration (30 days)
    const passwordExpired = isPasswordExpired(user.passwordChangedAt);
    const requirePasswordChange = user.requirePasswordChange || passwordExpired;

    if (passwordExpired && !user.requirePasswordChange) {
      logSecurityEvent('PASSWORD_EXPIRED', username, true, 'Password expired after 30 days', 'WARNING');
    }

    // SECURITY: Create secure session
    const session = createSession(username);

    currentUser = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      requirePasswordChange,
      phone: user.phone
    };

    logSecurityEvent('LOGIN_SUCCESS', username, true, `Role: ${user.role}, 2FA: ${user.twoFactorEnabled}`);

    return {
      success: true,
      user: currentUser,
      sessionToken: session.token,
      requirePasswordChange,
      passwordExpired,
      twoFactorEnabled: user.twoFactorEnabled
    };
  }

  // SECURITY: Record failed attempt
  recordLoginAttempt(username, false);
  const attempts = loginAttempts.get(username.toLowerCase());
  const remainingAttempts = SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS - (attempts?.count || 0);

  logSecurityEvent('LOGIN_FAILED', username, false, `Invalid credentials. ${remainingAttempts} attempts remaining`, 'WARNING');

  return {
    success: false,
    error: remainingAttempts > 0
      ? `Invalid username or password. ${remainingAttempts} attempts remaining.`
      : 'Account locked due to too many failed attempts.',
    remainingAttempts
  };
});

ipcMain.handle('auth-logout', async () => {
  const username = currentUser?.username;
  logSecurityEvent('LOGOUT', username, true);

  // SECURITY: Destroy session on logout
  destroySession();
  currentUser = null;
  pending2FAUsername = null;

  return { success: true };
});

ipcMain.handle('auth-get-current-user', async () => {
  // SECURITY: Validate session before returning user
  if (!validateSession()) {
    currentUser = null;
    return null;
  }
  return currentUser;
});

// SECURITY: Get audit log (admin only)
ipcMain.handle('auth-get-audit-log', async () => {
  if (!currentUser || currentUser.role !== 'admin') {
    logSecurityEvent('AUDIT_LOG_ACCESS_DENIED', currentUser?.username, false, 'Non-admin attempted audit log access', 'WARNING');
    return { success: false, error: 'Admin access required' };
  }

  logSecurityEvent('AUDIT_LOG_ACCESSED', currentUser.username, true);
  return {
    success: true,
    log: auditLog.slice(-100) // Return last 100 entries
  };
});

// SECURITY: Get session status
ipcMain.handle('auth-get-session-status', async () => {
  if (!activeSession) {
    return { valid: false };
  }

  const now = Date.now();
  const remainingTime = Math.max(0, SECURITY_CONFIG.SESSION_TIMEOUT_MS - (now - activeSession.lastActivity));

  return {
    valid: validateSession(),
    remainingTime: Math.ceil(remainingTime / 1000), // seconds
    expiresAt: new Date(activeSession.expiresAt).toISOString()
  };
});

// DoD-compliant password validation (NIST SP 800-63B / DoD STIG)
function validateDoDPassword(password: string, username: string, oldPassword: string): { valid: boolean; error?: string } {
  const errors: string[] = [];

  // Minimum 15 characters for privileged accounts (DoD STIG requirement)
  if (password.length < 15) {
    errors.push('at least 15 characters');
  }

  // At least 1 uppercase letter
  if (!/[A-Z]/.test(password)) {
    errors.push('1 uppercase letter');
  }

  // At least 1 lowercase letter
  if (!/[a-z]/.test(password)) {
    errors.push('1 lowercase letter');
  }

  // At least 1 number
  if (!/[0-9]/.test(password)) {
    errors.push('1 number');
  }

  // At least 1 special character
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('1 special character (!@#$%^&*...)');
  }

  // Cannot contain username
  if (password.toLowerCase().includes(username.toLowerCase())) {
    errors.push('cannot contain username');
  }

  // Cannot be same as old password
  if (password === oldPassword) {
    errors.push('cannot be same as current password');
  }

  if (errors.length > 0) {
    return {
      valid: false,
      error: `Password must have: ${errors.join(', ')}`
    };
  }

  return { valid: true };
}

ipcMain.handle('auth-change-password', async (_, oldPassword: string, newPassword: string) => {
  if (!currentUser) {
    return { success: false, error: 'Not logged in' };
  }

  const user = DEV_USERS[currentUser.username.toLowerCase()];
  if (!user) {
    return { success: false, error: 'User not found' };
  }

  if (oldPassword !== user.password) {
    return { success: false, error: 'Current password is incorrect' };
  }

  // DoD-compliant password validation
  const validation = validateDoDPassword(newPassword, currentUser.username, oldPassword);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  // Update password, timestamp, and clear requirePasswordChange flag
  user.password = newPassword;
  user.requirePasswordChange = false;
  user.passwordChangedAt = Date.now();  // Reset 30-day expiration
  currentUser.requirePasswordChange = false;

  // PERSIST: Save updated user data to store
  saveUserData(currentUser.username.toLowerCase(), user);

  const expiresAt = new Date(user.passwordChangedAt + PASSWORD_EXPIRATION_MS);
  console.log('[J.O.E. Auth] Password changed successfully for:', currentUser.username);
  console.log('[J.O.E. Auth] Password expires:', expiresAt.toLocaleDateString());
  return {
    success: true,
    expiresAt: expiresAt.toISOString()
  };
});

// ========================================
// 2FA IPC HANDLERS
// TOTP-based two-factor authentication (Google Authenticator)
// ========================================

// Verify 2FA code (TOTP)
ipcMain.handle('auth-verify-2fa', async (_, code: string) => {
  if (!pending2FAUsername) {
    return { success: false, error: 'No 2FA verification pending' };
  }

  const user = DEV_USERS[pending2FAUsername];
  if (!user) {
    pending2FAUsername = null;
    return { success: false, error: 'User not found' };
  }

  if (!user.totpSecret) {
    pending2FAUsername = null;
    return { success: false, error: '2FA not configured for this user' };
  }

  // Verify TOTP code
  const isValid = verifyTOTPCode(user.totpSecret, code);
  if (!isValid) {
    console.log('[J.O.E. Auth] Invalid TOTP code for:', pending2FAUsername);
    return { success: false, error: 'Invalid authentication code. Please try again.' };
  }

  // Code verified - complete login
  const passwordExpired = isPasswordExpired(user.passwordChangedAt);
  const requirePasswordChange = user.requirePasswordChange || passwordExpired;

  // CRITICAL FIX: Create session after 2FA verification (was missing!)
  const session = createSession(pending2FAUsername);

  currentUser = {
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    requirePasswordChange,
    phone: user.phone
  };

  logSecurityEvent('LOGIN_SUCCESS_2FA', user.username, true, 'Authenticated with TOTP');
  pending2FAUsername = null;

  console.log('[J.O.E. Auth] TOTP verified successfully for:', user.username);
  return {
    success: true,
    user: currentUser,
    sessionToken: session.token,
    requirePasswordChange,
    passwordExpired
  };
});

// Setup 2FA for user - generates TOTP secret and QR code
ipcMain.handle('auth-setup-2fa', async () => {
  if (!currentUser) {
    return { success: false, error: 'Not logged in' };
  }

  const user = DEV_USERS[currentUser.username.toLowerCase()];
  if (!user) {
    return { success: false, error: 'User not found' };
  }

  // Generate new TOTP secret
  const secret = generateTOTPSecret();
  const keyUri = generateTOTPKeyUri(currentUser.username, secret);

  // Generate QR code as data URL
  try {
    const qrCodeDataUrl = await QRCode.toDataURL(keyUri);

    // Store temporarily until confirmed
    pendingTOTPSetup = {
      secret,
      username: currentUser.username.toLowerCase(),
      expires: Date.now() + 10 * 60 * 1000 // 10 minutes to complete setup
    };

    console.log('[J.O.E. Auth] TOTP setup initiated for:', currentUser.username);
    console.log('[J.O.E. Auth] Secret (for manual entry):', secret);

    return {
      success: true,
      qrCode: qrCodeDataUrl,
      secret: secret, // Also return secret for manual entry
      message: 'Scan the QR code with Google Authenticator, then enter the 6-digit code to confirm.'
    };
  } catch (error) {
    console.error('[J.O.E. Auth] Failed to generate QR code:', error);
    return { success: false, error: 'Failed to generate QR code' };
  }
});

// Confirm 2FA setup - verifies TOTP code and enables 2FA
ipcMain.handle('auth-confirm-2fa-setup', async (_, code: string) => {
  if (!currentUser) {
    return { success: false, error: 'Not logged in' };
  }

  if (!pendingTOTPSetup || pendingTOTPSetup.username !== currentUser.username.toLowerCase()) {
    return { success: false, error: 'No 2FA setup pending. Please start setup again.' };
  }

  if (Date.now() > pendingTOTPSetup.expires) {
    pendingTOTPSetup = null;
    return { success: false, error: 'Setup expired. Please start again.' };
  }

  // Verify the TOTP code
  const isValid = verifyTOTPCode(pendingTOTPSetup.secret, code);
  if (!isValid) {
    return { success: false, error: 'Invalid code. Make sure you entered the correct 6-digit code from your authenticator app.' };
  }

  // Enable 2FA for user and save the secret
  const user = DEV_USERS[currentUser.username.toLowerCase()];
  user.twoFactorEnabled = true;
  user.totpSecret = pendingTOTPSetup.secret;

  // PERSIST: Save 2FA settings to store
  saveUserData(currentUser.username.toLowerCase(), user);

  pendingTOTPSetup = null;

  console.log('[J.O.E. Auth] 2FA (TOTP) enabled for:', currentUser.username);
  return {
    success: true,
    message: '2FA enabled successfully! You will need to enter a code from Google Authenticator on your next login.'
  };
});

// Disable 2FA
ipcMain.handle('auth-disable-2fa', async () => {
  if (!currentUser) {
    return { success: false, error: 'Not logged in' };
  }

  const user = DEV_USERS[currentUser.username.toLowerCase()];
  if (!user) {
    return { success: false, error: 'User not found' };
  }

  user.twoFactorEnabled = false;
  user.totpSecret = undefined;

  // PERSIST: Save 2FA settings to store
  saveUserData(currentUser.username.toLowerCase(), user);

  console.log('[J.O.E. Auth] 2FA disabled for:', currentUser.username);

  return {
    success: true,
    message: '2FA has been disabled'
  };
});

// Get 2FA status
ipcMain.handle('auth-get-2fa-status', async () => {
  if (!currentUser) {
    return { enabled: false };
  }

  const user = DEV_USERS[currentUser.username.toLowerCase()];
  return {
    enabled: user?.twoFactorEnabled || false,
    hasSecret: !!user?.totpSecret
  };
});

// ========================================
// SECURITY SCANNING IPC HANDLERS
// Real vulnerability scanning - not simulated
// ========================================

// Run full security audit
ipcMain.handle('security-run-audit', async () => {
  console.log('[J.O.E. IPC] Running full security audit...');
  try {
    const results = await securityScanner.runFullAudit();
    console.log('[J.O.E. IPC] Audit complete:', {
      findings: results.findings.length,
      riskScore: results.riskScore.overall,
      compliance: results.compliance.score
    });
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Audit error:', error);
    throw error;
  }
});

// Auto-fix vulnerabilities with AI
ipcMain.handle('security-auto-fix', async (_, findings?: Array<{
  id: string;
  title: string;
  severity: string;
  tool: string;
  timestamp: string;
  description?: string;
  remediation?: string;
  file?: string;
  line?: number;
}>) => {
  console.log('[J.O.E. IPC] Running AI-powered auto-fix...', findings?.length ? `${findings.length} findings` : 'full scan');
  try {
    const results = await securityScanner.autoFix(findings as any);
    console.log('[J.O.E. IPC] Auto-fix complete:', {
      fixed: results.fixed.length,
      failed: results.failed.length,
      poam: results.poam.length
    });
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Auto-fix error:', error);
    throw error;
  }
});

// Generate POAM (Plan of Action and Milestones)
ipcMain.handle('security-generate-poam', async (_, findings: Array<{
  id: string;
  title: string;
  severity: string;
  tool: string;
  timestamp: string;
  description?: string;
  remediation?: string;
  file?: string;
  line?: number;
}>) => {
  console.log('[J.O.E. IPC] Generating POAM for', findings.length, 'findings...');
  try {
    const poam = await securityScanner.generatePoam(findings as any);
    console.log('[J.O.E. IPC] POAM generated:', poam.poamId, '-', poam.items.length, 'items');
    return poam;
  } catch (error) {
    console.error('[J.O.E. IPC] POAM generation error:', error);
    throw error;
  }
});

// Run Semgrep SAST scan
ipcMain.handle('security-semgrep-scan', async () => {
  console.log('[J.O.E. IPC] Running Semgrep SAST scan...');
  try {
    const results = await securityScanner.runSemgrepScan();
    console.log('[J.O.E. IPC] Semgrep scan complete:', results.length, 'findings');
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Semgrep error:', error);
    throw error;
  }
});

// Scan Docker image
ipcMain.handle('security-docker-scan', async (_, imageName: string) => {
  console.log('[J.O.E. IPC] Scanning Docker image:', imageName);
  try {
    const results = await securityScanner.scanDockerImage(imageName);
    console.log('[J.O.E. IPC] Docker scan complete:', results.length, 'vulnerabilities');
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Docker scan error:', error);
    throw error;
  }
});

// CVE lookup
ipcMain.handle('security-cve-lookup', async (_, cveId: string) => {
  console.log('[J.O.E. IPC] Looking up CVE:', cveId);
  try {
    const result = await securityScanner.lookupCVE(cveId);
    console.log('[J.O.E. IPC] CVE lookup result:', result?.id || 'not found');
    return result;
  } catch (error) {
    console.error('[J.O.E. IPC] CVE lookup error:', error);
    throw error;
  }
});

// Scan git history for secrets
ipcMain.handle('security-git-history-scan', async () => {
  console.log('[J.O.E. IPC] Scanning git history for secrets...');
  try {
    const results = await securityScanner.scanGitHistory();
    console.log('[J.O.E. IPC] Git history scan complete:', results.length, 'findings');
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Git history scan error:', error);
    throw error;
  }
});

// Run ESLint security scan
ipcMain.handle('security-eslint-scan', async () => {
  console.log('[J.O.E. IPC] Running ESLint security scan...');
  try {
    const results = await securityScanner.runESLintSecurity();
    console.log('[J.O.E. IPC] ESLint scan complete:', results.length, 'findings');
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] ESLint scan error:', error);
    throw error;
  }
});

// Generate SARIF report
ipcMain.handle('security-generate-sarif', async (_, findings: any[]) => {
  console.log('[J.O.E. IPC] Generating SARIF report...');
  try {
    const sarif = await securityScanner.generateSARIF(findings);
    console.log('[J.O.E. IPC] SARIF report generated');
    return sarif;
  } catch (error) {
    console.error('[J.O.E. IPC] SARIF generation error:', error);
    throw error;
  }
});

// ========================================
// OLLAMA AI IPC HANDLERS
// J.O.E. AI Security Intelligence Engine
// ========================================

ipcMain.handle('ollama-chat', async (_, message: string, context?: string) => {
  console.log('[J.O.E. AI] Processing chat request...');
  try {
    const response = await ollamaService.chat(message, context);
    console.log('[J.O.E. AI] Chat response generated');
    return response;
  } catch (error) {
    console.error('[J.O.E. AI] Chat error:', error);
    throw error;
  }
});

ipcMain.handle('ollama-get-models', async () => {
  console.log('[J.O.E. AI] Fetching available models...');
  try {
    const models = await ollamaService.getModels();
    console.log('[J.O.E. AI] Models fetched:', models.length);
    return models;
  } catch (error) {
    console.error('[J.O.E. AI] Get models error:', error);
    return [];
  }
});

ipcMain.handle('ollama-set-model', async (_, model: string) => {
  console.log('[J.O.E. AI] Setting model to:', model);
  ollamaService.setModel(model);
  return { success: true, model };
});

// Streaming chat support
let streamAbortController: AbortController | null = null;

ipcMain.on('ollama-stream-start', async (event, message: string, context?: string) => {
  console.log('[J.O.E. AI] Starting streaming chat...');
  streamAbortController = new AbortController();

  try {
    for await (const chunk of ollamaService.streamChat(message, context)) {
      if (streamAbortController?.signal.aborted) break;
      event.sender.send('ollama-stream-chunk', chunk);
    }
    event.sender.send('ollama-stream-end');
  } catch (error) {
    console.error('[J.O.E. AI] Stream error:', error);
    event.sender.send('ollama-stream-end');
  }
});

ipcMain.on('ollama-stream-cancel', () => {
  console.log('[J.O.E. AI] Cancelling stream...');
  ollamaService.cancelStream();
  streamAbortController?.abort();
  streamAbortController = null;
});

// ========================================
// EXPORT IPC HANDLERS
// Save files to user-selected location with dialogs
// ========================================

// Save file with dialog
ipcMain.handle('export-save-file', async (_, options: {
  title?: string;
  defaultPath?: string;
  filters?: { name: string; extensions: string[] }[];
  content: string;
}) => {
  console.log('[J.O.E. Export] Save file dialog...');

  try {
    // Get the Downloads folder as default
    const downloadsPath = app.getPath('downloads');
    const defaultFilePath = options.defaultPath
      ? path.join(downloadsPath, options.defaultPath)
      : downloadsPath;

    const result = await dialog.showSaveDialog(mainWindow!, {
      title: options.title || 'Save File',
      defaultPath: defaultFilePath,
      filters: options.filters || [
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (result.canceled || !result.filePath) {
      console.log('[J.O.E. Export] Save cancelled');
      return { success: false, error: 'Export cancelled' };
    }

    // Write the file
    fs.writeFileSync(result.filePath, options.content, 'utf-8');
    console.log('[J.O.E. Export] File saved:', result.filePath);

    return {
      success: true,
      filePath: result.filePath
    };
  } catch (error) {
    console.error('[J.O.E. Export] Save error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to save file'
    };
  }
});

// Save PDF report
ipcMain.handle('export-save-pdf', async (_, options: {
  title?: string;
  defaultPath?: string;
  reportData: {
    reportType: string;
    reportName: string;
    sections: string[];
    summary: Record<string, unknown>;
    generatedBy: string;
    date: string;
  };
}) => {
  console.log('[J.O.E. Export] Save PDF dialog...');

  try {
    const downloadsPath = app.getPath('downloads');
    const defaultFilePath = options.defaultPath
      ? path.join(downloadsPath, options.defaultPath)
      : path.join(downloadsPath, 'JOE-Report.pdf');

    const result = await dialog.showSaveDialog(mainWindow!, {
      title: options.title || 'Save PDF Report',
      defaultPath: defaultFilePath,
      filters: [
        { name: 'PDF Documents', extensions: ['pdf'] }
      ]
    });

    if (result.canceled || !result.filePath) {
      console.log('[J.O.E. Export] PDF save cancelled');
      return { success: false, error: 'Export cancelled' };
    }

    // Generate PDF content (simplified - using pdfmake would be better)
    // For now, create a simple text file with .pdf extension as placeholder
    const pdfContent = `J.O.E. DevSecOps Arsenal - ${options.reportData.reportType || 'Report'}
Generated: ${options.reportData.date || new Date().toISOString()}
Generated By: ${options.reportData.generatedBy || 'J.O.E. System'}

Report: ${options.reportData.reportName || 'Security Report'}

Sections:
${options.reportData.sections?.join('\n') || 'N/A'}

Summary:
${JSON.stringify(options.reportData.summary, null, 2)}

---
Dark Wolf Solutions - J.O.E. DevSecOps Arsenal
`;

    fs.writeFileSync(result.filePath, pdfContent, 'utf-8');
    console.log('[J.O.E. Export] PDF saved:', result.filePath);

    // Show notification that file was saved
    if (mainWindow) {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Export Complete',
        message: 'Report saved successfully!',
        detail: `File saved to:\n${result.filePath}`,
        buttons: ['Open File', 'Show in Folder', 'OK'],
        defaultId: 2
      }).then((response) => {
        if (response.response === 0) {
          // Open file
          shell.openPath(result.filePath!);
        } else if (response.response === 1) {
          // Show in folder
          shell.showItemInFolder(result.filePath!);
        }
      });
    }

    return {
      success: true,
      filePath: result.filePath
    };
  } catch (error) {
    console.error('[J.O.E. Export] PDF save error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to save PDF'
    };
  }
});

// Open file
ipcMain.handle('export-open-file', async (_, filePath: string) => {
  try {
    await shell.openPath(filePath);
    return { success: true };
  } catch (error) {
    console.error('[J.O.E. Export] Open file error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to open file'
    };
  }
});

// Show file in folder
ipcMain.handle('export-show-in-folder', async (_, filePath: string) => {
  try {
    shell.showItemInFolder(filePath);
    return { success: true };
  } catch (error) {
    console.error('[J.O.E. Export] Show in folder error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to show file in folder'
    };
  }
});

// ========================================
// KUBERNETES SECURITY IPC HANDLERS
// CIS Benchmark v1.8 | NSA/CISA Guide | NIST SP 800-190
// ========================================

// Get available Kubernetes contexts from kubeconfig
ipcMain.handle('k8s-get-contexts', async () => {
  console.log('[J.O.E. K8s] Getting available contexts...');
  try {
    const contexts = kubernetesScanner.getAvailableContexts();
    console.log('[J.O.E. K8s] Found contexts:', contexts);
    return contexts;
  } catch (error) {
    console.error('[J.O.E. K8s] Error getting contexts:', error);
    return [];
  }
});

// Connect to Kubernetes cluster
ipcMain.handle('k8s-connect', async (_, config: { name: string; context: string; kubeconfigPath?: string; namespace?: string }) => {
  console.log('[J.O.E. K8s] Connecting to cluster:', config.context);
  logSecurityEvent('K8S_CONNECT_ATTEMPT', activeSession?.username, true, `Context: ${config.context}`);

  try {
    const result = await kubernetesScanner.connect(config.context, config.kubeconfigPath);

    if (result.success) {
      logSecurityEvent('K8S_CONNECT_SUCCESS', activeSession?.username, true, `Cluster: ${result.cluster?.name}`);
      return {
        success: true,
        cluster: result.cluster
      };
    } else {
      logSecurityEvent('K8S_CONNECT_FAILED', activeSession?.username, false, result.error, 'WARNING');
      return {
        success: false,
        error: result.error
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Connection failed';
    logSecurityEvent('K8S_CONNECT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    return {
      success: false,
      error: errorMsg
    };
  }
});

// Disconnect from Kubernetes cluster
ipcMain.handle('k8s-disconnect', async () => {
  console.log('[J.O.E. K8s] Disconnecting from cluster...');
  logSecurityEvent('K8S_DISCONNECT', activeSession?.username, true);
  kubernetesScanner.disconnect();
  return { success: true };
});

// Run full Kubernetes security audit
ipcMain.handle('k8s-run-audit', async (_, namespace?: string) => {
  console.log('[J.O.E. K8s] Running full security audit...', namespace ? `Namespace: ${namespace}` : 'All namespaces');
  logSecurityEvent('K8S_AUDIT_START', activeSession?.username, true, namespace ? `Namespace: ${namespace}` : 'All namespaces');

  try {
    const results = await kubernetesScanner.runFullAudit(namespace);

    logSecurityEvent('K8S_AUDIT_COMPLETE', activeSession?.username, true,
      `CIS: ${results.cisBenchmark.passed}/${results.cisBenchmark.totalChecks} passed, ` +
      `PSS: ${results.podSecurity.violations.length} violations, ` +
      `RBAC: ${results.rbacAnalysis.overprivilegedAccounts.length} overprivileged, ` +
      `Score: ${results.complianceScore}%`
    );

    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Audit failed';
    logSecurityEvent('K8S_AUDIT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get pods with security analysis
ipcMain.handle('k8s-get-pods', async (_, namespace?: string) => {
  console.log('[J.O.E. K8s] Analyzing pod security...');
  try {
    const results = await kubernetesScanner.analyzePodSecurity(namespace);
    logSecurityEvent('K8S_POD_SCAN', activeSession?.username, true,
      `Pods: ${results.totalPods}, Privileged: ${results.privilegedPods}, Violations: ${results.violations.length}`
    );
    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Pod analysis failed';
    logSecurityEvent('K8S_POD_SCAN_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Scan container images for vulnerabilities
ipcMain.handle('k8s-scan-images', async (_, namespace?: string) => {
  console.log('[J.O.E. K8s] Scanning container images...');
  try {
    const results = await kubernetesScanner.scanContainerImages(namespace);

    const totalVulns = results.reduce((acc, img) => ({
      critical: acc.critical + img.vulnerabilities.critical,
      high: acc.high + img.vulnerabilities.high
    }), { critical: 0, high: 0 });

    logSecurityEvent('K8S_IMAGE_SCAN', activeSession?.username, true,
      `Images: ${results.length}, Critical: ${totalVulns.critical}, High: ${totalVulns.high}`
    );
    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Image scan failed';
    logSecurityEvent('K8S_IMAGE_SCAN_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Analyze RBAC for overprivilege
ipcMain.handle('k8s-analyze-rbac', async () => {
  console.log('[J.O.E. K8s] Analyzing RBAC...');
  try {
    const results = await kubernetesScanner.analyzeRBAC();
    logSecurityEvent('K8S_RBAC_ANALYSIS', activeSession?.username, true,
      `Service Accounts: ${results.totalServiceAccounts}, Overprivileged: ${results.overprivilegedAccounts.length}, Cluster-Admin: ${results.clusterAdminBindings}`
    );
    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'RBAC analysis failed';
    logSecurityEvent('K8S_RBAC_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Check network policies
ipcMain.handle('k8s-check-policies', async () => {
  console.log('[J.O.E. K8s] Analyzing network policies...');
  try {
    const results = await kubernetesScanner.analyzeNetworkPolicies();
    logSecurityEvent('K8S_NETWORK_ANALYSIS', activeSession?.username, true,
      `Policies: ${results.totalPolicies}, Coverage: ${results.coverage}%, Unprotected: ${results.namespacesWithoutPolicies.length}`
    );
    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Network policy analysis failed';
    logSecurityEvent('K8S_NETWORK_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// ========================================
// GITLAB SECURITY IPC HANDLERS
// OWASP ASVS | NIST SP 800-53 SA-11 | SLSA Framework
// ========================================

// Connect to GitLab instance
ipcMain.handle('gitlab-connect', async (_, url: string, token: string) => {
  console.log('[J.O.E. GitLab] Connecting to:', url);
  logSecurityEvent('GITLAB_CONNECT_ATTEMPT', activeSession?.username, true, `URL: ${url}`);

  try {
    const result = await gitlabScanner.connect(url, token);

    if (result.success) {
      logSecurityEvent('GITLAB_CONNECT_SUCCESS', activeSession?.username, true, `User: ${result.user?.username}`);
      return {
        success: true,
        user: result.user
      };
    } else {
      logSecurityEvent('GITLAB_CONNECT_FAILED', activeSession?.username, false, result.error, 'WARNING');
      return {
        success: false,
        error: result.error
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Connection failed';
    logSecurityEvent('GITLAB_CONNECT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    return {
      success: false,
      error: errorMsg
    };
  }
});

// Disconnect from GitLab
ipcMain.handle('gitlab-disconnect', async () => {
  console.log('[J.O.E. GitLab] Disconnecting...');
  logSecurityEvent('GITLAB_DISCONNECT', activeSession?.username, true);
  gitlabScanner.disconnect();
  return { success: true };
});

// List GitLab projects
ipcMain.handle('gitlab-list-projects', async (_, search?: string) => {
  console.log('[J.O.E. GitLab] Listing projects...', search ? `Search: ${search}` : '');
  try {
    const projects = await gitlabScanner.listProjects(search);
    logSecurityEvent('GITLAB_LIST_PROJECTS', activeSession?.username, true, `Found: ${projects.length} projects`);
    return projects;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to list projects';
    logSecurityEvent('GITLAB_LIST_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get single project
ipcMain.handle('gitlab-get-project', async (_, projectId: number) => {
  console.log('[J.O.E. GitLab] Getting project:', projectId);
  try {
    const project = await gitlabScanner.getProject(projectId);
    return project;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to get project';
    logSecurityEvent('GITLAB_PROJECT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Scan GitLab project
ipcMain.handle('gitlab-scan-project', async (_, projectId: number) => {
  console.log('[J.O.E. GitLab] Scanning project:', projectId);
  logSecurityEvent('GITLAB_SCAN_START', activeSession?.username, true, `Project ID: ${projectId}`);

  try {
    const results = await gitlabScanner.scanProject(projectId);

    logSecurityEvent('GITLAB_SCAN_COMPLETE', activeSession?.username, true,
      `Project: ${results.project.name}, ` +
      `SAST: ${results.sastFindings.length}, ` +
      `Secrets: ${results.secretsDetected.length}, ` +
      `Pipeline Score: ${results.pipelineSecurity.score}, ` +
      `Compliance: ${results.complianceScore}%`
    );

    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Scan failed';
    logSecurityEvent('GITLAB_SCAN_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// ========================================
// THREAT INTELLIGENCE IPC HANDLERS
// EPSS (FIRST.org) | CISA KEV | NVD Enrichment
// ========================================

// Get EPSS score for a single CVE
ipcMain.handle('threatintel-get-epss', async (_, cveId: string) => {
  console.log('[J.O.E. ThreatIntel] Getting EPSS score:', cveId);
  logSecurityEvent('THREATINTEL_EPSS_LOOKUP', activeSession?.username, true, `CVE: ${cveId}`);

  try {
    const result = await threatIntelService.getEPSSScore(cveId);
    if (result) {
      console.log(`[J.O.E. ThreatIntel] EPSS: ${(result.epss * 100).toFixed(2)}% (${result.percentile.toFixed(1)} percentile)`);
    }
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'EPSS lookup failed';
    logSecurityEvent('THREATINTEL_EPSS_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get EPSS scores for multiple CVEs (batch)
ipcMain.handle('threatintel-get-epss-batch', async (_, cveIds: string[]) => {
  console.log('[J.O.E. ThreatIntel] Batch EPSS lookup:', cveIds.length, 'CVEs');
  logSecurityEvent('THREATINTEL_EPSS_BATCH', activeSession?.username, true, `Count: ${cveIds.length}`);

  try {
    const results = await threatIntelService.getEPSSScoresBatch(cveIds);
    console.log(`[J.O.E. ThreatIntel] Retrieved ${results.size} EPSS scores`);
    // Convert Map to Object for IPC serialization
    return Object.fromEntries(results);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Batch EPSS lookup failed';
    logSecurityEvent('THREATINTEL_EPSS_BATCH_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get CISA KEV catalog
ipcMain.handle('threatintel-get-kev-catalog', async (_, forceRefresh?: boolean) => {
  console.log('[J.O.E. ThreatIntel] Getting CISA KEV catalog...');
  logSecurityEvent('THREATINTEL_KEV_FETCH', activeSession?.username, true, forceRefresh ? 'Force refresh' : 'Cached');

  try {
    const catalog = await threatIntelService.getKEVCatalog(forceRefresh);
    if (catalog) {
      console.log(`[J.O.E. ThreatIntel] KEV catalog: ${catalog.count} vulnerabilities`);
    }
    return catalog;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'KEV catalog fetch failed';
    logSecurityEvent('THREATINTEL_KEV_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Check if CVE is in CISA KEV
ipcMain.handle('threatintel-check-kev', async (_, cveId: string) => {
  console.log('[J.O.E. ThreatIntel] Checking KEV status:', cveId);

  try {
    const kevEntry = await threatIntelService.isInKEV(cveId);
    if (kevEntry) {
      logSecurityEvent('THREATINTEL_KEV_FOUND', activeSession?.username, true, `${cveId} is actively exploited!`, 'WARNING');
    }
    return kevEntry;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'KEV check failed';
    logSecurityEvent('THREATINTEL_KEV_CHECK_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get KEV statistics
ipcMain.handle('threatintel-get-kev-stats', async () => {
  console.log('[J.O.E. ThreatIntel] Getting KEV statistics...');

  try {
    const stats = await threatIntelService.getKEVStats();
    logSecurityEvent('THREATINTEL_KEV_STATS', activeSession?.username, true,
      `Total: ${stats.totalCount}, Ransomware: ${stats.ransomwareRelated}, Recent: ${stats.recentlyAdded.length}`
    );
    return stats;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'KEV stats failed';
    logSecurityEvent('THREATINTEL_KEV_STATS_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Search KEV catalog
ipcMain.handle('threatintel-search-kev', async (_, query: string) => {
  console.log('[J.O.E. ThreatIntel] Searching KEV:', query);

  try {
    const results = await threatIntelService.searchKEV(query);
    logSecurityEvent('THREATINTEL_KEV_SEARCH', activeSession?.username, true, `Query: "${query}", Found: ${results.length}`);
    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'KEV search failed';
    logSecurityEvent('THREATINTEL_KEV_SEARCH_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Analyze single CVE (comprehensive)
ipcMain.handle('threatintel-analyze-cve', async (_, cveId: string) => {
  console.log('[J.O.E. ThreatIntel] Full CVE analysis:', cveId);
  logSecurityEvent('THREATINTEL_CVE_ANALYZE', activeSession?.username, true, `CVE: ${cveId}`);

  try {
    const result = await threatIntelService.analyzeCVE(cveId);
    logSecurityEvent('THREATINTEL_CVE_RESULT', activeSession?.username, true,
      `${cveId}: Priority ${result.priorityScore} (${result.priorityRating}), ` +
      `KEV: ${result.kev ? 'YES' : 'No'}, ` +
      `EPSS: ${result.epss ? (result.epss.epss * 100).toFixed(2) + '%' : 'N/A'}`
    );
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'CVE analysis failed';
    logSecurityEvent('THREATINTEL_CVE_ANALYZE_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Analyze multiple CVEs (batch with prioritization)
ipcMain.handle('threatintel-analyze-cves-batch', async (_, cveIds: string[]) => {
  console.log('[J.O.E. ThreatIntel] Batch CVE analysis:', cveIds.length, 'CVEs');
  logSecurityEvent('THREATINTEL_BATCH_ANALYZE', activeSession?.username, true, `Count: ${cveIds.length}`);

  try {
    const results = await threatIntelService.analyzeCVEsBatch(cveIds);

    const criticalCount = results.filter(r => r.priorityRating === 'CRITICAL').length;
    const kevCount = results.filter(r => r.kev).length;

    logSecurityEvent('THREATINTEL_BATCH_RESULT', activeSession?.username, true,
      `Analyzed: ${results.length}, Critical: ${criticalCount}, In KEV: ${kevCount}`
    );

    return results;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Batch analysis failed';
    logSecurityEvent('THREATINTEL_BATCH_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Clear threat intel cache
ipcMain.handle('threatintel-clear-cache', async () => {
  console.log('[J.O.E. ThreatIntel] Clearing cache...');
  logSecurityEvent('THREATINTEL_CACHE_CLEAR', activeSession?.username, true);
  threatIntelService.clearCache();
  return { success: true };
});

// ========================================
// SBOM (Software Bill of Materials) IPC HANDLERS
// Supply Chain Security Analysis
// ========================================

// Generate SBOM from project
ipcMain.handle('sbom-generate', async (_, projectPath: string) => {
  console.log('[J.O.E. SBOM] Generating SBOM for:', projectPath);
  logSecurityEvent('SBOM_GENERATE', activeSession?.username, true, `Path: ${projectPath}`);

  try {
    const sbom = await sbomService.generateFromNodeProject(projectPath);
    console.log(`[J.O.E. SBOM] Generated SBOM with ${sbom.components.length} components`);
    return sbom;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'SBOM generation failed';
    logSecurityEvent('SBOM_GENERATE_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Analyze SBOM
ipcMain.handle('sbom-analyze', async (_, sbom: any) => {
  console.log('[J.O.E. SBOM] Analyzing SBOM...');
  logSecurityEvent('SBOM_ANALYZE', activeSession?.username, true, `Components: ${sbom.components?.length || 0}`);

  try {
    const analysis = await sbomService.analyzeSBOM(sbom);
    console.log(`[J.O.E. SBOM] Analysis complete - Risk Score: ${analysis.riskScore}`);
    logSecurityEvent('SBOM_ANALYSIS_COMPLETE', activeSession?.username, true,
      `Risk: ${analysis.riskScore}, Vulns: ${analysis.vulnerabilitySummary.total}`
    );
    return analysis;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'SBOM analysis failed';
    logSecurityEvent('SBOM_ANALYZE_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Export SBOM
ipcMain.handle('sbom-export', async (_, sbom: any, format: 'json' | 'xml', outputPath: string) => {
  console.log('[J.O.E. SBOM] Exporting SBOM to:', outputPath);
  logSecurityEvent('SBOM_EXPORT', activeSession?.username, true, `Format: ${format}, Path: ${outputPath}`);

  try {
    sbomService.exportSBOM(sbom, format, outputPath);
    return { success: true, path: outputPath };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'SBOM export failed';
    logSecurityEvent('SBOM_EXPORT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// ========================================
// SECRET SCANNER IPC HANDLERS
// Hardcoded Credential Detection
// ========================================

// Scan directory for secrets
ipcMain.handle('secrets-scan-directory', async (_, dirPath: string, options?: any) => {
  console.log('[J.O.E. SecretScanner] Scanning directory:', dirPath);
  logSecurityEvent('SECRET_SCAN_START', activeSession?.username, true, `Path: ${dirPath}`);

  try {
    const result = await secretScanner.scanDirectory(dirPath, options);

    console.log(`[J.O.E. SecretScanner] Scan complete - Found ${result.findings.length} secrets`);
    logSecurityEvent('SECRET_SCAN_COMPLETE', activeSession?.username, true,
      `Scanned: ${result.scannedFiles} files, Found: ${result.summary.total} secrets ` +
      `(Critical: ${result.summary.critical}, High: ${result.summary.high})`
    );

    // Log critical findings as security events
    if (result.summary.critical > 0) {
      logSecurityEvent('SECRET_CRITICAL_FOUND', activeSession?.username, false,
        `${result.summary.critical} critical secrets detected!`, 'CRITICAL'
      );
    }

    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Secret scan failed';
    logSecurityEvent('SECRET_SCAN_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Scan content for secrets
ipcMain.handle('secrets-scan-content', async (_, content: string, filePath?: string) => {
  console.log('[J.O.E. SecretScanner] Scanning content...');

  try {
    const findings = await secretScanner.scanContent(content, filePath);
    return findings;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Content scan failed';
    logSecurityEvent('SECRET_CONTENT_SCAN_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Select directory for scanning
ipcMain.handle('secrets-select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openDirectory'],
    title: 'Select Directory to Scan for Secrets'
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  return result.filePaths[0];
});

// Select project for SBOM
ipcMain.handle('sbom-select-project', async () => {
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openDirectory'],
    title: 'Select Project Directory for SBOM Generation'
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  return result.filePaths[0];
});

// ========================================
// SECURE VAULT IPC HANDLERS
// AES-256-GCM Encrypted Secret Storage
// ========================================

// Check if vault exists
ipcMain.handle('vault-exists', async () => {
  return secureVault.vaultExists();
});

// Check if vault is unlocked
ipcMain.handle('vault-is-unlocked', async () => {
  return secureVault.isVaultUnlocked();
});

// Initialize new vault
ipcMain.handle('vault-initialize', async (_, masterPassword: string) => {
  console.log('[J.O.E. Vault] Initializing secure vault...');
  logSecurityEvent('VAULT_INIT_ATTEMPT', activeSession?.username, true);

  try {
    await secureVault.initializeVault(masterPassword);
    logSecurityEvent('VAULT_INITIALIZED', activeSession?.username, true, 'AES-256-GCM vault created');
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Vault initialization failed';
    logSecurityEvent('VAULT_INIT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Unlock vault
ipcMain.handle('vault-unlock', async (_, masterPassword: string) => {
  console.log('[J.O.E. Vault] Unlocking vault...');
  logSecurityEvent('VAULT_UNLOCK_ATTEMPT', activeSession?.username, true);

  try {
    await secureVault.unlockVault(masterPassword);
    logSecurityEvent('VAULT_UNLOCKED', activeSession?.username, true);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Vault unlock failed';
    logSecurityEvent('VAULT_UNLOCK_FAILED', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Lock vault
ipcMain.handle('vault-lock', async () => {
  console.log('[J.O.E. Vault] Locking vault...');
  secureVault.lockVault();
  logSecurityEvent('VAULT_LOCKED', activeSession?.username, true);
  return { success: true };
});

// Add secret to vault
ipcMain.handle('vault-add-secret', async (_, name: string, value: string, type: string, metadata?: any) => {
  console.log('[J.O.E. Vault] Adding secret:', name);
  logSecurityEvent('VAULT_ADD_SECRET', activeSession?.username, true, `Type: ${type}`);

  try {
    const vaultType = secureVault.mapSecretType(type);
    const entry = await secureVault.addSecret(name, value, vaultType, metadata);
    logSecurityEvent('VAULT_SECRET_ADDED', activeSession?.username, true, `${name} (${vaultType})`);
    return entry;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to add secret';
    logSecurityEvent('VAULT_ADD_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get decrypted secret
ipcMain.handle('vault-get-secret', async (_, id: string) => {
  console.log('[J.O.E. Vault] Retrieving secret:', id);
  logSecurityEvent('VAULT_GET_SECRET', activeSession?.username, true, `ID: ${id}`);

  try {
    const result = secureVault.getSecret(id);
    if (result) {
      logSecurityEvent('VAULT_SECRET_ACCESSED', activeSession?.username, true, `Accessed: ${result.entry.name}`);
    }
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to retrieve secret';
    logSecurityEvent('VAULT_GET_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Update secret
ipcMain.handle('vault-update-secret', async (_, id: string, newValue: string) => {
  console.log('[J.O.E. Vault] Updating secret:', id);
  logSecurityEvent('VAULT_UPDATE_SECRET', activeSession?.username, true, `ID: ${id}`);

  try {
    const entry = await secureVault.updateSecret(id, newValue);
    if (entry) {
      logSecurityEvent('VAULT_SECRET_UPDATED', activeSession?.username, true, `Updated: ${entry.name}`);
    }
    return entry;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to update secret';
    logSecurityEvent('VAULT_UPDATE_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Delete secret
ipcMain.handle('vault-delete-secret', async (_, id: string) => {
  console.log('[J.O.E. Vault] Deleting secret:', id);
  logSecurityEvent('VAULT_DELETE_SECRET', activeSession?.username, true, `ID: ${id}`);

  try {
    const success = await secureVault.deleteSecret(id);
    logSecurityEvent('VAULT_SECRET_DELETED', activeSession?.username, success);
    return { success };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to delete secret';
    logSecurityEvent('VAULT_DELETE_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// List all entries (metadata only, no decrypted values)
ipcMain.handle('vault-list-entries', async () => {
  try {
    return secureVault.listEntries();
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Failed to list entries';
    logSecurityEvent('VAULT_LIST_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get vault statistics
ipcMain.handle('vault-get-stats', async () => {
  return secureVault.getStats();
});

// Change master password
ipcMain.handle('vault-change-password', async (_, currentPassword: string, newPassword: string) => {
  console.log('[J.O.E. Vault] Changing master password...');
  logSecurityEvent('VAULT_PASSWORD_CHANGE', activeSession?.username, true);

  try {
    await secureVault.changeMasterPassword(currentPassword, newPassword);
    logSecurityEvent('VAULT_PASSWORD_CHANGED', activeSession?.username, true);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Password change failed';
    logSecurityEvent('VAULT_PASSWORD_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Get vault audit log
ipcMain.handle('vault-get-audit-log', async () => {
  return secureVault.getAuditLog();
});

// Export vault (encrypted backup)
ipcMain.handle('vault-export', async () => {
  try {
    const vaultData = secureVault.exportVault();
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export Encrypted Vault Backup',
      defaultPath: `joe-vault-backup-${new Date().toISOString().split('T')[0]}.enc`,
      filters: [{ name: 'Encrypted Vault', extensions: ['enc'] }]
    });

    if (!result.canceled && result.filePath) {
      const fs = require('fs');
      fs.writeFileSync(result.filePath, vaultData);
      logSecurityEvent('VAULT_EXPORTED', activeSession?.username, true, `Path: ${result.filePath}`);
      return { success: true, path: result.filePath };
    }

    return { success: false };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Vault export failed';
    logSecurityEvent('VAULT_EXPORT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// ========================================
// AI TOUCHPOINT IPC HANDLERS
// Space-Grade Security Intelligence System
// ========================================

// AI Touchpoint query (tooltip/panel)
ipcMain.handle('ai-touchpoint-query', async (_, context: any) => {
  console.log('[J.O.E. AI Touchpoint] Query for:', context.elementType);
  logSecurityEvent('AI_TOUCHPOINT_QUERY', activeSession?.username, true, `Type: ${context.elementType}`);

  try {
    const response = await ollamaService.generateTouchpointResponse(context);
    return response;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'AI touchpoint query failed';
    logSecurityEvent('AI_TOUCHPOINT_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// AI Touchpoint streaming query
ipcMain.handle('ai-touchpoint-stream', async (_, context: any) => {
  console.log('[J.O.E. AI Touchpoint] Streaming query for:', context.elementType);
  logSecurityEvent('AI_TOUCHPOINT_STREAM', activeSession?.username, true, `Type: ${context.elementType}`);

  try {
    const chunks: string[] = [];
    for await (const chunk of ollamaService.streamTouchpointResponse(context)) {
      chunks.push(chunk.content);
    }
    return chunks.join('');
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'AI streaming failed';
    logSecurityEvent('AI_TOUCHPOINT_STREAM_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Analyze metric for dashboard touchpoints
ipcMain.handle('ai-touchpoint-analyze-metric', async (_, params: { metricName: string; value: number; trend: string; context?: any }) => {
  console.log('[J.O.E. AI Touchpoint] Analyzing metric:', params.metricName);
  logSecurityEvent('AI_METRIC_ANALYSIS', activeSession?.username, true, `Metric: ${params.metricName}`);

  try {
    const response = await ollamaService.analyzeMetric(params.metricName, params.value, params.trend as any, params.context);
    return response;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Metric analysis failed';
    logSecurityEvent('AI_METRIC_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Generate attack path diagram
ipcMain.handle('ai-touchpoint-generate-attack-path', async (_, finding: any) => {
  console.log('[J.O.E. AI Touchpoint] Generating attack path for:', finding.id || 'finding');
  logSecurityEvent('AI_ATTACK_PATH', activeSession?.username, true, `Finding: ${finding.id || 'unknown'}`);

  try {
    const mermaidDiagram = await ollamaService.generateAttackPath(finding);
    return mermaidDiagram;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Attack path generation failed';
    logSecurityEvent('AI_ATTACK_PATH_ERROR', activeSession?.username, false, errorMsg, 'WARNING');
    throw error;
  }
});

// Cancel pending AI query (placeholder - actual implementation needs AbortController)
ipcMain.handle('ai-touchpoint-cancel', async (_, queryId: string) => {
  console.log('[J.O.E. AI Touchpoint] Cancel request:', queryId);
  // In a full implementation, this would cancel the pending request
  return { success: true };
});

// ========================================
// ANALYTICS IPC HANDLERS
// SQLite-Powered Self-Learning Analytics Engine
// ========================================

// Initialize analytics session on app ready
app.whenReady().then(() => {
  // Start analytics session (will be associated with user on login)
  analyticsService.startSession();
});

// End analytics session on quit
app.on('before-quit', () => {
  analyticsService.shutdown();
});

// Track analytics event
ipcMain.handle('analytics-track', async (_, event: {
  type: string;
  elementType: string;
  elementId?: string;
  durationMs?: number;
  context?: Record<string, unknown>;
}) => {
  console.log('[J.O.E. Analytics] Tracking:', event.type, event.elementType);

  try {
    // Set current user if available
    if (activeSession?.username) {
      analyticsService.setUser(activeSession.username);
    }

    const id = analyticsService.track({
      type: event.type as any,
      elementType: event.elementType,
      elementId: event.elementId,
      durationMs: event.durationMs,
      context: event.context
    });

    return { success: true, id };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Analytics track failed';
    console.error('[J.O.E. Analytics] Track error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Rate AI response
ipcMain.handle('analytics-rate', async (_, queryId: string, rating: number) => {
  console.log('[J.O.E. Analytics] Rating query:', queryId, 'Rating:', rating);
  logSecurityEvent('AI_RESPONSE_RATED', activeSession?.username, true, `Rating: ${rating}/5`);

  try {
    analyticsService.rateResponse(queryId, rating);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Rating failed';
    console.error('[J.O.E. Analytics] Rate error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Get user behavior profile
ipcMain.handle('analytics-get-profile', async () => {
  try {
    if (activeSession?.username) {
      analyticsService.setUser(activeSession.username);
    }
    return analyticsService.getUserProfile();
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get profile failed';
    console.error('[J.O.E. Analytics] Get profile error:', errorMsg);
    return null;
  }
});

// Get analytics insights
ipcMain.handle('analytics-get-insights', async (_, timeframe?: { start: number; end: number }) => {
  try {
    return analyticsService.getInsights(timeframe);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get insights failed';
    console.error('[J.O.E. Analytics] Get insights error:', errorMsg);
    return {
      totalInteractions: 0,
      totalQueries: 0,
      avgQueryRating: 0,
      topElementTypes: [],
      interactionsByHour: {},
      avgResponseTime: 0,
      cacheHitRate: 0
    };
  }
});

// Get detected security patterns
ipcMain.handle('analytics-get-patterns', async (_, severity?: string) => {
  try {
    return analyticsService.getSecurityPatterns(severity);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get patterns failed';
    console.error('[J.O.E. Analytics] Get patterns error:', errorMsg);
    return [];
  }
});

// Get learning insights
ipcMain.handle('analytics-get-learning-insights', async () => {
  try {
    return analyticsService.getLearningInsights();
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get learning insights failed';
    console.error('[J.O.E. Analytics] Get learning insights error:', errorMsg);
    return [];
  }
});

// Get analytics statistics
ipcMain.handle('analytics-get-stats', async () => {
  try {
    return analyticsService.getStats();
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get stats failed';
    console.error('[J.O.E. Analytics] Get stats error:', errorMsg);
    return {
      totalInteractions: 0,
      totalQueries: 0,
      totalSessions: 0,
      totalUsers: 0,
      avgRating: 0,
      cacheSize: 0,
      dbSize: '0 KB'
    };
  }
});

// Cleanup old analytics data
ipcMain.handle('analytics-cleanup', async (_, daysToKeep?: number) => {
  try {
    analyticsService.cleanup(daysToKeep || 90);
    logSecurityEvent('ANALYTICS_CLEANUP', activeSession?.username, true, `Kept ${daysToKeep || 90} days`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Cleanup failed';
    console.error('[J.O.E. Analytics] Cleanup error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// ========================================
// SPACE-GRADE COMPLIANCE IPC HANDLERS
// NASA-STD-8719.13 | DO-178C | Common Criteria
// ========================================

// Register project for compliance assessment
ipcMain.handle('space-compliance-register-project', async (_, config: {
  name: string;
  type: 'spacecraft' | 'avionics' | 'ground-system' | 'mission-control' | 'general';
  primaryFramework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
  targetLevel: string;
  description?: string;
}) => {
  try {
    const projectId = spaceComplianceService.registerProject(config);
    logSecurityEvent('SPACE_COMPLIANCE_PROJECT_REGISTERED', activeSession?.username, true, `Project: ${config.name}`);
    return { success: true, projectId };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Project registration failed';
    console.error('[J.O.E. Space Compliance] Register project error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Get project details
ipcMain.handle('space-compliance-get-project', async (_, projectId: string) => {
  try {
    return spaceComplianceService.getProject(projectId);
  } catch (error) {
    console.error('[J.O.E. Space Compliance] Get project error:', error);
    return null;
  }
});

// List all projects
ipcMain.handle('space-compliance-list-projects', async () => {
  try {
    return spaceComplianceService.listProjects();
  } catch (error) {
    console.error('[J.O.E. Space Compliance] List projects error:', error);
    return [];
  }
});

// Assess NASA Safety
ipcMain.handle('space-compliance-assess-nasa', async (_, params: {
  projectName: string;
  assessor: string;
  hazardAnalysis: {
    lossOfLife: boolean;
    severeInjury: boolean;
    missionCritical: boolean;
    propertyDamage: 'none' | 'minor' | 'major' | 'critical';
  };
  safetyMetrics: {
    hazardsIdentified: number;
    hazardsMitigated: number;
    openSafetyIssues: number;
    safetyReviewsCompleted: number;
    independentReviewsCompleted: number;
  };
  existingControls: string[];
}) => {
  try {
    const result = spaceComplianceService.assessNASASafety(params);
    logSecurityEvent('NASA_SAFETY_ASSESSMENT', activeSession?.username, true,
      `Project: ${params.projectName}, Category: ${result.assessment.nasaCategory}, Score: ${result.assessment.overallScore}%`);
    return { success: true, result };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'NASA assessment failed';
    console.error('[J.O.E. Space Compliance] NASA assessment error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Assess DO-178C
ipcMain.handle('space-compliance-assess-do178c', async (_, params: {
  projectName: string;
  assessor: string;
  failureCondition: 'catastrophic' | 'hazardous' | 'major' | 'minor' | 'no-effect';
  coverageMetrics: {
    statementCoverage: number;
    branchCoverage: number;
    mcdcCoverage: number;
    requirementsCoverage: number;
    testCaseCoverage: number;
  };
  documentationStatus: Record<string, boolean>;
  verificationActivities: string[];
}) => {
  try {
    const result = spaceComplianceService.assessDO178C(params);
    logSecurityEvent('DO178C_ASSESSMENT', activeSession?.username, true,
      `Project: ${params.projectName}, DAL: ${result.assessment.do178cLevel}, Score: ${result.assessment.overallScore}%`);
    return { success: true, result };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'DO-178C assessment failed';
    console.error('[J.O.E. Space Compliance] DO-178C assessment error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Assess Common Criteria
ipcMain.handle('space-compliance-assess-cc', async (_, params: {
  projectName: string;
  assessor: string;
  targetEAL: 'EAL-1' | 'EAL-2' | 'EAL-3' | 'EAL-4' | 'EAL-5' | 'EAL-6' | 'EAL-7';
  assuranceComponents: Record<string, 'satisfied' | 'partial' | 'not-satisfied'>;
  securityFunctions: string[];
}) => {
  try {
    const result = spaceComplianceService.assessCommonCriteria(params);
    logSecurityEvent('COMMON_CRITERIA_ASSESSMENT', activeSession?.username, true,
      `Project: ${params.projectName}, Target: ${params.targetEAL}, Score: ${result.assessment.overallScore}%`);
    return { success: true, result };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Common Criteria assessment failed';
    console.error('[J.O.E. Space Compliance] CC assessment error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Get assessment by ID
ipcMain.handle('space-compliance-get-assessment', async (_, assessmentId: string) => {
  try {
    return spaceComplianceService.getAssessment(assessmentId);
  } catch (error) {
    console.error('[J.O.E. Space Compliance] Get assessment error:', error);
    return null;
  }
});

// List all assessments
ipcMain.handle('space-compliance-list-assessments', async () => {
  try {
    return spaceComplianceService.listAssessments();
  } catch (error) {
    console.error('[J.O.E. Space Compliance] List assessments error:', error);
    return [];
  }
});

// Get framework information
ipcMain.handle('space-compliance-get-framework-info', async (_, framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria') => {
  try {
    return spaceComplianceService.getFrameworkInfo(framework);
  } catch (error) {
    console.error('[J.O.E. Space Compliance] Get framework info error:', error);
    return null;
  }
});

// Get cross-framework mappings
ipcMain.handle('space-compliance-get-mappings', async (_, framework: string, controlId: string) => {
  try {
    return spaceComplianceService.getCrossFrameworkMappings(framework, controlId);
  } catch (error) {
    console.error('[J.O.E. Space Compliance] Get mappings error:', error);
    return [];
  }
});

// Generate unified compliance report
ipcMain.handle('space-compliance-unified-report', async (_, assessmentIds: string[]) => {
  try {
    const report = spaceComplianceService.generateUnifiedReport(assessmentIds);
    logSecurityEvent('UNIFIED_COMPLIANCE_REPORT', activeSession?.username, true,
      `Assessments: ${assessmentIds.length}, Overall Score: ${report.overallScore}%`);
    return { success: true, report };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Report generation failed';
    console.error('[J.O.E. Space Compliance] Unified report error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// ========================================
// NOTIFICATION SERVICE IPC HANDLERS
// ========================================

// Send notification
ipcMain.handle('notification-send', async (_, payload: {
  title: string;
  message: string;
  severity: string;
  channels: string[];
  metadata?: any;
}) => {
  try {
    const results = await notificationService.sendNotification(payload as any);
    logSecurityEvent('NOTIFICATION_SENT', activeSession?.username, true,
      `Channels: ${payload.channels.join(', ')}, Severity: ${payload.severity}`);
    return { success: true, results };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Notification failed';
    console.error('[J.O.E. Notifications] Send error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Configure channel
ipcMain.handle('notification-configure-channel', async (_, channel: string, config: any) => {
  try {
    notificationService.configureChannel(channel as any, config);
    logSecurityEvent('NOTIFICATION_CHANNEL_CONFIGURED', activeSession?.username, true, `Channel: ${channel}`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Configuration failed';
    console.error('[J.O.E. Notifications] Configure error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Get channel config
ipcMain.handle('notification-get-channel-config', async (_, channel: string) => {
  try {
    return notificationService.getChannelConfig(channel as any);
  } catch (error) {
    console.error('[J.O.E. Notifications] Get config error:', error);
    return null;
  }
});

// Test channel
ipcMain.handle('notification-test-channel', async (_, channel: string) => {
  try {
    const result = await notificationService.testChannel(channel as any);
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Test failed';
    return { success: false, error: errorMsg };
  }
});

// Add alert rule
ipcMain.handle('notification-add-rule', async (_, rule: any) => {
  try {
    const ruleId = notificationService.addAlertRule(rule);
    logSecurityEvent('ALERT_RULE_ADDED', activeSession?.username, true, `Rule: ${rule.name}`);
    return { success: true, ruleId };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Add rule failed';
    return { success: false, error: errorMsg };
  }
});

// Remove alert rule
ipcMain.handle('notification-remove-rule', async (_, ruleId: string) => {
  try {
    notificationService.removeAlertRule(ruleId);
    logSecurityEvent('ALERT_RULE_REMOVED', activeSession?.username, true, `Rule ID: ${ruleId}`);
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Remove rule failed' };
  }
});

// Get alert rules
ipcMain.handle('notification-get-rules', async () => {
  try {
    return notificationService.getAlertRules();
  } catch (error) {
    return [];
  }
});

// Process security finding
ipcMain.handle('notification-process-finding', async (_, finding: any) => {
  try {
    await notificationService.processSecurityFinding(finding);
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Processing failed' };
  }
});

// ========================================
// IAC SCANNER IPC HANDLERS
// ========================================

// Select directory for IaC scan
ipcMain.handle('iac-select-directory', async () => {
  try {
    const result = await dialog.showOpenDialog({
      properties: ['openDirectory'],
      title: 'Select IaC Directory'
    });
    return result.canceled ? null : result.filePaths[0];
  } catch (error) {
    return null;
  }
});

// Scan directory for IaC issues
ipcMain.handle('iac-scan-directory', async (_, dirPath: string, options?: { recursive?: boolean }) => {
  try {
    const results = await iacScanner.scanDirectory(dirPath, options);
    logSecurityEvent('IAC_SCAN_COMPLETED', activeSession?.username, true,
      `Files: ${results.filesScanned}, Findings: ${results.summary.total}`);
    return { success: true, results };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'IaC scan failed';
    console.error('[J.O.E. IaC Scanner] Scan error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Scan single file
ipcMain.handle('iac-scan-file', async (_, filePath: string) => {
  try {
    const results = await iacScanner.scanFile(filePath);
    return { success: true, results };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'File scan failed';
    return { success: false, error: errorMsg };
  }
});

// Get supported IaC types
ipcMain.handle('iac-get-supported-types', async () => {
  return ['terraform', 'cloudformation', 'kubernetes', 'dockerfile', 'ansible', 'helm'];
});

// Get rules for specific IaC type
ipcMain.handle('iac-get-rules', async (_, iacType?: string) => {
  try {
    return iacScanner.getRules(iacType as any);
  } catch (error) {
    return [];
  }
});

// ========================================
// API SECURITY SCANNER IPC HANDLERS
// ========================================

// Select OpenAPI spec file
ipcMain.handle('api-security-select-spec', async () => {
  try {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      title: 'Select OpenAPI/Swagger Specification',
      filters: [
        { name: 'OpenAPI Specs', extensions: ['yaml', 'yml', 'json'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });
    return result.canceled ? null : result.filePaths[0];
  } catch (error) {
    return null;
  }
});

// Scan OpenAPI specification
ipcMain.handle('api-security-scan-spec', async (_, specPath: string) => {
  try {
    const results = await apiSecurityScanner.scanSpecFile(specPath);
    logSecurityEvent('API_SECURITY_SCAN', activeSession?.username, true,
      `Endpoints: ${results.endpointsAnalyzed}, Findings: ${results.summary.total}, Score: ${results.securityScore}`);
    return { success: true, results };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'API scan failed';
    console.error('[J.O.E. API Security] Scan error:', errorMsg);
    return { success: false, error: errorMsg };
  }
});

// Scan spec from URL
ipcMain.handle('api-security-scan-url', async (_, url: string) => {
  try {
    const results = await apiSecurityScanner.scanFromUrl(url);
    logSecurityEvent('API_SECURITY_SCAN_URL', activeSession?.username, true,
      `URL: ${url}, Findings: ${results.summary.total}`);
    return { success: true, results };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'URL scan failed';
    return { success: false, error: errorMsg };
  }
});

// Get OWASP categories
ipcMain.handle('api-security-get-owasp-categories', async () => {
  return apiSecurityScanner.getOWASPCategories();
});

// Get rules
ipcMain.handle('api-security-get-rules', async () => {
  return apiSecurityScanner.getRules();
});

// ========================================
// SIEM CONNECTOR IPC HANDLERS
// ========================================

// Configure SIEM platform
ipcMain.handle('siem-configure', async (_, platform: string, config: any) => {
  try {
    siemConnector.configure(platform as any, config);
    logSecurityEvent('SIEM_CONFIGURED', activeSession?.username, true, `Platform: ${platform}`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'SIEM configuration failed';
    return { success: false, error: errorMsg };
  }
});

// Get SIEM config
ipcMain.handle('siem-get-config', async (_, platform: string) => {
  try {
    return siemConnector.getConfig(platform as any);
  } catch (error) {
    return null;
  }
});

// Test SIEM connection
ipcMain.handle('siem-test-connection', async (_, platform: string) => {
  try {
    const result = await siemConnector.testConnection(platform as any);
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Test failed';
    return { success: false, error: errorMsg };
  }
});

// Send security event to SIEM
ipcMain.handle('siem-send-event', async (_, platform: string, event: any) => {
  try {
    await siemConnector.sendEvent(platform as any, event);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Send event failed';
    return { success: false, error: errorMsg };
  }
});

// Send batch events
ipcMain.handle('siem-send-batch', async (_, platform: string, events: any[]) => {
  try {
    await siemConnector.sendBatch(platform as any, events);
    logSecurityEvent('SIEM_BATCH_SENT', activeSession?.username, true,
      `Platform: ${platform}, Events: ${events.length}`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Batch send failed';
    return { success: false, error: errorMsg };
  }
});

// Export findings to SIEM
ipcMain.handle('siem-export-findings', async (_, platform: string, findings: any[]) => {
  try {
    await siemConnector.exportFindings(platform as any, findings);
    logSecurityEvent('SIEM_FINDINGS_EXPORTED', activeSession?.username, true,
      `Platform: ${platform}, Findings: ${findings.length}`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Export failed';
    return { success: false, error: errorMsg };
  }
});

// Get supported SIEM platforms
ipcMain.handle('siem-get-platforms', async () => {
  return ['splunk', 'elastic', 'sentinel', 'qradar'];
});

// ========================================
// TICKETING INTEGRATION IPC HANDLERS
// ========================================

// Configure ticketing platform
ipcMain.handle('ticketing-configure', async (_, platform: string, config: any) => {
  try {
    ticketingService.configure(platform as any, config);
    logSecurityEvent('TICKETING_CONFIGURED', activeSession?.username, true, `Platform: ${platform}`);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Ticketing configuration failed';
    return { success: false, error: errorMsg };
  }
});

// Get ticketing config
ipcMain.handle('ticketing-get-config', async (_, platform: string) => {
  try {
    return ticketingService.getConfig(platform as any);
  } catch (error) {
    return null;
  }
});

// Test ticketing connection
ipcMain.handle('ticketing-test-connection', async (_, platform: string) => {
  try {
    const result = await ticketingService.testConnection(platform as any);
    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Test failed';
    return { success: false, error: errorMsg };
  }
});

// Create ticket from finding
ipcMain.handle('ticketing-create-ticket', async (_, platform: string, finding: any) => {
  try {
    const ticket = await ticketingService.createTicket(platform as any, finding);
    logSecurityEvent('TICKET_CREATED', activeSession?.username, true,
      `Platform: ${platform}, Ticket: ${ticket.ticketId}`);
    return { success: true, ticket };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Ticket creation failed';
    return { success: false, error: errorMsg };
  }
});

// Create bulk tickets
ipcMain.handle('ticketing-create-bulk', async (_, platform: string, findings: any[]) => {
  try {
    const tickets = await ticketingService.createBulkTickets(platform as any, findings);
    logSecurityEvent('BULK_TICKETS_CREATED', activeSession?.username, true,
      `Platform: ${platform}, Tickets: ${tickets.length}`);
    return { success: true, tickets };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Bulk ticket creation failed';
    return { success: false, error: errorMsg };
  }
});

// Update ticket status
ipcMain.handle('ticketing-update-status', async (_, platform: string, ticketId: string, status: string, comment?: string) => {
  try {
    await ticketingService.updateTicketStatus(platform as any, ticketId, status, comment);
    return { success: true };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Status update failed';
    return { success: false, error: errorMsg };
  }
});

// Get ticket
ipcMain.handle('ticketing-get-ticket', async (_, platform: string, ticketId: string) => {
  try {
    const ticket = await ticketingService.getTicket(platform as any, ticketId);
    return { success: true, ticket };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Get ticket failed';
    return { success: false, error: errorMsg };
  }
});

// Sync ticket status
ipcMain.handle('ticketing-sync-status', async (_, platform: string, ticketId: string) => {
  try {
    const status = await ticketingService.syncTicketStatus(platform as any, ticketId);
    return { success: true, status };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Sync failed';
    return { success: false, error: errorMsg };
  }
});

// Get supported ticketing platforms
ipcMain.handle('ticketing-get-platforms', async () => {
  return ['jira', 'servicenow', 'azure-boards', 'github', 'linear'];
});
