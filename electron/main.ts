import { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage } from 'electron';
import path from 'path';
import { securityScanner } from './security-scanner';

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
  // Create the browser window with Dark Wolf styling
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    title: 'J.O.E. DevSecOps Arsenal - Dark Wolf Solutions',
    // icon: path.join(__dirname, '../../resources/icons/joe-icon.png'), // TODO: Add PNG icon
    backgroundColor: '#1E1E1E', // Dark Wolf primary dark
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#1E1E1E',
      symbolColor: '#00A8E8', // J.O.E. blue accent
      height: 40
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    },
    show: true // Show window immediately
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
  });

  // Close normally for now (disable tray minimize during development)
  // mainWindow.on('close', (event) => {
  //   if (!isQuitting) {
  //     event.preventDefault();
  //     mainWindow?.hide();
  //   }
  // });
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
let currentUser: { id: string; username: string; name: string; role: string; requirePasswordChange?: boolean } | null = null;

// Dev users - mutable for password changes
interface DevUser {
  id: string;
  username: string;
  password: string;
  name: string;
  role: string;
  requirePasswordChange: boolean;
}

const DEV_USERS: Record<string, DevUser> = {
  'mhoch': {
    id: 'dev-1',
    username: 'mhoch',
    password: 'admin123',
    name: 'Michael Hoch',
    role: 'admin',
    requirePasswordChange: true  // Force password change on first login
  },
  'jscholer': {
    id: 'dev-2',
    username: 'jscholer',
    password: 'user123',
    name: 'Joseph Scholer',
    role: 'standard',
    requirePasswordChange: true  // Force password change on first login
  }
};

ipcMain.handle('auth-login', async (_, username: string, password: string) => {
  console.log('[J.O.E. Auth] Login attempt:', username);

  const user = DEV_USERS[username.toLowerCase()];
  if (user && user.password === password) {
    currentUser = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      requirePasswordChange: user.requirePasswordChange
    };
    console.log('[J.O.E. Auth] Login successful, requirePasswordChange:', user.requirePasswordChange);
    return {
      success: true,
      user: currentUser,
      requirePasswordChange: user.requirePasswordChange
    };
  }

  console.log('[J.O.E. Auth] Login failed - invalid credentials');
  return { success: false, error: 'Invalid username or password' };
});

ipcMain.handle('auth-logout', async () => {
  console.log('[J.O.E. Auth] Logout');
  currentUser = null;
  return { success: true };
});

ipcMain.handle('auth-get-current-user', async () => {
  return currentUser;
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

  // Update password and clear requirePasswordChange flag
  user.password = newPassword;
  user.requirePasswordChange = false;
  currentUser.requirePasswordChange = false;

  console.log('[J.O.E. Auth] Password changed successfully for:', currentUser.username);
  return { success: true };
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

// Auto-fix vulnerabilities
ipcMain.handle('security-auto-fix', async () => {
  console.log('[J.O.E. IPC] Running auto-fix...');
  try {
    const results = await securityScanner.autoFix();
    console.log('[J.O.E. IPC] Auto-fix complete:', results);
    return results;
  } catch (error) {
    console.error('[J.O.E. IPC] Auto-fix error:', error);
    throw error;
  }
});
