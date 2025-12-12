/**
 * J.O.E. Secure Vault Service
 *
 * AES-256-GCM Encrypted Secrets Storage
 * NIST 800-53 / DoD STIG Compliant Key Management
 *
 * Features:
 * - AES-256-GCM encryption with authenticated encryption
 * - PBKDF2 key derivation with 100,000 iterations
 * - Secure random IV generation per entry
 * - Tamper detection via authentication tags
 * - Audit logging of all vault operations
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

// ========================================
// VAULT INTERFACES
// ========================================

export interface VaultEntry {
  id: string;
  name: string;
  type: SecretType;
  encryptedValue: string;
  iv: string;
  authTag: string;
  metadata: {
    createdAt: string;
    updatedAt: string;
    sourceFile?: string;
    sourceLine?: number;
    description?: string;
    tags?: string[];
  };
}

export interface VaultMetadata {
  version: string;
  createdAt: string;
  updatedAt: string;
  entryCount: number;
  encryptionAlgorithm: string;
  keyDerivation: string;
  salt: string;
  iterations: number;
}

export interface Vault {
  metadata: VaultMetadata;
  entries: VaultEntry[];
}

export type SecretType =
  | 'API_KEY'
  | 'DATABASE_CREDENTIAL'
  | 'SSH_KEY'
  | 'CERTIFICATE'
  | 'TOKEN'
  | 'PASSWORD'
  | 'ENCRYPTION_KEY'
  | 'WEBHOOK_URL'
  | 'SERVICE_ACCOUNT'
  | 'OTHER';

export interface VaultStats {
  totalEntries: number;
  byType: Record<SecretType, number>;
  lastUpdated: string;
  vaultSize: number;
  isLocked: boolean;
}

// ========================================
// ENCRYPTION CONSTANTS (NIST Compliant)
// ========================================

const ENCRYPTION_CONFIG = {
  // AES-256-GCM - Authenticated Encryption
  algorithm: 'aes-256-gcm' as const,

  // Key length in bytes (256 bits)
  keyLength: 32,

  // IV length in bytes (96 bits recommended for GCM)
  ivLength: 12,

  // Auth tag length in bytes
  authTagLength: 16,

  // Salt length for key derivation
  saltLength: 32,

  // PBKDF2 iterations (NIST minimum: 10,000; DoD recommended: 100,000+)
  pbkdf2Iterations: 100000,

  // Hash algorithm for PBKDF2
  hashAlgorithm: 'sha512' as const,

  // Vault file version
  vaultVersion: '1.0.0'
};

// ========================================
// SECURE VAULT SERVICE
// ========================================

class SecureVaultService {
  private vaultPath: string;
  private vault: Vault | null = null;
  private derivedKey: Buffer | null = null;
  private isUnlocked: boolean = false;
  private auditLog: Array<{ timestamp: string; action: string; details: string }> = [];

  constructor() {
    // Store vault in user data directory
    const userDataPath = app?.getPath('userData') || process.cwd();
    this.vaultPath = path.join(userDataPath, 'joe-secure-vault.enc');
  }

  // ========================================
  // KEY MANAGEMENT
  // ========================================

  /**
   * Derive encryption key from master password using PBKDF2
   */
  private deriveKey(masterPassword: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      masterPassword,
      salt,
      ENCRYPTION_CONFIG.pbkdf2Iterations,
      ENCRYPTION_CONFIG.keyLength,
      ENCRYPTION_CONFIG.hashAlgorithm
    );
  }

  /**
   * Generate cryptographically secure random bytes
   */
  private generateSecureRandom(length: number): Buffer {
    return crypto.randomBytes(length);
  }

  // ========================================
  // ENCRYPTION / DECRYPTION
  // ========================================

  /**
   * Encrypt a value using AES-256-GCM
   */
  private encrypt(plaintext: string, key: Buffer): { ciphertext: string; iv: string; authTag: string } {
    const iv = this.generateSecureRandom(ENCRYPTION_CONFIG.ivLength);
    const cipher = crypto.createCipheriv(ENCRYPTION_CONFIG.algorithm, key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    };
  }

  /**
   * Decrypt a value using AES-256-GCM
   */
  private decrypt(ciphertext: string, key: Buffer, iv: string, authTag: string): string {
    const decipher = crypto.createDecipheriv(
      ENCRYPTION_CONFIG.algorithm,
      key,
      Buffer.from(iv, 'base64')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'base64'));

    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // ========================================
  // VAULT OPERATIONS
  // ========================================

  /**
   * Initialize a new vault with master password
   */
  async initializeVault(masterPassword: string): Promise<boolean> {
    if (this.vaultExists()) {
      throw new Error('Vault already exists. Use unlockVault() instead.');
    }

    if (!this.validateMasterPassword(masterPassword)) {
      throw new Error('Master password does not meet security requirements');
    }

    const salt = this.generateSecureRandom(ENCRYPTION_CONFIG.saltLength);
    this.derivedKey = this.deriveKey(masterPassword, salt);

    this.vault = {
      metadata: {
        version: ENCRYPTION_CONFIG.vaultVersion,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        entryCount: 0,
        encryptionAlgorithm: ENCRYPTION_CONFIG.algorithm.toUpperCase(),
        keyDerivation: `PBKDF2-${ENCRYPTION_CONFIG.hashAlgorithm.toUpperCase()}`,
        salt: salt.toString('base64'),
        iterations: ENCRYPTION_CONFIG.pbkdf2Iterations
      },
      entries: []
    };

    await this.saveVault();
    this.isUnlocked = true;
    this.logAudit('VAULT_INITIALIZED', 'New secure vault created');

    return true;
  }

  /**
   * Unlock existing vault with master password
   */
  async unlockVault(masterPassword: string): Promise<boolean> {
    if (!this.vaultExists()) {
      throw new Error('Vault does not exist. Use initializeVault() first.');
    }

    try {
      const encryptedData = fs.readFileSync(this.vaultPath, 'utf8');
      const vaultData = JSON.parse(encryptedData);

      // Derive key from password and stored salt
      const salt = Buffer.from(vaultData.metadata.salt, 'base64');
      this.derivedKey = this.deriveKey(masterPassword, salt);

      // Verify key by attempting to decrypt first entry (if exists)
      if (vaultData.entries.length > 0) {
        const testEntry = vaultData.entries[0];
        try {
          this.decrypt(
            testEntry.encryptedValue,
            this.derivedKey,
            testEntry.iv,
            testEntry.authTag
          );
        } catch {
          this.derivedKey = null;
          throw new Error('Invalid master password');
        }
      }

      this.vault = vaultData;
      this.isUnlocked = true;
      this.logAudit('VAULT_UNLOCKED', 'Vault successfully unlocked');

      return true;
    } catch (error) {
      this.derivedKey = null;
      this.isUnlocked = false;
      if (error instanceof Error && error.message === 'Invalid master password') {
        throw error;
      }
      throw new Error('Failed to unlock vault: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  }

  /**
   * Lock the vault (clear derived key from memory)
   */
  lockVault(): void {
    if (this.derivedKey) {
      // Securely wipe key from memory
      this.derivedKey.fill(0);
    }
    this.derivedKey = null;
    this.vault = null;
    this.isUnlocked = false;
    this.logAudit('VAULT_LOCKED', 'Vault locked');
  }

  /**
   * Add a secret to the vault
   */
  async addSecret(
    name: string,
    value: string,
    type: SecretType,
    metadata?: {
      sourceFile?: string;
      sourceLine?: number;
      description?: string;
      tags?: string[];
    }
  ): Promise<VaultEntry> {
    this.ensureUnlocked();

    const id = crypto.randomUUID();
    const { ciphertext, iv, authTag } = this.encrypt(value, this.derivedKey!);

    const entry: VaultEntry = {
      id,
      name,
      type,
      encryptedValue: ciphertext,
      iv,
      authTag,
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...metadata
      }
    };

    this.vault!.entries.push(entry);
    this.vault!.metadata.entryCount = this.vault!.entries.length;
    this.vault!.metadata.updatedAt = new Date().toISOString();

    await this.saveVault();
    this.logAudit('SECRET_ADDED', `Added secret: ${name} (${type})`);

    return entry;
  }

  /**
   * Retrieve a decrypted secret by ID
   */
  getSecret(id: string): { entry: VaultEntry; decryptedValue: string } | null {
    this.ensureUnlocked();

    const entry = this.vault!.entries.find(e => e.id === id);
    if (!entry) return null;

    const decryptedValue = this.decrypt(
      entry.encryptedValue,
      this.derivedKey!,
      entry.iv,
      entry.authTag
    );

    this.logAudit('SECRET_ACCESSED', `Accessed secret: ${entry.name}`);

    return { entry, decryptedValue };
  }

  /**
   * Update a secret's value
   */
  async updateSecret(id: string, newValue: string): Promise<VaultEntry | null> {
    this.ensureUnlocked();

    const entryIndex = this.vault!.entries.findIndex(e => e.id === id);
    if (entryIndex === -1) return null;

    const { ciphertext, iv, authTag } = this.encrypt(newValue, this.derivedKey!);

    this.vault!.entries[entryIndex] = {
      ...this.vault!.entries[entryIndex],
      encryptedValue: ciphertext,
      iv,
      authTag,
      metadata: {
        ...this.vault!.entries[entryIndex].metadata,
        updatedAt: new Date().toISOString()
      }
    };

    this.vault!.metadata.updatedAt = new Date().toISOString();
    await this.saveVault();

    this.logAudit('SECRET_UPDATED', `Updated secret: ${this.vault!.entries[entryIndex].name}`);

    return this.vault!.entries[entryIndex];
  }

  /**
   * Delete a secret from the vault
   */
  async deleteSecret(id: string): Promise<boolean> {
    this.ensureUnlocked();

    const entryIndex = this.vault!.entries.findIndex(e => e.id === id);
    if (entryIndex === -1) return false;

    const deletedEntry = this.vault!.entries[entryIndex];
    this.vault!.entries.splice(entryIndex, 1);
    this.vault!.metadata.entryCount = this.vault!.entries.length;
    this.vault!.metadata.updatedAt = new Date().toISOString();

    await this.saveVault();
    this.logAudit('SECRET_DELETED', `Deleted secret: ${deletedEntry.name}`);

    return true;
  }

  /**
   * List all entries (without decrypted values)
   */
  listEntries(): Omit<VaultEntry, 'encryptedValue' | 'iv' | 'authTag'>[] {
    this.ensureUnlocked();

    return this.vault!.entries.map(({ encryptedValue, iv, authTag, ...rest }) => rest);
  }

  /**
   * Get vault statistics
   */
  getStats(): VaultStats {
    const byType: Record<SecretType, number> = {
      API_KEY: 0,
      DATABASE_CREDENTIAL: 0,
      SSH_KEY: 0,
      CERTIFICATE: 0,
      TOKEN: 0,
      PASSWORD: 0,
      ENCRYPTION_KEY: 0,
      WEBHOOK_URL: 0,
      SERVICE_ACCOUNT: 0,
      OTHER: 0
    };

    if (this.vault) {
      for (const entry of this.vault.entries) {
        byType[entry.type] = (byType[entry.type] || 0) + 1;
      }
    }

    return {
      totalEntries: this.vault?.entries.length || 0,
      byType,
      lastUpdated: this.vault?.metadata.updatedAt || '',
      vaultSize: this.vaultExists() ? fs.statSync(this.vaultPath).size : 0,
      isLocked: !this.isUnlocked
    };
  }

  /**
   * Export vault entries (encrypted) for backup
   */
  exportVault(): string {
    this.ensureUnlocked();
    return JSON.stringify(this.vault, null, 2);
  }

  /**
   * Change master password
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    this.ensureUnlocked();

    if (!this.validateMasterPassword(newPassword)) {
      throw new Error('New password does not meet security requirements');
    }

    // Verify current password
    const salt = Buffer.from(this.vault!.metadata.salt, 'base64');
    const verifyKey = this.deriveKey(currentPassword, salt);

    // Test decryption with current password
    if (this.vault!.entries.length > 0) {
      try {
        const testEntry = this.vault!.entries[0];
        this.decrypt(testEntry.encryptedValue, verifyKey, testEntry.iv, testEntry.authTag);
      } catch {
        throw new Error('Current password is incorrect');
      }
    }

    // Re-encrypt all entries with new key
    const newSalt = this.generateSecureRandom(ENCRYPTION_CONFIG.saltLength);
    const newKey = this.deriveKey(newPassword, newSalt);

    const reEncryptedEntries: VaultEntry[] = [];

    for (const entry of this.vault!.entries) {
      // Decrypt with old key
      const plaintext = this.decrypt(
        entry.encryptedValue,
        this.derivedKey!,
        entry.iv,
        entry.authTag
      );

      // Re-encrypt with new key
      const { ciphertext, iv, authTag } = this.encrypt(plaintext, newKey);

      reEncryptedEntries.push({
        ...entry,
        encryptedValue: ciphertext,
        iv,
        authTag
      });
    }

    // Update vault
    this.vault!.entries = reEncryptedEntries;
    this.vault!.metadata.salt = newSalt.toString('base64');
    this.vault!.metadata.updatedAt = new Date().toISOString();
    this.derivedKey = newKey;

    await this.saveVault();
    this.logAudit('PASSWORD_CHANGED', 'Master password changed successfully');

    return true;
  }

  /**
   * Get audit log
   */
  getAuditLog(): Array<{ timestamp: string; action: string; details: string }> {
    return [...this.auditLog];
  }

  // ========================================
  // HELPER METHODS
  // ========================================

  /**
   * Check if vault file exists
   */
  vaultExists(): boolean {
    return fs.existsSync(this.vaultPath);
  }

  /**
   * Check if vault is unlocked
   */
  isVaultUnlocked(): boolean {
    return this.isUnlocked;
  }

  /**
   * Ensure vault is unlocked before operations
   */
  private ensureUnlocked(): void {
    if (!this.isUnlocked || !this.derivedKey || !this.vault) {
      throw new Error('Vault is locked. Please unlock first.');
    }
  }

  /**
   * Validate master password meets security requirements
   */
  private validateMasterPassword(password: string): boolean {
    // DoD STIG requirements: 15+ chars, mixed case, numbers, symbols
    if (password.length < 15) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) return false;
    return true;
  }

  /**
   * Save vault to disk
   */
  private async saveVault(): Promise<void> {
    if (!this.vault) throw new Error('No vault to save');

    const vaultDir = path.dirname(this.vaultPath);
    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true });
    }

    fs.writeFileSync(this.vaultPath, JSON.stringify(this.vault, null, 2), {
      encoding: 'utf8',
      mode: 0o600 // Read/write only for owner
    });
  }

  /**
   * Log audit event
   */
  private logAudit(action: string, details: string): void {
    this.auditLog.push({
      timestamp: new Date().toISOString(),
      action,
      details
    });

    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Map detected secret type to vault secret type
   */
  mapSecretType(detectedType: string): SecretType {
    const mapping: Record<string, SecretType> = {
      'AWS_ACCESS_KEY': 'API_KEY',
      'AWS_SECRET_KEY': 'API_KEY',
      'AZURE_CLIENT_SECRET': 'API_KEY',
      'GCP_SERVICE_ACCOUNT': 'SERVICE_ACCOUNT',
      'GITHUB_TOKEN': 'TOKEN',
      'GITLAB_TOKEN': 'TOKEN',
      'SLACK_TOKEN': 'TOKEN',
      'SLACK_WEBHOOK': 'WEBHOOK_URL',
      'JWT_SECRET': 'ENCRYPTION_KEY',
      'PRIVATE_KEY': 'SSH_KEY',
      'SSH_KEY': 'SSH_KEY',
      'API_KEY': 'API_KEY',
      'DATABASE_URL': 'DATABASE_CREDENTIAL',
      'PASSWORD': 'PASSWORD',
      'BEARER_TOKEN': 'TOKEN',
      'BASIC_AUTH': 'PASSWORD',
      'STRIPE_KEY': 'API_KEY',
      'TWILIO_KEY': 'API_KEY',
      'SENDGRID_KEY': 'API_KEY',
      'NPM_TOKEN': 'TOKEN',
      'DOCKER_AUTH': 'PASSWORD',
      'KUBERNETES_SECRET': 'OTHER',
      'GENERIC_SECRET': 'OTHER',
      'HIGH_ENTROPY': 'OTHER'
    };

    return mapping[detectedType] || 'OTHER';
  }
}

export const secureVault = new SecureVaultService();
