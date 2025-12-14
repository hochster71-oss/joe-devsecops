import { describe, it, expect } from 'vitest';

/**
 * Security Utility Tests
 * Testing security-related validation and sanitization functions
 */

describe('Security Utils', () => {
  describe('Password Validation', () => {
    const validatePassword = (password: string): { valid: boolean; errors: string[] } => {
      const errors: string[] = [];

      if (password.length < 15) {
        errors.push('Password must be at least 15 characters (DoD requirement)');
      }
      if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain uppercase letter');
      }
      if (!/[a-z]/.test(password)) {
        errors.push('Password must contain lowercase letter');
      }
      if (!/[0-9]/.test(password)) {
        errors.push('Password must contain number');
      }
      if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain special character');
      }

      return { valid: errors.length === 0, errors };
    };

    it('should reject passwords shorter than 15 characters', () => {
      const result = validatePassword('Short1!');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must be at least 15 characters (DoD requirement)');
    });

    it('should require uppercase letters', () => {
      const result = validatePassword('alllowercase123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain uppercase letter');
    });

    it('should require lowercase letters', () => {
      const result = validatePassword('ALLUPPERCASE123!@#');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain lowercase letter');
    });

    it('should require numbers', () => {
      const result = validatePassword('NoNumbersHere!!@@');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain number');
    });

    it('should require special characters', () => {
      const result = validatePassword('NoSpecialChars123ABC');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain special character');
    });

    it('should accept valid strong passwords', () => {
      const result = validatePassword('MyStr0ngP@ssword!123');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should accept minimum valid password', () => {
      const result = validatePassword('Abc123!@#Def456');
      expect(result.valid).toBe(true);
    });
  });

  describe('Common Password Detection', () => {
    const isCommonPassword = (password: string): boolean => {
      const commonPatterns = [
        'password',
        '123456',
        'qwerty',
        'admin',
        'letmein',
        'welcome',
        'monkey',
        'dragon',
        'master',
        '111111',
        'abc123'
      ];
      return commonPatterns.some(p =>
        password.toLowerCase().includes(p)
      );
    };

    it('should detect "password" in input', () => {
      expect(isCommonPassword('password123')).toBe(true);
      expect(isCommonPassword('MyPassword!')).toBe(true);
      expect(isCommonPassword('PASSWORD')).toBe(true);
    });

    it('should detect common number sequences', () => {
      expect(isCommonPassword('user123456')).toBe(true);
      expect(isCommonPassword('111111test')).toBe(true);
    });

    it('should detect "admin"', () => {
      expect(isCommonPassword('admin@2024')).toBe(true);
      expect(isCommonPassword('sysadmin')).toBe(true);
    });

    it('should pass unique passwords', () => {
      expect(isCommonPassword('MyUniqueSecurePass!')).toBe(false);
      expect(isCommonPassword('X7k#mP9$vL2@nQ4')).toBe(false);
    });
  });

  describe('Input Sanitization', () => {
    const sanitizeInput = (input: string): string => {
      return input
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    };

    it('should escape HTML tags', () => {
      const input = '<script>alert("XSS")</script>';
      const sanitized = sanitizeInput(input);

      expect(sanitized).not.toContain('<script>');
      expect(sanitized).toContain('&lt;script&gt;');
    });

    it('should escape quotes', () => {
      const input = '"><img src=x onerror=alert(1)>';
      const sanitized = sanitizeInput(input);

      expect(sanitized).not.toContain('"');
      expect(sanitized).toContain('&quot;');
    });

    it('should escape single quotes', () => {
      const input = "'); DROP TABLE users;--";
      const sanitized = sanitizeInput(input);

      expect(sanitized).not.toContain("'");
      expect(sanitized).toContain('&#x27;');
    });

    it('should handle normal input without changes', () => {
      const input = 'Hello World 123';
      const sanitized = sanitizeInput(input);

      expect(sanitized).toBe('Hello World 123');
    });
  });

  describe('Session Token Validation', () => {
    const isValidToken = (token: string): boolean => {
      // Token should be 64 characters (32 bytes hex)
      if (token.length !== 64) return false;
      // Should only contain hex characters
      return /^[a-f0-9]+$/i.test(token);
    };

    it('should accept valid hex tokens', () => {
      const validToken = 'a'.repeat(64);
      expect(isValidToken(validToken)).toBe(true);
    });

    it('should reject short tokens', () => {
      const shortToken = 'abc123';
      expect(isValidToken(shortToken)).toBe(false);
    });

    it('should reject tokens with invalid characters', () => {
      const invalidToken = 'g'.repeat(64); // 'g' is not valid hex
      expect(isValidToken(invalidToken)).toBe(false);
    });

    it('should accept mixed case hex', () => {
      const mixedToken = 'aAbBcCdDeEfF'.repeat(5) + 'aabb';
      expect(isValidToken(mixedToken)).toBe(true);
    });
  });

  describe('Username Validation', () => {
    const validateUsername = (username: string): { valid: boolean; error?: string } => {
      if (username.length < 3) {
        return { valid: false, error: 'Username must be at least 3 characters' };
      }
      if (username.length > 32) {
        return { valid: false, error: 'Username must be at most 32 characters' };
      }
      if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return { valid: false, error: 'Username can only contain letters, numbers, and ._-' };
      }
      if (/^[._-]/.test(username)) {
        return { valid: false, error: 'Username cannot start with special characters' };
      }
      return { valid: true };
    };

    it('should accept valid usernames', () => {
      expect(validateUsername('mhoch').valid).toBe(true);
      expect(validateUsername('john_doe').valid).toBe(true);
      expect(validateUsername('user.name').valid).toBe(true);
      expect(validateUsername('user-123').valid).toBe(true);
    });

    it('should reject too short usernames', () => {
      const result = validateUsername('ab');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('at least 3');
    });

    it('should reject usernames with invalid characters', () => {
      const result = validateUsername('user@name');
      expect(result.valid).toBe(false);
    });

    it('should reject usernames starting with special chars', () => {
      const result = validateUsername('_admin');
      expect(result.valid).toBe(false);
    });
  });

  describe('CVE ID Validation', () => {
    const isValidCVE = (cve: string): boolean => {
      // CVE format: CVE-YYYY-NNNNN (year and 4+ digit number)
      return /^CVE-\d{4}-\d{4,}$/i.test(cve);
    };

    it('should accept valid CVE IDs', () => {
      expect(isValidCVE('CVE-2024-12345')).toBe(true);
      expect(isValidCVE('CVE-2021-44228')).toBe(true); // Log4Shell
      expect(isValidCVE('cve-2024-1234')).toBe(true); // Case insensitive
    });

    it('should reject invalid CVE IDs', () => {
      expect(isValidCVE('CVE-24-12345')).toBe(false); // 2-digit year
      expect(isValidCVE('CVE-2024-123')).toBe(false); // Too short number
      expect(isValidCVE('CVE2024-12345')).toBe(false); // Missing hyphen
      expect(isValidCVE('VULN-2024-12345')).toBe(false); // Wrong prefix
    });
  });

  describe('Rate Limiting Logic', () => {
    const createRateLimiter = (maxAttempts: number, windowMs: number) => {
      const attempts: Map<string, { count: number; firstAttempt: number }> = new Map();

      return {
        isAllowed: (key: string): boolean => {
          const now = Date.now();
          const record = attempts.get(key);

          if (!record) {
            attempts.set(key, { count: 1, firstAttempt: now });
            return true;
          }

          // Reset if outside window
          if (now - record.firstAttempt > windowMs) {
            attempts.set(key, { count: 1, firstAttempt: now });
            return true;
          }

          if (record.count >= maxAttempts) {
            return false;
          }

          record.count++;
          return true;
        },
        reset: (key: string) => {
          attempts.delete(key);
        }
      };
    };

    it('should allow requests within limit', () => {
      const limiter = createRateLimiter(5, 60000);

      expect(limiter.isAllowed('user1')).toBe(true);
      expect(limiter.isAllowed('user1')).toBe(true);
      expect(limiter.isAllowed('user1')).toBe(true);
    });

    it('should block requests over limit', () => {
      const limiter = createRateLimiter(3, 60000);

      expect(limiter.isAllowed('user2')).toBe(true);
      expect(limiter.isAllowed('user2')).toBe(true);
      expect(limiter.isAllowed('user2')).toBe(true);
      expect(limiter.isAllowed('user2')).toBe(false); // 4th attempt blocked
    });

    it('should track different keys independently', () => {
      const limiter = createRateLimiter(2, 60000);

      expect(limiter.isAllowed('userA')).toBe(true);
      expect(limiter.isAllowed('userA')).toBe(true);
      expect(limiter.isAllowed('userA')).toBe(false);

      // Different user should still be allowed
      expect(limiter.isAllowed('userB')).toBe(true);
    });
  });
});
