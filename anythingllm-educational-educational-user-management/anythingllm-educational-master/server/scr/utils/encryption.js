// server/src/utils/encryption.js
/**
 * Encryption Utilities for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in encryption operations
 */
import crypto from 'crypto';
import { generateAnonymizedId } from './compliance.js';

class EncryptionUtils {
  /**
   * Generate secure encryption key
   * @param {number} length - Key length in bytes
   * @returns {string} Generated key
   */
  static generateKey(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Encrypt data with AES-256-GCM
   * @param {string} data - Data to encrypt
   * @param {string} key - Encryption key
   * @returns {Object} Encrypted data and metadata
   */
  static encryptData(data, key) {
    try {
      if (!data || !key) {
        throw new Error('Data and key are required for encryption');
      }

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipherGCM('aes-256-gcm', key);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag().toString('hex');
      
      return {
        encryptedData: encrypted,
        iv: iv.toString('hex'),
        authTag,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data with AES-256-GCM
   * @param {Object} encryptedData - Encrypted data with metadata
   * @param {string} key - Decryption key
   * @returns {string} Decrypted data
   */
  static decryptData(encryptedData, key) {
    try {
      if (!encryptedData || !key) {
        throw new Error('Encrypted data and key are required for decryption');
      }

      const decipher = crypto.createDecipherGCM(
        'aes-256-gcm',
        key
      );
      
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const authTag = Buffer.from(encryptedData.authTag, 'hex');
      const data = Buffer.from(encryptedData.encryptedData, 'hex');
      
      decipher.setAuthTag(authTag);
      decipher.setAAD(iv);
      
      let decrypted = decipher.update(data);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Hash data with SHA-256
   * @param {string} data - Data to hash
   * @returns {string} Hashed data
   */
  static hashData(data) {
    try {
      if (!data) {
        throw new Error('Data is required for hashing');
      }

      const hash = crypto.createHash('sha256');
      hash.update(data);
      return hash.digest('hex');
    } catch (error) {
      throw new Error(`Hashing failed: ${error.message}`);
    }
  }

  /**
   * Generate secure token
   * @param {number} length - Token length
   * @returns {string} Secure token
   */
  static generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Create HMAC for data integrity
   * @param {string} data - Data to sign
   * @param {string} key - Signing key
   * @returns {string} HMAC signature
   */
  static createHMAC(data, key) {
    try {
      if (!data || !key) {
        throw new Error('Data and key are required for HMAC creation');
      }

      const hmac = crypto.createHmac('sha256', key);
      hmac.update(data);
      return hmac.digest('hex');
    } catch (error) {
      throw new Error(`HMAC creation failed: ${error.message}`);
    }
  }

  /**
   * Verify HMAC signature
   * @param {string} data - Data to verify
   * @param {string} key - Verification key
   * @param {string} signature - Expected signature
   * @returns {boolean} Verification result
   */
  static verifyHMAC(data, key, signature) {
    try {
      const expectedSignature = this.createHMAC(data, key);
      return crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(signature)
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Encrypt user session data
   * @param {Object} sessionData - Session data to encrypt
   * @param {string} encryptionKey - Key for encryption
   * @returns {Object} Encrypted session data
   */
  static encryptSessionData(sessionData, encryptionKey) {
    try {
      const jsonString = JSON.stringify(sessionData);
      return this.encryptData(jsonString, encryptionKey);
    } catch (error) {
      throw new Error(`Session data encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt user session data
   * @param {Object} encryptedSessionData - Encrypted session data
   * @param {string} encryptionKey - Key for decryption
   * @returns {Object} Decrypted session data
   */
  static decryptSessionData(encryptedSessionData, encryptionKey) {
    try {
      const decryptedString = this.decryptData(encryptedSessionData, encryptionKey);
      return JSON.parse(decryptedString);
    } catch (error) {
      throw new Error(`Session data decryption failed: ${error.message}`);
    }
  }

  /**
   * Generate encryption key from password
   * @param {string} password - Password to derive key from
   * @param {string} salt - Salt for key derivation
   * @returns {string} Derived encryption key
   */
  static deriveKeyFromPassword(password, salt) {
    try {
      if (!password || !salt) {
        throw new Error('Password and salt are required for key derivation');
      }

      return crypto.pbkdf2Sync(
        password,
        salt,
        100000,
        32,
        'sha256'
      ).toString('hex');
    } catch (error) {
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }

  /**
   * Validate encryption key
   * @param {string} key - Key to validate
   * @returns {boolean} Validation result
   */
  static validateKey(key) {
    if (!key || typeof key !== 'string') {
      return false;
    }
    
    // Check if key is a valid hex string of proper length
    const isValidHex = /^[0-9a-fA-F]+$/.test(key);
    const keyLength = key.length;
    
    // AES-256 requires 32 bytes (64 hex characters)
    return isValidHex && keyLength >= 64;
  }

  /**
   * Generate anonymized identifier for encrypted data
   * @param {string} originalId - Original identifier
   * @returns {string} Anonymized identifier
   */
  static generateAnonymizedIdentifier(originalId) {
    return generateAnonymizedId(originalId);
  }

  /**
   * Get encryption algorithm information
   * @returns {Object} Algorithm details
   */
  static getAlgorithmInfo() {
    return {
      encryption: 'AES-256-GCM',
      hashing: 'SHA-256',
      keyDerivation: 'PBKDF2',
      keyLength: 32,
      ivLength: 12,
      authTagLength: 16
    };
  }

  /**
   * Generate encryption audit entry
   * @param {string} operation - Operation performed
   * @param {Object} metadata - Operation metadata
   * @returns {Object} Audit entry
   */
  static generateAuditEntry(operation, metadata = {}) {
    return {
      timestamp: new Date().toISOString(),
      operation,
      algorithm: this.getAlgorithmInfo(),
      userId: metadata.userId ? generateAnonymizedId(metadata.userId) : null,
      dataId: metadata.dataId ? generateAnonymizedId(metadata.dataId) : null,
      success: metadata.success || false
    };
  }

  /**
   * Validate encrypted data integrity
   * @param {Object} encryptedData - Encrypted data to validate
   * @returns {boolean} Integrity validation result
   */
  static validateDataIntegrity(encryptedData) {
    try {
      // Basic validation of required fields
      if (!encryptedData || 
          !encryptedData.encryptedData || 
          !encryptedData.iv || 
          !encryptedData.authTag) {
        return false;
      }
      
      // Validate data types
      const validTypes = [
        typeof encryptedData.encryptedData === 'string',
        typeof encryptedData.iv === 'string', 
        typeof encryptedData.authTag === 'string'
      ];
      
      return validTypes.every(valid => valid);
    } catch (error) {
      return false;
    }
  }
}

export default EncryptionUtils;

// Export individual functions for direct use
export const generateKey = EncryptionUtils.generateKey;
export const encryptData = EncryptionUtils.encryptData;
export const decryptData = EncryptionUtils.decryptData;
export const hashData = EncryptionUtils.hashData;
export const generateSecureToken = EncryptionUtils.generateSecureToken;
export const createHMAC = EncryptionUtils.createHMAC;
export const verifyHMAC = EncryptionUtils.verifyHMAC;
export const encryptSessionData = EncryptionUtils.encryptSessionData;
export const decryptSessionData = EncryptionUtils.decryptSessionData;
export const deriveKeyFromPassword = EncryptionUtils.deriveKeyFromPassword;
export const validateKey = EncryptionUtils.validateKey;
export const generateAnonymizedIdentifier = EncryptionUtils.generateAnonymizedIdentifier;
export const getAlgorithmInfo = EncryptionUtils.getAlgorithmInfo;
export const generateAuditEntry = EncryptionUtils.generateAuditEntry;
export const validateDataIntegrity = EncryptionUtils.validateDataIntegrity;
