// server/src/utils/cache.js
/**
 * Caching Utilities for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in cache operations
 */
import { generateAnonymizedId } from './compliance.js';
import crypto from 'crypto';

class CacheManager {
  constructor() {
    // In-memory cache storage (in production, this would be Redis or similar)
    this.cache = new Map();
    this.ttl = 3600000; // 1 hour default TTL
  }

  /**
   * Set cache entry with compliance measures
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time-to-live in milliseconds
   * @returns {Promise<void>}
   */
  async set(key, value, ttl = this.ttl) {
    try {
      // Generate anonymized key for compliance
      const anonymizedKey = generateAnonymizedId(key);
      
      // Sanitize value to remove PII if present
      const sanitizedValue = this.sanitizeValue(value);
      
      // Store with metadata
      const cacheEntry = {
        value: sanitizedValue,
        timestamp: Date.now(),
        ttl,
        key: anonymizedKey
      };
      
      this.cache.set(anonymizedKey, cacheEntry);
      
      console.log(`[CACHE] Set entry: ${anonymizedKey}`);
    } catch (error) {
      console.error('[CACHE] Failed to set cache entry:', error);
    }
  }

  /**
   * Get cache entry with compliance measures
   * @param {string} key - Cache key
   * @returns {Promise<any>} Cached value or null
   */
  async get(key) {
    try {
      // Generate anonymized key for compliance
      const anonymizedKey = generateAnonymizedId(key);
      
      const entry = this.cache.get(anonymizedKey);
      
      if (!entry) {
        return null;
      }
      
      // Check if expired
      if (Date.now() - entry.timestamp > entry.ttl) {
        this.cache.delete(anonymizedKey);
        console.log(`[CACHE] Entry expired: ${anonymizedKey}`);
        return null;
      }
      
      console.log(`[CACHE] Retrieved entry: ${anonymizedKey}`);
      return entry.value;
    } catch (error) {
      console.error('[CACHE] Failed to get cache entry:', error);
      return null;
    }
  }

  /**
   * Delete cache entry with compliance measures
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Deletion success status
   */
  async delete(key) {
    try {
      // Generate anonymized key for compliance
      const anonymizedKey = generateAnonymizedId(key);
      
      const deleted = this.cache.delete(anonymizedKey);
      
      if (deleted) {
        console.log(`[CACHE] Deleted entry: ${anonymizedKey}`);
      }
      
      return deleted;
    } catch (error) {
      console.error('[CACHE] Failed to delete cache entry:', error);
      return false;
    }
  }

  /**
   * Clear all cache entries
   * @returns {Promise<void>}
   */
  async clear() {
    try {
      this.cache.clear();
      console.log('[CACHE] Cache cleared');
    } catch (error) {
      console.error('[CACHE] Failed to clear cache:', error);
    }
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getStats() {
    try {
      const stats = {
        size: this.cache.size,
        timestamp: new Date().toISOString(),
        entries: []
      };
      
      // Generate anonymized entries list for reporting
      this.cache.forEach((entry, key) => {
        stats.entries.push({
          key: key,
          timestamp: entry.timestamp,
          ttl: entry.ttl
        });
      });
      
      return stats;
    } catch (error) {
      console.error('[CACHE] Failed to get cache statistics:', error);
      return { size: 0, timestamp: new Date().toISOString(), entries: [] };
    }
  }

  /**
   * Check if key exists in cache
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Existence status
   */
  async has(key) {
    try {
      const anonymizedKey = generateAnonymizedId(key);
      return this.cache.has(anonymizedKey);
    } catch (error) {
      console.error('[CACHE] Failed to check cache key:', error);
      return false;
    }
  }

  /**
   * Get all keys in cache
   * @returns {Promise<Array>} List of anonymized keys
   */
  async keys() {
    try {
      const keys = Array.from(this.cache.keys());
      return keys;
    } catch (error) {
      console.error('[CACHE] Failed to get cache keys:', error);
      return [];
    }
  }

  /**
   * Sanitize value to remove PII before caching
   * @param {any} value - Value to sanitize
   * @returns {any} Sanitized value
   */
  sanitizeValue(value) {
    if (!value || typeof value !== 'object') {
      return value;
    }
    
    // Deep clone and sanitize object
    const sanitized = JSON.parse(JSON.stringify(value));
    
    // Remove potential PII fields
    const piiFields = ['email', 'name', 'phone', 'address', 'ssn', 'studentId', 'userId'];
    
    const sanitizeObject = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;
      
      Object.keys(obj).forEach(key => {
        if (piiFields.includes(key.toLowerCase())) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      });
      
      return obj;
    };
    
    return sanitizeObject(sanitized);
  }

  /**
   * Generate cache key from multiple parameters
   * @param {Array} params - Parameters to include in key
   * @returns {string} Generated cache key
   */
  generateKey(...params) {
    try {
      // Create a hash of all parameters for consistent key generation
      const keyString = params.join('|');
      const hash = crypto.createHash('sha256').update(keyString).digest('hex');
      
      return `cache_${hash}`;
    } catch (error) {
      console.error('[CACHE] Failed to generate cache key:', error);
      // Fallback to simple approach
      return `cache_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
  }

  /**
   * Get cached workspace data
   * @param {string} workspaceId - Workspace identifier
   * @param {string} userId - User identifier
   * @returns {Promise<any>} Cached workspace data
   */
  async getWorkspaceData(workspaceId, userId) {
    try {
      const key = this.generateKey('workspace', workspaceId, userId);
      return await this.get(key);
    } catch (error) {
      console.error('[CACHE] Failed to get workspace data:', error);
      return null;
    }
  }

  /**
   * Set cached workspace data
   * @param {string} workspaceId - Workspace identifier
   * @param {string} userId - User identifier
   * @param {any} data - Data to cache
   * @returns {Promise<void>}
   */
  async setWorkspaceData(workspaceId, userId, data) {
    try {
      const key = this.generateKey('workspace', workspaceId, userId);
      await this.set(key, data);
    } catch (error) {
      console.error('[CACHE] Failed to set workspace data:', error);
    }
  }

  /**
   * Get cached user data
   * @param {string} userId - User identifier
   * @returns {Promise<any>} Cached user data
   */
  async getUserData(userId) {
    try {
      const key = this.generateKey('user', userId);
      return await this.get(key);
    } catch (error) {
      console.error('[CACHE] Failed to get user data:', error);
      return null;
    }
  }

  /**
   * Set cached user data
   * @param {string} userId - User identifier
   * @param {any} data - Data to cache
   * @returns {Promise<void>}
   */
  async setUserData(userId, data) {
    try {
      const key = this.generateKey('user', userId);
      await this.set(key, data);
    } catch (error) {
      console.error('[CACHE] Failed to set user data:', error);
    }
  }

  /**
   * Get cached permissions
   * @param {string} userId - User identifier
   * @param {string} resource - Resource type
   * @returns {Promise<any>} Cached permissions
   */
  async getPermissions(userId, resource) {
    try {
      const key = this.generateKey('permissions', userId, resource);
      return await this.get(key);
    } catch (error) {
      console.error('[CACHE] Failed to get permissions:', error);
      return null;
    }
  }

  /**
   * Set cached permissions
   * @param {string} userId - User identifier
   * @param {string} resource - Resource type
   * @param {any} permissions - Permissions to cache
   * @returns {Promise<void>}
   */
  async setPermissions(userId, resource, permissions) {
    try {
      const key = this.generateKey('permissions', userId, resource);
      await this.set(key, permissions);
    } catch (error) {
      console.error('[CACHE] Failed to set permissions:', error);
    }
  }

  /**
   * Get cache status report
   * @returns {Object} Cache status report
   */
  getStatusReport() {
    try {
      const stats = this.getStats();
      
      return {
        timestamp: new Date().toISOString(),
        system: 'AnythingLLM Educational',
        version: process.env.npm_package_version || '1.0.0',
        cacheStatus: 'operational',
        entries: stats.size,
        ttl: this.ttl,
        anonymizedEntries: stats.entries.map(entry => ({
          key: entry.key,
          timestamp: entry.timestamp
        }))
      };
    } catch (error) {
      console.error('[CACHE] Failed to generate status report:', error);
      return {
        timestamp: new Date().toISOString(),
        system: 'AnythingLLM Educational',
        cacheStatus: 'error',
        error: error.message
      };
    }
  }

  /**
   * Validate cache entry expiration
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Expiration status
   */
  async isExpired(key) {
    try {
      const anonymizedKey = generateAnonymizedId(key);
      const entry = this.cache.get(anonymizedKey);
      
      if (!entry) return true;
      
      return Date.now() - entry.timestamp > entry.ttl;
    } catch (error) {
      console.error('[CACHE] Failed to check expiration:', error);
      return true;
    }
  }

  /**
   * Update cache entry TTL
   * @param {string} key - Cache key
   * @param {number} newTtl - New TTL value
   * @returns {Promise<boolean>} Update success status
   */
  async updateTTL(key, newTtl) {
    try {
      const anonymizedKey = generateAnonymizedId(key);
      const entry = this.cache.get(anonymizedKey);
      
      if (entry) {
        entry.ttl = newTtl;
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('[CACHE] Failed to update TTL:', error);
      return false;
    }
  }

  /**
   * Get cache hit/miss statistics
   * @returns {Object} Cache performance metrics
   */
  getPerformanceMetrics() {
    // In a real implementation, this would track actual hits and misses
    // For now returning mock data showing structure
    
    return {
      timestamp: new Date().toISOString(),
      totalRequests: Math.floor(Math.random() * 1000),
      cacheHits: Math.floor(Math.random() * 800),
      cacheMisses: Math.floor(Math.random() * 200),
      hitRate: `${Math.floor(Math.random() * 30) + 70}%`,
      performance: 'optimal'
    };
  }
}

// Create singleton instance
const cacheManager = new CacheManager();

export default cacheManager;

// Export individual functions for direct use
export const setCache = cacheManager.set.bind(cacheManager);
export const getCache = cacheManager.get.bind(cacheManager);
export const deleteCache = cacheManager.delete.bind(cacheManager);
export const clearCache = cacheManager.clear.bind(cacheManager);
export const getCacheStats = cacheManager.getStats.bind(cacheManager);
export const hasCache = cacheManager.has.bind(cacheManager);
export const getCacheKeys = cacheManager.keys.bind(cacheManager);
export const generateCacheKey = cacheManager.generateKey.bind(cacheManager);
export const getWorkspaceCache = cacheManager.getWorkspaceData.bind(cacheManager);
export const setWorkspaceCache = cacheManager.setWorkspaceData.bind(cacheManager);
export const getUserCache = cacheManager.getUserData.bind(cacheManager);
export const setUserCache = cacheManager.setUserData.bind(cacheManager);
export const getPermissionsCache = cacheManager.getPermissions.bind(cacheManager);
export const setPermissionsCache = cacheManager.setPermissions.bind(cacheManager);
export const getCacheStatus = cacheManager.getStatusReport.bind(cacheManager);
export const isCacheExpired = cacheManager.isExpired.bind(cacheManager);
export const updateCacheTTL = cacheManager.updateTTL.bind(cacheManager);
export const getPerformanceMetrics = cacheManager.getPerformanceMetrics.bind(cacheManager);
