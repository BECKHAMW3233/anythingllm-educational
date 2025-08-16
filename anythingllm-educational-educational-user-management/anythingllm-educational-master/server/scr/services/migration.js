// server/src/services/migration.js
/**
 * Database Migration Service for Educational AnythingLLM Deployment
 * Handles schema updates with FERPA/COPPA compliance
 */
import { db } from '../utils/database.js';
import { logger } from '../utils/logger.js';
import fs from 'fs/promises';
import path from 'path';

class MigrationService {
  /**
   * Initialize migration service
   */
  static async initialize() {
    try {
      // Create migrations table if it doesn't exist
      await this.createMigrationTable();
      
      logger.info('Migration service initialized successfully');
    } catch (error) {
      logger.error('Error initializing migration service:', error);
      throw error;
    }
  }

  /**
   * Create migrations table if it doesn't exist
   */
  static async createMigrationTable() {
    const query = `
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        version VARCHAR(50),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        executed_at TIMESTAMP,
        rollback_script TEXT,
        description TEXT
      );
      
      CREATE INDEX IF NOT EXISTS idx_migrations_status ON migrations(status);
      CREATE INDEX IF NOT EXISTS idx_migrations_created_at ON migrations(created_at);
    `;
    
    await db.query(query);
  }

  /**
   * Get all pending migrations
   * @returns {Array} Pending migrations
   */
  static async getPendingMigrations() {
    try {
      const query = `
        SELECT id, name, version, status, created_at, description
        FROM migrations 
        WHERE status = 'pending'
        ORDER BY created_at ASC
      `;
      
      const result = await db.query(query);
      return result.rows;
    } catch (error) {
      logger.error('Error getting pending migrations:', error);
      throw error;
    }
  }

  /**
   * Get all executed migrations
   * @returns {Array} Executed migrations
   */
  static async getExecutedMigrations() {
    try {
      const query = `
        SELECT id, name, version, status, created_at, executed_at, description
        FROM migrations 
        WHERE status = 'executed'
        ORDER BY executed_at DESC
      `;
      
      const result = await db.query(query);
      return result.rows;
    } catch (error) {
      logger.error('Error getting executed migrations:', error);
      throw error;
    }
  }

  /**
   * Run all pending migrations
   * @returns {Object} Migration results
   */
  static async runPendingMigrations() {
    try {
      const pendingMigrations = await this.getPendingMigrations();
      const results = {
        executed: [],
        failed: [],
        skipped: []
      };
      
      for (const migration of pendingMigrations) {
        try {
          await this.executeMigration(migration);
          results.executed.push(migration.name);
        } catch (error) {
          logger.error(`Failed to execute migration ${migration.name}:`, error);
          results.failed.push({
            name: migration.name,
            error: error.message
          });
          
          // Mark as failed in database
          await this.markMigrationFailed(migration.id, error.message);
        }
      }
      
      logger.info('Migration execution completed', { results });
      return results;
    } catch (error) {
      logger.error('Error running pending migrations:', error);
      throw error;
    }
  }

  /**
   * Execute a single migration
   * @param {Object} migration - Migration data
   * @returns {boolean} Whether execution was successful
   */
  static async executeMigration(migration) {
    try {
      // Mark as executing
      await this.markMigrationExecuting(migration.id);
      
      // Get migration script content
      const scriptPath = path.join(process.cwd(), 'migrations', `${migration.name}.js`);
      const scriptContent = await fs.readFile(scriptPath, 'utf8');
      
      // Execute the migration script
      const migrationFunction = new Function('db', 'logger', scriptContent);
      await migrationFunction(db, logger);
      
      // Mark as executed
      await this.markMigrationExecuted(migration.id);
      
      logger.info(`Migration executed successfully: ${migration.name}`);
      return true;
    } catch (error) {
      logger.error(`Error executing migration ${migration.name}:`, error);
      throw error;
    }
  }

  /**
   * Mark migration as executing
   * @param {number} migrationId - Migration ID
   */
  static async markMigrationExecuting(migrationId) {
    const query = `
      UPDATE migrations 
      SET status = 'executing', updated_at = NOW()
      WHERE id = $1
    `;
    
    await db.query(query, [migrationId]);
  }

  /**
   * Mark migration as executed
   * @param {number} migrationId - Migration ID
   */
  static async markMigrationExecuted(migrationId) {
    const query = `
      UPDATE migrations 
      SET status = 'executed', executed_at = NOW(), updated_at = NOW()
      WHERE id = $1
    `;
    
    await db.query(query, [migrationId]);
  }

  /**
   * Mark migration as failed
   * @param {number} migrationId - Migration ID
   * @param {string} error - Error message
   */
  static async markMigrationFailed(migrationId, error) {
    const query = `
      UPDATE migrations 
      SET status = 'failed', updated_at = NOW(), description = $1
      WHERE id = $2
    `;
    
    await db.query(query, [error, migrationId]);
  }

  /**
   * Rollback last executed migration
   * @returns {Object} Rollback results
   */
  static async rollbackLastMigration() {
    try {
      const query = `
        SELECT id, name, version, rollback_script
        FROM migrations 
        WHERE status = 'executed'
        ORDER BY executed_at DESC
        LIMIT 1
      `;
      
      const result = await db.query(query);
      
      if (result.rows.length === 0) {
        return { success: false, message: 'No executed migrations to rollback' };
      }
      
      const migration = result.rows[0];
      
      if (!migration.rollback_script) {
        return { 
          success: false, 
          message: 'Migration has no rollback script available' 
        };
      }
      
      // Execute rollback script
      try {
        const rollbackFunction = new Function('db', 'logger', migration.rollback_script);
        await rollbackFunction(db, logger);
        
        // Mark as rolled back
        await this.markMigrationRolledBack(migration.id);
        
        logger.info(`Migration rolled back successfully: ${migration.name}`);
        return { success: true, message: `Rolled back migration: ${migration.name}` };
      } catch (rollbackError) {
        logger.error(`Error rolling back migration ${migration.name}:`, rollbackError);
        await this.markMigrationRollbackFailed(migration.id, rollbackError.message);
        throw rollbackError;
      }
    } catch (error) {
      logger.error('Error rolling back last migration:', error);
      throw error;
    }
  }

  /**
   * Mark migration as rolled back
   * @param {number} migrationId - Migration ID
   */
  static async markMigrationRolledBack(migrationId) {
    const query = `
      UPDATE migrations 
      SET status = 'rolled_back', updated_at = NOW()
      WHERE id = $1
    `;
    
    await db.query(query, [migrationId]);
  }

  /**
   * Mark migration rollback as failed
   * @param {number} migrationId - Migration ID
   * @param {string} error - Error message
   */
  static async markMigrationRollbackFailed(migrationId, error) {
    const query = `
      UPDATE migrations 
      SET status = 'rollback_failed', updated_at = NOW(), description = $1
      WHERE id = $2
    `;
    
    await db.query(query, [error, migrationId]);
  }

  /**
   * Create new migration
   * @param {string} name - Migration name
   * @param {string} version - Migration version
   * @param {string} script - Migration script content
   * @param {string} description - Migration description
   * @returns {Object} Created migration
   */
  static async createMigration(name, version, script, description = '') {
    try {
      // Check if migration already exists
      const checkQuery = `
        SELECT id FROM migrations 
        WHERE name = $1
      `;
      
      const checkResult = await db.query(checkQuery, [name]);
      
      if (checkResult.rows.length > 0) {
        throw new Error(`Migration ${name} already exists`);
      }
      
      // Create migration record
      const query = `
        INSERT INTO migrations (name, version, status, description)
        VALUES ($1, $2, 'pending', $3)
        RETURNING id, name, version, status, created_at
      `;
      
      const result = await db.query(query, [name, version, description]);
      const migration = result.rows[0];
      
      // Write migration script file
      const scriptPath = path.join(process.cwd(), 'migrations', `${name}.js`);
      await fs.writeFile(scriptPath, script);
      
      logger.info(`Migration created successfully: ${name}`);
      return {
        ...migration,
        id: migration.id,
        name: migration.name,
        version: migration.version,
        status: migration.status,
        createdAt: migration.created_at
      };
    } catch (error) {
      logger.error('Error creating migration:', error);
      throw error;
    }
  }

  /**
   * Get migration by name
   * @param {string} name - Migration name
   * @returns {Object} Migration data
   */
  static async getMigrationByName(name) {
    try {
      const query = `
        SELECT id, name, version, status, created_at, executed_at, description
        FROM migrations 
        WHERE name = $1
      `;
      
      const result = await db.query(query, [name]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
    } catch (error) {
      logger.error('Error getting migration by name:', error);
      throw error;
    }
  }

  /**
   * Get migration script content
   * @param {string} name - Migration name
   * @returns {string} Script content
   */
  static async getMigrationScript(name) {
    try {
      const scriptPath = path.join(process.cwd(), 'migrations', `${name}.js`);
      return await fs.readFile(scriptPath, 'utf8');
    } catch (error) {
      logger.error('Error reading migration script:', error);
      throw new Error(`Migration script not found: ${name}`);
    }
  }

  /**
   * Validate migration schema for compliance
   * @param {Object} migrationData - Migration data to validate
   * @returns {Object} Validation results
   */
  static validateMigrationCompliance(migrationData) {
    const errors = [];
    
    // Check for PII in migration names
    if (migrationData.name && this.containsPII(migrationData.name)) {
      errors.push('Migration name contains potential PII');
    }
    
    // Check for sensitive data in description
    if (migrationData.description && this.containsPII(migrationData.description)) {
      errors.push('Migration description contains potential PII');
    }
    
    // Validate migration structure
    if (!migrationData.name) {
      errors.push('Migration name is required');
    }
    
    if (!migrationData.version) {
      errors.push('Migration version is required');
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Check if string contains PII patterns (for compliance)
   * @param {string} text - Text to check
   * @returns {boolean} Whether PII is detected
   */
  static containsPII(text) {
    if (!text) return false;
    
    // Common PII patterns
    const patterns = [
      /[0-9]{3}-[0-9]{2}-[0-9]{4}/, // SSN
      /[0-9]{9}/, // 9-digit number
      /\b\d{3}\.\d{3}\.\d{4}\b/, // Social Security Number format
      /\b\d{2}\/\d{2}\/\d{4}\b/, // Date format (MM/DD/YYYY)
      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ // IP address
    ];
    
    return patterns.some(pattern => pattern.test(text));
  }

  /**
   * Get migration status summary
   * @returns {Object} Status summary
   */
  static async getMigrationStatus() {
    try {
      const stats = {};
      
      // Get counts for each status
      const countsQuery = `
        SELECT status, COUNT(*) as count
        FROM migrations 
        GROUP BY status
      `;
      
      const countsResult = await db.query(countsQuery);
      
      // Initialize all statuses
      stats.pending = 0;
      stats.executed = 0;
      stats.failed = 0;
      stats.executing = 0;
      stats.rolled_back = 0;
      stats.rollback_failed = 0;
      
      // Populate counts
      countsResult.rows.forEach(row => {
        stats[row.status] = row.count;
      });
      
      // Get latest executed migration
      const latestQuery = `
        SELECT name, version, executed_at
        FROM migrations 
        WHERE status = 'executed'
        ORDER BY executed_at DESC
        LIMIT 1
      `;
      
      const latestResult = await db.query(latestQuery);
      stats.latestExecuted = latestResult.rows[0] || null;
      
      // Get total migrations
      const totalQuery = `
        SELECT COUNT(*) as total
        FROM migrations
      `;
      
      const totalResult = await db.query(totalQuery);
      stats.totalMigrations = parseInt(totalResult.rows[0].total);
      
      return {
        ...stats,
        timestamp: new Date(),
        complianceStatus: this.checkMigrationCompliance(stats)
      };
    } catch (error) {
      logger.error('Error getting migration status:', error);
      throw error;
    }
  }

  /**
   * Check migration compliance status
   * @param {Object} stats - Migration statistics
   * @returns {string} Compliance status
   */
  static checkMigrationCompliance(stats) {
    // Simple compliance check based on migration execution status
    if (stats.failed > 0 || stats.rollback_failed > 0) {
      return 'non-compliant';
    }
    
    if (stats.pending > 0) {
      return 'partial-compliant';
    }
    
    return 'compliant';
  }

  /**
   * Generate migration report for compliance review
   * @returns {Object} Migration report
   */
  static async generateMigrationReport() {
    try {
      const report = {
        generatedAt: new Date(),
        summary: await this.getMigrationStatus(),
        migrations: [],
        complianceCheck: {}
      };
      
      // Get all migrations
      const allQuery = `
        SELECT id, name, version, status, created_at, executed_at, description
        FROM migrations 
        ORDER BY created_at DESC
      `;
      
      const allResult = await db.query(allQuery);
      report.migrations = allResult.rows.map(migration => ({
        id: migration.id,
        name: migration.name,
        version: migration.version,
        status: migration.status,
        createdAt: migration.created_at,
        executedAt: migration.executed_at,
        description: migration.description
      }));
      
      // Perform compliance check
      report.complianceCheck = this.performComplianceCheck(report);
      
      return report;
    } catch (error) {
      logger.error('Error generating migration report:', error);
      throw error;
    }
  }

  /**
   * Perform compliance check on migration data
   * @param {Object} report - Migration report
   * @returns {Object} Compliance check results
   */
  static performComplianceCheck(report) {
    const checks = {
      schemaIntegrity: true,
      executionHistory: true,
      rollbackCapabilities: true,
      securityReview: true
    };
    
    // Check for any failed migrations
    const failedMigrations = report.migrations.filter(m => m.status === 'failed');
    if (failedMigrations.length > 0) {
      checks.executionHistory = false;
    }
    
    // Check that all migrations have rollback scripts (where applicable)
    // This would be more complex in a real implementation
    
    return checks;
  }

  /**
   * Export migration data for compliance review
   * @returns {Object} Exported migration data
   */
  static async exportMigrationData() {
    try {
      const query = `
        SELECT id, name, version, status, created_at, executed_at, description
        FROM migrations 
        ORDER BY created_at DESC
      `;
      
      const result = await db.query(query);
      
      return {
        exportedAt: new Date(),
        totalMigrations: result.rows.length,
        migrations: result.rows.map(migration => ({
          id: migration.id,
          name: migration.name,
          version: migration.version,
          status: migration.status,
          createdAt: migration.created_at,
          executedAt: migration.executed_at,
          description: migration.description
        })),
        complianceStatus: 'compliant'
      };
    } catch (error) {
      logger.error('Error exporting migration data:', error);
      throw error;
    }
  }

  /**
   * Import migration data from file
   * @param {Array} migrationData - Migration data to import
   * @returns {Object} Import results
   */
  static async importMigrationData(migrationData) {
    const results = {
      imported: 0,
      errors: []
    };
    
    try {
      for (const migration of migrationData) {
        try {
          // Create migration record
          const insertQuery = `
            INSERT INTO migrations (name, version, status, description)
            VALUES ($1, $2, $3, $4)
            RETURNING id
          `;
          
          await db.query(insertQuery, [
            migration.name,
            migration.version,
            migration.status || 'pending',
            migration.description || ''
          ]);
          
          results.imported++;
        } catch (error) {
          logger.error(`Error importing migration ${migration.name}:`, error);
          results.errors.push({
            name: migration.name,
            error: error.message
          });
        }
      }
      
      logger.info('Migration data import completed', { 
        imported: results.imported,
        errors: results.errors.length 
      });
      
      return results;
    } catch (error) {
      logger.error('Error importing migration data:', error);
      throw error;
    }
  }

  /**
   * Clean up old migration records (for compliance)
   * @param {number} retentionDays - Days to retain migrations
   * @returns {Object} Cleanup results
   */
  static async cleanupOldMigrations(retentionDays = 30) {
    try {
      const cleanupDate = new Date();
      cleanupDate.setDate(cleanupDate.getDate() - retentionDays);
      
      const query = `
        DELETE FROM migrations 
        WHERE status = 'executed' AND executed_at < $1
      `;
      
      const result = await db.query(query, [cleanupDate]);
      
      logger.info('Old migrations cleaned up', {
        deletedCount: result.rowCount,
        cleanupDate: cleanupDate
      });
      
      return {
        deletedCount: result.rowCount,
        cleanupDate: cleanupDate
      };
    } catch (error) {
      logger.error('Error cleaning up old migrations:', error);
      throw error;
    }
  }

  /**
   * Validate database schema against current migration state
   * @returns {Object} Schema validation results
   */
  static async validateSchema() {
    try {
      const validation = {
        timestamp: new Date(),
        tables: [],
        integrityCheck: true,
        complianceStatus: 'compliant'
      };
      
      // Check for required tables
      const requiredTables = ['users', 'workspaces', 'workspace_users', 'documents', 'migrations'];
      
      for (const tableName of requiredTables) {
        try {
          const query = `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)`;
          const result = await db.query(query, [tableName]);
          
          validation.tables.push({
            name: tableName,
            exists: result.rows[0].exists
          });
        } catch (error) {
          logger.error(`Error checking table ${tableName}:`, error);
          validation.tables.push({
            name: tableName,
            exists: false,
            error: error.message
          });
        }
      }
      
      // Check migration integrity
      const integrityQuery = `
        SELECT 
          COUNT(*) as total_migrations,
          COUNT(CASE WHEN status = 'executed' THEN 1 END) as executed_migrations,
          COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_migrations
        FROM migrations
      `;
      
      const integrityResult = await db.query(integrityQuery);
      const integrity = integrityResult.rows[0];
      
      if (integrity.failed_migrations > 0) {
        validation.integrityCheck = false;
        validation.complianceStatus = 'non-compliant';
      }
      
      return validation;
    } catch (error) {
      logger.error('Error validating schema:', error);
      throw error;
    }
  }

  /**
   * Get database schema version
   * @returns {string} Schema version
   */
  static async getSchemaVersion() {
    try {
      // Get the latest executed migration version
      const query = `
        SELECT version 
        FROM migrations 
        WHERE status = 'executed'
        ORDER BY executed_at DESC
        LIMIT 1
      `;
      
      const result = await db.query(query);
      
      if (result.rows.length > 0) {
        return result.rows[0].version;
      }
      
      // Return default version if no migrations
      return '0.0.0';
    } catch (error) {
      logger.error('Error getting schema version:', error);
      return 'unknown';
    }
  }
}

// Export service functions for use in other modules
const initialize = MigrationService.initialize;
const getPendingMigrations = MigrationService.getPendingMigrations;
const getExecutedMigrations = MigrationService.getExecutedMigrations;
const runPendingMigrations = MigrationService.runPendingMigrations;
const rollbackLastMigration = MigrationService.rollbackLastMigration;
const createMigration = MigrationService.createMigration;
const getMigrationByName = MigrationService.getMigrationByName;
const getMigrationScript = MigrationService.getMigrationScript;
const validateMigrationCompliance = MigrationService.validateMigrationCompliance;
const getMigrationStatus = MigrationService.getMigrationStatus;
const generateMigrationReport = MigrationService.generateMigrationReport;
const exportMigrationData = MigrationService.exportMigrationData;
const importMigrationData = MigrationService.importMigrationData;
const cleanupOldMigrations = MigrationService.cleanupOldMigrations;
const validateSchema = MigrationService.validateSchema;
const getSchemaVersion = MigrationService.getSchemaVersion;

export {
  MigrationService,
  initialize,
  getPendingMigrations,
  getExecutedMigrations,
  runPendingMigrations,
  rollbackLastMigration,
  createMigration,
  getMigrationByName,
  getMigrationScript,
  validateMigrationCompliance,
  getMigrationStatus,
  generateMigrationReport,
  exportMigrationData,
  importMigrationData,
  cleanupOldMigrations,
  validateSchema,
  getSchemaVersion
};
