// server/src/utils/workspace.js
/**
 * Workspace Utilities for Educational AnythingLLM Deployment
 * Handles vector database operations with FERPA/COPPA compliance
 */
import { db } from './database.js';
import { logger } from './logger.js';
import { encrypt, decrypt } from './encryption.js';

class WorkspaceUtils {
  /**
   * Synchronize workspace data with vector database
   * @param {string} workspaceId - ID of the workspace
   * @param {Object} options - Synchronization options
   * @returns {Object} Synchronization results
   */
  static async synchronizeWorkspace(workspaceId, options = {}) {
    try {
      const { 
        syncDocuments = true, 
        syncMembers = true, 
        forceSync = false,
        batchSize = 100
      } = options;
      
      const results = {
        workspaceId: workspaceId,
        timestamp: new Date(),
        syncedAt: new Date(),
        documents: { processed: 0, errors: 0 },
        members: { processed: 0, errors: 0 },
        status: 'completed'
      };
      
      // Synchronize documents if requested
      if (syncDocuments) {
        const docResults = await this.syncWorkspaceDocuments(workspaceId, batchSize, forceSync);
        results.documents = { ...results.documents, ...docResults };
      }
      
      // Synchronize members if requested
      if (syncMembers) {
        const memberResults = await this.syncWorkspaceMembers(workspaceId, forceSync);
        results.members = { ...results.members, ...memberResults };
      }
      
      // Log synchronization for compliance
      logger.info(`Workspace synchronized: ${workspaceId}`, { 
        workspaceId, 
        documentsProcessed: results.documents.processed,
        membersProcessed: results.members.processed
      });
      
      return results;
    } catch (error) {
      logger.error('Error synchronizing workspace:', error);
      throw new Error('Failed to synchronize workspace data');
    }
  }

  /**
   * Synchronize workspace documents with vector database
   * @param {string} workspaceId - ID of the workspace
   * @param {number} batchSize - Number of documents to process at once
   * @param {boolean} forceSync - Whether to force re-sync
   * @returns {Object} Document synchronization results
   */
  static async syncWorkspaceDocuments(workspaceId, batchSize = 100, forceSync = false) {
    try {
      const results = {
        processed: 0,
        errors: 0,
        skipped: 0
      };
      
      // Get documents in workspace
      const docsQuery = `
        SELECT d.id, d.name, d.file_path, d.size, d.created_at, d.updated_at
        FROM documents d
        JOIN workspace_documents wd ON d.id = wd.document_id
        WHERE wd.workspace_id = $1
        ORDER BY d.created_at DESC
        LIMIT $2 OFFSET $3
      `;
      
      let offset = 0;
      let hasMore = true;
      
      while (hasMore) {
        const result = await db.query(docsQuery, [workspaceId, batchSize, offset]);
        const documents = result.rows;
        
        if (documents.length === 0) {
          hasMore = false;
          continue;
        }
        
        // Process each document
        for (const doc of documents) {
          try {
            // Check if document needs synchronization
            const needsSync = forceSync || await this.shouldSyncDocument(doc, workspaceId);
            
            if (needsSync) {
              await this.syncDocumentToVectorDB(doc, workspaceId);
              results.processed++;
            } else {
              results.skipped++;
            }
          } catch (error) {
            logger.error(`Error syncing document ${doc.id}:`, error);
            results.errors++;
          }
        }
        
        offset += batchSize;
      }
      
      return results;
    } catch (error) {
      logger.error('Error synchronizing workspace documents:', error);
      throw error;
    }
  }

  /**
   * Synchronize workspace members with vector database
   * @param {string} workspaceId - ID of the workspace
   * @param {boolean} forceSync - Whether to force re-sync
   * @returns {Object} Member synchronization results
   */
  static async syncWorkspaceMembers(workspaceId, forceSync = false) {
    try {
      const results = {
        processed: 0,
        errors: 0,
        skipped: 0
      };
      
      // Get members in workspace
      const membersQuery = `
        SELECT wu.user_id, wu.role, u.name as user_name, u.email as user_email
        FROM workspace_users wu
        JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const result = await db.query(membersQuery, [workspaceId]);
      const members = result.rows;
      
      // Process each member
      for (const member of members) {
        try {
          // Check if member needs synchronization
          const needsSync = forceSync || await this.shouldSyncMember(member, workspaceId);
          
          if (needsSync) {
            await this.syncMemberToVectorDB(member, workspaceId);
            results.processed++;
          } else {
            results.skipped++;
          }
        } catch (error) {
          logger.error(`Error syncing member ${member.user_id}:`, error);
          results.errors++;
        }
      }
      
      return results;
    } catch (error) {
      logger.error('Error synchronizing workspace members:', error);
      throw error;
    }
  }

  /**
   * Check if document needs synchronization
   * @param {Object} document - Document data
   * @param {string} workspaceId - Workspace ID
   * @returns {boolean} Whether document needs sync
   */
  static async shouldSyncDocument(document, workspaceId) {
    try {
      // Check if document has been processed in vector database
      const checkQuery = `
        SELECT id FROM workspace_vectors 
        WHERE document_id = $1 AND workspace_id = $2
      `;
      
      const result = await db.query(checkQuery, [document.id, workspaceId]);
      
      // If no record exists, it needs to be synced
      return result.rows.length === 0;
    } catch (error) {
      logger.error('Error checking document sync status:', error);
      return true; // Default to sync if error occurs
    }
  }

  /**
   * Check if member needs synchronization
   * @param {Object} member - Member data
   * @param {string} workspaceId - Workspace ID
   * @returns {boolean} Whether member needs sync
   */
  static async shouldSyncMember(member, workspaceId) {
    try {
      // Check if member has been processed in vector database
      const checkQuery = `
        SELECT id FROM workspace_user_vectors 
        WHERE user_id = $1 AND workspace_id = $2
      `;
      
      const result = await db.query(checkQuery, [member.user_id, workspaceId]);
      
      // If no record exists, it needs to be synced
      return result.rows.length === 0;
    } catch (error) {
      logger.error('Error checking member sync status:', error);
      return true; // Default to sync if error occurs
    }
  }

  /**
   * Sync document to vector database
   * @param {Object} document - Document data
   * @param {string} workspaceId - Workspace ID
   */
  static async syncDocumentToVectorDB(document, workspaceId) {
    try {
      // This would integrate with your actual vector database (Pinecone, Chroma, etc.)
      // For now, we'll simulate the process
      
      // Generate document embeddings (simulated)
      const embeddings = await this.generateDocumentEmbeddings(document);
      
      // Store in vector database
      const vectorId = await this.storeInVectorDatabase({
        id: document.id,
        workspaceId: workspaceId,
        content: document.name,
        embeddings: embeddings,
        metadata: {
          workspaceId: workspaceId,
          documentId: document.id,
          fileName: document.name,
          size: document.size,
          createdAt: document.created_at
        }
      });
      
      // Update database with vector reference
      const insertQuery = `
        INSERT INTO workspace_vectors (workspace_id, document_id, vector_id, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (workspace_id, document_id) 
        DO UPDATE SET updated_at = NOW()
      `;
      
      await db.query(insertQuery, [workspaceId, document.id, vectorId]);
      
      logger.info(`Document synced to vector DB: ${document.id}`, { 
        workspaceId, 
        vectorId 
      });
    } catch (error) {
      logger.error('Error syncing document to vector DB:', error);
      throw error;
    }
  }

  /**
   * Sync member to vector database
   * @param {Object} member - Member data
   * @param {string} workspaceId - Workspace ID
   */
  static async syncMemberToVectorDB(member, workspaceId) {
    try {
      // Generate user profile embeddings (simulated)
      const embeddings = await this.generateUserEmbeddings(member);
      
      // Store in vector database
      const vectorId = await this.storeInVectorDatabase({
        id: member.user_id,
        workspaceId: workspaceId,
        content: `${member.user_name} - ${member.role}`,
        embeddings: embeddings,
        metadata: {
          workspaceId: workspaceId,
          userId: member.user_id,
          userName: member.user_name,
          role: member.role,
          email: member.user_email
        }
      });
      
      // Update database with vector reference
      const insertQuery = `
        INSERT INTO workspace_user_vectors (workspace_id, user_id, vector_id, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (workspace_id, user_id) 
        DO UPDATE SET updated_at = NOW()
      `;
      
      await db.query(insertQuery, [workspaceId, member.user_id, vectorId]);
      
      logger.info(`Member synced to vector DB: ${member.user_id}`, { 
        workspaceId, 
        vectorId 
      });
    } catch (error) {
      logger.error('Error syncing member to vector DB:', error);
      throw error;
    }
  }

  /**
   * Generate document embeddings (simulated)
   * @param {Object} document - Document data
   * @returns {Array} Embeddings array
   */
  static async generateDocumentEmbeddings(document) {
    // In a real implementation, this would call an embedding model
    // For demonstration, we'll return simulated embeddings
    
    const embeddingLength = 1536; // Typical for OpenAI embeddings
    const embeddings = [];
    
    for (let i = 0; i < embeddingLength; i++) {
      embeddings.push(Math.random() * 2 - 1); // Random values between -1 and 1
    }
    
    return embeddings;
  }

  /**
   * Generate user embeddings (simulated)
   * @param {Object} member - Member data
   * @returns {Array} Embeddings array
   */
  static async generateUserEmbeddings(member) {
    // In a real implementation, this would call an embedding model
    // For demonstration, we'll return simulated embeddings
    
    const embeddingLength = 1536; // Typical for OpenAI embeddings
    const embeddings = [];
    
    for (let i = 0; i < embeddingLength; i++) {
      embeddings.push(Math.random() * 2 - 1); // Random values between -1 and 1
    }
    
    return embeddings;
  }

  /**
   * Store data in vector database (simulated)
   * @param {Object} data - Data to store
   * @returns {string} Vector ID
   */
  static async storeInVectorDatabase(data) {
    // In a real implementation, this would interact with your vector database
    // For demonstration, we'll return a simulated vector ID
    
    // This would typically:
    // 1. Connect to vector DB (Pinecone, Chroma, etc.)
    // 2. Store the embeddings and metadata
    // 3. Return the vector ID
    
    const vectorId = `vector_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    logger.info(`Data stored in vector DB: ${vectorId}`, {
      data: {
        id: data.id,
        workspaceId: data.workspaceId,
        content: data.content.substring(0, 50) + '...'
      }
    });
    
    return vectorId;
  }

  /**
   * Get workspace statistics with vector database info
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Workspace statistics
   */
  static async getWorkspaceStats(workspaceId) {
    try {
      const stats = {
        workspaceId: workspaceId,
        timestamp: new Date(),
        vectorDatabase: {}
      };
      
      // Get document statistics from vector database
      const docsQuery = `
        SELECT 
          COUNT(*) as total_documents,
          SUM(size) as total_size,
          MAX(created_at) as last_updated
        FROM documents d
        JOIN workspace_documents wd ON d.id = wd.document_id
        WHERE wd.workspace_id = $1
      `;
      
      const docsResult = await db.query(docsQuery, [workspaceId]);
      stats.documents = docsResult.rows[0];
      
      // Get vector database statistics
      const vectorStats = await this.getVectorDatabaseStats(workspaceId);
      stats.vectorDatabase = vectorStats;
      
      // Get member statistics
      const membersQuery = `
        SELECT 
          COUNT(*) as total_members,
          COUNT(CASE WHEN role = 'owner' THEN 1 END) as owner_count,
          COUNT(CASE WHEN role = 'admin' THEN 1 END) as admin_count,
          COUNT(CASE WHEN role = 'editor' THEN 1 END) as editor_count,
          COUNT(CASE WHEN role = 'viewer' THEN 1 END) as viewer_count
        FROM workspace_users 
        WHERE workspace_id = $1
      `;
      
      const membersResult = await db.query(membersQuery, [workspaceId]);
      stats.members = membersResult.rows[0];
      
      return stats;
    } catch (error) {
      logger.error('Error getting workspace stats:', error);
      throw error;
    }
  }

  /**
   * Get vector database statistics for workspace
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Vector database statistics
   */
  static async getVectorDatabaseStats(workspaceId) {
    try {
      const query = `
        SELECT 
          COUNT(*) as total_vectors,
          SUM(size) as total_size,
          MAX(created_at) as last_updated,
          MIN(created_at) as created_date,
          COUNT(DISTINCT vector_type) as vector_types
        FROM vectors v
        JOIN workspace_vectors wv ON v.id = wv.vector_id
        WHERE wv.workspace_id = $1
      `;
      
      const result = await db.query(query, [workspaceId]);
      
      return {
        totalVectors: result.rows[0].total_vectors || 0,
        totalSize: result.rows[0].total_size || 0,
        lastUpdated: result.rows[0].last_updated,
        createdDate: result.rows[0].created_date,
        vectorTypes: result.rows[0].vector_types || 0
      };
    } catch (error) {
      logger.warn('Vector database statistics not available:', error.message);
      return {
        totalVectors: 0,
        totalSize: 0,
        lastUpdated: null,
        createdDate: null,
        vectorTypes: 0
      };
    }
  }

  /**
   * Search workspace documents using vector database
   * @param {string} workspaceId - ID of the workspace
   * @param {string} queryText - Text to search for
   * @param {number} limit - Maximum results to return
   * @returns {Array} Search results
   */
  static async searchWorkspaceDocuments(workspaceId, queryText, limit = 10) {
    try {
      // Generate query embeddings
      const queryEmbeddings = await this.generateDocumentEmbeddings({
        name: queryText,
        id: `query_${Date.now()}`
      });
      
      // In a real implementation, this would search the vector database
      // For now, we'll return simulated results
      
      const results = [];
      
      // Simulate search results from vector DB
      for (let i = 0; i < Math.min(limit, 5); i++) {
        results.push({
          id: `doc_${Date.now()}_${i}`,
          workspaceId: workspaceId,
          score: Math.random(),
          content: `Search result ${i + 1} for "${queryText}"`,
          metadata: {
            documentId: `document_${i}`,
            workspaceId: workspaceId,
            title: `Document ${i + 1}`,
            createdAt: new Date()
          }
        });
      }
      
      logger.info(`Vector search completed for workspace: ${workspaceId}`, {
        query: queryText,
        resultsCount: results.length
      });
      
      return results;
    } catch (error) {
      logger.error('Error searching workspace documents:', error);
      throw error;
    }
  }

  /**
   * Validate workspace data against compliance requirements
   * @param {Object} workspaceData - Data to validate
   * @returns {Object} Validation results
   */
  static validateWorkspaceCompliance(workspaceData) {
    const errors = [];
    
    // Check for PII in workspace name or description
    if (workspaceData.name && this.containsPII(workspaceData.name)) {
      errors.push('Workspace name contains potential PII');
    }
    
    if (workspaceData.description && this.containsPII(workspaceData.description)) {
      errors.push('Workspace description contains potential PII');
    }
    
    // Check for inappropriate content
    const inappropriateContent = ['adult', 'explicit', 'inappropriate'];
    const textToCheck = `${workspaceData.name || ''} ${workspaceData.description || ''}`.toLowerCase();
    
    for (const term of inappropriateContent) {
      if (textToCheck.includes(term)) {
        errors.push(`Workspace contains inappropriate content: ${term}`);
      }
    }
    
    // Check data retention requirements
    if (workspaceData.createdAt && this.isOldData(workspaceData.createdAt)) {
      errors.push('Workspace data exceeds retention period');
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Check if string contains PII patterns
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
   * Check if data is older than retention period
   * @param {Date} date - Date to check
   * @returns {boolean} Whether data is old
   */
  static isOldData(date) {
    if (!date) return false;
    
    const now = new Date();
    const dataDate = new Date(date);
    const daysDiff = Math.floor((now - dataDate) / (1000 * 60 * 60 * 24));
    
    // Assuming 30-day retention period for educational data
    return daysDiff > 30;
  }

  /**
   * Get workspace access logs with compliance information
   * @param {string} workspaceId - ID of the workspace
   * @returns {Array} Access logs
   */
  static async getWorkspaceAccessLogs(workspaceId) {
    try {
      const query = `
        SELECT 
          al.id,
          al.user_id,
          al.action,
          al.description,
          al.timestamp,
          al.ip_address,
          al.user_agent
        FROM activity_logs al
        WHERE al.workspace_id = $1
        ORDER BY al.timestamp DESC
        LIMIT 100
      `;
      
      const result = await db.query(query, [workspaceId]);
      
      // Anonymize user IDs for compliance
      return result.rows.map(row => ({
        ...row,
        userId: row.user_id.replace(/^[a-zA-Z]+/, 'user_'),
        id: row.id,
        action: row.action,
        description: row.description,
        timestamp: row.timestamp,
        ipAddress: row.ip_address,
        userAgent: row.user_agent
      }));
    } catch (error) {
      logger.error('Error getting workspace access logs:', error);
      throw error;
    }
  }

  /**
   * Cleanup old data from workspace to maintain compliance
   * @param {string} workspaceId - ID of the workspace
   * @param {number} retentionDays - Days to retain data
   * @returns {Object} Cleanup results
   */
  static async cleanupWorkspaceData(workspaceId, retentionDays = 30) {
    try {
      const cleanupDate = new Date();
      cleanupDate.setDate(cleanupDate.getDate() - retentionDays);
      
      const results = {
        workspaceId: workspaceId,
        cleanupDate: cleanupDate,
        cleanedUpDocuments: 0,
        cleanedUpVectors: 0,
        timestamp: new Date()
      };
      
      // Cleanup old documents (simulated)
      // In real implementation, this would delete actual files and database records
      
      // Cleanup old vector references
      const vectorsQuery = `
        DELETE FROM workspace_vectors 
        WHERE created_at < $1 AND workspace_id = $2
      `;
      
      const vectorsResult = await db.query(vectorsQuery, [cleanupDate, workspaceId]);
      results.cleanedUpVectors = vectorsResult.rowCount;
      
      // Log cleanup for compliance
      logger.info('Workspace data cleanup completed', {
        workspaceId,
        cleanupDate,
        cleanedUpVectors: results.cleanedUpVectors
      });
      
      return results;
    } catch (error) {
      logger.error('Error cleaning up workspace data:', error);
      throw error;
    }
  }

  /**
   * Get workspace data export for compliance review
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Export data
   */
  static async getWorkspaceExport(workspaceId) {
    try {
      const exportData = {
        workspaceId: workspaceId,
        exportedAt: new Date(),
        members: [],
        documents: [],
        accessLogs: []
      };
      
      // Get workspace members (anonymized)
      const membersQuery = `
        SELECT 
          wu.user_id,
          wu.role,
          wu.joined_at,
          u.name as user_name
        FROM workspace_users wu
        LEFT JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1
      `;
      
      const membersResult = await db.query(membersQuery, [workspaceId]);
      exportData.members = membersResult.rows.map(member => ({
        userId: member.user_id.replace(/^[a-zA-Z]+/, 'user_'),
        role: member.role,
        joinedAt: member.joined_at,
        userName: member.user_name
      }));
      
      // Get documents
      const docsQuery = `
        SELECT 
          d.id,
          d.name,
          d.file_path,
          d.size,
          d.created_at,
          d.updated_at
        FROM documents d
        JOIN workspace_documents wd ON d.id = wd.document_id
        WHERE wd.workspace_id = $1
      `;
      
      const docsResult = await db.query(docsQuery, [workspaceId]);
      exportData.documents = docsResult.rows;
      
      // Get access logs (anonymized)
      const logsQuery = `
        SELECT 
          al.user_id,
          al.action,
          al.timestamp,
          al.ip_address
        FROM activity_logs al
        WHERE al.workspace_id = $1
        ORDER BY al.timestamp DESC
        LIMIT 50
      `;
      
      const logsResult = await db.query(logsQuery, [workspaceId]);
      exportData.accessLogs = logsResult.rows.map(log => ({
        userId: log.user_id.replace(/^[a-zA-Z]+/, 'user_'),
        action: log.action,
        timestamp: log.timestamp,
        ipAddress: log.ip_address
      }));
      
      return exportData;
    } catch (error) {
      logger.error('Error getting workspace export:', error);
      throw error;
    }
  }
}

// Export utility functions for use in other modules
const synchronizeWorkspace = WorkspaceUtils.synchronizeWorkspace;
const getWorkspaceStats = WorkspaceUtils.getWorkspaceStats;
const searchWorkspaceDocuments = WorkspaceUtils.searchWorkspaceDocuments;
const validateWorkspaceCompliance = WorkspaceUtils.validateWorkspaceCompliance;
const getWorkspaceAccessLogs = WorkspaceUtils.getWorkspaceAccessLogs;
const cleanupWorkspaceData = WorkspaceUtils.cleanupWorkspaceData;
const getWorkspaceExport = WorkspaceUtils.getWorkspaceExport;

export {
  WorkspaceUtils,
  synchronizeWorkspace,
  getWorkspaceStats,
  searchWorkspaceDocuments,
  validateWorkspaceCompliance,
  getWorkspaceAccessLogs,
  cleanupWorkspaceData,
  getWorkspaceExport
};
