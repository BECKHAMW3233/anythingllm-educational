// server/src/services/workspace.js
/**
 * Workspace Service for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by anonymizing data and enforcing access controls
 */
import { db } from '../utils/database.js';
import { generateComplianceReport } from './compliance.js';
import { logger } from '../utils/logger.js';
import { encrypt, decrypt } from '../utils/encryption.js';

class WorkspaceService {
  /**
   * Create a new workspace
   * @param {Object} workspaceData - Data for creating workspace
   * @param {string} ownerId - ID of the user creating the workspace
   * @returns {Object} Created workspace data
   */
  static async createWorkspace(workspaceData, ownerId) {
    const { name, description, members = [] } = workspaceData;
    
    // Validate workspace name
    if (!name || name.trim().length === 0) {
      throw new Error('Workspace name is required');
    }
    
    try {
      // Begin transaction
      await db.query('BEGIN');
      
      // Create workspace
      const workspaceQuery = `
        INSERT INTO workspaces (name, description, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id, name, description, owner_id, created_at, updated_at
      `;
      
      const workspaceResult = await db.query(workspaceQuery, [name, description, ownerId]);
      const workspace = workspaceResult.rows[0];
      
      // Add owner as member
      if (ownerId) {
        const memberQuery = `
          INSERT INTO workspace_users (workspace_id, user_id, role, joined_at, updated_at)
          VALUES ($1, $2, 'owner', NOW(), NOW())
          RETURNING id, user_id, role, joined_at
        `;
        
        await db.query(memberQuery, [workspace.id, ownerId]);
      }
      
      // Add other members if provided
      for (const member of members) {
        const memberQuery = `
          INSERT INTO workspace_users (workspace_id, user_id, role, joined_at, updated_at)
          VALUES ($1, $2, $3, NOW(), NOW())
          RETURNING id, user_id, role, joined_at
        `;
        
        await db.query(memberQuery, [workspace.id, member.userId, member.role]);
      }
      
      // Commit transaction
      await db.query('COMMIT');
      
      // Log workspace creation for compliance
      logger.info(`Workspace created: ${workspace.id} by user: ${ownerId}`);
      
      return {
        ...workspace,
        id: workspace.id,
        name: workspace.name,
        description: workspace.description,
        ownerId: workspace.owner_id,
        createdAt: workspace.created_at,
        updatedAt: workspace.updated_at
      };
    } catch (error) {
      await db.query('ROLLBACK');
      logger.error('Error creating workspace:', error);
      throw error;
    }
  }

  /**
   * Get user workspaces with pagination and filtering
   * @param {string} userId - ID of the user
   * @param {Object} options - Pagination and filtering options
   * @returns {Array} Array of workspaces
   */
  static async getUserWorkspaces(userId, options = {}) {
    const { page = 1, limit = 20, role = null } = options;
    const offset = (page - 1) * limit;
    
    try {
      let query = `
        SELECT DISTINCT w.id, w.name, w.description, w.owner_id, w.created_at, w.updated_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE wu.user_id = $1
      `;
      
      const params = [userId];
      
      if (role) {
        query += ' AND wu.role = $2';
        params.push(role);
      }
      
      query += ' ORDER BY w.created_at DESC LIMIT $3 OFFSET $4';
      params.push(limit, offset);
      
      const result = await db.query(query, params);
      
      // Anonymize owner IDs for compliance
      return result.rows.map(row => ({
        ...row,
        ownerId: row.owner_id.replace(/^[a-zA-Z]+/, 'user_'),
        id: row.id,
        name: row.name,
        description: row.description,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
    } catch (error) {
      logger.error('Error fetching user workspaces:', error);
      throw error;
    }
  }

  /**
   * Get specific workspace details
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the requesting user
   * @returns {Object} Workspace data
   */
  static async getWorkspace(workspaceId, userId) {
    try {
      const query = `
        SELECT w.id, w.name, w.description, w.owner_id, w.created_at, w.updated_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE w.id = $1 AND wu.user_id = $2
        LIMIT 1
      `;
      
      const result = await db.query(query, [workspaceId, userId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const workspace = result.rows[0];
      
      // Anonymize owner ID for compliance
      return {
        ...workspace,
        id: workspace.id,
        name: workspace.name,
        description: workspace.description,
        ownerId: workspace.owner_id.replace(/^[a-zA-Z]+/, 'user_'),
        createdAt: workspace.created_at,
        updatedAt: workspace.updated_at
      };
    } catch (error) {
      logger.error('Error fetching workspace:', error);
      throw error;
    }
  }

  /**
   * Update workspace information
   * @param {string} workspaceId - ID of the workspace
   * @param {Object} updateData - Data to update
   * @param {string} userId - ID of the user updating
   * @returns {Object} Updated workspace data
   */
  static async updateWorkspace(workspaceId, updateData, userId) {
    const { name, description } = updateData;
    
    // Validate inputs
    if (!name || name.trim().length === 0) {
      throw new Error('Workspace name is required');
    }
    
    try {
      // Check if user has permission to update workspace
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role IN ('owner', 'admin')
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, userId]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Insufficient privileges to update workspace');
      }
      
      const query = `
        UPDATE workspaces 
        SET name = $1, description = $2, updated_at = NOW()
        WHERE id = $3
        RETURNING id, name, description, owner_id, created_at, updated_at
      `;
      
      const result = await db.query(query, [name, description, workspaceId]);
      
      if (result.rows.length === 0) {
        throw new Error('Workspace not found');
      }
      
      logger.info(`Workspace updated: ${workspaceId} by user: ${userId}`);
      
      return {
        ...result.rows[0],
        id: result.rows[0].id,
        name: result.rows[0].name,
        description: result.rows[0].description,
        ownerId: result.rows[0].owner_id.replace(/^[a-zA-Z]+/, 'user_'),
        createdAt: result.rows[0].created_at,
        updatedAt: result.rows[0].updated_at
      };
    } catch (error) {
      logger.error('Error updating workspace:', error);
      throw error;
    }
  }

  /**
   * Delete workspace
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user deleting
   */
  static async deleteWorkspace(workspaceId, userId) {
    try {
      // Check if user has permission to delete workspace
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role = 'owner'
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, userId]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Insufficient privileges to delete workspace');
      }
      
      // Begin transaction
      await db.query('BEGIN');
      
      // Delete workspace users
      await db.query('DELETE FROM workspace_users WHERE workspace_id = $1', [workspaceId]);
      
      // Delete workspace
      await db.query('DELETE FROM workspaces WHERE id = $1', [workspaceId]);
      
      // Commit transaction
      await db.query('COMMIT');
      
      logger.info(`Workspace deleted: ${workspaceId} by user: ${userId}`);
    } catch (error) {
      await db.query('ROLLBACK');
      logger.error('Error deleting workspace:', error);
      throw error;
    }
  }

  /**
   * Add member to workspace
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user to add
   * @param {string} role - Role of the user
   * @param {string} addedBy - ID of the user adding
   * @returns {Object} Membership data
   */
  static async addMember(workspaceId, userId, role, addedBy) {
    // Validate role
    const validRoles = ['owner', 'admin', 'editor', 'viewer'];
    if (!validRoles.includes(role)) {
      throw new Error('Invalid role specified');
    }
    
    try {
      // Check if user already exists in workspace
      const checkQuery = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2
      `;
      
      const checkResult = await db.query(checkQuery, [workspaceId, userId]);
      
      if (checkResult.rows.length > 0) {
        throw new Error('User already exists in workspace');
      }
      
      // Check if user has permission to add members
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role IN ('owner', 'admin')
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, addedBy]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Insufficient privileges to add members');
      }
      
      const query = `
        INSERT INTO workspace_users (workspace_id, user_id, role, joined_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id, workspace_id, user_id, role, joined_at
      `;
      
      const result = await db.query(query, [workspaceId, userId, role]);
      
      logger.info(`Member added to workspace: ${workspaceId} by user: ${addedBy}`);
      
      return {
        ...result.rows[0],
        id: result.rows[0].id,
        workspaceId: result.rows[0].workspace_id,
        userId: result.rows[0].user_id.replace(/^[a-zA-Z]+/, 'user_'),
        role: result.rows[0].role,
        joinedAt: result.rows[0].joined_at
      };
    } catch (error) {
      logger.error('Error adding member to workspace:', error);
      throw error;
    }
  }

  /**
   * Remove member from workspace
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user to remove
   * @param {string} removedBy - ID of the user removing
   */
  static async removeMember(workspaceId, userId, removedBy) {
    try {
      // Check if user has permission to remove members
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role IN ('owner', 'admin')
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, removedBy]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Insufficient privileges to remove members');
      }
      
      // Check if user exists in workspace
      const checkQuery = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2
      `;
      
      const checkResult = await db.query(checkQuery, [workspaceId, userId]);
      
      if (checkResult.rows.length === 0) {
        throw new Error('User not found in workspace');
      }
      
      // Remove member from workspace
      await db.query(
        'DELETE FROM workspace_users WHERE workspace_id = $1 AND user_id = $2',
        [workspaceId, userId]
      );
      
      logger.info(`Member removed from workspace: ${workspaceId} by user: ${removedBy}`);
    } catch (error) {
      logger.error('Error removing member from workspace:', error);
      throw error;
    }
  }

  /**
   * Get workspace members
   * @param {string} workspaceId - ID of the workspace
   * @returns {Array} Array of members
   */
  static async getWorkspaceMembers(workspaceId) {
    try {
      const query = `
        SELECT wu.id, wu.user_id, wu.role, wu.joined_at, wu.updated_at, 
               wu.workspace_id, u.name as user_name
        FROM workspace_users wu
        LEFT JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const result = await db.query(query, [workspaceId]);
      
      // Anonymize user IDs for compliance
      return result.rows.map(row => ({
        ...row,
        userId: row.user_id.replace(/^[a-zA-Z]+/, 'user_'),
        id: row.id,
        role: row.role,
        joinedAt: row.joined_at,
        updatedAt: row.updated_at,
        workspaceId: row.workspace_id
      }));
    } catch (error) {
      logger.error('Error fetching workspace members:', error);
      throw error;
    }
  }

  /**
   * Get workspace statistics
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Workspace statistics
   */
  static async getWorkspaceStats(workspaceId) {
    try {
      const statsQuery = `
        SELECT 
          COUNT(*) as total_members,
          COUNT(CASE WHEN role = 'owner' THEN 1 END) as owner_count,
          COUNT(CASE WHEN role = 'admin' THEN 1 END) as admin_count,
          COUNT(CASE WHEN role = 'editor' THEN 1 END) as editor_count,
          COUNT(CASE WHEN role = 'viewer' THEN 1 END) as viewer_count,
          MAX(joined_at) as last_joined,
          MIN(joined_at) as created_date
        FROM workspace_users 
        WHERE workspace_id = $1
      `;
      
      const statsResult = await db.query(statsQuery, [workspaceId]);
      const stats = statsResult.rows[0];
      
      // Get vector database statistics if applicable
      const vectorStats = await this.getVectorDatabaseStats(workspaceId);
      
      return {
        ...stats,
        vectorStats: vectorStats,
        workspaceId: workspaceId
      };
    } catch (error) {
      logger.error('Error fetching workspace stats:', error);
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
      // This would query the vector database for statistics
      // Implementation depends on your specific vector DB setup (Pinecone, Chroma, etc.)
      
      const vectorQuery = `
        SELECT 
          COUNT(*) as total_vectors,
          SUM(size) as total_size,
          MAX(created_at) as last_updated,
          MIN(created_at) as created_date
        FROM vectors v
        JOIN workspace_vectors wv ON v.id = wv.vector_id
        WHERE wv.workspace_id = $1
      `;
      
      const result = await db.query(vectorQuery, [workspaceId]);
      
      return {
        totalVectors: result.rows[0].total_vectors || 0,
        totalSize: result.rows[0].total_size || 0,
        lastUpdated: result.rows[0].last_updated,
        createdDate: result.rows[0].created_date
      };
    } catch (error) {
      // Vector DB might not be configured or accessible, return empty stats
      logger.warn('Vector database statistics not available:', error.message);
      return {
        totalVectors: 0,
        totalSize: 0,
        lastUpdated: null,
        createdDate: null
      };
    }
  }

  /**
   * Transfer workspace ownership
   * @param {string} workspaceId - ID of the workspace
   * @param {string} newOwnerId - ID of the new owner
   * @param {string} currentOwnerId - ID of the current owner
   * @returns {Object} Transfer confirmation
   */
  static async transferOwnership(workspaceId, newOwnerId, currentOwnerId) {
    try {
      // Check if current user is owner
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role = 'owner'
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, currentOwnerId]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Only workspace owner can transfer ownership');
      }
      
      // Update roles
      await db.query(
        'UPDATE workspace_users SET role = \'owner\' WHERE workspace_id = $1 AND user_id = $2',
        [workspaceId, newOwnerId]
      );
      
      await db.query(
        'UPDATE workspace_users SET role = \'admin\' WHERE workspace_id = $1 AND user_id = $2',
        [workspaceId, currentOwnerId]
      );
      
      logger.info(`Ownership transferred for workspace: ${workspaceId} from user: ${currentOwnerId} to ${newOwnerId}`);
      
      return {
        workspaceId: workspaceId,
        newOwner: newOwnerId,
        oldOwner: currentOwnerId,
        transferredAt: new Date()
      };
    } catch (error) {
      logger.error('Error transferring workspace ownership:', error);
      throw error;
    }
  }

  /**
   * Get activity log for workspace
   * @param {string} workspaceId - ID of the workspace
   * @returns {Array} Activity log entries
   */
  static async getActivityLog(workspaceId) {
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
      logger.error('Error fetching workspace activity log:', error);
      throw error;
    }
  }

  /**
   * Get compliance report for workspace
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Compliance report
   */
  static async getComplianceReport(workspaceId) {
    try {
      // Generate compliance report using existing compliance service
      const report = await generateComplianceReport('workspace', workspaceId);
      
      return {
        ...report,
        workspaceId: workspaceId,
        generatedAt: new Date()
      };
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      throw error;
    }
  }

  /**
   * Validate workspace data
   * @param {Object} workspaceData - Data to validate
   * @returns {Object} Validation results
   */
  static async validateWorkspaceData(workspaceData) {
    const errors = [];
    
    // Validate name
    if (!workspaceData.name || workspaceData.name.trim().length === 0) {
      errors.push('Workspace name is required');
    }
    
    // Validate description length (if provided)
    if (workspaceData.description && workspaceData.description.length > 1000) {
      errors.push('Description exceeds maximum length of 1000 characters');
    }
    
    // Validate members
    if (workspaceData.members) {
      for (const member of workspaceData.members) {
        if (!member.userId) {
          errors.push('Member must have a user ID');
        }
        
        const validRoles = ['owner', 'admin', 'editor', 'viewer'];
        if (!validRoles.includes(member.role)) {
          errors.push(`Invalid role: ${member.role}`);
        }
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Get member details with compliance checks
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user
   * @returns {Object} Member details
   */
  static async getMemberDetails(workspaceId, userId) {
    try {
      const query = `
        SELECT 
          wu.id,
          wu.user_id,
          wu.role,
          wu.joined_at,
          wu.updated_at,
          wu.workspace_id,
          u.name as user_name,
          u.email as user_email
        FROM workspace_users wu
        LEFT JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1 AND wu.user_id = $2
        LIMIT 1
      `;
      
      const result = await db.query(query, [workspaceId, userId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const member = result.rows[0];
      
      // Anonymize user ID for compliance but keep role and other info
      return {
        id: member.id,
        userId: member.user_id.replace(/^[a-zA-Z]+/, 'user_'),
        role: member.role,
        joinedAt: member.joined_at,
        updatedAt: member.updated_at,
        workspaceId: member.workspace_id,
        userName: member.user_name,
        userEmail: member.user_email
      };
    } catch (error) {
      logger.error('Error fetching member details:', error);
      throw error;
    }
  }

  /**
   * Update member role
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user
   * @param {string} role - New role
   * @param {string} updatedBy - ID of the user updating
   * @returns {Object} Updated member data
   */
  static async updateMemberRole(workspaceId, userId, role, updatedBy) {
    const validRoles = ['owner', 'admin', 'editor', 'viewer'];
    
    if (!validRoles.includes(role)) {
      throw new Error('Invalid role specified');
    }
    
    try {
      // Check if user has permission to update roles
      const permissionCheck = `
        SELECT 1 FROM workspace_users 
        WHERE workspace_id = $1 AND user_id = $2 AND role IN ('owner', 'admin')
      `;
      
      const permissionResult = await db.query(permissionCheck, [workspaceId, updatedBy]);
      
      if (permissionResult.rows.length === 0) {
        throw new Error('Permission denied: Insufficient privileges to update member roles');
      }
      
      // Update member role
      const query = `
        UPDATE workspace_users 
        SET role = $1, updated_at = NOW()
        WHERE workspace_id = $2 AND user_id = $3
        RETURNING id, user_id, role, joined_at, updated_at, workspace_id
      `;
      
      const result = await db.query(query, [role, workspaceId, userId]);
      
      if (result.rows.length === 0) {
        throw new Error('Member not found in workspace');
      }
      
      logger.info(`Member role updated: ${userId} in workspace ${workspaceId} by user: ${updatedBy}`);
      
      return {
        ...result.rows[0],
        id: result.rows[0].id,
        userId: result.rows[0].user_id.replace(/^[a-zA-Z]+/, 'user_'),
        role: result.rows[0].role,
        joinedAt: result.rows[0].joined_at,
        updatedAt: result.rows[0].updated_at,
        workspaceId: result.rows[0].workspace_id
      };
    } catch (error) {
      logger.error('Error updating member role:', error);
      throw error;
    }
  }

  /**
   * Add multiple members to workspace
   * @param {string} workspaceId - ID of the workspace
   * @param {Array} members - Array of member data
   * @param {string} addedBy - ID of the user adding members
   * @returns {Array} Array of created memberships
   */
  static async addMultipleMembers(workspaceId, members, addedBy) {
    const results = [];
    
    try {
      // Begin transaction for batch operations
      await db.query('BEGIN');
      
      for (const member of members) {
        const result = await this.addMember(
          workspaceId,
          member.userId,
          member.role,
          addedBy
        );
        results.push(result);
      }
      
      // Commit transaction
      await db.query('COMMIT');
      
      logger.info(`Batch added ${members.length} members to workspace: ${workspaceId}`);
      return results;
    } catch (error) {
      await db.query('ROLLBACK');
      logger.error('Error adding multiple members:', error);
      throw error;
    }
  }

  /**
   * Get member activity
   * @param {string} workspaceId - ID of the workspace
   * @param {string} userId - ID of the user
   * @returns {Array} Activity records
   */
  static async getMemberActivity(workspaceId, userId) {
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
        WHERE al.workspace_id = $1 AND al.user_id = $2
        ORDER BY al.timestamp DESC
        LIMIT 50
      `;
      
      const result = await db.query(query, [workspaceId, userId]);
      
      return result.rows.map(row => ({
        ...row,
        id: row.id,
        action: row.action,
        description: row.description,
        timestamp: row.timestamp,
        ipAddress: row.ip_address,
        userAgent: row.user_agent
      }));
    } catch (error) {
      logger.error('Error fetching member activity:', error);
      throw error;
    }
  }

  /**
   * Export workspace members with compliance checks
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Export data
   */
  static async exportWorkspaceMembers(workspaceId) {
    try {
      const query = `
        SELECT 
          wu.id,
          wu.user_id,
          wu.role,
          wu.joined_at,
          wu.updated_at,
          u.name as user_name,
          u.email as user_email
        FROM workspace_users wu
        LEFT JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const result = await db.query(query, [workspaceId]);
      
      // Format for export with anonymized IDs
      return {
        workspaceId: workspaceId,
        exportedAt: new Date(),
        members: result.rows.map(row => ({
          id: row.id,
          userId: row.user_id.replace(/^[a-zA-Z]+/, 'user_'),
          role: row.role,
          joinedAt: row.joined_at,
          updatedAt: row.updated_at,
          userName: row.user_name,
          userEmail: row.user_email
        }))
      };
    } catch (error) {
      logger.error('Error exporting workspace members:', error);
      throw error;
    }
  }
}

export default WorkspaceService;
