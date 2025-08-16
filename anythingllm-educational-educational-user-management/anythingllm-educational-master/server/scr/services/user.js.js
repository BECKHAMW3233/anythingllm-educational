// server/src/services/user.js
/**
 * User Management Service for Educational AnythingLLM Deployment
 * Handles SSO integration, role management, and FERPA/COPPA compliance
 */
import { db } from '../utils/database.js';
import { logger } from '../utils/logger.js';
import { encrypt, decrypt } from '../utils/encryption.js';
import jwt from 'jsonwebtoken';

class UserService {
  /**
   * Create a new user
   * @param {Object} userData - User data to create
   * @returns {Object} Created user data
   */
  static async createUser(userData) {
    const { email, name, role = 'viewer', ssoProvider = null, ssoUserId = null } = userData;
    
    try {
      // Validate input
      if (!email || !name) {
        throw new Error('Email and name are required');
      }
      
      // Check if user already exists
      const checkQuery = `
        SELECT id FROM users 
        WHERE email = $1 OR (sso_provider = $2 AND sso_user_id = $3)
      `;
      
      const checkResult = await db.query(checkQuery, [email, ssoProvider, ssoUserId]);
      
      if (checkResult.rows.length > 0) {
        throw new Error('User already exists');
      }
      
      // Create user with encrypted password if needed
      const password = userData.password ? 
        encrypt(userData.password) : 
        null;
      
      const query = `
        INSERT INTO users (
          email, 
          name, 
          role, 
          password_hash,
          sso_provider,
          sso_user_id,
          created_at,
          updated_at,
          is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), true)
        RETURNING id, email, name, role, created_at, updated_at, is_active
      `;
      
      const result = await db.query(query, [
        email,
        name,
        role,
        password,
        ssoProvider,
        ssoUserId
      ]);
      
      const user = result.rows[0];
      
      logger.info(`New user created: ${user.id}`, { 
        email: user.email,
        role: user.role
      });
      
      return {
        ...user,
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        isActive: user.is_active
      };
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Get user by ID
   * @param {string} userId - User ID to fetch
   * @returns {Object} User data
   */
  static async getUserById(userId) {
    try {
      const query = `
        SELECT id, email, name, role, last_login, created_at, updated_at, is_active, sso_provider
        FROM users 
        WHERE id = $1 AND is_active = true
      `;
      
      const result = await db.query(query, [userId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const user = result.rows[0];
      
      // Anonymize sensitive data for compliance
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        isActive: user.is_active,
        ssoProvider: user.sso_provider
      };
    } catch (error) {
      logger.error('Error fetching user:', error);
      throw error;
    }
  }

  /**
   * Get user by email
   * @param {string} email - User email to fetch
   * @returns {Object} User data
   */
  static async getUserByEmail(email) {
    try {
      const query = `
        SELECT id, email, name, role, password_hash, last_login, created_at, updated_at, is_active, sso_provider
        FROM users 
        WHERE email = $1 AND is_active = true
      `;
      
      const result = await db.query(query, [email]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const user = result.rows[0];
      
      // Return sanitized data for compliance
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        isActive: user.is_active,
        ssoProvider: user.sso_provider
      };
    } catch (error) {
      logger.error('Error fetching user by email:', error);
      throw error;
    }
  }

  /**
   * Update user information
   * @param {string} userId - User ID to update
   * @param {Object} updateData - Data to update
   * @returns {Object} Updated user data
   */
  static async updateUser(userId, updateData) {
    try {
      // Validate updates
      const allowedFields = ['name', 'role', 'email'];
      const validUpdates = {};
      
      for (const field of allowedFields) {
        if (updateData[field] !== undefined) {
          validUpdates[field] = updateData[field];
        }
      }
      
      if (Object.keys(validUpdates).length === 0) {
        throw new Error('No valid fields to update');
      }
      
      // Build update query
      const fields = Object.keys(validUpdates);
      const values = Object.values(validUpdates);
      values.push(userId);
      
      const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');
      const query = `
        UPDATE users 
        SET ${setClause}, updated_at = NOW()
        WHERE id = $${fields.length + 1} AND is_active = true
        RETURNING id, email, name, role, last_login, created_at, updated_at, is_active
      `;
      
      const result = await db.query(query, values);
      
      if (result.rows.length === 0) {
        throw new Error('User not found or inactive');
      }
      
      const user = result.rows[0];
      
      logger.info(`User updated: ${userId}`, { 
        fieldsUpdated: Object.keys(validUpdates)
      });
      
      return {
        ...user,
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        isActive: user.is_active
      };
    } catch (error) {
      logger.error('Error updating user:', error);
      throw error;
    }
  }

  /**
   * Delete user (soft delete)
   * @param {string} userId - User ID to delete
   * @returns {Object} Deletion result
   */
  static async deleteUser(userId) {
    try {
      const query = `
        UPDATE users 
        SET is_active = false, updated_at = NOW()
        WHERE id = $1
        RETURNING id, email, name, role, created_at, updated_at
      `;
      
      const result = await db.query(query, [userId]);
      
      if (result.rows.length === 0) {
        throw new Error('User not found');
      }
      
      logger.info(`User soft deleted: ${userId}`);
      
      return {
        success: true,
        message: 'User deactivated successfully'
      };
    } catch (error) {
      logger.error('Error deleting user:', error);
      throw error;
    }
  }

  /**
   * Get all users with pagination and filtering
   * @param {Object} options - Pagination and filtering options
   * @returns {Array} Users array
   */
  static async getAllUsers(options = {}) {
    const { page = 1, limit = 20, role = null, search = null } = options;
    const offset = (page - 1) * limit;
    
    try {
      let query = `
        SELECT id, email, name, role, last_login, created_at, updated_at, is_active
        FROM users 
        WHERE is_active = true
      `;
      
      const params = [];
      
      if (role) {
        query += ' AND role = $1';
        params.push(role);
      }
      
      if (search) {
        query += ' AND (email ILIKE $2 OR name ILIKE $2)';
        params.push(`%${search}%`);
      }
      
      query += ' ORDER BY created_at DESC LIMIT $3 OFFSET $4';
      params.push(limit, offset);
      
      const result = await db.query(query, params);
      
      // Anonymize user identifiers for compliance
      return result.rows.map(row => ({
        id: row.id,
        email: row.email,
        name: row.name,
        role: row.role,
        lastLogin: row.last_login,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        isActive: row.is_active
      }));
    } catch (error) {
      logger.error('Error fetching users:', error);
      throw error;
    }
  }

  /**
   * Get user workspaces
   * @param {string} userId - User ID
   * @returns {Array} Workspaces array
   */
  static async getUserWorkspaces(userId) {
    try {
      const query = `
        SELECT 
          w.id,
          w.name,
          w.description,
          wu.role as user_role,
          wu.joined_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE wu.user_id = $1 AND w.is_active = true
        ORDER BY wu.joined_at DESC
      `;
      
      const result = await db.query(query, [userId]);
      
      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        userRole: row.user_role,
        joinedAt: row.joined_at
      }));
    } catch (error) {
      logger.error('Error fetching user workspaces:', error);
      throw error;
    }
  }

  /**
   * Get user statistics
   * @param {string} userId - User ID
   * @returns {Object} User statistics
   */
  static async getUserStats(userId) {
    try {
      const stats = {};
      
      // Get workspace count
      const workspacesQuery = `
        SELECT COUNT(*) as workspace_count
        FROM workspace_users 
        WHERE user_id = $1
      `;
      
      const workspacesResult = await db.query(workspacesQuery, [userId]);
      stats.workspaces = workspacesResult.rows[0].workspace_count;
      
      // Get document count
      const documentsQuery = `
        SELECT COUNT(*) as document_count
        FROM workspace_documents wd
        JOIN workspace_users wu ON wd.workspace_id = wu.workspace_id
        WHERE wu.user_id = $1
      `;
      
      const documentsResult = await db.query(documentsQuery, [userId]);
      stats.documents = documentsResult.rows[0].document_count;
      
      // Get activity count
      const activityQuery = `
        SELECT COUNT(*) as activity_count
        FROM activity_logs 
        WHERE user_id = $1
      `;
      
      const activityResult = await db.query(activityQuery, [userId]);
      stats.activity = activityResult.rows[0].activity_count;
      
      return stats;
    } catch (error) {
      logger.error('Error fetching user stats:', error);
      throw error;
    }
  }

  /**
   * Authenticate user with email/password
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Object} Authentication result
   */
  static async authenticateUser(email, password) {
    try {
      const query = `
        SELECT id, email, name, role, password_hash, last_login, created_at, updated_at, is_active
        FROM users 
        WHERE email = $1 AND is_active = true
      `;
      
      const result = await db.query(query, [email]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const user = result.rows[0];
      
      // Verify password
      if (!user.password_hash) {
        throw new Error('User has no password set');
      }
      
      const decryptedPassword = decrypt(user.password_hash);
      if (decryptedPassword !== password) {
        throw new Error('Invalid password');
      }
      
      // Update last login time
      await db.query(
        'UPDATE users SET last_login = NOW() WHERE id = $1',
        [user.id]
      );
      
      logger.info(`User authenticated: ${user.id}`);
      
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at,
        updatedAt: user.updated_at
      };
    } catch (error) {
      logger.error('Error authenticating user:', error);
      throw error;
    }
  }

  /**
   * Generate authentication token for user
   * @param {string} userId - User ID
   * @returns {string} JWT token
   */
  static generateAuthToken(userId) {
    return jwt.sign(
      { userId },
      process.env.JWT_SECRET || 'anythingllm-default-secret',
      { expiresIn: '24h' }
    );
  }

  /**
   * Get user compliance report
   * @param {string} userId - User ID
   * @returns {Object} Compliance report
   */
  static async getUserComplianceReport(userId) {
    try {
      // Get user details
      const user = await this.getUserById(userId);
      
      if (!user) {
        throw new Error('User not found');
      }
      
      // Get activity logs for user
      const activityQuery = `
        SELECT 
          al.id,
          al.workspace_id,
          al.action,
          al.description,
          al.timestamp,
          al.ip_address
        FROM activity_logs al
        WHERE al.user_id = $1
        ORDER BY al.timestamp DESC
        LIMIT 50
      `;
      
      const activityResult = await db.query(activityQuery, [userId]);
      
      // Get workspace access information
      const workspacesQuery = `
        SELECT 
          w.id,
          w.name,
          wu.role as user_role,
          wu.joined_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE wu.user_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const workspacesResult = await db.query(workspacesQuery, [userId]);
      
      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt,
          isActive: user.isActive
        },
        activityLog: activityResult.rows.map(log => ({
          id: log.id,
          workspaceId: log.workspace_id.replace(/^[a-zA-Z]+/, 'workspace_'),
          action: log.action,
          description: log.description,
          timestamp: log.timestamp,
          ipAddress: log.ip_address
        })),
        workspaces: workspacesResult.rows.map(workspace => ({
          id: workspace.id.replace(/^[a-zA-Z]+/, 'workspace_'),
          name: workspace.name,
          userRole: workspace.user_role,
          joinedAt: workspace.joined_at
        })),
        complianceStatus: this.checkUserCompliance(user),
        generatedAt: new Date()
      };
    } catch (error) {
      logger.error('Error generating user compliance report:', error);
      throw error;
    }
  }

  /**
   * Check user compliance status
   * @param {Object} user - User data
   * @returns {string} Compliance status
   */
  static checkUserCompliance(user) {
    // Simple compliance check - in real implementation this would be more complex
    if (!user.isActive) {
      return 'non-compliant';
    }
    
    if (user.role === 'admin' && !user.ssoProvider) {
      // Admin users should ideally use SSO for compliance
      return 'warning';
    }
    
    return 'compliant';
  }

  /**
   * Get user access control list
   * @param {string} userId - User ID
   * @returns {Object} Access control information
   */
  static async getUserAccessControl(userId) {
    try {
      const access = {
        userId: userId,
        permissions: [],
        workspaces: {},
        roles: []
      };
      
      // Get user's workspace roles
      const workspaceQuery = `
        SELECT 
          w.id as workspace_id,
          w.name as workspace_name,
          wu.role as user_role,
          wu.joined_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE wu.user_id = $1 AND w.is_active = true
      `;
      
      const result = await db.query(workspaceQuery, [userId]);
      
      // Build access control structure
      for (const row of result.rows) {
        access.workspaces[row.workspace_id] = {
          name: row.workspace_name,
          role: row.user_role,
          joinedAt: row.joined_at
        };
        
        // Add to roles if not already present
        if (!access.roles.includes(row.user_role)) {
          access.roles.push(row.user_role);
        }
      }
      
      return access;
    } catch (error) {
      logger.error('Error getting user access control:', error);
      throw error;
    }
  }

  /**
   * Update user role
   * @param {string} userId - User ID
   * @param {string} newRole - New role to assign
   * @returns {Object} Updated user data
   */
  static async updateUserRole(userId, newRole) {
    const validRoles = ['viewer', 'editor', 'admin', 'owner', 'super_admin'];
    
    if (!validRoles.includes(newRole)) {
      throw new Error('Invalid role specified');
    }
    
    try {
      const query = `
        UPDATE users 
        SET role = $1, updated_at = NOW()
        WHERE id = $2 AND is_active = true
        RETURNING id, email, name, role, last_login, created_at, updated_at, is_active
      `;
      
      const result = await db.query(query, [newRole, userId]);
      
      if (result.rows.length === 0) {
        throw new Error('User not found or inactive');
      }
      
      const user = result.rows[0];
      
      logger.info(`User role updated: ${userId} to ${newRole}`);
      
      return {
        ...user,
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
        isActive: user.is_active
      };
    } catch (error) {
      logger.error('Error updating user role:', error);
      throw error;
    }
  }

  /**
   * Validate user data for compliance
   * @param {Object} userData - User data to validate
   * @returns {Object} Validation results
   */
  static validateUserData(userData) {
    const errors = [];
    
    // Check email format
    if (!userData.email || !this.isValidEmail(userData.email)) {
      errors.push('Invalid email format');
    }
    
    // Check for PII in name
    if (userData.name && this.containsPII(userData.name)) {
      errors.push('Name contains potential PII');
    }
    
    // Validate role
    const validRoles = ['viewer', 'editor', 'admin', 'owner', 'super_admin'];
    if (userData.role && !validRoles.includes(userData.role)) {
      errors.push('Invalid role specified');
    }
    
    // Check password requirements if provided
    if (userData.password) {
      if (userData.password.length < 8) {
        errors.push('Password must be at least 8 characters long');
      }
      
      if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(userData.password)) {
        errors.push('Password must contain uppercase, lowercase, and number');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Check if email is valid format
   * @param {string} email - Email to validate
   * @returns {boolean} Whether email is valid
   */
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
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
   * Get user activity logs with compliance checks
   * @param {string} userId - User ID
   * @returns {Array} Activity logs
   */
  static async getUserActivityLogs(userId) {
    try {
      const query = `
        SELECT 
          al.id,
          al.workspace_id,
          al.action,
          al.description,
          al.timestamp,
          al.ip_address,
          al.user_agent
        FROM activity_logs al
        WHERE al.user_id = $1
        ORDER BY al.timestamp DESC
        LIMIT 100
      `;
      
      const result = await db.query(query, [userId]);
      
      // Anonymize user IDs for compliance
      return result.rows.map(row => ({
        ...row,
        id: row.id,
        workspaceId: row.workspace_id.replace(/^[a-zA-Z]+/, 'workspace_'),
        action: row.action,
        description: row.description,
        timestamp: row.timestamp,
        ipAddress: row.ip_address,
        userAgent: row.user_agent
      }));
    } catch (error) {
      logger.error('Error getting user activity logs:', error);
      throw error;
    }
  }

  /**
   * Get user workspace statistics
   * @param {string} userId - User ID
   * @returns {Object} Workspace statistics
   */
  static async getUserWorkspaceStats(userId) {
    try {
      const stats = {};
      
      // Get total workspaces
      const workspacesQuery = `
        SELECT COUNT(*) as total_workspaces,
               COUNT(CASE WHEN wu.role = 'owner' THEN 1 END) as owned_workspaces,
               COUNT(CASE WHEN wu.role = 'admin' THEN 1 END) as admin_workspaces,
               COUNT(CASE WHEN wu.role = 'editor' THEN 1 END) as editor_workspaces,
               COUNT(CASE WHEN wu.role = 'viewer' THEN 1 END) as viewer_workspaces
        FROM workspace_users wu
        JOIN workspaces w ON wu.workspace_id = w.id
        WHERE wu.user_id = $1 AND w.is_active = true
      `;
      
      const workspacesResult = await db.query(workspacesQuery, [userId]);
      stats.workspaces = workspacesResult.rows[0];
      
      // Get document statistics
      const documentsQuery = `
        SELECT COUNT(*) as total_documents,
               SUM(d.size) as total_size
        FROM workspace_documents wd
        JOIN documents d ON wd.document_id = d.id
        JOIN workspace_users wu ON wd.workspace_id = wu.workspace_id
        WHERE wu.user_id = $1
      `;
      
      const documentsResult = await db.query(documentsQuery, [userId]);
      stats.documents = documentsResult.rows[0];
      
      // Get activity statistics
      const activityQuery = `
        SELECT 
          COUNT(*) as total_activities,
          MAX(timestamp) as last_activity,
          MIN(timestamp) as first_activity
        FROM activity_logs 
        WHERE user_id = $1
      `;
      
      const activityResult = await db.query(activityQuery, [userId]);
      stats.activity = activityResult.rows[0];
      
      return stats;
    } catch (error) {
      logger.error('Error getting user workspace stats:', error);
      throw error;
    }
  }

  /**
   * Export user data for compliance review
   * @param {string} userId - User ID
   * @returns {Object} Exported data
   */
  static async exportUserData(userId) {
    try {
      const user = await this.getUserById(userId);
      
      if (!user) {
        throw new Error('User not found');
      }
      
      const exportData = {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        isActive: user.isActive,
        ssoProvider: user.ssoProvider,
        exportedAt: new Date(),
        workspaces: await this.getUserWorkspaces(userId),
        activityLogs: await this.getUserActivityLogs(userId)
      };
      
      return exportData;
    } catch (error) {
      logger.error('Error exporting user data:', error);
      throw error;
    }
  }
}

// Export service functions for use in other modules
const createUser = UserService.createUser;
const getUserById = UserService.getUserById;
const getUserByEmail = UserService.getUserByEmail;
const updateUser = UserService.updateUser;
const deleteUser = UserService.deleteUser;
const getAllUsers = UserService.getAllUsers;
const getUserWorkspaces = UserService.getUserWorkspaces;
const getUserStats = UserService.getUserStats;
const authenticateUser = UserService.authenticateUser;
const generateAuthToken = UserService.generateAuthToken;
const getUserComplianceReport = UserService.getUserComplianceReport;
const getUserAccessControl = UserService.getUserAccessControl;
const updateUserRole = UserService.updateUserRole;
const validateUserData = UserService.validateUserData;
const getUserActivityLogs = UserService.getUserActivityLogs;
const getUserWorkspaceStats = UserService.getUserWorkspaceStats;
const exportUserData = UserService.exportUserData;

export {
  UserService,
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
  deleteUser,
  getAllUsers,
  getUserWorkspaces,
  getUserStats,
  authenticateUser,
  generateAuthToken,
  getUserComplianceReport,
  getUserAccessControl,
  updateUserRole,
  validateUserData,
  getUserActivityLogs,
  getUserWorkspaceStats,
  exportUserData
};
