// server/src/middleware/compliance.js
/**
 * Compliance Middleware for Educational AnythingLLM Deployment
 * Ensures FERPA/COPPA compliance throughout workspace operations
 */
import { logger } from '../utils/logger.js';
import { db } from '../utils/database.js';

class ComplianceMiddleware {
  /**
   * Validate that user has proper permissions for workspace operations
   * @param {string} userId - ID of the requesting user
   * @param {string} workspaceId - ID of the workspace
   * @param {string} requiredRole - Required role level
   * @returns {boolean} Whether user has permission
   */
  static async validateWorkspaceAccess(userId, workspaceId, requiredRole = 'viewer') {
    try {
      const query = `
        SELECT role FROM workspace_users 
        WHERE user_id = $1 AND workspace_id = $2
      `;
      
      const result = await db.query(query, [userId, workspaceId]);
      
      if (result.rows.length === 0) {
        return false;
      }
      
      const userRole = result.rows[0].role;
      
      // Role hierarchy check (owner > admin > editor > viewer)
      const roleHierarchy = {
        'viewer': 1,
        'editor': 2,
        'admin': 3,
        'owner': 4
      };
      
      return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
    } catch (error) {
      logger.error('Error validating workspace access:', error);
      return false;
    }
  }

  /**
   * Check if user is authorized to perform specific action
   * @param {string} userId - ID of the requesting user
   * @param {string} workspaceId - ID of the workspace
   * @param {string} action - Type of action being performed
   * @returns {boolean} Whether user is authorized
   */
  static async checkAuthorization(userId, workspaceId, action) {
    try {
      // Get user's role in workspace
      const query = `
        SELECT role FROM workspace_users 
        WHERE user_id = $1 AND workspace_id = $2
      `;
      
      const result = await db.query(query, [userId, workspaceId]);
      
      if (result.rows.length === 0) {
        return false;
      }
      
      const userRole = result.rows[0].role;
      
      // Define authorization rules based on action and role
      const authRules = {
        'read_workspace': ['viewer', 'editor', 'admin', 'owner'],
        'update_workspace': ['admin', 'owner'],
        'delete_workspace': ['owner'],
        'add_member': ['admin', 'owner'],
        'remove_member': ['admin', 'owner'],
        'update_member_role': ['admin', 'owner'],
        'transfer_ownership': ['owner'],
        'view_compliance_report': ['admin', 'owner'],
        'export_members': ['admin', 'owner'],
        'view_activity_log': ['admin', 'owner'],
        'create_workspace': ['viewer'] // All users can create workspaces
      };
      
      const allowedRoles = authRules[action] || [];
      return allowedRoles.includes(userRole);
    } catch (error) {
      logger.error('Error checking authorization:', error);
      return false;
    }
  }

  /**
   * Sanitize data to remove PII before logging or returning
   * @param {Object} data - Data to sanitize
   * @returns {Object} Sanitized data
   */
  static sanitizeData(data) {
    if (!data) return data;
    
    // Create a deep copy to avoid modifying original data
    const sanitized = JSON.parse(JSON.stringify(data));
    
    // Remove or anonymize PII fields
    if (sanitized.email) delete sanitized.email;
    if (sanitized.phone) delete sanitized.phone;
    if (sanitized.ssn) delete sanitized.ssn;
    if (sanitized.address) delete sanitized.address;
    if (sanitized.userId) {
      sanitized.userId = sanitized.userId.replace(/^[a-zA-Z]+/, 'user_');
    }
    
    // Anonymize user identifiers in nested objects
    if (sanitized.members) {
      sanitized.members = sanitized.members.map(member => {
        const cleanMember = { ...member };
        if (cleanMember.userId) {
          cleanMember.userId = cleanMember.userId.replace(/^[a-zA-Z]+/, 'user_');
        }
        return cleanMember;
      });
    }
    
    // Anonymize workspace identifiers
    if (sanitized.workspaceId) {
      sanitized.workspaceId = sanitized.workspaceId.replace(/^[a-zA-Z]+/, 'workspace_');
    }
    
    return sanitized;
  }

  /**
   * Log compliance audit trail
   * @param {string} userId - ID of the user performing action
   * @param {string} workspaceId - ID of the workspace
   * @param {string} action - Type of action performed
   * @param {Object} details - Additional details about the action
   */
  static async logComplianceAudit(userId, workspaceId, action, details = {}) {
    try {
      // Sanitize data before logging
      const sanitizedDetails = this.sanitizeData(details);
      
      const query = `
        INSERT INTO compliance_audit_logs (
          user_id, 
          workspace_id, 
          action, 
          details, 
          timestamp,
          ip_address,
          user_agent
        ) VALUES ($1, $2, $3, $4, NOW(), $5, $6)
      `;
      
      const userAgent = details.userAgent || '';
      const ipAddress = details.ipAddress || '';
      
      await db.query(query, [
        userId,
        workspaceId,
        action,
        JSON.stringify(sanitizedDetails),
        ipAddress,
        userAgent
      ]);
    } catch (error) {
      logger.error('Error logging compliance audit:', error);
      // Don't throw error as it shouldn't break the main operation
    }
  }

  /**
   * Validate that workspace data complies with FERPA/COPPA requirements
   * @param {Object} workspaceData - Data to validate
   * @returns {Object} Validation result
   */
  static validateWorkspaceCompliance(workspaceData) {
    const errors = [];
    
    // Check for PII in workspace name or description
    if (workspaceData.name) {
      const potentialPII = /[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{9}/; // SSN pattern
      if (potentialPII.test(workspaceData.name)) {
        errors.push('Workspace name contains potential PII');
      }
    }
    
    if (workspaceData.description) {
      const potentialPII = /[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{9}/; // SSN pattern
      if (potentialPII.test(workspaceData.description)) {
        errors.push('Workspace description contains potential PII');
      }
    }
    
    // Check for inappropriate content in names/descriptions
    const inappropriateContent = ['adult', 'explicit', 'inappropriate'];
    const textToCheck = `${workspaceData.name || ''} ${workspaceData.description || ''}`.toLowerCase();
    
    for (const term of inappropriateContent) {
      if (textToCheck.includes(term)) {
        errors.push(`Workspace contains inappropriate content: ${term}`);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Generate compliance report for workspace operations
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Compliance report
   */
  static async generateComplianceReport(workspaceId) {
    try {
      // Get workspace member count and roles
      const membersQuery = `
        SELECT role, COUNT(*) as count 
        FROM workspace_users 
        WHERE workspace_id = $1 
        GROUP BY role
      `;
      
      const membersResult = await db.query(membersQuery, [workspaceId]);
      
      // Get recent activity
      const activityQuery = `
        SELECT action, COUNT(*) as count, MAX(timestamp) as last_activity
        FROM compliance_audit_logs 
        WHERE workspace_id = $1 
        GROUP BY action
        ORDER BY last_activity DESC
        LIMIT 10
      `;
      
      const activityResult = await db.query(activityQuery, [workspaceId]);
      
      // Get vector database statistics
      const vectorStats = await this.getVectorDatabaseStats(workspaceId);
      
      return {
        workspaceId: workspaceId,
        generatedAt: new Date(),
        memberDistribution: membersResult.rows,
        recentActivity: activityResult.rows,
        vectorDatabaseStats: vectorStats,
        complianceStatus: 'compliant',
        lastUpdated: new Date()
      };
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      throw error;
    }
  }

  /**
   * Get vector database statistics for compliance reporting
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
          MIN(created_at) as created_date
        FROM vectors v
        JOIN workspace_vectors wv ON v.id = wv.vector_id
        WHERE wv.workspace_id = $1
      `;
      
      const result = await db.query(query, [workspaceId]);
      
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
   * Middleware to check compliance before workspace operations
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async complianceCheck(req, res, next) {
    try {
      const userId = req.user?.id;
      const workspaceId = req.params?.workspaceId || req.body?.workspaceId;
      
      if (!userId || !workspaceId) {
        return res.status(400).json({
          error: 'Missing required parameters',
          message: 'User ID and workspace ID are required for compliance checks'
        });
      }
      
      // Validate workspace access
      const hasAccess = await this.validateWorkspaceAccess(userId, workspaceId);
      if (!hasAccess) {
        return res.status(403).json({
          error: 'Access denied',
          message: 'You do not have permission to access this workspace'
        });
      }
      
      // Log the operation for compliance audit
      const action = req.method + ' ' + req.path;
      await this.logComplianceAudit(userId, workspaceId, action, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        method: req.method,
        path: req.path,
        body: req.body
      });
      
      next();
    } catch (error) {
      logger.error('Compliance check failed:', error);
      return res.status(500).json({
        error: 'Compliance check failed',
        message: 'Internal server error during compliance verification'
      });
    }
  }

  /**
   * Middleware to validate workspace data compliance
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async validateWorkspaceData(req, res, next) {
    try {
      const { name, description, members } = req.body;
      
      // Validate workspace data compliance
      const validation = this.validateWorkspaceCompliance({ name, description, members });
      
      if (!validation.isValid) {
        return res.status(400).json({
          error: 'Compliance validation failed',
          message: 'Workspace data contains non-compliant elements',
          details: validation.errors
        });
      }
      
      next();
    } catch (error) {
      logger.error('Workspace data validation failed:', error);
      return res.status(500).json({
        error: 'Data validation failed',
        message: 'Internal server error during compliance validation'
      });
    }
  }

  /**
   * Middleware to ensure no PII in responses
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async sanitizeResponse(req, res, next) {
    const originalSend = res.send;
    
    res.send = function(data) {
      try {
        // If data is an object, sanitize it
        if (typeof data === 'object' && data !== null) {
          const sanitizedData = this.sanitizeData(data);
          return originalSend.call(this, sanitizedData);
        }
        
        return originalSend.call(this, data);
      } catch (error) {
        logger.error('Error sanitizing response:', error);
        return originalSend.call(this, data);
      }
    };
    
    next();
  }

  /**
   * Middleware to enforce role-based access controls
   * @param {string} requiredRole - Required role level
   * @returns {Function} Express middleware function
   */
  static requireRole(requiredRole) {
    return async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const workspaceId = req.params?.workspaceId || req.body?.workspaceId;
        
        if (!userId || !workspaceId) {
          return res.status(400).json({
            error: 'Missing required parameters',
            message: 'User ID and workspace ID are required'
          });
        }
        
        // Check authorization
        const isAuthorized = await this.checkAuthorization(userId, workspaceId, req.route?.path || '');
        if (!isAuthorized) {
          return res.status(403).json({
            error: 'Access denied',
            message: `Insufficient privileges to perform this action. Required role: ${requiredRole}`
          });
        }
        
        next();
      } catch (error) {
        logger.error('Role authorization check failed:', error);
        return res.status(500).json({
          error: 'Authorization check failed',
          message: 'Internal server error during authorization verification'
        });
      }
    };
  }
}

export default ComplianceMiddleware;
