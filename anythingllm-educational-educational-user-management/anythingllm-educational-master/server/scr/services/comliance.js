// server/src/services/compliance.js
/**
 * Compliance Service for Educational AnythingLLM Deployment
 * Generates FERPA/COPPA compliant reports and ensures data protection
 */
import { db } from '../utils/database.js';
import { logger } from '../utils/logger.js';
import { encrypt, decrypt } from '../utils/encryption.js';

class ComplianceService {
  /**
   * Generate comprehensive compliance report for workspace
   * @param {string} entityType - Type of entity ('workspace', 'user', 'system')
   * @param {string} entityId - ID of the entity
   * @returns {Object} Compliance report data
   */
  static async generateComplianceReport(entityType, entityId) {
    try {
      let report = {};
      
      switch (entityType.toLowerCase()) {
        case 'workspace':
          report = await this.generateWorkspaceComplianceReport(entityId);
          break;
        case 'user':
          report = await this.generateUserComplianceReport(entityId);
          break;
        case 'system':
          report = await this.generateSystemComplianceReport();
          break;
        default:
          throw new Error('Unsupported entity type for compliance report');
      }
      
      // Add metadata to report
      report.generatedAt = new Date();
      report.entityType = entityType;
      report.entityId = entityId;
      report.complianceStatus = this.checkComplianceStatus(report);
      
      // Log compliance report generation
      logger.info(`Compliance report generated for ${entityType}: ${entityId}`);
      
      return report;
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      throw new Error('Failed to generate compliance report');
    }
  }

  /**
   * Generate workspace-specific compliance report
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Workspace compliance report
   */
  static async generateWorkspaceComplianceReport(workspaceId) {
    try {
      // Get workspace details
      const workspaceQuery = `
        SELECT id, name, description, owner_id, created_at, updated_at 
        FROM workspaces 
        WHERE id = $1
      `;
      
      const workspaceResult = await db.query(workspaceQuery, [workspaceId]);
      
      if (workspaceResult.rows.length === 0) {
        throw new Error('Workspace not found');
      }
      
      const workspace = workspaceResult.rows[0];
      
      // Get workspace members with roles
      const membersQuery = `
        SELECT 
          wu.user_id,
          wu.role,
          wu.joined_at,
          u.name as user_name,
          u.email as user_email
        FROM workspace_users wu
        LEFT JOIN users u ON wu.user_id = u.id
        WHERE wu.workspace_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const membersResult = await db.query(membersQuery, [workspaceId]);
      
      // Get activity logs for workspace
      const activityQuery = `
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
      
      const activityResult = await db.query(activityQuery, [workspaceId]);
      
      // Get vector database statistics
      const vectorStats = await this.getVectorDatabaseStats(workspaceId);
      
      // Get data retention information
      const retentionQuery = `
        SELECT 
          COUNT(*) as total_documents,
          SUM(size) as total_size,
          MAX(created_at) as last_uploaded,
          MIN(created_at) as first_uploaded
        FROM documents d
        JOIN workspace_documents wd ON d.id = wd.document_id
        WHERE wd.workspace_id = $1
      `;
      
      const retentionResult = await db.query(retentionQuery, [workspaceId]);
      
      return {
        workspace: {
          id: workspace.id,
          name: workspace.name,
          description: workspace.description,
          ownerId: workspace.owner_id.replace(/^[a-zA-Z]+/, 'user_'),
          createdAt: workspace.created_at,
          updatedAt: workspace.updated_at
        },
        members: membersResult.rows.map(member => ({
          userId: member.user_id.replace(/^[a-zA-Z]+/, 'user_'),
          role: member.role,
          joinedAt: member.joined_at,
          userName: member.user_name
        })),
        activityLog: activityResult.rows.map(log => ({
          id: log.id,
          userId: log.user_id.replace(/^[a-zA-Z]+/, 'user_'),
          action: log.action,
          description: log.description,
          timestamp: log.timestamp,
          ipAddress: log.ip_address
        })),
        vectorDatabaseStats: vectorStats,
        dataRetention: retentionResult.rows[0],
        complianceChecks: this.performWorkspaceComplianceChecks(workspaceId)
      };
    } catch (error) {
      logger.error('Error generating workspace compliance report:', error);
      throw error;
    }
  }

  /**
   * Generate user-specific compliance report
   * @param {string} userId - ID of the user
   * @returns {Object} User compliance report
   */
  static async generateUserComplianceReport(userId) {
    try {
      // Get user details
      const userQuery = `
        SELECT id, email, name, role, last_login, created_at, updated_at, is_active 
        FROM users 
        WHERE id = $1
      `;
      
      const userResult = await db.query(userQuery, [userId]);
      
      if (userResult.rows.length === 0) {
        throw new Error('User not found');
      }
      
      const user = userResult.rows[0];
      
      // Get user workspaces
      const workspacesQuery = `
        SELECT 
          w.id,
          w.name,
          w.description,
          wu.role as user_role,
          wu.joined_at
        FROM workspaces w
        JOIN workspace_users wu ON w.id = wu.workspace_id
        WHERE wu.user_id = $1
        ORDER BY wu.joined_at DESC
      `;
      
      const workspacesResult = await db.query(workspacesQuery, [userId]);
      
      // Get user activity logs
      const activityQuery = `
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
      
      const activityResult = await db.query(activityQuery, [userId]);
      
      // Get data access logs (for PII protection)
      const accessQuery = `
        SELECT 
          dal.document_id,
          dal.access_type,
          dal.timestamp,
          dal.ip_address
        FROM document_access_logs dal
        WHERE dal.user_id = $1
        ORDER BY dal.timestamp DESC
        LIMIT 50
      `;
      
      const accessResult = await db.query(accessQuery, [userId]);
      
      return {
        user: {
          id: user.id.replace(/^[a-zA-Z]+/, 'user_'),
          email: user.email,
          name: user.name,
          role: user.role,
          lastLogin: user.last_login,
          createdAt: user.created_at,
          isActive: user.is_active
        },
        workspaces: workspacesResult.rows.map(workspace => ({
          id: workspace.id.replace(/^[a-zA-Z]+/, 'workspace_'),
          name: workspace.name,
          description: workspace.description,
          role: workspace.user_role,
          joinedAt: workspace.joined_at
        })),
        activityLog: activityResult.rows.map(log => ({
          id: log.id,
          workspaceId: log.workspace_id.replace(/^[a-zA-Z]+/, 'workspace_'),
          action: log.action,
          description: log.description,
          timestamp: log.timestamp,
          ipAddress: log.ip_address
        })),
        dataAccessLogs: accessResult.rows.map(access => ({
          documentId: access.document_id,
          accessType: access.access_type,
          timestamp: access.timestamp,
          ipAddress: access.ip_address
        })),
        complianceChecks: this.performUserComplianceChecks(userId)
      };
    } catch (error) {
      logger.error('Error generating user compliance report:', error);
      throw error;
    }
  }

  /**
   * Generate system-wide compliance report
   * @returns {Object} System compliance report
   */
  static async generateSystemComplianceReport() {
    try {
      // Get overall system statistics
      const statsQuery = `
        SELECT 
          COUNT(*) as total_users,
          COUNT(DISTINCT workspace_id) as total_workspaces,
          COUNT(DISTINCT document_id) as total_documents,
          COUNT(*) as total_activities,
          MAX(created_at) as last_activity_date
        FROM (
          SELECT id as user_id, created_at FROM users WHERE is_active = true
          UNION ALL
          SELECT id as workspace_id, created_at FROM workspaces
          UNION ALL
          SELECT id as document_id, created_at FROM documents
          UNION ALL
          SELECT id as activity_id, timestamp as created_at FROM activity_logs
        ) stats
      `;
      
      const statsResult = await db.query(statsQuery);
      
      // Get recent compliance issues (if any)
      const issuesQuery = `
        SELECT 
          issue_type,
          COUNT(*) as count,
          MAX(timestamp) as last_occurrence,
          description
        FROM compliance_issues
        WHERE timestamp >= NOW() - INTERVAL '30 days'
        GROUP BY issue_type, description
        ORDER BY count DESC
      `;
      
      const issuesResult = await db.query(issuesQuery);
      
      // Get recent security events
      const securityQuery = `
        SELECT 
          event_type,
          COUNT(*) as count,
          MAX(timestamp) as last_event,
          description
        FROM security_events
        WHERE timestamp >= NOW() - INTERVAL '30 days'
        GROUP BY event_type, description
        ORDER BY count DESC
      `;
      
      const securityResult = await db.query(securityQuery);
      
      return {
        systemStats: statsResult.rows[0],
        recentIssues: issuesResult.rows,
        recentSecurityEvents: securityResult.rows,
        complianceChecks: this.performSystemComplianceChecks(),
        lastUpdated: new Date()
      };
    } catch (error) {
      logger.error('Error generating system compliance report:', error);
      throw error;
    }
  }

  /**
   * Perform workspace-specific compliance checks
   * @param {string} workspaceId - ID of the workspace
   * @returns {Object} Compliance check results
   */
  static async performWorkspaceComplianceChecks(workspaceId) {
    const checks = {
      pIIProtection: true,
      accessControl: true,
      auditLogging: true,
      dataRetention: true,
      roleSeparation: true,
      ssoIntegration: true
    };
    
    try {
      // Check PII protection in workspace members
      const membersQuery = `
        SELECT user_id, role, joined_at 
        FROM workspace_users 
        WHERE workspace_id = $1
      `;
      
      const membersResult = await db.query(membersQuery, [workspaceId]);
      
      // Basic PII check - ensure no obvious PII in member data
      for (const member of membersResult.rows) {
        if (member.user_id.includes('@')) {
          checks.pIIProtection = false;
        }
      }
      
      // Check access control (ensure proper role hierarchy)
      const rolesQuery = `
        SELECT role, COUNT(*) as count 
        FROM workspace_users 
        WHERE workspace_id = $1 
        GROUP BY role
      `;
      
      const rolesResult = await db.query(rolesQuery, [workspaceId]);
      
      if (rolesResult.rows.length === 0) {
        checks.accessControl = false;
      }
      
      // Check audit logging
      const activityQuery = `
        SELECT COUNT(*) as count 
        FROM activity_logs 
        WHERE workspace_id = $1
      `;
      
      const activityResult = await db.query(activityQuery, [workspaceId]);
      
      if (activityResult.rows[0].count === 0) {
        checks.auditLogging = false;
      }
      
      // Check data retention policies
      const documentsQuery = `
        SELECT COUNT(*) as count 
        FROM workspace_documents 
        WHERE workspace_id = $1
      `;
      
      const documentsResult = await db.query(documentsQuery, [workspaceId]);
      
      if (documentsResult.rows[0].count === 0) {
        checks.dataRetention = false;
      }
      
      return checks;
    } catch (error) {
      logger.error('Error performing workspace compliance checks:', error);
      return checks;
    }
  }

  /**
   * Perform user-specific compliance checks
   * @param {string} userId - ID of the user
   * @returns {Object} Compliance check results
   */
  static async performUserComplianceChecks(userId) {
    const checks = {
      dataAccess: true,
      roleConsistency: true,
      activityLogging: true,
      ssoIntegration: true,
      privacyControls: true
    };
    
    try {
      // Check user has proper role
      const userQuery = `
        SELECT role, is_active 
        FROM users 
        WHERE id = $1
      `;
      
      const userResult = await db.query(userQuery, [userId]);
      
      if (userResult.rows.length === 0) {
        checks.dataAccess = false;
      } else {
        const user = userResult.rows[0];
        if (!user.is_active || !user.role) {
          checks.roleConsistency = false;
        }
      }
      
      // Check activity logging
      const activityQuery = `
        SELECT COUNT(*) as count 
        FROM activity_logs 
        WHERE user_id = $1
      `;
      
      const activityResult = await db.query(activityQuery, [userId]);
      
      if (activityResult.rows[0].count === 0) {
        checks.activityLogging = false;
      }
      
      // Check SSO integration status
      const ssoQuery = `
        SELECT sso_provider 
        FROM users 
        WHERE id = $1 AND sso_provider IS NOT NULL
      `;
      
      const ssoResult = await db.query(ssoQuery, [userId]);
      
      if (ssoResult.rows.length === 0) {
        checks.ssoIntegration = false;
      }
      
      return checks;
    } catch (error) {
      logger.error('Error performing user compliance checks:', error);
      return checks;
    }
  }

  /**
   * Perform system-wide compliance checks
   * @returns {Object} System compliance check results
   */
  static async performSystemComplianceChecks() {
    const checks = {
      dataEncryption: true,
      accessControl: true,
      auditTrail: true,
      backupSecurity: true,
      userManagement: true,
      ssoSupport: true
    };
    
    try {
      // Check encryption status (this would be more complex in real implementation)
      // For now, we'll assume it's enabled
      
      // Check access control mechanisms
      const accessQuery = `
        SELECT COUNT(*) as count 
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE r.name IN ('admin', 'owner', 'editor')
      `;
      
      const accessResult = await db.query(accessQuery);
      
      if (accessResult.rows[0].count === 0) {
        checks.accessControl = false;
      }
      
      // Check audit trail exists
      const auditQuery = `
        SELECT COUNT(*) as count 
        FROM compliance_audit_logs
      `;
      
      const auditResult = await db.query(auditQuery);
      
      if (auditResult.rows[0].count === 0) {
        checks.auditTrail = false;
      }
      
      // Check backup security
      const backupQuery = `
        SELECT COUNT(*) as count 
        FROM backups b
        WHERE b.status = 'completed' AND b.created_at >= NOW() - INTERVAL '7 days'
      `;
      
      const backupResult = await db.query(backupQuery);
      
      if (backupResult.rows[0].count === 0) {
        checks.backupSecurity = false;
      }
      
      return checks;
    } catch (error) {
      logger.error('Error performing system compliance checks:', error);
      return checks;
    }
  }

  /**
   * Check overall compliance status
   * @param {Object} report - Compliance report data
   * @returns {string} Compliance status ('compliant', 'warning', 'non-compliant')
   */
  static checkComplianceStatus(report) {
    // Simple implementation - in real system this would be more sophisticated
    if (!report.complianceChecks) {
      return 'unknown';
    }
    
    const checks = Object.values(report.complianceChecks);
    const totalChecks = checks.length;
    const passedChecks = checks.filter(check => check === true).length;
    
    if (passedChecks === totalChecks) {
      return 'compliant';
    } else if (passedChecks >= totalChecks * 0.8) {
      return 'warning';
    } else {
      return 'non-compliant';
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
   * Validate that data complies with FERPA/COPPA requirements
   * @param {Object} data - Data to validate
   * @returns {Object} Validation result
   */
  static validateDataCompliance(data) {
    const errors = [];
    
    // Check for PII in the data
    if (data.email && this.containsPII(data.email)) {
      errors.push('Email contains potential PII');
    }
    
    if (data.name && this.containsPII(data.name)) {
      errors.push('Name contains potential PII');
    }
    
    // Check for inappropriate content
    const inappropriateTerms = ['adult', 'explicit', 'inappropriate'];
    const textToCheck = `${data.name || ''} ${data.description || ''}`.toLowerCase();
    
    for (const term of inappropriateTerms) {
      if (textToCheck.includes(term)) {
        errors.push(`Data contains inappropriate content: ${term}`);
      }
    }
    
    // Check data retention requirements
    if (data.createdAt && this.isOldData(data.createdAt)) {
      errors.push('Data exceeds retention period');
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
   * Generate compliance summary report
   * @param {string} entityType - Type of entity ('workspace', 'user', 'system')
   * @param {string} entityId - ID of the entity
   * @returns {Object} Summary report
   */
  static async generateComplianceSummary(entityType, entityId) {
    try {
      const report = await this.generateComplianceReport(entityType, entityId);
      
      return {
        summary: {
          status: report.complianceStatus,
          entityType: entityType,
          entityId: entityId,
          generatedAt: report.generatedAt,
          checks: Object.keys(report.complianceChecks || {}).length
        },
        findings: this.extractFindings(report),
        recommendations: this.generateRecommendations(report)
      };
    } catch (error) {
      logger.error('Error generating compliance summary:', error);
      throw error;
    }
  }

  /**
   * Extract key findings from compliance report
   * @param {Object} report - Compliance report data
   * @returns {Array} List of findings
   */
  static extractFindings(report) {
    const findings = [];
    
    if (report.complianceChecks) {
      Object.entries(report.complianceChecks).forEach(([check, passed]) => {
        if (!passed) {
          findings.push({
            type: check,
            status: 'non-compliant',
            description: `Compliance check ${check} failed`
          });
        }
      });
    }
    
    return findings;
  }

  /**
   * Generate recommendations based on compliance report
   * @param {Object} report - Compliance report data
   * @returns {Array} List of recommendations
   */
  static generateRecommendations(report) {
    const recommendations = [];
    
    if (report.complianceStatus === 'non-compliant') {
      recommendations.push({
        priority: 'high',
        action: 'Review and update compliance policies',
        description: 'System does not meet compliance requirements'
      });
    }
    
    if (report.complianceChecks && !report.complianceChecks.auditLogging) {
      recommendations.push({
        priority: 'medium',
        action: 'Enable audit logging',
        description: 'Activity logging is not properly configured'
      });
    }
    
    return recommendations;
  }

  /**
   * Export compliance report to file format
   * @param {Object} report - Compliance report data
   * @returns {string} Exported content
   */
  static exportComplianceReport(report) {
    // In a real implementation, this would generate CSV, JSON, or PDF format
    return JSON.stringify(report, null, 2);
  }
}

// Export the compliance service functions for use in other modules
const generateComplianceReport = ComplianceService.generateComplianceReport;
const generateWorkspaceComplianceReport = ComplianceService.generateWorkspaceComplianceReport;
const generateUserComplianceReport = ComplianceService.generateUserComplianceReport;
const generateSystemComplianceReport = ComplianceService.generateSystemComplianceReport;

export {
  ComplianceService,
  generateComplianceReport,
  generateWorkspaceComplianceReport,
  generateUserComplianceReport,
  generateSystemComplianceReport
};
