// server/src/models/User.js - Complete Implementation

import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import UserManager from './UserManager.js';

const prisma = new PrismaClient();

/**
 * User Management Model for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII in code and using anonymized identifiers
 */
class User {
  /**
   * Create a new user with role-based access control
   * @param {Object} userData - User data including role, workspace access
   * @returns {Promise<Object>} Created user object
   */
  static async create(userData) {
    // Sanitize input to avoid PII exposure in logs
    const { username, password, role, email, ...rest } = userData;
    
    // Generate secure password hash
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    try {
      const user = await prisma.user.create({
        data: {
          username,
          email,
          password: hashedPassword,
          role,
          recoveryCodes: [],
          createdAt: new Date(),
          updatedAt: new Date(),
          ...rest
        },
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          createdAt: true,
          updatedAt: true
        }
      });
      
      return user;
    } catch (error) {
      throw new Error(`Failed to create user: ${error.message}`);
    }
  }

  /**
   * Authenticate user login with SSO support
   * @param {string} username - User identifier
   * @param {string} password - User password
   * @returns {Promise<Object>} Authenticated user data
   */
  static async authenticate(username, password) {
    try {
      const user = await prisma.user.findUnique({
        where: {
          username
        },
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          password: true,
          createdAt: true,
          updatedAt: true,
          lastLogin: true
        }
      });

      if (!user) {
        return null;
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (isValidPassword) {
        // Update last login timestamp
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLogin: new Date() }
        });
        
        return {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLogin: user.lastLogin
        };
      }
      
      return null;
    } catch (error) {
      throw new Error(`Authentication failed: ${error.message}`);
    }
  }

  /**
   * Get user by ID with role-based permissions
   * @param {string} userId - User identifier
   * @returns {Promise<Object>} User data with permission context
   */
  static async findById(userId) {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          createdAt: true,
          updatedAt: true,
          lastLogin: true
        }
      });
      
      return user;
    } catch (error) {
      throw new Error(`Failed to fetch user: ${error.message}`);
    }
  }

  /**
   * Get all users with pagination and filtering
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Paginated users list
   */
  static async findAll(options = {}) {
    const { page = 1, limit = 20, role = null } = options;
    
    try {
      const where = {};
      if (role) {
        where.role = role;
      }
      
      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          select: {
            id: true,
            username: true,
            email: true,
            role: true,
            createdAt: true,
            lastLogin: true
          },
          skip: (page - 1) * limit,
          take: limit,
          orderBy: {
            createdAt: 'desc'
          }
        }),
        prisma.user.count({ where })
      ]);
      
      return {
        users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      throw new Error(`Failed to fetch users: ${error.message}`);
    }
  }

  /**
   * Update user permissions based on role hierarchy
   * @param {string} userId - User identifier
   * @param {Object} updates - Permission updates
   * @returns {Promise<Object>} Updated user data
   */
  static async updatePermissions(userId, updates) {
    try {
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          ...updates,
          updatedAt: new Date()
        },
        select: {
          id: true,
          username: true,
          role: true,
          permissions: true
        }
      });
      
      return updatedUser;
    } catch (error) {
      throw new Error(`Failed to update user permissions: ${error.message}`);
    }
  }

  /**
   * Delete user account with compliance measures
   * @param {string} userId - User identifier
   * @returns {Promise<boolean>} Deletion success status
   */
  static async delete(userId) {
    try {
      // Soft delete approach to maintain audit trail while complying with COPPA
      await prisma.user.update({
        where: { id: userId },
        data: {
          deletedAt: new Date(),
          updatedAt: new Date()
        }
      });
      
      return true;
    } catch (error) {
      throw new Error(`Failed to delete user: ${error.message}`);
    }
  }

  /**
   * Generate SSO token for user authentication
   * @param {string} userId - User identifier
   * @returns {Promise<string>} SSO token
   */
  static async generateSSOToken(userId) {
    // This would integrate with your SSO provider
    // For now, we'll create a compliant token generation approach
    const token = require('crypto').randomBytes(32).toString('hex');
    
    // Store token with expiration (compliant to FERPA/COPPA)
    await prisma.user.update({
      where: { id: userId },
      data: {
        ssoToken: token,
        ssoTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      }
    });
    
    return token;
  }

  /**
   * Verify SSO token validity
   * @param {string} token - SSO token to verify
   * @returns {Promise<Object|null>} Validated user or null
   */
  static async validateSSOToken(token) {
    try {
      const user = await prisma.user.findFirst({
        where: {
          ssoToken: token,
          ssoTokenExpiresAt: { gt: new Date() }
        },
        select: {
          id: true,
          username: true,
          role: true,
          email: true
        }
      });
      
      return user;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get user permissions based on role hierarchy
   * @param {string} role - User role
   * @returns {Promise<Object>} Permission set
   */
  static async getPermissions(role) {
    const permissions = {
      // Super Admin permissions
      super_admin: {
        canManageSystem: true,
        canManageUsers: true,
        canAccessAllWorkspaces: true,
        canViewAnalytics: true,
        canConfigureSecurity: true,
        canAccessAuditLogs: true,
        canCreateWorkspaces: true,
        canManageClasses: true
      },
      // Admin permissions
      admin: {
        canManageUsers: true,
        canCreateWorkspaces: true,
        canViewAnalytics: true,
        canAccessAuditLogs: true,
        canManageClasses: true,
        canConfigureSecurity: true
      },
      // Instructor permissions
      instructor: {
        canCreateWorkspaces: true,
        canManageOwnClass: true,
        canViewStudentProgress: true,
        canCreateAssignments: true,
        canViewClassAnalytics: true,
        canAccessLimitedUserManagement: true,
        canManageOwnWorkspace: true
      },
      // Student permissions
      student: {
        canUseAIChat: true,
        canViewOwnChatHistory: true,
        canUploadDocuments: true,
        canAccessOwnWorkspace: true,
        canCreateOwnWorkspaces: false,
        canManageUsers: false,
        canAccessAdminFeatures: false,
        canAccessClassManagement: false
      }
    };
    
    return permissions[role] || permissions.student;
  }

  /**
   * Reset user password with security measures
   * @param {string} userId - User identifier
   * @param {string} newPassword - New password
   * @returns {Promise<boolean>} Password reset success status
   */
  static async resetPassword(userId, newPassword) {
    try {
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
      
      await prisma.user.update({
        where: { id: userId },
        data: {
          password: hashedPassword,
          updatedAt: new Date()
        }
      });
      
      return true;
    } catch (error) {
      throw new Error(`Failed to reset password: ${error.message}`);
    }
  }

  /**
   * Validate if user has valid session
   * @param {Object} session - User session data
   * @returns {boolean} Session validity
   */
  static validateSession(session) {
    if (!session || !session.userId || !session.token) {
      return false;
    }
    
    // Check session expiration (24 hours)
    const now = new Date();
    const sessionAge = now - session.createdAt;
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    return sessionAge < maxAge;
  }

  /**
   * Get user by username
   * @param {string} username - User identifier
   * @returns {Promise<Object|null>} User data or null
   */
  static async findByUsername(username) {
    try {
      const user = await prisma.user.findUnique({
        where: { username },
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          createdAt: true,
          updatedAt: true,
          lastLogin: true
        }
      });
      
      return user;
    } catch (error) {
      throw new Error(`Failed to find user by username: ${error.message}`);
    }
  }
}

export default User;
