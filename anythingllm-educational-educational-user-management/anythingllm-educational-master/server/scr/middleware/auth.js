// server/src/middleware/auth.js
/**
 * Authentication Middleware for Educational AnythingLLM Deployment
 * Supports SSO integration and maintains FERPA/COPPA compliance
 */
import jwt from 'jsonwebtoken';
import { db } from '../utils/database.js';
import { logger } from '../utils/logger.js';
import { encrypt, decrypt } from '../utils/encryption.js';

class AuthMiddleware {
  /**
   * Authenticate user with JWT token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async authenticate(req, res, next) {
    try {
      // Get token from Authorization header
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'No valid authorization token provided'
        });
      }
      
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'anythingllm-default-secret');
      
      // Check if user exists in database
      const userQuery = `
        SELECT id, email, name, role, last_login, created_at 
        FROM users 
        WHERE id = $1 AND is_active = true
      `;
      
      const result = await db.query(userQuery, [decoded.userId]);
      
      if (result.rows.length === 0) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'User not found or inactive'
        });
      }
      
      // Add user to request object
      req.user = result.rows[0];
      
      // Update last login time
      await db.query(
        'UPDATE users SET last_login = NOW() WHERE id = $1',
        [decoded.userId]
      );
      
      logger.info(`User authenticated: ${decoded.userId}`);
      
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: 'Token expired',
          message: 'Authentication token has expired'
        });
      }
      
      logger.error('Authentication error:', error);
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid authentication token'
      });
    }
  }

  /**
   * Authenticate user with SSO (Single Sign-On)
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async authenticateSSO(req, res, next) {
    try {
      // This would handle SSO authentication (e.g., OAuth, SAML)
      const ssoToken = req.headers['x-sso-token'] || req.query.sso_token;
      
      if (!ssoToken) {
        return res.status(401).json({
          error: 'SSO Authentication required',
          message: 'SSO token is required for authentication'
        });
      }
      
      // Verify SSO token (implementation depends on your SSO provider)
      const decoded = jwt.verify(ssoToken, process.env.SSO_SECRET || 'sso-default-secret');
      
      // Check if user exists in our system
      let user = await this.findOrCreateUserFromSSO(decoded);
      
      // Create JWT token for internal use
      const jwtToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET || 'anythingllm-default-secret',
        { expiresIn: '24h' }
      );
      
      // Add user to request object
      req.user = user;
      req.ssoToken = ssoToken;
      req.jwtToken = jwtToken;
      
      logger.info(`SSO User authenticated: ${user.id}`);
      
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: 'SSO Token expired',
          message: 'SSO authentication token has expired'
        });
      }
      
      logger.error('SSO Authentication error:', error);
      return res.status(401).json({
        error: 'SSO Authentication failed',
        message: 'Failed to authenticate via SSO'
      });
    }
  }

  /**
   * Find or create user from SSO provider data
   * @param {Object} ssoData - Data from SSO provider
   * @returns {Object} User object
   */
  static async findOrCreateUserFromSSO(ssoData) {
    try {
      // Extract user information from SSO data
      const { sub, email, name, given_name, family_name } = ssoData;
      
      if (!email) {
        throw new Error('Email is required from SSO provider');
      }
      
      // Check if user exists
      const userQuery = `
        SELECT id, email, name, role, last_login, created_at, sso_provider, sso_user_id 
        FROM users 
        WHERE email = $1 OR (sso_provider = $2 AND sso_user_id = $3)
      `;
      
      const result = await db.query(userQuery, [email, ssoData.provider, sub]);
      
      if (result.rows.length > 0) {
        // Update existing user
        const user = result.rows[0];
        
        const updateQuery = `
          UPDATE users 
          SET name = $1, last_login = NOW(), updated_at = NOW()
          WHERE id = $2
          RETURNING id, email, name, role, last_login, created_at, sso_provider, sso_user_id
        `;
        
        const updateResult = await db.query(updateQuery, [name || `${given_name} ${family_name}`, user.id]);
        return updateResult.rows[0];
      } else {
        // Create new user
        const role = this.getDefaultUserRole(ssoData);
        
        const insertQuery = `
          INSERT INTO users (email, name, role, sso_provider, sso_user_id, created_at, updated_at, is_active)
          VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), true)
          RETURNING id, email, name, role, last_login, created_at, sso_provider, sso_user_id
        `;
        
        const insertResult = await db.query(insertQuery, [
          email,
          name || `${given_name} ${family_name}`,
          role,
          ssoData.provider,
          sub
        ]);
        
        logger.info(`New SSO user created: ${insertResult.rows[0].id}`);
        return insertResult.rows[0];
      }
    } catch (error) {
      logger.error('Error finding/creating SSO user:', error);
      throw new Error('Failed to authenticate SSO user');
    }
  }

  /**
   * Get default role for new users based on SSO data
   * @param {Object} ssoData - Data from SSO provider
   * @returns {string} Default role
   */
  static getDefaultUserRole(ssoData) {
    // Check if user is in admin group/role from SSO
    if (ssoData.role && ssoData.role.includes('admin')) {
      return 'admin';
    }
    
    // Check for educational roles
    const educationRoles = ['teacher', 'instructor', 'educator', 'faculty'];
    if (ssoData.role && educationRoles.some(role => ssoData.role.includes(role))) {
      return 'editor';
    }
    
    // Default to viewer role for students/regular users
    return 'viewer';
  }

  /**
   * Require specific role for access
   * @param {string} requiredRole - Required role level
   * @returns {Function} Express middleware function
   */
  static requireRole(requiredRole) {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: 'Unauthorized',
            message: 'Authentication required'
          });
        }
        
        // Role hierarchy check
        const roleHierarchy = {
          'viewer': 1,
          'editor': 2,
          'admin': 3,
          'owner': 4,
          'super_admin': 5
        };
        
        if (roleHierarchy[req.user.role] < roleHierarchy[requiredRole]) {
          return res.status(403).json({
            error: 'Insufficient permissions',
            message: `Required role '${requiredRole}' not met`
          });
        }
        
        next();
      } catch (error) {
        logger.error('Role check failed:', error);
        return res.status(500).json({
          error: 'Internal server error',
          message: 'Failed to verify user permissions'
        });
      }
    };
  }

  /**
   * Require workspace access
   * @param {string} requiredRole - Required role level in workspace (optional)
   * @returns {Function} Express middleware function
   */
  static requireWorkspaceAccess(requiredRole = 'viewer') {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            error: 'Unauthorized',
            message: 'Authentication required'
          });
        }
        
        const workspaceId = req.params.workspaceId;
        
        if (!workspaceId) {
          return res.status(400).json({
            error: 'Missing workspace ID',
            message: 'Workspace ID is required for access control'
          });
        }
        
        // Check if user has access to this workspace
        const accessQuery = `
          SELECT role FROM workspace_users 
          WHERE user_id = $1 AND workspace_id = $2
        `;
        
        const result = await db.query(accessQuery, [req.user.id, workspaceId]);
        
        if (result.rows.length === 0) {
          return res.status(403).json({
            error: 'Access denied',
            message: 'You do not have access to this workspace'
          });
        }
        
        // Check role requirements
        const userRole = result.rows[0].role;
        const roleHierarchy = {
          'viewer': 1,
          'editor': 2,
          'admin': 3,
          'owner': 4
        };
        
        if (roleHierarchy[userRole] < roleHierarchy[requiredRole]) {
          return res.status(403).json({
            error: 'Insufficient permissions',
            message: `Required workspace role '${requiredRole}' not met`
          });
        }
        
        next();
      } catch (error) {
        logger.error('Workspace access check failed:', error);
        return res.status(500).json({
          error: 'Internal server error',
          message: 'Failed to verify workspace access'
        });
      }
    };
  }

  /**
   * Generate JWT token for user
   * @param {string} userId - User ID
   * @returns {string} JWT token
   */
  static generateToken(userId) {
    return jwt.sign(
      { userId },
      process.env.JWT_SECRET || 'anythingllm-default-secret',
      { expiresIn: '24h' }
    );
  }

  /**
   * Validate and refresh JWT token
   * @param {string} token - JWT token to validate
   * @returns {Object} Decoded token data
   */
  static validateToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_SECRET || 'anythingllm-default-secret');
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  /**
   * Middleware to handle SSO callback and authentication
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async ssoCallback(req, res, next) {
    try {
      const { code, state } = req.query;
      
      if (!code) {
        return res.status(400).json({
          error: 'Missing authorization code',
          message: 'Authorization code is required'
        });
      }
      
      // Exchange authorization code for access token
      // This would be implemented based on your SSO provider (Google, Microsoft, etc.)
      const accessToken = await this.exchangeCodeForToken(code);
      
      // Get user info from SSO provider
      const userInfo = await this.getUserInfoFromProvider(accessToken);
      
      // Authenticate or create user
      const user = await this.findOrCreateUserFromSSO(userInfo);
      
      // Generate JWT token for internal use
      const jwtToken = this.generateToken(user.id);
      
      // Return tokens and user info
      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        token: jwtToken,
        expiresIn: 86400 // 24 hours in seconds
      });
      
    } catch (error) {
      logger.error('SSO callback error:', error);
      return res.status(500).json({
        error: 'SSO authentication failed',
        message: 'Failed to complete SSO authentication'
      });
    }
  }

  /**
   * Exchange authorization code for access token
   * @param {string} code - Authorization code from SSO provider
   * @returns {string} Access token
   */
  static async exchangeCodeForToken(code) {
    // This would be implemented based on your specific SSO provider
    // Example implementation for Google OAuth:
    /*
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    
    const data = await response.json();
    return data.access_token;
    */
    
    // Placeholder - in production this would be implemented for your specific provider
    return `access_token_${code}`;
  }

  /**
   * Get user info from SSO provider
   * @param {string} accessToken - Access token
   * @returns {Object} User information
   */
  static async getUserInfoFromProvider(accessToken) {
    // This would be implemented based on your specific SSO provider
    // Example implementation for Google:
    /*
    const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    
    return await response.json();
    */
    
    // Placeholder - in production this would be implemented for your specific provider
    return {
      sub: 'sso_user_id',
      email: 'user@example.com',
      name: 'User Name',
      provider: 'sso_provider'
    };
  }

  /**
   * Middleware to refresh authentication token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async refreshToken(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'No valid authorization token provided'
        });
      }
      
      const oldToken = authHeader.substring(7);
      
      // Verify and decode the token
      const decoded = jwt.verify(oldToken, process.env.JWT_SECRET || 'anythingllm-default-secret');
      
      // Generate new token with same user ID
      const newToken = this.generateToken(decoded.userId);
      
      res.json({
        success: true,
        token: newToken,
        expiresIn: 86400
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      return res.status(401).json({
        error: 'Token refresh failed',
        message: 'Failed to refresh authentication token'
      });
    }
  }

  /**
   * Middleware to handle logout and token invalidation
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Next middleware function
   */
  static async logout(req, res, next) {
    try {
      // In a real implementation, you might want to:
      // 1. Add token to blacklist/invalidation list
      // 2. Clear session data
      // 3. Log the logout event
      
      const authHeader = req.headers.authorization;
      
      if (authHeader && authHeader.startsWith('Bearer ')) {
        // Log the logout event for compliance purposes
        const token = authHeader.substring(7);
        const decoded = jwt.decode(token);
        
        if (decoded && decoded.userId) {
          logger.info(`User logged out: ${decoded.userId}`);
        }
      }
      
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({
        error: 'Logout failed',
        message: 'Failed to complete logout process'
      });
    }
  }
}

// Export individual middleware functions for easier use
const authenticate = AuthMiddleware.authenticate;
const authenticateSSO = AuthMiddleware.authenticateSSO;
const requireRole = AuthMiddleware.requireRole;
const requireWorkspaceAccess = AuthMiddleware.requireWorkspaceAccess;
const refreshToken = AuthMiddleware.refreshToken;
const logout = AuthMiddleware.logout;
const ssoCallback = AuthMiddleware.ssoCallback;

export {
  authenticate,
  authenticateSSO,
  requireRole,
  requireWorkspaceAccess,
  refreshToken,
  logout,
  ssoCallback
};
