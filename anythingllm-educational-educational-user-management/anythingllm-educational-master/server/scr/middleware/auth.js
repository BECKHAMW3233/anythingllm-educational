// server/src/middleware/auth.js
/**
 * Authentication Middleware for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in authentication flows
 */
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { validateSession } from '../utils/security.js';

const JWT_SECRET = process.env.JWT_SECRET || 'anythingllm-educational-secret-key';
const SSO_COOKIE_NAME = 'sso_token';

/**
 * Authentication middleware for protecting routes
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {Promise<void>}
 */
export const authenticate = async (req, res, next) => {
  try {
    // Check for JWT token in Authorization header
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.cookies && req.cookies[SSO_COOKIE_NAME]) {
      // Check for SSO cookie
      token = req.cookies[SSO_COOKIE_NAME];
    }

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'No authentication token provided'
      });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists and is valid
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'User not found'
      });
    }

    // Validate session (if applicable)
    if (decoded.sessionId && !validateSession({ ...decoded, createdAt: new Date(decoded.iat * 1000) })) {
      return res.status(401).json({
        error: 'Session expired',
        message: 'Your session has expired'
      });
    }

    // Attach user to request object
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      lastLogin: user.lastLogin
    };

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Authentication token has expired'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Authentication token is invalid'
      });
    }

    return res.status(500).json({
      error: 'Authentication error',
      message: 'Failed to authenticate user'
    });
  }
};

/**
 * SSO authentication middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {Promise<void>}
 */
export const authenticateSSO = async (req, res, next) => {
  try {
    // Check for SSO token in cookies or headers
    let ssoToken = null;
    
    if (req.headers['x-sso-token']) {
      ssoToken = req.headers['x-sso-token'];
    } else if (req.cookies && req.cookies[SSO_COOKIE_NAME]) {
      ssoToken = req.cookies[SSO_COOKIE_NAME];
    }

    if (!ssoToken) {
      return res.status(401).json({
        error: 'SSO authentication required',
        message: 'No SSO token provided'
      });
    }

    // Validate SSO token
    const user = await User.validateSSOToken(ssoToken);
    
    if (!user) {
      return res.status(401).json({
        error: 'Invalid SSO token',
        message: 'SSO authentication failed'
      });
    }

    // Attach authenticated user to request
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    next();
  } catch (error) {
    return res.status(500).json({
      error: 'SSO authentication error',
      message: 'Failed to authenticate via SSO'
    });
  }
};

/**
 * Generate JWT token for user
 * @param {Object} userData - User data to include in token
 * @returns {string} JWT token
 */
export const generateToken = (userData) => {
  const payload = {
    userId: userData.id,
    username: userData.username,
    role: userData.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
  };

  return jwt.sign(payload, JWT_SECRET);
};

/**
 * Generate SSO token for user
 * @param {string} userId - User identifier
 * @returns {Promise<string>} SSO token
 */
export const generateSSOToken = async (userId) => {
  return await User.generateSSOToken(userId);
};

/**
 * Verify user role access
 * @param {string} requiredRole - Required role level
 * @returns {Function} Express middleware function
 */
export const requireRole = (requiredRole) => {
  return async (req, res, next) => {
    try {
      // If no user in request, authentication likely failed
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'You must be logged in to access this resource'
        });
      }

      // Super Admin can do everything
      if (req.user.role === 'super_admin') {
        return next();
      }

      // Validate permissions based on role hierarchy
      const roleHierarchy = ['student', 'instructor', 'admin', 'super_admin'];
      const userLevel = roleHierarchy.indexOf(req.user.role);
      const requiredLevel = roleHierarchy.indexOf(requiredRole);
      
      if (userLevel >= requiredLevel) {
        return next();
      }
      
      return res.status(403).json({
        error: 'Access denied',
        message: 'Insufficient permissions for this action'
      });
    } catch (error) {
      return res.status(500).json({
        error: 'Authorization error',
        message: 'Failed to verify user permissions'
      });
    }
  };
};

/**
 * Verify user workspace access
 * @param {string} workspaceId - Workspace identifier
 * @returns {Function} Express middleware function
 */
export const requireWorkspaceAccess = (workspaceId) => {
  return async (req, res, next) => {
    try {
      // For educational purposes, we'll implement basic workspace access logic
      // In a full implementation, this would check user's assigned workspaces
      
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'You must be logged in to access this workspace'
        });
      }
      
      // All users can access their own workspace data based on role
      if (req.user.role === 'student') {
        // Students have limited access to their own workspaces
        return next();
      }
      
      // Admins and instructors can access more workspaces
      if (['instructor', 'admin', 'super_admin'].includes(req.user.role)) {
        return next();
      }
      
      return res.status(403).json({
        error: 'Workspace access denied',
        message: 'You do not have permission to access this workspace'
      });
    } catch (error) {
      return res.status(500).json({
        error: 'Access control error',
        message: 'Failed to verify workspace permissions'
      });
    }
  };
};
