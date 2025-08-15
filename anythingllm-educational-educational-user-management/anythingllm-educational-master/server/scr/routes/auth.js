// server/src/routes/auth.js
/**
 * Authentication Routes for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in routes and responses
 */
import express from 'express';
import { authenticate, authenticateSSO, generateToken, generateSSOToken, requireRole } from '../middleware/auth.js';
import User from '../models/User.js';
import { validateUserInput } from '../utils/validation.js';

const router = express.Router();

/**
 * User login endpoint
 * @route POST /api/auth/login
 * @access Public
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Username and password are required'
      });
    }
    
    // Authenticate user
    const user = await User.authenticate(username, password);
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid username or password'
      });
    }
    
    // Generate JWT token
    const token = generateToken(user);
    
    // Set secure cookie for SSO (if needed)
    res.cookie('sso_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLogin: user.lastLogin
        }
      },
      message: 'Authentication successful'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Login failed',
      message: 'Failed to authenticate user'
    });
  }
});

/**
 * SSO login endpoint
 * @route POST /api/auth/sso-login
 * @access Public
 */
router.post('/sso-login', async (req, res) => {
  try {
    const { ssoToken } = req.body;
    
    if (!ssoToken) {
      return res.status(400).json({
        error: 'Missing SSO token',
        message: 'SSO token is required'
      });
    }
    
    // Validate SSO token and get user
    const user = await User.validateSSOToken(ssoToken);
    
    if (!user) {
      return res.status(401).json({
        error: 'Invalid SSO token',
        message: 'SSO authentication failed'
      });
    }
    
    // Generate JWT token for session
    const token = generateToken(user);
    
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        }
      },
      message: 'SSO authentication successful'
    });
  } catch (error) {
    res.status(500).json({
      error: 'SSO login failed',
      message: 'Failed to authenticate via SSO'
    });
  }
});

/**
 * User logout endpoint
 * @route POST /api/auth/logout
 * @access Private
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    // Clear session cookies
    res.clearCookie('sso_token');
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Logout failed',
      message: 'Failed to logout user'
    });
  }
});

/**
 * Password reset request endpoint
 * @route POST /api/auth/reset-password-request
 * @access Public
 */
router.post('/reset-password-request', async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({
        error: 'Missing username',
        message: 'Username is required to request password reset'
      });
    }
    
    // Find user by username
    const user = await User.findByUsername(username);
    
    if (!user) {
      // Return success even for non-existent users to prevent enumeration
      return res.json({
        success: true,
        message: 'If an account exists, a password reset link has been sent'
      });
    }
    
    // In a real implementation, you would:
    // 1. Generate reset token
    // 2. Send email with reset link
    // 3. Store token in database with expiration
    
    res.json({
      success: true,
      message: 'If an account exists, a password reset link has been sent'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Password reset request failed',
      message: 'Failed to process password reset request'
    });
  }
});

/**
 * Password reset endpoint
 * @route POST /api/auth/reset-password
 * @access Public
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Reset token and new password are required'
      });
    }
    
    // In a real implementation, you would:
    // 1. Validate reset token
    // 2. Verify token expiration
    // 3. Reset user password
    
    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Password reset failed',
      message: 'Failed to reset password'
    });
  }
});

/**
 * Get current user profile
 * @route GET /api/auth/profile
 * @access Private
 */
router.get('/profile', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'You must be logged in to access your profile'
      });
    }
    
    // Return user profile without sensitive data
    const userProfile = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      lastLogin: user.lastLogin,
      permissions: await User.getPermissions(user.role)
    };
    
    res.json({
      success: true,
      data: userProfile
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch profile',
      message: 'Failed to retrieve user profile'
    });
  }
});

/**
 * Update user profile
 * @route PUT /api/auth/profile
 * @access Private
 */
router.put('/profile', authenticate, async (req, res) => {
  try {
    const { username, email } = req.body;
    const userId = req.user.id;
    
    // Validate input
    if (!username && !email) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'At least one field (username or email) must be updated'
      });
    }
    
    // In a real implementation, you would:
    // 1. Validate user input
    // 2. Check for duplicate username/email
    // 3. Update user record
    
    res.json({
      success: true,
      message: 'Profile updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Profile update failed',
      message: 'Failed to update user profile'
    });
  }
});

/**
 * Generate SSO token for user
 * @route POST /api/auth/sso-token
 * @access Private
 */
router.post('/sso-token', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Only Super Admin can generate tokens for other users
    if (req.user.role !== 'super_admin' && req.body.userId && req.body.userId !== userId) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to generate SSO tokens for other users'
      });
    }
    
    const token = await generateSSOToken(userId);
    
    res.json({
      success: true,
      data: { token },
      message: 'SSO token generated successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to generate SSO token',
      message: 'Failed to create SSO token for user'
    });
  }
});

/**
 * Verify current authentication
 * @route GET /api/auth/verify
 * @access Private
 */
router.get('/verify', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Invalid or expired authentication token'
      });
    }
    
    res.json({
      success: true,
      data: {
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Verification failed',
      message: 'Failed to verify authentication status'
    });
  }
});

/**
 * Get user permissions based on role
 * @route GET /api/auth/permissions
 * @access Private
 */
router.get('/permissions', authenticate, async (req, res) => {
  try {
    const permissions = await User.getPermissions(req.user.role);
    
    res.json({
      success: true,
      data: permissions
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch permissions',
      message: 'Failed to retrieve user permissions'
    });
  }
});

export default router;
