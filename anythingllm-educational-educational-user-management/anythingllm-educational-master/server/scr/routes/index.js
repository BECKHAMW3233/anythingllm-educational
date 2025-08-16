// server/src/routes/index.js
/**
 * Main API Routes for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in route definitions
 */
import express from 'express';
import authRoutes from './auth.js';
import userRoutes from './userManagement.js';
import workspaceRoutes from './workspace.js';
import complianceRoutes from './compliance.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Health check endpoint (no authentication required)
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'AnythingLLM Educational API is running',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Public endpoints
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Welcome to AnythingLLM Educational API',
    endpoints: [
      '/api/health',
      '/api/auth/login',
      '/api/auth/sso-login',
      '/api/auth/logout',
      '/api/compliance/status',
      '/api/compliance/report'
    ]
  });
});

// Protected routes (require authentication)
router.use('/auth', authRoutes);
router.use('/users', authenticate, userRoutes);
router.use('/workspaces', authenticate, workspaceRoutes);
router.use('/compliance', authenticate, complianceRoutes);

// Error handling for undefined routes
router.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `The requested route ${req.originalUrl} was not found`
  });
});

export default router;
