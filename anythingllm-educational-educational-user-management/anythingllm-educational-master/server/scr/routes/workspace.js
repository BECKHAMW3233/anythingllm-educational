// server/src/routes/workspace.js
/**
 * Workspace Management Routes for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in routes and responses
 */
import express from 'express';
import { authenticate, requireRole, requireWorkspaceAccess } from '../middleware/auth.js';
import WorkspaceService from '../services/workspace.js';
import ComplianceMiddleware from '../middleware/compliance.js';

const router = express.Router();

/**
 * Create a new workspace
 * @route POST /api/workspaces
 * @access Private (Authenticated users)
 * @middleware authenticate
 */
router.post('/', authenticate, async (req, res) => {
  try {
    const { name, description, members } = req.body;
    const ownerId = req.user.id;
    
    // Validate input
    if (!name) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Workspace name is required'
      });
    }
    
    // Create workspace through service
    const workspace = await WorkspaceService.createWorkspace(
      { name, description, members },
      ownerId
    );
    
    res.status(201).json({
      success: true,
      data: workspace,
      message: 'Workspace created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to create workspace',
      message: error.message
    });
  }
});

/**
 * Get all workspaces for current user
 * @route GET /api/workspaces
 * @access Private (Authenticated users)
 * @middleware authenticate
 */
router.get('/', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { page = 1, limit = 20, role } = req.query;
    
    // Get user workspaces through service
    const workspaces = await WorkspaceService.getUserWorkspaces(userId, { page, limit, role });
    
    res.json({
      success: true,
      data: workspaces,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: workspaces.length
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspaces',
      message: error.message
    });
  }
});

/**
 * Get specific workspace details
 * @route GET /api/workspaces/:workspaceId
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.get('/:workspaceId', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const userId = req.user.id;
    
    // Get workspace through service
    const workspace = await WorkspaceService.getWorkspace(workspaceId, userId);
    
    if (!workspace) {
      return res.status(404).json({
        error: 'Workspace not found',
        message: 'The requested workspace does not exist'
      });
    }
    
    res.json({
      success: true,
      data: workspace
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspace',
      message: error.message
    });
  }
});

/**
 * Update workspace information
 * @route PUT /api/workspaces/:workspaceId
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.put('/:workspaceId', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const { name, description } = req.body;
    const userId = req.user.id;
    
    // Validate input
    if (!name) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Workspace name is required'
      });
    }
    
    // Update workspace through service
    const updatedWorkspace = await WorkspaceService.updateWorkspace(
      workspaceId,
      { name, description },
      userId
    );
    
    res.json({
      success: true,
      data: updatedWorkspace,
      message: 'Workspace updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to update workspace',
      message: error.message
    });
  }
});

/**
 * Delete workspace
 * @route DELETE /api/workspaces/:workspaceId
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.delete('/:workspaceId', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const userId = req.user.id;
    
    // Delete workspace through service
    await WorkspaceService.deleteWorkspace(workspaceId, userId);
    
    res.json({
      success: true,
      message: 'Workspace deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to delete workspace',
      message: error.message
    });
  }
});

/**
 * Add member to workspace
 * @route POST /api/workspaces/:workspaceId/members
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.post('/:workspaceId/members', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const { userId, role } = req.body;
    const addedBy = req.user.id;
    
    // Validate input
    if (!userId || !role) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'User ID and role are required'
      });
    }
    
    // Add member through service
    const membership = await WorkspaceService.addMember(
      workspaceId,
      userId,
      role,
      addedBy
    );
    
    res.status(201).json({
      success: true,
      data: membership,
      message: 'Member added to workspace successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to add member',
      message: error.message
    });
  }
});

/**
 * Remove member from workspace
 * @route DELETE /api/workspaces/:workspaceId/members/:userId
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.delete('/:workspaceId/members/:userId', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId, userId } = req.params;
    const removedBy = req.user.id;
    
    // Remove member through service
    await WorkspaceService.removeMember(workspaceId, userId, removedBy);
    
    res.json({
      success: true,
      message: 'Member removed from workspace successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to remove member',
      message: error.message
    });
  }
});

/**
 * Get workspace members
 * @route GET /api/workspaces/:workspaceId/members
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.get('/:workspaceId/members', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    
    // Get members through service
    const members = await WorkspaceService.getWorkspaceMembers(workspaceId);
    
    res.json({
      success: true,
      data: members
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspace members',
      message: error.message
    });
  }
});

/**
 * Get workspace statistics
 * @route GET /api/workspaces/:workspaceId/stats
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.get('/:workspaceId/stats', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    
    // Get statistics through service
    const stats = await WorkspaceService.getWorkspaceStats(workspaceId);
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspace statistics',
      message: error.message
    });
  }
});

/**
 * Transfer workspace ownership
 * @route PUT /api/workspaces/:workspaceId/transfer
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.put('/:workspaceId/transfer', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const { newOwnerId } = req.body;
    const currentOwnerId = req.user.id;
    
    // Validate input
    if (!newOwnerId) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'New owner ID is required'
      });
    }
    
    // Transfer ownership through service
    const transfer = await WorkspaceService.transferOwnership(
      workspaceId,
      newOwnerId,
      currentOwnerId
    );
    
    res.json({
      success: true,
      data: transfer,
      message: 'Workspace ownership transferred successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to transfer workspace ownership',
      message: error.message
    });
  }
});

/**
 * Get workspace activity log
 * @route GET /api/workspaces/:workspaceId/activity
 * @access Private (Authenticated users)
 * @middleware authenticate
 * @middleware requireWorkspaceAccess
 */
router.get('/:workspaceId/activity', authenticate, requireWorkspaceAccess(), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    
    // Get activity log through service
    const activities = await WorkspaceService.getActivityLog(workspaceId);
    
    res.json({
      success: true,
      data: activities
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspace activity',
      message: error.message
    });
  }
});

/**
 * Get workspace compliance report
 * @route GET /api/workspaces/:workspaceId/compliance
 * @access Private (Admin or Super Admin only)
 * @middleware authenticate
 * @middleware requireRole(admin)
 */
router.get('/:workspaceId/compliance', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    
    // Get compliance report through service
    const report = await WorkspaceService.getComplianceReport(workspaceId);
    
    res.json({
      success: true,
      data: report
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch workspace compliance report',
      message: error.message
    });
  }
});

/**
 * Validate workspace data
 * @route POST /api/workspaces/validate
 * @access Private (Authenticated users)
 * @middleware authenticate
 */
router.post('/validate', authenticate, async (req, res) => {
  try {
    const { workspaceData } = req.body;
    
    // Validate workspace data through service
    const validation = await WorkspaceService.validateWorkspaceData(workspaceData);
    
    res.json({
      success: true,
      data: validation
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to validate workspace data',
      message: error.message
    });
  }
});

export default router;
