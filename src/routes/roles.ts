import { Router } from 'express';
import { RolesController } from '../controllers/roles';
import { 
  requireAuth, 
  requirePermission, 
  requireRole,
  requireAdmin 
} from '../middleware/rbac';
import { 
  rateLimiters,
  validateBody,
  validationSchemas,
  securityMiddleware 
} from '../middleware';
import { PERMISSIONS } from '../utils/permissions';

const router = Router();

// Apply base security middleware to all role routes
router.use(securityMiddleware.auth);

// All role management routes require authentication
router.use(requireAuth);

/**
 * GET /api/roles
 * Get all roles
 * Requires: role:read permission
 */
router.get(
  '/',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getAllRoles
);

/**
 * GET /api/roles/:id
 * Get role by ID
 * Requires: role:read permission
 */
router.get(
  '/:id',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getRoleById
);

/**
 * POST /api/roles
 * Create a new role
 * Requires: role:write permission
 */
router.post(
  '/',
  requirePermission(PERMISSIONS.ROLE_WRITE),
  rateLimiters.adminActions,
  validateBody(validationSchemas.roleCreate),
  RolesController.createRole
);

/**
 * PUT /api/roles/:id
 * Update a role
 * Requires: role:write permission
 */
router.put(
  '/:id',
  requirePermission(PERMISSIONS.ROLE_WRITE),
  rateLimiters.adminActions,
  validateBody(validationSchemas.roleUpdate),
  RolesController.updateRole
);

/**
 * DELETE /api/roles/:id
 * Delete a role
 * Requires: role:delete permission
 */
router.delete(
  '/:id',
  requirePermission(PERMISSIONS.ROLE_DELETE),
  rateLimiters.adminActions,
  RolesController.deleteRole
);

/**
 * POST /api/roles/assign
 * Assign role to user
 * Requires: role:assign permission
 */
router.post(
  '/assign',
  requirePermission(PERMISSIONS.ROLE_ASSIGN),
  rateLimiters.adminActions,
  validateBody(validationSchemas.roleAssign),
  RolesController.assignRoleToUser
);

/**
 * POST /api/roles/remove
 * Remove role from user
 * Requires: role:assign permission
 */
router.post(
  '/remove',
  requirePermission(PERMISSIONS.ROLE_ASSIGN),
  rateLimiters.adminActions,
  validateBody(validationSchemas.roleRemove),
  RolesController.removeRoleFromUser
);

/**
 * GET /api/roles/users/:userId
 * Get user roles
 * Requires: role:read permission
 */
router.get(
  '/users/:userId',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getUserRoles
);

/**
 * GET /api/roles/users/:userId/permissions
 * Get user permissions
 * Requires: role:read permission
 */
router.get(
  '/users/:userId/permissions',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getUserPermissions
);

/**
 * GET /api/roles/permissions
 * Get available permissions
 * Requires: role:read permission
 */
router.get(
  '/permissions',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getAvailablePermissions
);

/**
 * GET /api/roles/:roleId/users
 * Get users with specific role
 * Requires: role:read permission
 */
router.get(
  '/:roleId/users',
  requirePermission(PERMISSIONS.ROLE_READ),
  RolesController.getRoleUsers
);

// Admin-only routes for sensitive operations
/**
 * GET /api/roles/admin/audit
 * Get role management audit logs
 * Requires: admin role
 */
router.get(
  '/admin/audit',
  requireAdmin,
  async (req, res) => {
    try {
      // This would typically fetch audit logs related to role management
      // For now, return a placeholder response
      res.json({
        success: true,
        data: {
          message: 'Role management audit logs endpoint',
          note: 'This endpoint would return audit logs for role management operations'
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve audit logs'
      });
    }
  }
);

/**
 * POST /api/roles/admin/bulk-assign
 * Bulk assign roles to multiple users
 * Requires: admin role
 */
router.post(
  '/admin/bulk-assign',
  requireAdmin,
  rateLimiters.adminActions,
  async (req, res) => {
    try {
      const { userIds, roleIds } = req.body;
      
      if (!Array.isArray(userIds) || !Array.isArray(roleIds)) {
        return void res.status(400).json({
          success: false,
          error: 'Validation error',
          message: 'userIds and roleIds must be arrays'
        });
      }

      // This would implement bulk role assignment logic
      res.json({
        success: true,
        data: {
          message: 'Bulk role assignment endpoint',
          note: 'This endpoint would handle bulk role assignments',
          userIds,
          roleIds
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to perform bulk role assignment'
      });
    }
  }
);

export default router;