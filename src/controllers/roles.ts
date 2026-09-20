import { Request, Response } from 'express';
import { RoleModel } from '../models/Role';
import { UserModel } from '../models/User';
import { AuditLogModel } from '../models/AuditLog';
import { logger } from '../utils/logger';
import { PERMISSIONS } from '../utils/permissions';
import { v4 as uuidv4 } from 'uuid';

/**
 * Role Management Controller
 * Handles role and permission management with proper authorization and audit logging
 */
export class RolesController {
  /**
   * Get all roles
   * Requires: role:read permission
   */
  static async getAllRoles(req: Request, res: Response): Promise<void> {
    try {
      const roles = await RoleModel.findAll();
      
      logger.info('Retrieved all roles', { 
        userId: req.session?.userId,
        roleCount: roles.length 
      });

      res.json({
        success: true,
        data: roles,
        message: 'Roles retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving roles', { error, userId: req.session?.userId });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve roles'
      });
    }
  }

  /**
   * Get role by ID
   * Requires: role:read permission
   */
  static async getRoleById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const role = await RoleModel.findById(id);

      if (!role) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      logger.info('Retrieved role by ID', { 
        userId: req.session?.userId,
        roleId: id,
        roleName: role.name
      });

      res.json({
        success: true,
        data: role,
        message: 'Role retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving role by ID', { 
        error, 
        userId: req.session?.userId,
        roleId: req.params.id
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve role'
      });
    }
  }

  /**
   * Create a new role
   * Requires: role:write permission
   */
  static async createRole(req: Request, res: Response): Promise<void> {
    try {
      const { name, description, permissions } = req.body;
      const userId = req.session?.userId;

      // Validate required fields
      if (!name || !permissions || !Array.isArray(permissions)) {
        res.status(400).json({
          success: false,
          error: 'Validation error',
          message: 'Name and permissions array are required'
        });
        return;
      }

      // Check if role already exists
      const existingRole = await RoleModel.findByName(name);
      if (existingRole) {
        res.status(409).json({
          success: false,
          error: 'Role already exists',
          message: 'A role with this name already exists'
        });
        return;
      }

      // Create the role
      const role = await RoleModel.create({
        name,
        description,
        permissions
      });

      // Log audit event
      await AuditLogModel.create({
        user_id: userId!,
        action: 'role_created',
        resource_type: 'role',
        resource_id: role.id,
        ip_address: req.ip || 'unknown',
        success: true,
        details: {
          roleName: name,
          permissions,
          description
        }
      });

      logger.info('Role created successfully', { 
        userId,
        roleId: role.id,
        roleName: name,
        permissions: permissions.length
      });

      res.status(201).json({
        success: true,
        data: role,
        message: 'Role created successfully'
      });
    } catch (error) {
      logger.error('Error creating role', { 
        error, 
        userId: req.session?.userId,
        roleData: req.body
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to create role'
      });
    }
  }

  /**
   * Update a role
   * Requires: role:write permission
   */
  static async updateRole(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { name, description, permissions } = req.body;
      const userId = req.session?.userId;

      // Get existing role
      const existingRole = await RoleModel.findById(id);
      if (!existingRole) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      // Check if name is being changed and already exists
      if (name && name !== existingRole.name) {
        const roleWithSameName = await RoleModel.findByName(name);
        if (roleWithSameName) {
          res.status(409).json({
            success: false,
            error: 'Role name already exists',
            message: 'A role with this name already exists'
          });
        }
      }

      // Update the role
      const updatedRole = await RoleModel.update(id, {
        name,
        description,
        permissions
      });

      if (!updatedRole) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role was not found or could not be updated'
        });
        return;
      }

      // Log audit event
      await AuditLogModel.create({
        user_id: userId!,
        action: 'role_updated',
        resource_type: 'role',
        resource_id: id,
        ip_address: req.ip || 'unknown',
        success: true,
        details: {
          oldRole: existingRole,
          newRole: updatedRole,
          changes: req.body
        }
      });

      logger.info('Role updated successfully', { 
        userId,
        roleId: id,
        roleName: updatedRole.name
      });

      res.json({
        success: true,
        data: updatedRole,
        message: 'Role updated successfully'
      });
    } catch (error) {
      logger.error('Error updating role', { 
        error, 
        userId: req.session?.userId,
        roleId: req.params.id,
        updateData: req.body
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to update role'
      });
    }
  }

  /**
   * Delete a role
   * Requires: role:delete permission
   */
  static async deleteRole(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.session?.userId;

      // Get existing role for audit log
      const existingRole = await RoleModel.findById(id);
      if (!existingRole) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      // Prevent deletion of default system roles
      if (['admin', 'user', 'moderator'].includes(existingRole.name)) {
        res.status(403).json({
          success: false,
          error: 'Cannot delete system role',
          message: 'System roles cannot be deleted'
        });
        return;
      }

      // Check if role is assigned to any users
      const assignedUsers = await RoleModel.getRoleUsers(id);
      if (assignedUsers.length > 0) {
        res.status(409).json({
          success: false,
          error: 'Role in use',
          message: `Role is assigned to ${assignedUsers.length} user(s) and cannot be deleted`
        });
        return;
      }

      // Delete the role
      const deleted = await RoleModel.delete(id);
      if (!deleted) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role was not found or could not be deleted'
        });
        return;
      }

      // Log audit event
      await AuditLogModel.create({
        user_id: userId!,
        action: 'role_deleted',
        resource_type: 'role',
        resource_id: id,
        ip_address: req.ip || 'unknown',
        success: true,
        details: {
          deletedRole: existingRole
        }
      });

      logger.info('Role deleted successfully', { 
        userId,
        roleId: id,
        roleName: existingRole.name
      });

      res.json({
        success: true,
        message: 'Role deleted successfully'
      });
    } catch (error) {
      logger.error('Error deleting role', { 
        error, 
        userId: req.session?.userId,
        roleId: req.params.id
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to delete role'
      });
    }
  }

  /**
   * Assign role to user
   * Requires: role:assign permission
   */
  static async assignRoleToUser(req: Request, res: Response): Promise<void> {
    try {
      const { userId: targetUserId, roleId } = req.body;
      const assignedBy = req.session?.userId;

      // Validate required fields
      if (!targetUserId || !roleId) {
        res.status(400).json({
          success: false,
          error: 'Validation error',
          message: 'User ID and Role ID are required'
        });
        return;
      }

      // Check if user exists
      const user = await UserModel.findById(targetUserId);
      if (!user) {
        res.status(404).json({
          success: false,
          error: 'User not found',
          message: 'User with the specified ID does not exist'
        });
        return;
      }

      // Check if role exists
      const role = await RoleModel.findById(roleId);
      if (!role) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      // Assign the role
      const userRole = await RoleModel.assignToUser({
        user_id: targetUserId,
        role_id: roleId,
        assigned_by: assignedBy!
      });

      // Log audit event
      await AuditLogModel.create({
        user_id: assignedBy!,
        action: 'role_assigned',
        resource_type: 'user_role',
        resource_id: targetUserId,
        ip_address: req.ip || 'unknown',
        success: true,
        details: {
          targetUserId,
          roleId,
          roleName: role.name,
          userEmail: user.email
        }
      });

      logger.info('Role assigned to user', { 
        assignedBy,
        targetUserId,
        roleId,
        roleName: role.name
      });

      res.json({
        success: true,
        data: userRole,
        message: 'Role assigned successfully'
      });
    } catch (error) {
      logger.error('Error assigning role to user', { 
        error, 
        assignedBy: req.session?.userId,
        assignmentData: req.body
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to assign role'
      });
    }
  }

  /**
   * Remove role from user
   * Requires: role:assign permission
   */
  static async removeRoleFromUser(req: Request, res: Response): Promise<void> {
    try {
      const { userId: targetUserId, roleId } = req.body;
      const removedBy = req.session?.userId;

      // Validate required fields
      if (!targetUserId || !roleId) {
        res.status(400).json({
          success: false,
          error: 'Validation error',
          message: 'User ID and Role ID are required'
        });
        return;
      }

      // Get user and role for audit log
      const [user, role] = await Promise.all([
        UserModel.findById(targetUserId),
        RoleModel.findById(roleId)
      ]);

      if (!user) {
        res.status(404).json({
          success: false,
          error: 'User not found',
          message: 'User with the specified ID does not exist'
        });
        return;
      }

      if (!role) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      // Remove the role
      const removed = await RoleModel.removeFromUser(targetUserId, roleId);
      if (!removed) {
        res.status(404).json({
          success: false,
          error: 'Role assignment not found',
          message: 'User does not have the specified role'
        });
        return;
      }

      // Log audit event
      await AuditLogModel.create({
        user_id: removedBy!,
        action: 'role_removed',
        resource_type: 'user_role',
        resource_id: targetUserId,
        ip_address: req.ip || 'unknown',
        success: true,
        details: {
          targetUserId,
          roleId,
          roleName: role.name,
          userEmail: user.email
        }
      });

      logger.info('Role removed from user', { 
        removedBy,
        targetUserId,
        roleId,
        roleName: role.name
      });

      res.json({
        success: true,
        message: 'Role removed successfully'
      });
    } catch (error) {
      logger.error('Error removing role from user', { 
        error, 
        removedBy: req.session?.userId,
        removalData: req.body
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to remove role'
      });
    }
  }

  /**
   * Get user roles
   * Requires: role:read permission
   */
  static async getUserRoles(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;

      // Check if user exists
      const user = await UserModel.findById(userId);
      if (!user) {
        res.status(404).json({
          success: false,
          error: 'User not found',
          message: 'User with the specified ID does not exist'
        });
        return;
      }

      // Get user roles
      const roles = await RoleModel.getUserRoles(userId);

      logger.info('Retrieved user roles', { 
        requestedBy: req.session?.userId,
        targetUserId: userId,
        roleCount: roles.length
      });

      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          roles
        },
        message: 'User roles retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving user roles', { 
        error, 
        requestedBy: req.session?.userId,
        targetUserId: req.params.userId
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve user roles'
      });
    }
  }

  /**
   * Get user permissions
   * Requires: role:read permission
   */
  static async getUserPermissions(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;

      // Check if user exists
      const user = await UserModel.findById(userId);
      if (!user) {
        res.status(404).json({
          success: false,
          error: 'User not found',
          message: 'User with the specified ID does not exist'
        });
        return;
      }

      // Get user permissions
      const permissions = await RoleModel.getUserPermissions(userId);

      logger.info('Retrieved user permissions', { 
        requestedBy: req.session?.userId,
        targetUserId: userId,
        permissionCount: permissions.length
      });

      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          permissions
        },
        message: 'User permissions retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving user permissions', { 
        error, 
        requestedBy: req.session?.userId,
        targetUserId: req.params.userId
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve user permissions'
      });
    }
  }

  /**
   * Get available permissions
   * Requires: role:read permission
   */
  static async getAvailablePermissions(req: Request, res: Response): Promise<void> {
    try {
      const permissions = Object.values(PERMISSIONS);
      
      res.json({
        success: true,
        data: {
          permissions,
          total: permissions.length
        },
        message: 'Available permissions retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving available permissions', { 
        error, 
        userId: req.session?.userId
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve available permissions'
      });
    }
  }

  /**
   * Get role users
   * Requires: role:read permission
   */
  static async getRoleUsers(req: Request, res: Response): Promise<void> {
    try {
      const { roleId } = req.params;

      // Check if role exists
      const role = await RoleModel.findById(roleId);
      if (!role) {
        res.status(404).json({
          success: false,
          error: 'Role not found',
          message: 'Role with the specified ID does not exist'
        });
        return;
      }

      // Get users with this role
      const userIds = await RoleModel.getRoleUsers(roleId);
      
      // Get user details
      const users = await Promise.all(
        userIds.map(async (userId) => {
          const user = await UserModel.findById(userId);
          return user ? { id: user.id, email: user.email } : null;
        })
      );

      // Filter out null values
      const validUsers = users.filter(user => user !== null);

      logger.info('Retrieved role users', { 
        requestedBy: req.session?.userId,
        roleId,
        roleName: role.name,
        userCount: validUsers.length
      });

      res.json({
        success: true,
        data: {
          role: {
            id: role.id,
            name: role.name
          },
          users: validUsers
        },
        message: 'Role users retrieved successfully'
      });
    } catch (error) {
      logger.error('Error retrieving role users', { 
        error, 
        requestedBy: req.session?.userId,
        roleId: req.params.roleId
      });
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: 'Failed to retrieve role users'
      });
    }
  }
}

export default RolesController;