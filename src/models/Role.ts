import { v4 as uuidv4 } from 'uuid';
import { PoolClient } from 'pg';
import {
  Role,
  CreateRoleInput,
  UpdateRoleInput,
  UserRole,
  AssignRoleInput,
} from '../types/role';
import { db } from '../database/connection';
import { logger } from '../utils/logger';
import { parseJsonColumn } from '../utils/pgJson';

export class RoleModel {
  static async create(
    input: CreateRoleInput,
    client?: PoolClient
  ): Promise<Role> {
    const id = uuidv4();
    const now = new Date();
    
    const query = `
      INSERT INTO roles (id, name, description, permissions, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `;

    const values = [
      id,
      input.name,
      input.description || null,
      JSON.stringify(input.permissions),
      now,
      now,
    ];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const role = result.rows[0];
      role.permissions = parseJsonColumn<string[]>(role.permissions, []);

      logger.info('Role created successfully', { roleId: id, name: input.name });
      return role;
    } catch (error) {
      logger.error('Error creating role', { name: input.name, error });
      throw error;
    }
  }

  static async findById(
    id: string,
    client?: PoolClient
  ): Promise<Role | null> {
    const query = `SELECT * FROM roles WHERE id = $1`;
    const values = [id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const role = result.rows[0];
      if (role) {
        role.permissions = parseJsonColumn<string[]>(role.permissions, []);
      }

      return role || null;
    } catch (error) {
      logger.error('Error finding role by ID', { roleId: id, error });
      throw error;
    }
  }

  static async findByName(
    name: string,
    client?: PoolClient
  ): Promise<Role | null> {
    const query = `SELECT * FROM roles WHERE name = $1`;
    const values = [name];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const role = result.rows[0];
      if (role) {
        role.permissions = parseJsonColumn<string[]>(role.permissions, []);
      }

      return role || null;
    } catch (error) {
      logger.error('Error finding role by name', { name, error });
      throw error;
    }
  }

  static async findAll(client?: PoolClient): Promise<Role[]> {
    const query = `SELECT * FROM roles ORDER BY name`;

    try {
      const result = client
        ? await client.query(query)
        : await db.query(query);

      return result.rows.map(role => ({
        ...role,
        permissions: parseJsonColumn<string[]>(role.permissions, []),
      }));
    } catch (error) {
      logger.error('Error finding all roles', { error });
      throw error;
    }
  }

  static async update(
    id: string,
    input: UpdateRoleInput,
    client?: PoolClient
  ): Promise<Role | null> {
    const fields: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.name !== undefined) {
      fields.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }

    if (input.description !== undefined) {
      fields.push(`description = $${paramIndex++}`);
      values.push(input.description);
    }

    if (input.permissions !== undefined) {
      fields.push(`permissions = $${paramIndex++}`);
      values.push(JSON.stringify(input.permissions));
    }

    if (fields.length === 0) {
      return await this.findById(id, client);
    }

    fields.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    const query = `
      UPDATE roles 
      SET ${fields.join(', ')} 
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const role = result.rows[0];
      if (role) {
        role.permissions = parseJsonColumn<string[]>(role.permissions, []);
        logger.info('Role updated successfully', { roleId: id });
      }

      return role || null;
    } catch (error) {
      logger.error('Error updating role', { roleId: id, error });
      throw error;
    }
  }

  static async delete(id: string, client?: PoolClient): Promise<boolean> {
    const query = `DELETE FROM roles WHERE id = $1`;
    const values = [id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const deleted = result.rowCount > 0;
      if (deleted) {
        logger.info('Role deleted successfully', { roleId: id });
      }
      return deleted;
    } catch (error) {
      logger.error('Error deleting role', { roleId: id, error });
      throw error;
    }
  }

  static async assignToUser(
    input: AssignRoleInput,
    client?: PoolClient
  ): Promise<UserRole> {
    const now = new Date();
    
    const query = `
      INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_id, role_id) 
      DO UPDATE SET assigned_at = $3, assigned_by = $4
      RETURNING *
    `;

    const values = [
      input.user_id,
      input.role_id,
      now,
      input.assigned_by,
    ];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      logger.info('Role assigned to user', { 
        userId: input.user_id,
        roleId: input.role_id,
        assignedBy: input.assigned_by 
      });
      return result.rows[0];
    } catch (error) {
      logger.error('Error assigning role to user', { 
        userId: input.user_id,
        roleId: input.role_id,
        error 
      });
      throw error;
    }
  }

  static async removeFromUser(
    userId: string,
    roleId: string,
    client?: PoolClient
  ): Promise<boolean> {
    const query = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`;
    const values = [userId, roleId];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const removed = result.rowCount > 0;
      if (removed) {
        logger.info('Role removed from user', { userId, roleId });
      }
      return removed;
    } catch (error) {
      logger.error('Error removing role from user', { userId, roleId, error });
      throw error;
    }
  }

  static async getUserRoles(
    userId: string,
    client?: PoolClient
  ): Promise<Role[]> {
    const query = `
      SELECT r.* FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1
      ORDER BY r.name
    `;

    const values = [userId];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(role => ({
        ...role,
        permissions: parseJsonColumn<string[]>(role.permissions, []),
      }));
    } catch (error) {
      logger.error('Error getting user roles', { userId, error });
      throw error;
    }
  }

  static async getRoleUsers(
    roleId: string,
    client?: PoolClient
  ): Promise<string[]> {
    const query = `
      SELECT user_id FROM user_roles 
      WHERE role_id = $1
    `;

    const values = [roleId];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(row => row.user_id);
    } catch (error) {
      logger.error('Error getting role users', { roleId, error });
      throw error;
    }
  }

  static async getUserPermissions(
    userId: string,
    client?: PoolClient
  ): Promise<string[]> {
    const query = `
      SELECT DISTINCT jsonb_array_elements_text(r.permissions::jsonb) as permission
      FROM roles r
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1
    `;

    const values = [userId];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(row => row.permission);
    } catch (error) {
      logger.error('Error getting user permissions', { userId, error });
      throw error;
    }
  }

  static async hasPermission(
    userId: string,
    permission: string,
    client?: PoolClient
  ): Promise<boolean> {
    const query = `
      SELECT EXISTS(
        SELECT 1 FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.permissions::jsonb ? $2
      ) as has_permission
    `;

    const values = [userId, permission];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows[0].has_permission;
    } catch (error) {
      logger.error('Error checking user permission', { userId, permission, error });
      throw error;
    }
  }
}