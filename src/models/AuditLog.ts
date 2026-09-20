import { v4 as uuidv4 } from 'uuid';
import { PoolClient } from 'pg';
import {
  AuditLog,
  CreateAuditLogInput,
  AuditActions,
  ResourceTypes,
} from '../types/audit';
import { db } from '../database/connection';
import { logger } from '../utils/logger';

export class AuditLogModel {
  static async create(
    input: CreateAuditLogInput,
    client?: PoolClient
  ): Promise<AuditLog> {
    const id = uuidv4();
    const now = new Date();
    
    const query = `
      INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, timestamp, ip_address, user_agent, details, success, error_message)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *
    `;

    const values = [
      id,
      input.user_id || null,
      input.action,
      input.resource_type,
      input.resource_id || null,
      now,
      input.ip_address,
      input.user_agent || null,
      JSON.stringify(input.details || {}),
      input.success,
      input.error_message || null,
    ];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const auditLog = result.rows[0];
      auditLog.details = JSON.parse(auditLog.details);

      // Don't log the audit log creation itself to prevent infinite loops
      return auditLog;
    } catch (error) {
      logger.error('Error creating audit log', { 
        action: input.action,
        resourceType: input.resource_type,
        error 
      });
      throw error;
    }
  }

  static async findById(
    id: string,
    client?: PoolClient
  ): Promise<AuditLog | null> {
    const query = `SELECT * FROM audit_logs WHERE id = $1`;
    const values = [id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const auditLog = result.rows[0];
      if (auditLog) {
        auditLog.details = JSON.parse(auditLog.details);
      }

      return auditLog || null;
    } catch (error) {
      logger.error('Error finding audit log by ID', { auditLogId: id, error });
      throw error;
    }
  }

  static async findByUserId(
    userId: string,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE user_id = $1 
      ORDER BY timestamp DESC 
      LIMIT $2 OFFSET $3
    `;

    const values = [userId, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by user ID', { userId, error });
      throw error;
    }
  }

  static async findByAction(
    action: AuditActions,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE action = $1 
      ORDER BY timestamp DESC 
      LIMIT $2 OFFSET $3
    `;

    const values = [action, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by action', { action, error });
      throw error;
    }
  }

  static async findByResourceType(
    resourceType: ResourceTypes,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE resource_type = $1 
      ORDER BY timestamp DESC 
      LIMIT $2 OFFSET $3
    `;

    const values = [resourceType, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by resource type', { resourceType, error });
      throw error;
    }
  }

  static async findByResourceId(
    resourceId: string,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE resource_id = $1 
      ORDER BY timestamp DESC 
      LIMIT $2 OFFSET $3
    `;

    const values = [resourceId, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by resource ID', { resourceId, error });
      throw error;
    }
  }

  static async findByDateRange(
    startDate: Date,
    endDate: Date,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE timestamp >= $1 AND timestamp <= $2 
      ORDER BY timestamp DESC 
      LIMIT $3 OFFSET $4
    `;

    const values = [startDate, endDate, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by date range', { 
        startDate, 
        endDate, 
        error 
      });
      throw error;
    }
  }

  static async findByIpAddress(
    ipAddress: string,
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE ip_address = $1 
      ORDER BY timestamp DESC 
      LIMIT $2 OFFSET $3
    `;

    const values = [ipAddress, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding audit logs by IP address', { ipAddress, error });
      throw error;
    }
  }

  static async findFailedActions(
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<AuditLog[]> {
    const query = `
      SELECT * FROM audit_logs 
      WHERE success = false 
      ORDER BY timestamp DESC 
      LIMIT $1 OFFSET $2
    `;

    const values = [limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(auditLog => ({
        ...auditLog,
        details: JSON.parse(auditLog.details),
      }));
    } catch (error) {
      logger.error('Error finding failed audit logs', { error });
      throw error;
    }
  }

  static async getActionCounts(
    startDate?: Date,
    endDate?: Date,
    client?: PoolClient
  ): Promise<Array<{ action: string; count: number }>> {
    let query = `
      SELECT action, COUNT(*) as count
      FROM audit_logs
    `;

    const values: unknown[] = [];
    const conditions: string[] = [];

    if (startDate) {
      conditions.push(`timestamp >= $${values.length + 1}`);
      values.push(startDate);
    }

    if (endDate) {
      conditions.push(`timestamp <= $${values.length + 1}`);
      values.push(endDate);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    query += ` GROUP BY action ORDER BY count DESC`;

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(row => ({
        action: row.action,
        count: parseInt(row.count, 10),
      }));
    } catch (error) {
      logger.error('Error getting action counts', { error });
      throw error;
    }
  }

  static async cleanupOldLogs(
    daysToKeep = 365,
    client?: PoolClient
  ): Promise<number> {
    const query = `
      DELETE FROM audit_logs 
      WHERE timestamp < NOW() - INTERVAL '${daysToKeep} days'
    `;

    try {
      const result = client
        ? await client.query(query)
        : await db.query(query);

      const deletedCount = result.rowCount;
      logger.info('Old audit logs cleaned up', { deletedCount, daysToKeep });
      return deletedCount;
    } catch (error) {
      logger.error('Error cleaning up old audit logs', { error });
      throw error;
    }
  }

  // Helper method to log authentication events
  static async logAuthEvent(
    action: AuditActions,
    userId: string | null,
    ipAddress: string,
    userAgent: string | null,
    success: boolean,
    details: Record<string, any> = {},
    errorMessage?: string,
    client?: PoolClient
  ): Promise<AuditLog> {
    return await this.create({
      user_id: userId,
      action,
      resource_type: ResourceTypes.USER,
      resource_id: userId,
      ip_address: ipAddress,
      user_agent: userAgent,
      success,
      details,
      error_message: errorMessage,
    }, client);
  }

  // Helper method to log user management events
  static async logUserEvent(
    action: AuditActions,
    targetUserId: string,
    performedByUserId: string,
    ipAddress: string,
    userAgent: string | null,
    success: boolean,
    details: Record<string, any> = {},
    errorMessage?: string,
    client?: PoolClient
  ): Promise<AuditLog> {
    return await this.create({
      user_id: performedByUserId,
      action,
      resource_type: ResourceTypes.USER,
      resource_id: targetUserId,
      ip_address: ipAddress,
      user_agent: userAgent,
      success,
      details,
      error_message: errorMessage,
    }, client);
  }
}