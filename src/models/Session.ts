import { v4 as uuidv4 } from 'uuid';
import { PoolClient } from 'pg';
import {
  Session,
  CreateSessionInput,
  UpdateSessionInput,
} from '../types/session';
import { db } from '../database/connection';
import { logger } from '../utils/logger';

export class SessionModel {
  static async create(
    input: CreateSessionInput,
    client?: PoolClient
  ): Promise<Session> {
    const id = uuidv4();
    const now = new Date();
    
    const query = `
      INSERT INTO sessions (id, user_id, token, expires_at, created_at, ip_address, user_agent, is_active, last_accessed)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;

    const values = [
      id,
      input.user_id,
      input.token,
      input.expires_at,
      now,
      input.ip_address,
      input.user_agent || null,
      true,
      now,
    ];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      logger.info('Session created successfully', { 
        sessionId: id, 
        userId: input.user_id,
        expiresAt: input.expires_at 
      });
      return result.rows[0];
    } catch (error) {
      logger.error('Error creating session', { userId: input.user_id, error });
      throw error;
    }
  }

  static async findByToken(
    token: string,
    client?: PoolClient
  ): Promise<Session | null> {
    const query = `
      SELECT * FROM sessions 
      WHERE token = $1 AND is_active = true AND expires_at > NOW()
    `;

    const values = [token];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error finding session by token', { error });
      throw error;
    }
  }

  static async findByUserId(
    userId: string,
    activeOnly = true,
    client?: PoolClient
  ): Promise<Session[]> {
    let query = `SELECT * FROM sessions WHERE user_id = $1`;
    const values = [userId];

    if (activeOnly) {
      query += ` AND is_active = true AND expires_at > NOW()`;
    }

    query += ` ORDER BY created_at DESC`;

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows;
    } catch (error) {
      logger.error('Error finding sessions by user ID', { userId, error });
      throw error;
    }
  }

  static async update(
    id: string,
    input: UpdateSessionInput,
    client?: PoolClient
  ): Promise<Session | null> {
    const fields: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.expires_at !== undefined) {
      fields.push(`expires_at = $${paramIndex++}`);
      values.push(input.expires_at);
    }

    if (input.is_active !== undefined) {
      fields.push(`is_active = $${paramIndex++}`);
      values.push(input.is_active);
    }

    if (input.last_accessed !== undefined) {
      fields.push(`last_accessed = $${paramIndex++}`);
      values.push(input.last_accessed);
    }

    if (fields.length === 0) {
      return await this.findById(id, client);
    }

    values.push(id);

    const query = `
      UPDATE sessions 
      SET ${fields.join(', ')} 
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      logger.info('Session updated successfully', { sessionId: id });
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error updating session', { sessionId: id, error });
      throw error;
    }
  }

  static async findById(
    id: string,
    client?: PoolClient
  ): Promise<Session | null> {
    const query = `SELECT * FROM sessions WHERE id = $1`;
    const values = [id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error finding session by ID', { sessionId: id, error });
      throw error;
    }
  }

  static async invalidateByToken(
    token: string,
    client?: PoolClient
  ): Promise<boolean> {
    const query = `
      UPDATE sessions 
      SET is_active = false 
      WHERE token = $1 AND is_active = true
    `;

    const values = [token];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const invalidated = result.rowCount > 0;
      if (invalidated) {
        logger.info('Session invalidated by token');
      }
      return invalidated;
    } catch (error) {
      logger.error('Error invalidating session by token', { error });
      throw error;
    }
  }

  static async invalidateByUserId(
    userId: string,
    excludeSessionId?: string,
    client?: PoolClient
  ): Promise<number> {
    let query = `
      UPDATE sessions 
      SET is_active = false 
      WHERE user_id = $1 AND is_active = true
    `;
    
    const values = [userId];

    if (excludeSessionId) {
      query += ` AND id != $2`;
      values.push(excludeSessionId);
    }

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const invalidatedCount = result.rowCount;
      logger.info('Sessions invalidated by user ID', { 
        userId, 
        invalidatedCount,
        excludeSessionId 
      });
      return invalidatedCount;
    } catch (error) {
      logger.error('Error invalidating sessions by user ID', { userId, error });
      throw error;
    }
  }

  static async cleanupExpiredSessions(client?: PoolClient): Promise<number> {
    const query = `
      DELETE FROM sessions 
      WHERE expires_at < NOW() OR (is_active = false AND created_at < NOW() - INTERVAL '30 days')
    `;

    try {
      const result = client
        ? await client.query(query)
        : await db.query(query);

      const deletedCount = result.rowCount;
      logger.info('Expired sessions cleaned up', { deletedCount });
      return deletedCount;
    } catch (error) {
      logger.error('Error cleaning up expired sessions', { error });
      throw error;
    }
  }

  static async updateLastAccessed(
    id: string,
    client?: PoolClient
  ): Promise<void> {
    const query = `
      UPDATE sessions 
      SET last_accessed = NOW()
      WHERE id = $1
    `;

    const values = [id];

    try {
      await (client ? client.query(query, values) : db.query(query, values));
    } catch (error) {
      logger.error('Error updating session last accessed', { sessionId: id, error });
      throw error;
    }
  }

  static async extendExpiration(
    id: string,
    newExpiresAt: Date,
    client?: PoolClient
  ): Promise<Session | null> {
    const query = `
      UPDATE sessions 
      SET expires_at = $1, last_accessed = NOW()
      WHERE id = $2 AND is_active = true
      RETURNING *
    `;

    const values = [newExpiresAt, id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const session = result.rows[0] || null;
      if (session) {
        logger.info('Session expiration extended', { sessionId: id, newExpiresAt });
      }
      return session;
    } catch (error) {
      logger.error('Error extending session expiration', { sessionId: id, error });
      throw error;
    }
  }
}