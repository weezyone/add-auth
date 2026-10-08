import { v4 as uuidv4 } from 'uuid';
import { PoolClient } from 'pg';
import {
  User,
  CreateUserInput,
  UpdateUserInput,
  UserWithoutPassword,
  UserStatus,
  CreateOAuthUserInput,
  OAuthAccount,
} from '../types/user';
import { db } from '../database/connection';
import { logger } from '../utils/logger';

/**
 * node-postgres already parses JSON/JSONB columns. JSON.parse() on the parsed
 * value (an array/object) threw, which broke every OAuth sign-up and login.
 */
function parseJsonColumn<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

/**
 * Run fn inside a transaction on a single connection. Issuing BEGIN/COMMIT
 * through the pool (db.query) sends each statement to whichever connection is
 * free, so nothing was actually transactional and a stray BEGIN could leave a
 * pooled connection idle-in-transaction.
 */
async function inTransaction<T>(
  client: PoolClient | undefined,
  fn: (c: PoolClient) => Promise<T>
): Promise<T> {
  return client ? fn(client) : db.transaction(fn);
}

export class UserModel {
  static async create(
    input: CreateUserInput,
    client?: PoolClient
  ): Promise<UserWithoutPassword> {
    const id = uuidv4();
    const now = new Date();
    
    const query = `
      INSERT INTO users (id, email, password_hash, created_at, updated_at, status, email_verified, failed_login_attempts)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until
    `;

    const values = [
      id,
      input.email.toLowerCase(),
      input.password, // This should be hashed before calling this method
      now,
      now,
      UserStatus.ACTIVE,
      false,
      0,
    ];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      logger.info('User created successfully', { userId: id, email: input.email });
      return result.rows[0];
    } catch (error) {
      logger.error('Error creating user', { email: input.email, error });
      throw error;
    }
  }

  static async findById(
    id: string,
    includePassword = false,
    client?: PoolClient
  ): Promise<User | UserWithoutPassword | null> {
    const fields = includePassword
      ? 'id, email, password_hash, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until'
      : 'id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until';

    const query = `SELECT ${fields} FROM users WHERE id = $1 AND status != $2`;
    const values = [id, UserStatus.DELETED];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error finding user by ID', { userId: id, error });
      throw error;
    }
  }

  static async findByEmail(
    email: string,
    includePassword = false,
    client?: PoolClient
  ): Promise<User | UserWithoutPassword | null> {
    const fields = includePassword
      ? 'id, email, password_hash, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until'
      : 'id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until';

    const query = `SELECT ${fields} FROM users WHERE email = $1 AND status != $2`;
    const values = [email.toLowerCase(), UserStatus.DELETED];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error finding user by email', { email, error });
      throw error;
    }
  }

  static async update(
    id: string,
    input: UpdateUserInput,
    client?: PoolClient
  ): Promise<UserWithoutPassword | null> {
    const fields: string[] = [];
    const values: unknown[] = [];
    let paramIndex = 1;

    if (input.email !== undefined) {
      fields.push(`email = $${paramIndex++}`);
      values.push(input.email.toLowerCase());
    }

    if (input.status !== undefined) {
      fields.push(`status = $${paramIndex++}`);
      values.push(input.status);
    }

    if (input.email_verified !== undefined) {
      fields.push(`email_verified = $${paramIndex++}`);
      values.push(input.email_verified);
    }

    if (fields.length === 0) {
      const user = await this.findById(id, false, client);
      return user as UserWithoutPassword;
    }

    fields.push(`updated_at = $${paramIndex++}`);
    values.push(new Date());

    values.push(id);

    const query = `
      UPDATE users 
      SET ${fields.join(', ')} 
      WHERE id = $${paramIndex} AND status != $${paramIndex + 1}
      RETURNING id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until
    `;

    values.push(UserStatus.DELETED);

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      logger.info('User updated successfully', { userId: id });
      return result.rows[0] || null;
    } catch (error) {
      logger.error('Error updating user', { userId: id, error });
      throw error;
    }
  }

  static async updateLastLogin(
    id: string,
    client?: PoolClient
  ): Promise<void> {
    const query = `
      UPDATE users 
      SET last_login = $1, failed_login_attempts = 0, locked_until = NULL
      WHERE id = $2
    `;

    const values = [new Date(), id];

    try {
      await (client ? client.query(query, values) : db.query(query, values));
      logger.info('User last login updated', { userId: id });
    } catch (error) {
      logger.error('Error updating user last login', { userId: id, error });
      throw error;
    }
  }

  static async incrementFailedLoginAttempts(
    id: string,
    client?: PoolClient
  ): Promise<void> {
    const query = `
      UPDATE users 
      SET failed_login_attempts = failed_login_attempts + 1,
          locked_until = CASE 
            WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
            ELSE locked_until
          END
      WHERE id = $1
    `;

    const values = [id];

    try {
      await (client ? client.query(query, values) : db.query(query, values));
      logger.info('User failed login attempts incremented', { userId: id });
    } catch (error) {
      logger.error('Error incrementing failed login attempts', { userId: id, error });
      throw error;
    }
  }

  static async updatePassword(
    id: string,
    passwordHash: string,
    client?: PoolClient
  ): Promise<void> {
    const query = `
      UPDATE users 
      SET password_hash = $1, updated_at = $2
      WHERE id = $3
    `;

    const values = [passwordHash, new Date(), id];

    try {
      await (client ? client.query(query, values) : db.query(query, values));
      logger.info('User password updated', { userId: id });
    } catch (error) {
      logger.error('Error updating user password', { userId: id, error });
      throw error;
    }
  }

  static async delete(id: string, client?: PoolClient): Promise<boolean> {
    const query = `
      UPDATE users 
      SET status = $1, updated_at = $2
      WHERE id = $3 AND status != $1
    `;

    const values = [UserStatus.DELETED, new Date(), id];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const deleted = result.rowCount > 0;
      if (deleted) {
        logger.info('User deleted successfully', { userId: id });
      }
      return deleted;
    } catch (error) {
      logger.error('Error deleting user', { userId: id, error });
      throw error;
    }
  }

  static async findAll(
    offset = 0,
    limit = 50,
    client?: PoolClient
  ): Promise<UserWithoutPassword[]> {
    const query = `
      SELECT id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until
      FROM users 
      WHERE status != $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const values = [UserStatus.DELETED, limit, offset];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows;
    } catch (error) {
      logger.error('Error finding all users', { error });
      throw error;
    }
  }

  // OAuth-related methods
  static async createFromOAuth(
    input: CreateOAuthUserInput,
    client?: PoolClient
  ): Promise<UserWithoutPassword> {
    const userId = uuidv4();
    const now = new Date();
    
    const userQuery = `
      INSERT INTO users (id, email, created_at, updated_at, status, email_verified, first_name, last_name, oauth_providers, failed_login_attempts)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, email, created_at, updated_at, status, email_verified, last_login, failed_login_attempts, locked_until, first_name, last_name, oauth_providers
    `;

    const [firstName, lastName] = this.parseFullName(input.name);
    const oauthProviders = [input.provider];

    const userValues = [
      userId,
      input.email.toLowerCase(),
      now,
      now,
      UserStatus.ACTIVE,
      input.emailVerified || false,
      firstName,
      lastName,
      JSON.stringify(oauthProviders),
      0,
    ];

    const oauthQuery = `
      INSERT INTO oauth_accounts (user_id, provider, provider_id, access_token, refresh_token, profile_data, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const oauthValues = [
      userId,
      input.provider,
      input.providerId,
      input.oauthData?.accessToken || null,
      input.oauthData?.refreshToken || null,
      JSON.stringify(input.oauthData?.profile || {}),
      now,
      now,
    ];

    try {
      const userResult = await inTransaction(client, async (c) => {
        const result = await c.query(userQuery, userValues);
        await c.query(oauthQuery, oauthValues);
        return result;
      });

      const user = userResult.rows[0];
      user.oauth_providers = parseJsonColumn<string[]>(user.oauth_providers, []);

      logger.info('User created from OAuth successfully', { 
        userId, 
        email: input.email,
        provider: input.provider 
      });
      
      return user;
    } catch (error) {
      logger.error('Error creating user from OAuth', { 
        email: input.email,
        provider: input.provider,
        error 
      });
      throw error;
    }
  }

  static async findByOAuthProvider(
    provider: string,
    providerId: string,
    client?: PoolClient
  ): Promise<UserWithoutPassword | null> {
    const query = `
      SELECT u.id, u.email, u.created_at, u.updated_at, u.status, u.email_verified, 
             u.last_login, u.failed_login_attempts, u.locked_until, u.first_name, 
             u.last_name, u.oauth_providers
      FROM users u
      JOIN oauth_accounts oa ON u.id = oa.user_id
      WHERE oa.provider = $1 AND oa.provider_id = $2 AND u.status != $3
    `;

    const values = [provider, providerId, UserStatus.DELETED];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      const user = result.rows[0];
      if (user) {
        user.oauth_providers = parseJsonColumn<string[]>(user.oauth_providers, []);
      }

      return user || null;
    } catch (error) {
      logger.error('Error finding user by OAuth provider', { 
        provider, 
        providerId, 
        error 
      });
      throw error;
    }
  }

  static async linkOAuthAccount(
    userId: string,
    provider: string,
    providerId: string,
    oauthData: any,
    client?: PoolClient
  ): Promise<void> {
    const now = new Date();
    
    const oauthQuery = `
      INSERT INTO oauth_accounts (user_id, provider, provider_id, access_token, refresh_token, profile_data, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (provider, provider_id) 
      DO UPDATE SET 
        access_token = $4,
        refresh_token = $5,
        profile_data = $6,
        updated_at = $8
    `;

    const oauthValues = [
      userId,
      provider,
      providerId,
      oauthData.accessToken || null,
      oauthData.refreshToken || null,
      JSON.stringify(oauthData.profile || {}),
      now,
      now,
    ];

    const updateUserQuery = `
      UPDATE users 
      SET oauth_providers = (
        SELECT COALESCE(
          jsonb_agg(DISTINCT elem), 
          '[]'::jsonb
        )
        FROM (
          SELECT jsonb_array_elements(COALESCE(oauth_providers::jsonb, '[]'::jsonb)) as elem
          UNION 
          SELECT $2::jsonb as elem
        ) sub
      )
      WHERE id = $1
    `;

    const updateUserValues = [userId, JSON.stringify(provider)];

    try {
      await inTransaction(client, async (c) => {
        await c.query(oauthQuery, oauthValues);
        await c.query(updateUserQuery, updateUserValues);
      });

      logger.info('OAuth account linked successfully', { 
        userId, 
        provider, 
        providerId 
      });
    } catch (error) {
      logger.error('Error linking OAuth account', { 
        userId, 
        provider, 
        providerId, 
        error 
      });
      throw error;
    }
  }

  static async updateOAuthTokens(
    userId: string,
    provider: string,
    tokens: { accessToken?: string; refreshToken?: string },
    client?: PoolClient
  ): Promise<void> {
    const query = `
      UPDATE oauth_accounts 
      SET access_token = $1, refresh_token = $2, updated_at = $3
      WHERE user_id = $4 AND provider = $5
    `;

    const values = [
      tokens.accessToken || null,
      tokens.refreshToken || null,
      new Date(),
      userId,
      provider,
    ];

    try {
      await (client ? client.query(query, values) : db.query(query, values));
      logger.info('OAuth tokens updated', { userId, provider });
    } catch (error) {
      logger.error('Error updating OAuth tokens', { 
        userId, 
        provider, 
        error 
      });
      throw error;
    }
  }

  static async getOAuthAccounts(
    userId: string,
    client?: PoolClient
  ): Promise<OAuthAccount[]> {
    const query = `
      SELECT * FROM oauth_accounts 
      WHERE user_id = $1 
      ORDER BY created_at DESC
    `;

    const values = [userId];

    try {
      const result = client
        ? await client.query(query, values)
        : await db.query(query, values);

      return result.rows.map(row => ({
        ...row,
        profile_data: parseJsonColumn<Record<string, unknown>>(row.profile_data, {}),
      }));
    } catch (error) {
      logger.error('Error getting OAuth accounts', { userId, error });
      throw error;
    }
  }

  static async unlinkOAuthAccount(
    userId: string,
    provider: string,
    client?: PoolClient
  ): Promise<boolean> {
    const deleteQuery = `
      DELETE FROM oauth_accounts 
      WHERE user_id = $1 AND provider = $2
    `;

    const updateUserQuery = `
      UPDATE users 
      SET oauth_providers = (
        SELECT COALESCE(
          jsonb_agg(elem), 
          '[]'::jsonb
        )
        FROM (
          SELECT jsonb_array_elements(COALESCE(oauth_providers::jsonb, '[]'::jsonb)) as elem
          WHERE elem::text != $2::text
        ) sub
      )
      WHERE id = $1
    `;

    const values = [userId, provider];

    try {
      const result = await inTransaction(client, async (c) => {
        const deleted = await c.query(deleteQuery, values);
        await c.query(updateUserQuery, values);
        return deleted;
      });

      const unlinked = (result.rowCount ?? 0) > 0;
      if (unlinked) {
        logger.info('OAuth account unlinked successfully', { userId, provider });
      }
      return unlinked;
    } catch (error) {
      logger.error('Error unlinking OAuth account', { 
        userId, 
        provider, 
        error 
      });
      throw error;
    }
  }

  private static parseFullName(name: string): [string | null, string | null] {
    if (!name) return [null, null];
    
    const parts = name.trim().split(' ');
    if (parts.length === 1) {
      return [parts[0], null];
    }
    
    const firstName = parts[0];
    const lastName = parts.slice(1).join(' ');
    return [firstName, lastName];
  }
}