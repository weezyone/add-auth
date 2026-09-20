/**
 * SQL Injection Prevention Middleware
 * Implements comprehensive SQL injection protection and detection
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * SQL Injection Detection Configuration
 */
export interface SQLInjectionConfig {
  strict?: boolean;
  whitelistedFields?: string[];
  customPatterns?: RegExp[];
  logAttempts?: boolean;
  blockRequests?: boolean;
}

/**
 * Common SQL injection patterns
 */
const sqlInjectionPatterns = [
  // Basic SQL injection patterns
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE|CAST|CONVERT)\b)/gi,
  
  // SQL comments
  /(--|\*\/|\*\*|#)/gi,
  
  // SQL quotes and escapes
  /('|(\\')|('')|(%27)|(%22))/gi,
  
  // SQL logic operators
  /(\b(AND|OR|NOT|XOR)\b.*\b(TRUE|FALSE|\d+\s*=\s*\d+|\d+\s*<\s*\d+|\d+\s*>\s*\d+))/gi,
  
  // SQL functions
  /(\b(SUBSTRING|CHAR|ASCII|CONCAT|CAST|CONVERT|LOAD_FILE|OUTFILE|DUMPFILE|BENCHMARK|SLEEP|DELAY|WAITFOR)\b)/gi,
  
  // SQL system tables and schemas
  /(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|SYSUSERS|MASTER|TEMPDB|MSDB|MODEL)\b)/gi,
  
  // SQL injection specific patterns
  /(\b(0x[0-9a-fA-F]+|HAVING|GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET)\b)/gi,
  
  // SQL union-based injection
  /(\bUNION\b.*\bSELECT\b)/gi,
  
  // SQL boolean-based injection
  /(\b(AND|OR)\b.*\b(\d+\s*=\s*\d+|\d+\s*<>\s*\d+))/gi,
  
  // SQL time-based injection
  /(\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\b)/gi,
  
  // SQL error-based injection
  /(\b(EXTRACTVALUE|UPDATEXML|EXP|CAST|CONVERT)\b.*\()/gi,
  
  // SQL stacked queries
  /(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC))/gi,
  
  // SQL hex encoding
  /(0x[0-9a-fA-F]+)/gi,
  
  // SQL concatenation
  /(\|\||CONCAT\()/gi,
  
  // SQL version detection
  /(\b(@@version|version\(\)|user\(\)|database\(\)|current_user)\b)/gi,
  
  // SQL privilege escalation
  /(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)/gi,
  
  // SQL stored procedures
  /(\b(sp_|xp_|cmdshell|sp_password|sp_helpdb)\b)/gi,
  
  // NoSQL injection patterns
  /(\$where|\$ne|\$gt|\$lt|\$regex|\$or|\$and|\$in|\$nin)/gi,
  
  // Advanced patterns
  /(\b(CHAR|CHR|ASCII|ORD|HEX|UNHEX|LENGTH|SUBSTR|SUBSTRING|LEFT|RIGHT|MID|REVERSE|CONCAT|CONCAT_WS|LCASE|UCASE|LOWER|UPPER|TRIM|LTRIM|RTRIM|REPLACE|REPEAT|SPACE|STUFF|SOUNDEX|DIFFERENCE|QUOTENAME|REPLICATE|REVERSE|PATINDEX|CHARINDEX|LEN|DATALENGTH|RIGHT|LEFT|SUBSTRING|STUFF|REPLACE|REPLICATE|REVERSE|UPPER|LOWER|LTRIM|RTRIM|TRIM|SPACE|REPEAT|CONCAT|CONCAT_WS|LCASE|UCASE|SOUNDEX|DIFFERENCE|QUOTENAME|PATINDEX|CHARINDEX|LEN|DATALENGTH)\b)/gi
];

/**
 * Advanced SQL injection patterns (more strict)
 */
const advancedSQLPatterns = [
  // Blind SQL injection patterns
  /(\b(AND|OR)\b.*\b(SUBSTRING|SUBSTR|MID|LENGTH|ASCII|ORD|CHAR|CHR)\b)/gi,
  
  // Time-based blind SQL injection
  /(\b(AND|OR)\b.*\b(SLEEP|BENCHMARK|WAITFOR|DELAY|pg_sleep)\b)/gi,
  
  // Error-based SQL injection
  /(\b(EXTRACTVALUE|UPDATEXML|EXP|CAST|CONVERT)\b.*\()/gi,
  
  // Union-based SQL injection
  /(\bUNION\b.*\bSELECT\b.*\bFROM\b)/gi,
  
  // Stacked queries
  /(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE))/gi,
  
  // SQL injection with encoding
  /(CHAR\(|CHR\(|ASCII\(|0x[0-9a-fA-F]+)/gi,
  
  // Database fingerprinting
  /(\b(@@version|version\(\)|user\(\)|database\(\)|current_user|current_database|schema\(\)|system_user)\b)/gi,
  
  // Privilege escalation
  /(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE|sp_|xp_|cmdshell)\b)/gi,
  
  // Information gathering
  /(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|SYSUSERS|MASTER|TEMPDB|MSDB|MODEL|pg_|mysql\.|sqlite_)\b)/gi,
  
  // NoSQL injection
  /(\$where|\$ne|\$gt|\$lt|\$regex|\$or|\$and|\$in|\$nin|\$exists|\$type|\$size|\$all|\$elemMatch)/gi
];

/**
 * Detect SQL injection attempts in input
 */
export const detectSQLInjection = (input: string, config: SQLInjectionConfig = {}): { detected: boolean; patterns: string[] } => {
  if (typeof input !== 'string') {
    return { detected: false, patterns: [] };
  }

  const patterns = config.strict ? advancedSQLPatterns : sqlInjectionPatterns;
  const detectedPatterns: string[] = [];

  // Add custom patterns if provided
  if (config.customPatterns) {
    patterns.push(...config.customPatterns);
  }

  // URL decode the input first
  const decodedInput = decodeURIComponent(input);
  
  // Check against all patterns
  for (const pattern of patterns) {
    if (pattern.test(decodedInput)) {
      detectedPatterns.push(pattern.source);
    }
  }

  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns
  };
};

/**
 * Sanitize input to prevent SQL injection
 */
export const sanitizeSQLInput = (input: string): string => {
  if (typeof input !== 'string') {
    return input;
  }

  return input
    // Remove SQL comments
    .replace(/(--|\*\/|\*\*|#)/g, '')
    // Escape single quotes
    .replace(/'/g, "''")
    // Remove SQL keywords in dangerous contexts
    .replace(/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/gi, '')
    // Remove SQL functions
    .replace(/(\b(SUBSTRING|CHAR|ASCII|CONCAT|CAST|CONVERT|LOAD_FILE|OUTFILE|DUMPFILE|BENCHMARK|SLEEP|DELAY|WAITFOR)\b)/gi, '')
    // Remove semicolons (to prevent stacked queries)
    .replace(/;/g, '')
    // Remove SQL operators in dangerous contexts
    .replace(/(\b(AND|OR|NOT|XOR)\b.*\b(TRUE|FALSE|\d+\s*=\s*\d+))/gi, '')
    // Trim whitespace
    .trim();
};

/**
 * Sanitize object recursively
 */
export const sanitizeObjectSQL = (obj: any): any => {
  if (typeof obj === 'string') {
    return sanitizeSQLInput(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObjectSQL(item));
  }

  if (obj && typeof obj === 'object' && obj.constructor === Object) {
    const sanitized: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        // Sanitize both key and value
        const sanitizedKey = sanitizeSQLInput(key);
        sanitized[sanitizedKey] = sanitizeObjectSQL(obj[key]);
      }
    }
    return sanitized;
  }

  return obj;
};

/**
 * SQL injection prevention middleware
 */
export const sqlInjectionPrevention = (config: SQLInjectionConfig = {}) => {
  const defaultConfig: SQLInjectionConfig = {
    strict: true,
    whitelistedFields: [],
    customPatterns: [],
    logAttempts: true,
    blockRequests: true
  };

  const cfg = { ...defaultConfig, ...config };

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const checkInput = (obj: any, path: string = '', isWhitelisted: boolean = false) => {
        if (typeof obj === 'string') {
          // Skip whitelisted fields
          if (isWhitelisted || cfg.whitelistedFields?.includes(path)) {
            return null;
          }

          const detection = detectSQLInjection(obj, cfg);
          if (detection.detected) {
            if (cfg.logAttempts) {
              logger.warn('SQL injection attempt detected', {
                path,
                patterns: detection.patterns,
                input: obj.substring(0, 200),
                ip: req.ip,
                userAgent: req.get('user-agent'),
                method: req.method,
                url: req.url,
                headers: req.headers
              });
            }

            if (cfg.blockRequests) {
              return void res.status(400).json({
                error: 'Malicious input detected',
                message: 'Request blocked due to potential SQL injection attack'
              });
            }
          }
        } else if (Array.isArray(obj)) {
          for (let i = 0; i < obj.length; i++) {
            const result = checkInput(obj[i], `${path}[${i}]`, isWhitelisted);
            if (result) return result;
          }
        } else if (obj && typeof obj === 'object') {
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              const fieldPath = path ? `${path}.${key}` : key;
              const isFieldWhitelisted = cfg.whitelistedFields?.includes(fieldPath);
              const result = checkInput(obj[key], fieldPath, isFieldWhitelisted);
              if (result) return result;
            }
          }
        }
        return null;
      };

      // Check body, query, and params
      const bodyResult = req.body ? checkInput(req.body, 'body') : null;
      if (bodyResult) return bodyResult;

      const queryResult = req.query ? checkInput(req.query, 'query') : null;
      if (queryResult) return queryResult;

      const paramsResult = req.params ? checkInput(req.params, 'params') : null;
      if (paramsResult) return paramsResult;

      next();
    } catch (error) {
      logger.error('SQL injection prevention middleware failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Security validation failed'
      });
    }
  };
};

/**
 * SQL injection sanitization middleware
 */
export const sqlInjectionSanitization = (config: SQLInjectionConfig = {}) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObjectSQL(req.body);
      }

      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObjectSQL(req.query);
      }

      // Sanitize route parameters
      if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObjectSQL(req.params);
      }

      next();
    } catch (error) {
      logger.error('SQL injection sanitization failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Input sanitization failed'
      });
    }
  };
};

/**
 * Parameterized query helper
 */
export const createParameterizedQuery = (query: string, params: any[]): { text: string; values: any[] } => {
  return {
    text: query,
    values: params
  };
};

/**
 * Safe query builder for PostgreSQL
 */
export const buildSafeQuery = (table: string, conditions: { [key: string]: any }, operation: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' = 'SELECT'): { text: string; values: any[] } => {
  const allowedTables = ['users', 'sessions', 'roles', 'audit_logs']; // Define allowed tables
  
  if (!allowedTables.includes(table)) {
    throw new Error('Invalid table name');
  }

  const keys = Object.keys(conditions);
  const values = Object.values(conditions);

  switch (operation) {
    case 'SELECT':
      const whereClause = keys.map((key, index) => `${key} = $${index + 1}`).join(' AND ');
      return {
        text: `SELECT * FROM ${table} WHERE ${whereClause}`,
        values: values
      };
    
    case 'INSERT':
      const insertKeys = keys.join(', ');
      const insertPlaceholders = keys.map((_, index) => `$${index + 1}`).join(', ');
      return {
        text: `INSERT INTO ${table} (${insertKeys}) VALUES (${insertPlaceholders}) RETURNING *`,
        values: values
      };
    
    case 'UPDATE':
      const updateSet = keys.map((key, index) => `${key} = $${index + 1}`).join(', ');
      return {
        text: `UPDATE ${table} SET ${updateSet} WHERE id = $${keys.length + 1}`,
        values: [...values, conditions.id]
      };
    
    case 'DELETE':
      const deleteWhere = keys.map((key, index) => `${key} = $${index + 1}`).join(' AND ');
      return {
        text: `DELETE FROM ${table} WHERE ${deleteWhere}`,
        values: values
      };
    
    default:
      throw new Error('Invalid operation');
  }
};

/**
 * Validate table and column names
 */
export const validateIdentifier = (identifier: string): boolean => {
  // Only allow alphanumeric characters and underscores
  const validPattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
  return validPattern.test(identifier);
};

/**
 * Escape SQL identifiers (table names, column names)
 */
export const escapeIdentifier = (identifier: string): string => {
  if (!validateIdentifier(identifier)) {
    throw new Error('Invalid SQL identifier');
  }
  return `"${identifier.replace(/"/g, '""')}"`;
};

/**
 * Advanced query builder with comprehensive validation
 */
export class SecureQueryBuilder {
  private allowedTables: Set<string>;
  private allowedColumns: Map<string, Set<string>>;
  private allowedOperators: Set<string>;
  
  constructor() {
    this.allowedTables = new Set([
      'users', 'sessions', 'roles', 'audit_logs', 'permissions',
      'user_roles', 'role_permissions', 'oauth_tokens', 'password_resets'
    ]);
    
    this.allowedColumns = new Map([
      ['users', new Set(['id', 'email', 'username', 'password_hash', 'first_name', 'last_name', 'created_at', 'updated_at', 'last_login', 'status', 'email_verified'])],
      ['sessions', new Set(['id', 'user_id', 'session_token', 'expires_at', 'created_at', 'ip_address', 'user_agent'])],
      ['roles', new Set(['id', 'name', 'description', 'created_at', 'updated_at'])],
      ['audit_logs', new Set(['id', 'user_id', 'action', 'resource', 'details', 'ip_address', 'created_at'])],
      ['permissions', new Set(['id', 'name', 'description', 'resource', 'action'])]
    ]);
    
    this.allowedOperators = new Set([
      '=', '!=', '<>', '<', '>', '<=', '>=', 'LIKE', 'ILIKE', 'IN', 'NOT IN',
      'IS NULL', 'IS NOT NULL', 'BETWEEN', 'NOT BETWEEN'
    ]);
  }
  
  validateTable(table: string): boolean {
    return this.allowedTables.has(table);
  }
  
  validateColumn(table: string, column: string): boolean {
    const tableColumns = this.allowedColumns.get(table);
    return tableColumns ? tableColumns.has(column) : false;
  }
  
  validateOperator(operator: string): boolean {
    return this.allowedOperators.has(operator.toUpperCase());
  }
  
  /**
   * Build secure SELECT query
   */
  select(table: string, columns: string[] = ['*'], conditions: { [key: string]: any } = {}, options: {
    limit?: number;
    offset?: number;
    orderBy?: { column: string; direction: 'ASC' | 'DESC' }[];
    groupBy?: string[];
  } = {}): { text: string; values: any[] } {
    if (!this.validateTable(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    
    // Validate columns
    const validColumns = columns.filter(col => {
      if (col === '*') return true;
      return this.validateColumn(table, col);
    });
    
    if (validColumns.length === 0) {
      throw new Error('No valid columns specified');
    }
    
    let query = `SELECT ${validColumns.join(', ')} FROM ${escapeIdentifier(table)}`;
    const values: any[] = [];
    let paramIndex = 1;
    
    // WHERE clause
    if (Object.keys(conditions).length > 0) {
      const whereClauses: string[] = [];
      for (const [column, value] of Object.entries(conditions)) {
        if (!this.validateColumn(table, column)) {
          throw new Error(`Invalid column: ${column}`);
        }
        whereClauses.push(`${escapeIdentifier(column)} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
      query += ` WHERE ${whereClauses.join(' AND ')}`;
    }
    
    // GROUP BY
    if (options.groupBy && options.groupBy.length > 0) {
      const validGroupColumns = options.groupBy.filter(col => this.validateColumn(table, col));
      if (validGroupColumns.length > 0) {
        query += ` GROUP BY ${validGroupColumns.map(escapeIdentifier).join(', ')}`;
      }
    }
    
    // ORDER BY
    if (options.orderBy && options.orderBy.length > 0) {
      const orderClauses = options.orderBy
        .filter(order => this.validateColumn(table, order.column))
        .map(order => `${escapeIdentifier(order.column)} ${order.direction}`);
      if (orderClauses.length > 0) {
        query += ` ORDER BY ${orderClauses.join(', ')}`;
      }
    }
    
    // LIMIT and OFFSET
    if (options.limit && options.limit > 0) {
      query += ` LIMIT $${paramIndex}`;
      values.push(Math.min(options.limit, 1000)); // Cap at 1000
      paramIndex++;
      
      if (options.offset && options.offset > 0) {
        query += ` OFFSET $${paramIndex}`;
        values.push(options.offset);
        paramIndex++;
      }
    }
    
    return { text: query, values };
  }
  
  /**
   * Build secure INSERT query
   */
  insert(table: string, data: { [key: string]: any }): { text: string; values: any[] } {
    if (!this.validateTable(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    
    const validEntries = Object.entries(data).filter(([column]) => 
      this.validateColumn(table, column)
    );
    
    if (validEntries.length === 0) {
      throw new Error('No valid columns for insert');
    }
    
    const columns = validEntries.map(([column]) => escapeIdentifier(column));
    const placeholders = validEntries.map((_, index) => `$${index + 1}`);
    const values = validEntries.map(([, value]) => value);
    
    const query = `INSERT INTO ${escapeIdentifier(table)} (${columns.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`;
    
    return { text: query, values };
  }
  
  /**
   * Build secure UPDATE query
   */
  update(table: string, data: { [key: string]: any }, conditions: { [key: string]: any }): { text: string; values: any[] } {
    if (!this.validateTable(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    
    const validDataEntries = Object.entries(data).filter(([column]) => 
      this.validateColumn(table, column)
    );
    
    const validConditionEntries = Object.entries(conditions).filter(([column]) => 
      this.validateColumn(table, column)
    );
    
    if (validDataEntries.length === 0) {
      throw new Error('No valid columns for update');
    }
    
    if (validConditionEntries.length === 0) {
      throw new Error('No valid conditions for update');
    }
    
    const setClauses = validDataEntries.map(([column], index) => 
      `${escapeIdentifier(column)} = $${index + 1}`
    );
    
    const whereClauses = validConditionEntries.map(([column], index) => 
      `${escapeIdentifier(column)} = $${validDataEntries.length + index + 1}`
    );
    
    const values = [
      ...validDataEntries.map(([, value]) => value),
      ...validConditionEntries.map(([, value]) => value)
    ];
    
    const query = `UPDATE ${escapeIdentifier(table)} SET ${setClauses.join(', ')} WHERE ${whereClauses.join(' AND ')} RETURNING *`;
    
    return { text: query, values };
  }
  
  /**
   * Build secure DELETE query
   */
  delete(table: string, conditions: { [key: string]: any }): { text: string; values: any[] } {
    if (!this.validateTable(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    
    const validConditionEntries = Object.entries(conditions).filter(([column]) => 
      this.validateColumn(table, column)
    );
    
    if (validConditionEntries.length === 0) {
      throw new Error('No valid conditions for delete');
    }
    
    const whereClauses = validConditionEntries.map(([column], index) => 
      `${escapeIdentifier(column)} = $${index + 1}`
    );
    
    const values = validConditionEntries.map(([, value]) => value);
    
    const query = `DELETE FROM ${escapeIdentifier(table)} WHERE ${whereClauses.join(' AND ')}`;
    
    return { text: query, values };
  }
}

/**
 * Global secure query builder instance
 */
export const secureQueryBuilder = new SecureQueryBuilder();

/**
 * SQL injection detection for specific fields with enhanced tracking
 */
export const sqlInjectionDetectionFields = (fields: string[], config: SQLInjectionConfig = {}) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const checkFields = (obj: any, fieldsList: string[]) => {
        for (const field of fieldsList) {
          if (obj[field] && typeof obj[field] === 'string') {
            const detection = detectSQLInjection(obj[field], config);
            if (detection.detected) {
              logger.warn('SQL injection detected in specific field', {
                field,
                patterns: detection.patterns,
                input: obj[field].substring(0, 200),
                ip: req.ip,
                userAgent: req.get('user-agent'),
                method: req.method,
                url: req.url,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
              });
              
              // Track repeated attempts
              const attemptKey = `${req.ip}_${field}_sql_injection`;
              logger.warn('Tracking SQL injection attempt', { attemptKey });
              
              return void res.status(400).json({
                error: 'Malicious input detected',
                message: `SQL injection detected in field: ${field}`,
                timestamp: new Date().toISOString()
              });
            }
          }
        }
        return null;
      };

      // Check specified fields in body and query
      if (req.body && typeof req.body === 'object') {
        const result = checkFields(req.body, fields);
        if (result) return result;
      }

      if (req.query && typeof req.query === 'object') {
        const result = checkFields(req.query, fields);
        if (result) return result;
      }

      next();
    } catch (error) {
      logger.error('SQL injection detection for fields failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Security validation failed'
      });
    }
  };
};

/**
 * Transaction wrapper with SQL injection protection
 */
export const secureTransaction = async <T>(
  client: any,
  operations: (builder: SecureQueryBuilder) => Promise<T>
): Promise<T> => {
  try {
    await client.query('BEGIN');
    const result = await operations(secureQueryBuilder);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Secure transaction failed:', error);
    throw error;
  }
};

/**
 * Prepared statement cache to prevent SQL injection
 */
class PreparedStatementCache {
  private cache = new Map<string, string>();
  private maxSize = 1000;
  
  getKey(query: string, params: any[]): string {
    return crypto.createHash('sha256')
      .update(query + JSON.stringify(params.map(p => typeof p)))
      .digest('hex');
  }
  
  get(key: string): string | undefined {
    return this.cache.get(key);
  }
  
  set(key: string, preparedQuery: string): void {
    if (this.cache.size >= this.maxSize) {
      // Remove oldest entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, preparedQuery);
  }
  
  clear(): void {
    this.cache.clear();
  }
  
  getStats(): { size: number; maxSize: number; hitRate: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      hitRate: 0 // Would need hit/miss tracking
    };
  }
}

export const preparedStatementCache = new PreparedStatementCache();

/**
 * Enhanced parameterized query with caching
 */
export const createSecureParameterizedQuery = (
  query: string,
  params: any[],
  options: { useCache?: boolean; validateParams?: boolean } = {}
): { text: string; values: any[]; cacheKey?: string } => {
  const { useCache = true, validateParams = true } = options;
  
  if (validateParams) {
    // Validate parameter types and values
    params.forEach((param, index) => {
      if (typeof param === 'string') {
        const detection = detectSQLInjection(param);
        if (detection.detected) {
          throw new Error(`SQL injection detected in parameter ${index + 1}`);
        }
      }
    });
  }
  
  let cacheKey: string | undefined;
  
  if (useCache) {
    cacheKey = preparedStatementCache.getKey(query, params);
    const cachedQuery = preparedStatementCache.get(cacheKey);
    
    if (cachedQuery) {
      return { text: cachedQuery, values: params, cacheKey };
    }
  }
  
  // Validate query structure
  const normalizedQuery = query.trim().toUpperCase();
  const allowedStarters = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WITH'];
  
  if (!allowedStarters.some(starter => normalizedQuery.startsWith(starter))) {
    throw new Error('Invalid query type');
  }
  
  const result = { text: query, values: params, cacheKey };
  
  if (useCache && cacheKey) {
    preparedStatementCache.set(cacheKey, query);
  }
  
  return result;
};

/**
 * SQL injection monitoring and alerting
 */
export const sqlInjectionMonitor = {
  attempts: new Map<string, { count: number; lastAttempt: Date; patterns: Set<string> }>(),
  
  recordAttempt(ip: string, pattern: string, userAgent?: string): void {
    const key = ip;
    const current = this.attempts.get(key) || {
      count: 0,
      lastAttempt: new Date(),
      patterns: new Set()
    };
    
    current.count++;
    current.lastAttempt = new Date();
    current.patterns.add(pattern);
    
    this.attempts.set(key, current);
    
    // Alert on repeated attempts
    if (current.count >= 5) {
      logger.error('Critical SQL injection attempt pattern detected', {
        ip,
        attempts: current.count,
        patterns: Array.from(current.patterns),
        userAgent,
        severity: 'CRITICAL'
      });
    }
  },
  
  getStats(): any {
    const stats = {
      totalIPs: this.attempts.size,
      totalAttempts: 0,
      topOffenders: [] as any[],
      commonPatterns: new Map<string, number>()
    };
    
    for (const [ip, data] of this.attempts.entries()) {
      stats.totalAttempts += data.count;
      stats.topOffenders.push({ ip, ...data, patterns: Array.from(data.patterns) });
      
      for (const pattern of data.patterns) {
        stats.commonPatterns.set(pattern, (stats.commonPatterns.get(pattern) || 0) + 1);
      }
    }
    
    stats.topOffenders.sort((a, b) => b.count - a.count);
    stats.topOffenders = stats.topOffenders.slice(0, 10);
    
    return stats;
  },
  
  cleanup(olderThanHours: number = 24): void {
    const cutoff = new Date(Date.now() - olderThanHours * 60 * 60 * 1000);
    let cleaned = 0;
    
    for (const [key, data] of this.attempts.entries()) {
      if (data.lastAttempt < cutoff) {
        this.attempts.delete(key);
        cleaned++;
      }
    }
    
    logger.info('SQL injection attempt cleanup completed', {
      cleaned,
      remaining: this.attempts.size
    });
  }
};

// Periodic cleanup
setInterval(() => {
  sqlInjectionMonitor.cleanup();
}, 60 * 60 * 1000); // Every hour

export default {
  sqlInjectionPrevention,
  sqlInjectionSanitization,
  sqlInjectionDetectionFields,
  detectSQLInjection,
  sanitizeSQLInput,
  sanitizeObjectSQL,
  createParameterizedQuery,
  createSecureParameterizedQuery,
  buildSafeQuery,
  validateIdentifier,
  escapeIdentifier,
  SecureQueryBuilder,
  secureQueryBuilder,
  secureTransaction,
  preparedStatementCache,
  sqlInjectionMonitor
};