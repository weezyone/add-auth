export interface AuditLog {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  timestamp: Date;
  ip_address: string;
  user_agent: string | null;
  details: Record<string, any>;
  success: boolean;
  error_message: string | null;
}

export interface CreateAuditLogInput {
  user_id?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip_address: string;
  user_agent?: string | null;
  details?: Record<string, any>;
  success: boolean;
  error_message?: string | null;
}

export enum AuditActions {
  // Authentication
  LOGIN = 'login',
  LOGOUT = 'logout',
  LOGIN_FAILED = 'login_failed',
  PASSWORD_CHANGE = 'password_change',
  PASSWORD_RESET = 'password_reset',
  
  // User Management
  USER_CREATE = 'user_create',
  USER_UPDATE = 'user_update',
  USER_DELETE = 'user_delete',
  USER_SUSPEND = 'user_suspend',
  USER_ACTIVATE = 'user_activate',
  
  // Role Management
  ROLE_ASSIGN = 'role_assign',
  ROLE_REVOKE = 'role_revoke',
  ROLE_CREATE = 'role_create',
  ROLE_UPDATE = 'role_update',
  ROLE_DELETE = 'role_delete',
  
  // Session Management
  SESSION_CREATE = 'session_create',
  SESSION_INVALIDATE = 'session_invalidate',
  SESSION_EXTEND = 'session_extend',
}

export enum ResourceTypes {
  USER = 'user',
  ROLE = 'role',
  SESSION = 'session',
  SYSTEM = 'system',
}