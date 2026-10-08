/**
 * Validation Middleware
 * Implements comprehensive input validation using Joi for request validation
 */

import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { logger } from '../utils/logger';
import { detectXSS } from './xssProtection';
import { detectSQLInjection } from './sqlInjectionPrevention';
import { 
  detectLanguage, 
  getLocalizedMessage, 
  getLocalizedError, 
  createValidationErrorResponse,
  SupportedLanguage 
} from './localization';

/**
 * Validation target types
 */
export type ValidationTarget = 'body' | 'query' | 'params' | 'headers';

class RequestFieldAssigner {
  static set(req: Request, target: ValidationTarget, value: unknown): void {
    switch (target) {
      case 'body':
        req.body = value;
        return;
      case 'query':
        req.query = value as Request['query'];
        return;
      case 'params':
        req.params = value as Request['params'];
        return;
      case 'headers':
        Object.assign(req.headers, value as Request['headers']);
        return;
      default: {
        const exhaustive: never = target;
        throw new Error(`Unsupported validation target: ${String(exhaustive)}`);
      }
    }
  }
}

/**
 * Validation options
 */
export interface ValidationOptions {
  abortEarly?: boolean;
  allowUnknown?: boolean;
  stripUnknown?: boolean;
  target?: ValidationTarget;
  customMessages?: { [key: string]: string };
  enableXSSDetection?: boolean;
  enableSQLInjectionDetection?: boolean;
  enablePasswordComplexity?: boolean;
  enableRateLimiting?: boolean;
  customValidators?: { [key: string]: (value: any) => boolean | string };
}

/**
 * Common validation schemas
 */
export const validationSchemas = {
  // User registration schema
  userRegistration: Joi.object({
    username: Joi.string()
      .alphanum()
      .min(3)
      .max(30)
      .required()
      .messages({
        'string.alphanum': 'Username must only contain alphanumeric characters',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 30 characters',
        'any.required': 'Username is required'
      }),
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.max': 'Password cannot exceed 128 characters',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'Password is required'
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required'
      }),
    firstName: Joi.string()
      .min(1)
      .max(50)
      .pattern(new RegExp('^[a-zA-Z\\s]+$'))
      .optional()
      .messages({
        'string.min': 'First name must be at least 1 character long',
        'string.max': 'First name cannot exceed 50 characters',
        'string.pattern.base': 'First name must only contain letters and spaces'
      }),
    lastName: Joi.string()
      .min(1)
      .max(50)
      .pattern(new RegExp('^[a-zA-Z\\s]+$'))
      .optional()
      .messages({
        'string.min': 'Last name must be at least 1 character long',
        'string.max': 'Last name cannot exceed 50 characters',
        'string.pattern.base': 'Last name must only contain letters and spaces'
      })
  }),

  // User login schema
  userLogin: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
    password: Joi.string()
      .min(1)
      .max(128)
      .required()
      .messages({
        'string.min': 'Password is required',
        'string.max': 'Password cannot exceed 128 characters',
        'any.required': 'Password is required'
      }),
    rememberMe: Joi.boolean()
      .optional()
      .default(false)
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string()
      .required()
      .messages({
        'any.required': 'Refresh token is required'
      })
  }),

  emailVerification: Joi.object({
    token: Joi.string()
      .trim()
      .max(256)
      .required()
      .messages({
        'any.required': 'Verification token is required'
      })
  }),

  resendVerification: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      })
  }),

  emailParam: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      })
  }),

  // Password reset request schema
  passwordResetRequest: Joi.object({
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      })
  }),

  // Password reset schema
  passwordReset: Joi.object({
    token: Joi.string()
      .required()
      .messages({
        'any.required': 'Reset token is required'
      }),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
      .required()
      .messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.max': 'Password cannot exceed 128 characters',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'Password is required'
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required'
      })
  }),

  // Password change schema
  passwordChange: Joi.object({
    currentPassword: Joi.string()
      .required()
      .messages({
        'any.required': 'Current password is required'
      }),
    newPassword: Joi.string()
      .min(8)
      .max(128)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
      .required()
      .messages({
        'string.min': 'New password must be at least 8 characters long',
        'string.max': 'New password cannot exceed 128 characters',
        'string.pattern.base': 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
        'any.required': 'New password is required'
      }),
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Password confirmation is required'
      })
  }),

  // User profile update schema
  userProfileUpdate: Joi.object({
    firstName: Joi.string()
      .min(1)
      .max(50)
      .pattern(new RegExp('^[a-zA-Z\\s]+$'))
      .optional()
      .messages({
        'string.min': 'First name must be at least 1 character long',
        'string.max': 'First name cannot exceed 50 characters',
        'string.pattern.base': 'First name must only contain letters and spaces'
      }),
    lastName: Joi.string()
      .min(1)
      .max(50)
      .pattern(new RegExp('^[a-zA-Z\\s]+$'))
      .optional()
      .messages({
        'string.min': 'Last name must be at least 1 character long',
        'string.max': 'Last name cannot exceed 50 characters',
        'string.pattern.base': 'Last name must only contain letters and spaces'
      }),
    email: Joi.string()
      .email({ tlds: { allow: false } })
      .optional()
      .messages({
        'string.email': 'Please provide a valid email address'
      })
  }),

  // Common parameter validation
  idParam: Joi.object({
    id: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid ID format',
        'any.required': 'ID is required'
      })
  }),

  // Pagination schema
  pagination: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .optional()
      .default(1)
      .messages({
        'number.integer': 'Page must be an integer',
        'number.min': 'Page must be at least 1'
      }),
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .optional()
      .default(10)
      .messages({
        'number.integer': 'Limit must be an integer',
        'number.min': 'Limit must be at least 1',
        'number.max': 'Limit cannot exceed 100'
      }),
    sortBy: Joi.string()
      .valid('createdAt', 'updatedAt', 'name', 'email')
      .optional()
      .default('createdAt')
      .messages({
        'any.only': 'Invalid sort field'
      }),
    sortOrder: Joi.string()
      .valid('asc', 'desc')
      .optional()
      .default('desc')
      .messages({
        'any.only': 'Sort order must be either "asc" or "desc"'
      })
  }),

  // Two-factor authentication schema
  twoFactorAuth: Joi.object({
    token: Joi.string()
      .length(6)
      .pattern(/^[0-9]+$/)
      .required()
      .messages({
        'string.length': 'Two-factor token must be exactly 6 digits',
        'string.pattern.base': 'Two-factor token must contain only numbers',
        'any.required': 'Two-factor token is required'
      }),
    remember: Joi.boolean()
      .optional()
      .default(false)
  }),

  // Device registration schema
  deviceRegistration: Joi.object({
    deviceName: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z0-9\s\-_]+$/)
      .required()
      .messages({
        'string.min': 'Device name must be at least 1 character',
        'string.max': 'Device name cannot exceed 100 characters',
        'string.pattern.base': 'Device name can only contain letters, numbers, spaces, hyphens, and underscores',
        'any.required': 'Device name is required'
      }),
    deviceType: Joi.string()
      .valid('mobile', 'desktop', 'tablet', 'other')
      .required()
      .messages({
        'any.only': 'Device type must be one of: mobile, desktop, tablet, other',
        'any.required': 'Device type is required'
      }),
    fingerprint: Joi.string()
      .required()
      .messages({
        'any.required': 'Device fingerprint is required'
      })
  }),

  // Account preferences schema
  accountPreferences: Joi.object({
    theme: Joi.string()
      .valid('light', 'dark', 'auto')
      .optional()
      .default('auto')
      .messages({
        'any.only': 'Theme must be one of: light, dark, auto'
      }),
    language: Joi.string()
      .valid('en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja', 'ko')
      .optional()
      .default('en')
      .messages({
        'any.only': 'Language must be a valid language code'
      }),
    notifications: Joi.object({
      email: Joi.boolean().optional().default(true),
      sms: Joi.boolean().optional().default(false),
      push: Joi.boolean().optional().default(true),
      marketing: Joi.boolean().optional().default(false)
    }).optional(),
    timezone: Joi.string()
      .optional()
      .default('UTC')
      .messages({
        'string.base': 'Timezone must be a valid timezone string'
      })
  }),

  // Session management schema
  sessionManagement: Joi.object({
    sessionId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid session ID format',
        'any.required': 'Session ID is required'
      })
  }),

  // API key generation schema
  apiKeyGeneration: Joi.object({
    name: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z0-9\s\-_]+$/)
      .required()
      .messages({
        'string.min': 'API key name must be at least 1 character',
        'string.max': 'API key name cannot exceed 100 characters',
        'string.pattern.base': 'API key name can only contain letters, numbers, spaces, hyphens, and underscores',
        'any.required': 'API key name is required'
      }),
    permissions: Joi.array()
      .items(Joi.string().valid('read', 'write', 'delete', 'admin'))
      .min(1)
      .required()
      .messages({
        'array.min': 'At least one permission must be specified',
        'any.required': 'Permissions are required'
      }),
    expiresAt: Joi.date()
      .greater('now')
      .optional()
      .messages({
        'date.greater': 'Expiration date must be in the future'
      })
  }),

  // OAuth schema
  oauth: Joi.object({
    provider: Joi.string()
      .valid('google', 'github', 'facebook', 'twitter')
      .required()
      .messages({
        'any.only': 'Invalid OAuth provider',
        'any.required': 'OAuth provider is required'
      }),
    code: Joi.string()
      .required()
      .messages({
        'any.required': 'OAuth code is required'
      }),
    state: Joi.string()
      .optional()
      .messages({
        'string.base': 'OAuth state must be a string'
      }),
    redirectUri: Joi.string()
      .uri()
      .optional()
      .messages({
        'string.uri': 'Invalid redirect URI format'
      })
  }),

  // Role management schemas
  roleCreate: Joi.object({
    name: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .required()
      .messages({
        'string.min': 'Role name must be at least 1 character',
        'string.max': 'Role name cannot exceed 100 characters',
        'string.pattern.base': 'Role name can only contain letters, numbers, underscores, and hyphens',
        'any.required': 'Role name is required'
      }),
    description: Joi.string()
      .max(500)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Description cannot exceed 500 characters'
      }),
    permissions: Joi.array()
      .items(Joi.string().pattern(/^[a-z_]+:[a-z_]+$/))
      .min(1)
      .required()
      .messages({
        'array.min': 'At least one permission must be specified',
        'any.required': 'Permissions are required',
        'string.pattern.base': 'Permissions must be in format "resource:action"'
      })
  }),

  roleUpdate: Joi.object({
    name: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .optional()
      .messages({
        'string.min': 'Role name must be at least 1 character',
        'string.max': 'Role name cannot exceed 100 characters',
        'string.pattern.base': 'Role name can only contain letters, numbers, underscores, and hyphens'
      }),
    description: Joi.string()
      .max(500)
      .optional()
      .allow('')
      .messages({
        'string.max': 'Description cannot exceed 500 characters'
      }),
    permissions: Joi.array()
      .items(Joi.string().pattern(/^[a-z_]+:[a-z_]+$/))
      .min(1)
      .optional()
      .messages({
        'array.min': 'At least one permission must be specified',
        'string.pattern.base': 'Permissions must be in format "resource:action"'
      })
  }),

  roleAssign: Joi.object({
    userId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid user ID format',
        'any.required': 'User ID is required'
      }),
    roleId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid role ID format',
        'any.required': 'Role ID is required'
      })
  }),

  roleRemove: Joi.object({
    userId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid user ID format',
        'any.required': 'User ID is required'
      }),
    roleId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid role ID format',
        'any.required': 'Role ID is required'
      })
  })
};

/**
 * Create validation middleware
 */
export const validate = (schema: Joi.ObjectSchema, options: ValidationOptions = {}) => {
  const defaultOptions: ValidationOptions = {
    abortEarly: false,
    allowUnknown: true,
    stripUnknown: true,
    target: 'body',
    enableXSSDetection: true,
    enableSQLInjectionDetection: true,
    enablePasswordComplexity: true,
    customValidators: {}
  };

  const opts = { ...defaultOptions, ...options };

  return async (req: Request, res: Response, next: NextFunction) => {
    const targetData = req[opts.target!];
    const language = detectLanguage(req);
    
    if (!targetData) {
      return void res.status(400).json({
        error: 'Validation failed',
        message: getLocalizedMessage('FIELD_REQUIRED', language),
        language,
        timestamp: new Date().toISOString()
      });
    }

    try {
      // Pre-validation security checks
      if (opts.enableXSSDetection && typeof targetData === 'object') {
        const xssResults = await performXSSDetection(targetData);
        if (xssResults.detected) {
          logger.warn('XSS attempt detected during validation', {
            target: opts.target,
            patterns: xssResults.patterns,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            path: req.path
          });
          const errorObj = getLocalizedError('XSS_ATTEMPT_DETECTED', language);
          return void res.status(400).json({
            error: 'Security validation failed',
            message: errorObj.message,
            code: errorObj.code,
            severity: errorObj.severity,
            language,
            timestamp: new Date().toISOString()
          });
        }
      }

      if (opts.enableSQLInjectionDetection && typeof targetData === 'object') {
        const sqlResults = await performSQLInjectionDetection(targetData);
        if (sqlResults.detected) {
          logger.warn('SQL injection attempt detected during validation', {
            target: opts.target,
            patterns: sqlResults.patterns,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            path: req.path
          });
          const errorObj = getLocalizedError('SQL_INJECTION_DETECTED', language);
          return void res.status(400).json({
            error: 'Security validation failed',
            message: errorObj.message,
            code: errorObj.code,
            severity: errorObj.severity,
            language,
            timestamp: new Date().toISOString()
          });
        }
      }

      // Joi validation
      const { error, value } = schema.validate(targetData, {
        abortEarly: opts.abortEarly,
        allowUnknown: opts.allowUnknown,
        stripUnknown: opts.stripUnknown
      });

      if (error) {
        const validationErrors = error.details.map(detail => {
          const field = detail.path.join('.');
          let errorCode = 'FIELD_REQUIRED';
          let params: Record<string, any> = {};
          
          // Map Joi error types to localized error codes
          switch (detail.type) {
            case 'any.required':
              errorCode = 'FIELD_REQUIRED';
              break;
            case 'string.email':
              errorCode = 'EMAIL_INVALID';
              break;
            case 'string.min':
              if (field === 'password') {
                errorCode = 'PASSWORD_TOO_SHORT';
                params = { minLength: detail.context?.limit || 8 };
              }
              break;
            case 'string.pattern.base':
              if (field === 'password') {
                errorCode = 'PASSWORD_COMPLEXITY';
              }
              break;
            case 'any.only':
              if (field === 'confirmPassword') {
                errorCode = 'PASSWORDS_NO_MATCH';
              }
              break;
            // Business rule error mappings
            case 'business.emailDomainNotAllowed':
              errorCode = 'EMAIL_DOMAIN_NOT_ALLOWED';
              params = detail.context || {};
              break;
            case 'business.passwordTooCommon':
              errorCode = 'PASSWORD_COMMON';
              break;
            case 'business.usernameReserved':
              errorCode = 'USERNAME_RESERVED';
              break;
            case 'business.profanityDetected':
              errorCode = 'PROFANITY_DETECTED';
              break;
            case 'business.phoneNumberInvalid':
              errorCode = 'PHONE_NUMBER_INVALID';
              break;
            case 'business.ageInvalid':
              errorCode = 'AGE_INVALID';
              params = detail.context || {};
              break;
            case 'business.dateRangeInvalid':
              errorCode = 'DATE_RANGE_INVALID';
              params = detail.context || {};
              break;
            default:
              errorCode = 'FIELD_REQUIRED';
          }
          
          return {
            field,
            code: errorCode,
            message: getLocalizedMessage(errorCode, language, params),
            value: detail.context?.value
          };
        });

        logger.warn('Validation failed', {
          target: opts.target,
          errors: validationErrors,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          path: req.path
        });

        return void res.status(400).json(createValidationErrorResponse(
          validationErrors.map(err => ({
            field: err.field,
            code: err.code,
            params: err.field === 'password' ? { minLength: 8 } : undefined
          })),
          language
        ));
      }

      // Custom validators
      if (opts.customValidators) {
        for (const [field, validator] of Object.entries(opts.customValidators)) {
          if (value[field] !== undefined) {
            const result = validator(value[field]);
            if (result !== true) {
              logger.warn('Custom validation failed', {
                field,
                value: value[field],
                ip: req.ip,
                path: req.path
              });
              
              // Determine error code based on field and validator
              let errorCode = 'FIELD_REQUIRED';
              if (field === 'email' && validator === businessRuleValidators.allowedEmailDomain) {
                errorCode = 'EMAIL_DOMAIN_NOT_ALLOWED';
              } else if (field === 'password' && validator === businessRuleValidators.notCommonPassword) {
                errorCode = 'PASSWORD_COMMON';
              } else if (field === 'username' && validator === businessRuleValidators.notReservedUsername) {
                errorCode = 'USERNAME_RESERVED';
              } else if (validator === businessRuleValidators.noProfanity) {
                errorCode = 'PROFANITY_DETECTED';
              }
              
              const errorObj = getLocalizedError(errorCode, language);
              return void res.status(400).json({
                error: 'Validation failed',
                message: errorObj.message,
                code: errorObj.code,
                severity: errorObj.severity,
                field,
                language,
                timestamp: new Date().toISOString()
              });
            }
          }
        }
      }

      // Replace the target data with the validated and sanitized value
      RequestFieldAssigner.set(req, opts.target!, value);
      next();
    } catch (validationError) {
      logger.error('Validation middleware error:', validationError);
      return void res.status(500).json({
        error: 'Internal server error',
        message: getLocalizedMessage('FIELD_REQUIRED', language),
        language,
        timestamp: new Date().toISOString()
      });
    }
  };
};

/**
 * Validate request body
 */
export const validateBody = (schema: Joi.ObjectSchema, options: Omit<ValidationOptions, 'target'> = {}) => {
  return validate(schema, { ...options, target: 'body' });
};

/**
 * Validate query parameters
 */
export const validateQuery = (schema: Joi.ObjectSchema, options: Omit<ValidationOptions, 'target'> = {}) => {
  return validate(schema, { ...options, target: 'query' });
};

/**
 * Validate route parameters
 */
export const validateParams = (schema: Joi.ObjectSchema, options: Omit<ValidationOptions, 'target'> = {}) => {
  return validate(schema, { ...options, target: 'params' });
};

/**
 * Validate headers
 */
export const validateHeaders = (schema: Joi.ObjectSchema, options: Omit<ValidationOptions, 'target'> = {}) => {
  return validate(schema, { ...options, target: 'headers' });
};

/**
 * Sanitize string input to prevent XSS
 */
export const sanitizeString = (str: string): string => {
  if (typeof str !== 'string') return str;
  
  return str
    .replace(/[<>]/g, '') // Remove basic HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .trim();
};

/**
 * Sanitize object recursively
 */
export const sanitizeObject = (obj: any): any => {
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  
  if (obj && typeof obj === 'object') {
    const sanitized: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        sanitized[key] = sanitizeObject(obj[key]);
      }
    }
    return sanitized;
  }
  
  return obj;
};

/**
 * Sanitization middleware
 */
export const sanitizeInput = (target: ValidationTarget = 'body') => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const targetData = req[target];
      
      if (targetData && typeof targetData === 'object') {
        RequestFieldAssigner.set(req, target, sanitizeObject(targetData));
      }
      
      next();
    } catch (error) {
      logger.error('Input sanitization failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Input sanitization failed'
      });
    }
  };
};

/**
 * Combined validation and sanitization middleware
 */
export const validateAndSanitize = (schema: Joi.ObjectSchema, options: ValidationOptions = {}) => {
  return [
    sanitizeInput(options.target),
    validate(schema, options)
  ];
};

/**
 * Email validation utility
 */
export const isValidEmail = (email: string): boolean => {
  const emailSchema = Joi.string().email({ tlds: { allow: false } });
  const { error } = emailSchema.validate(email);
  return !error;
};

/**
 * Password strength validation utility
 */
export const isStrongPassword = (password: string): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Advanced security detection helper functions
 */
const performXSSDetection = async (data: any): Promise<{ detected: boolean; patterns: string[] }> => {
  const checkData = (obj: any): { detected: boolean; patterns: string[] } => {
    const allPatterns: string[] = [];
    let detected = false;

    const traverse = (value: any) => {
      if (typeof value === 'string') {
        const xssResult = detectXSS(value);
        if (xssResult.detected) {
          detected = true;
          allPatterns.push(...xssResult.patterns);
        }
      } else if (Array.isArray(value)) {
        value.forEach(traverse);
      } else if (value && typeof value === 'object') {
        Object.values(value).forEach(traverse);
      }
    };

    traverse(obj);
    return { detected, patterns: allPatterns };
  };

  return checkData(data);
};

const performSQLInjectionDetection = async (data: any): Promise<{ detected: boolean; patterns: string[] }> => {
  const checkData = (obj: any): { detected: boolean; patterns: string[] } => {
    const allPatterns: string[] = [];
    let detected = false;

    const traverse = (value: any) => {
      if (typeof value === 'string') {
        const sqlResult = detectSQLInjection(value);
        if (sqlResult.detected) {
          detected = true;
          allPatterns.push(...sqlResult.patterns);
        }
      } else if (Array.isArray(value)) {
        value.forEach(traverse);
      } else if (value && typeof value === 'object') {
        Object.values(value).forEach(traverse);
      }
    };

    traverse(obj);
    return { detected, patterns: allPatterns };
  };

  return checkData(data);
};

/**
 * Advanced business rule validators with localized error support
 */
export const businessRuleValidators = {
  /**
   * Check if email domain is allowed
   */
  allowedEmailDomain: (email: string, allowedDomains: string[] = []) => {
    if (allowedDomains.length === 0) return true;
    const domain = email.split('@')[1]?.toLowerCase();
    return allowedDomains.includes(domain);
  },

  /**
   * Check password against common passwords list
   */
  notCommonPassword: (password: string) => {
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123', 'password1',
      'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
      'master', 'hello', 'login', 'pass', 'administrator', 'root'
    ];
    return !commonPasswords.includes(password.toLowerCase());
  },

  /**
   * Check if username is not reserved
   */
  notReservedUsername: (username: string) => {
    const reservedUsernames = [
      'admin', 'administrator', 'root', 'system', 'test', 'demo', 'api',
      'www', 'mail', 'ftp', 'webmaster', 'hostmaster', 'postmaster',
      'support', 'help', 'info', 'contact', 'sales', 'marketing',
      'null', 'undefined', 'true', 'false', 'anonymous', 'guest'
    ];
    return !reservedUsernames.includes(username.toLowerCase());
  },

  /**
   * Check if value doesn't contain profanity
   */
  noProfanity: (value: string) => {
    const profanityWords = [
      // Add your profanity filter words here
      'spam', 'scam', 'fraud'
    ];
    const lowerValue = value.toLowerCase();
    return !profanityWords.some(word => lowerValue.includes(word));
  },

  /**
   * Check if phone number format is valid
   */
  validPhoneNumber: (phone: string) => {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''));
  },

  /**
   * Check if date is within acceptable range
   */
  validDateRange: (date: string, minDate?: Date, maxDate?: Date) => {
    const inputDate = new Date(date);
    if (isNaN(inputDate.getTime())) return false;
    
    if (minDate && inputDate < minDate) return false;
    if (maxDate && inputDate > maxDate) return false;
    
    return true;
  },

  /**
   * Check if age is within acceptable range
   */
  validAge: (birthDate: string, minAge: number = 13, maxAge: number = 120) => {
    const birth = new Date(birthDate);
    const today = new Date();
    const age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      return age - 1 >= minAge && age - 1 <= maxAge;
    }
    return age >= minAge && age <= maxAge;
  }
};

/**
 * Create localized business rule validator
 */
export const createLocalizedValidator = (
  validatorFn: (value: any, ...args: any[]) => boolean,
  errorCode: string,
  ...args: any[]
) => {
  return (value: any) => {
    const isValid = validatorFn(value, ...args);
    if (!isValid) {
      return { valid: false, errorCode, params: args.length > 0 ? { args } : {} };
    }
    return { valid: true };
  };
};

/**
 * Custom Joi validators for business rules
 */
export const createCustomJoiValidators = () => {
  return {
    /**
     * Email domain validation
     */
    allowedEmailDomain: (allowedDomains: string[] = []) => {
      return {
        name: 'allowedEmailDomain',
        validate: (value: string, helpers: any) => {
          if (allowedDomains.length === 0) return value;
          const domain = value.split('@')[1]?.toLowerCase();
          if (!allowedDomains.includes(domain)) {
            return helpers.error('business.emailDomainNotAllowed', { domain });
          }
          return value;
        }
      };
    },

    /**
     * Common password validation
     */
    notCommonPassword: () => {
      return {
        name: 'notCommonPassword',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.notCommonPassword(value)) {
            return helpers.error('business.passwordTooCommon');
          }
          return value;
        }
      };
    },

    /**
     * Reserved username validation
     */
    notReservedUsername: () => {
      return {
        name: 'notReservedUsername',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.notReservedUsername(value)) {
            return helpers.error('business.usernameReserved');
          }
          return value;
        }
      };
    },

    /**
     * Profanity validation
     */
    noProfanity: () => {
      return {
        name: 'noProfanity',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        }
      };
    },

    /**
     * Phone number validation
     */
    validPhoneNumber: () => {
      return {
        name: 'validPhoneNumber',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.validPhoneNumber(value)) {
            return helpers.error('business.phoneNumberInvalid');
          }
          return value;
        }
      };
    },

    /**
     * Age validation
     */
    validAge: (minAge: number = 13, maxAge: number = 120) => {
      return {
        name: 'validAge',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.validAge(value, minAge, maxAge)) {
            return helpers.error('business.ageInvalid', { minAge, maxAge });
          }
          return value;
        }
      };
    },

    /**
     * Date range validation
     */
    validDateRange: (minDate?: Date, maxDate?: Date) => {
      return {
        name: 'validDateRange',
        validate: (value: string, helpers: any) => {
          if (!businessRuleValidators.validDateRange(value, minDate, maxDate)) {
            return helpers.error('business.dateRangeInvalid', { minDate, maxDate });
          }
          return value;
        }
      };
    }
  };
};

/**
 * Create extended Joi instance with custom validators and localized error messages
 */
export const createExtendedJoi = (language: SupportedLanguage = 'en') => {
  const customValidators = createCustomJoiValidators();
  
  // Extend Joi with custom validators
  const extendedJoi = Joi.extend(
    ...Object.values(customValidators).map(validator => (joi: any) => ({
      type: 'string',
      base: joi.string(),
      messages: {
        'business.emailDomainNotAllowed': getLocalizedMessage('EMAIL_DOMAIN_NOT_ALLOWED', language),
        'business.passwordTooCommon': getLocalizedMessage('PASSWORD_COMMON', language),
        'business.usernameReserved': getLocalizedMessage('USERNAME_RESERVED', language),
        'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED', language),
        'business.phoneNumberInvalid': getLocalizedMessage('PHONE_NUMBER_INVALID', language),
        'business.ageInvalid': getLocalizedMessage('AGE_INVALID', language),
        'business.dateRangeInvalid': getLocalizedMessage('DATE_RANGE_INVALID', language)
      },
      rules: {
        [validator().name]: validator()
      }
    }))
  );

  return extendedJoi;
};

/**
 * Enhanced validation schemas with business rules
 */
export const enhancedValidationSchemas = {
  // Enhanced user registration with business rules
  userRegistrationWithBusinessRules: (options: {
    allowedEmailDomains?: string[];
    requireUniqueUsername?: boolean;
    minAge?: number;
    maxAge?: number;
  } = {}) => {
    const { allowedEmailDomains = [], minAge = 13, maxAge = 120 } = options;
    
    return Joi.object({
      username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .required()
        .custom((value, helpers) => {
          if (!businessRuleValidators.notReservedUsername(value)) {
            return helpers.error('business.usernameReserved');
          }
          if (!businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        })
        .messages({
          'string.alphanum': 'Username must only contain alphanumeric characters',
          'string.min': 'Username must be at least 3 characters long',
          'string.max': 'Username cannot exceed 30 characters',
          'any.required': 'Username is required',
          'business.usernameReserved': getLocalizedMessage('USERNAME_RESERVED'),
          'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED')
        }),
      email: Joi.string()
        .email({ tlds: { allow: false } })
        .required()
        .custom((value, helpers) => {
          if (allowedEmailDomains.length > 0) {
            const domain = value.split('@')[1]?.toLowerCase();
            if (!allowedEmailDomains.includes(domain)) {
              return helpers.error('business.emailDomainNotAllowed', { domain });
            }
          }
          return value;
        })
        .messages({
          'string.email': 'Please provide a valid email address',
          'any.required': 'Email is required',
          'business.emailDomainNotAllowed': getLocalizedMessage('EMAIL_DOMAIN_NOT_ALLOWED')
        }),
      password: Joi.string()
        .min(8)
        .max(128)
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
        .required()
        .custom((value, helpers) => {
          if (!businessRuleValidators.notCommonPassword(value)) {
            return helpers.error('business.passwordTooCommon');
          }
          return value;
        })
        .messages({
          'string.min': 'Password must be at least 8 characters long',
          'string.max': 'Password cannot exceed 128 characters',
          'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
          'any.required': 'Password is required',
          'business.passwordTooCommon': getLocalizedMessage('PASSWORD_COMMON')
        }),
      confirmPassword: Joi.string()
        .valid(Joi.ref('password'))
        .required()
        .messages({
          'any.only': 'Passwords do not match',
          'any.required': 'Password confirmation is required'
        }),
      firstName: Joi.string()
        .min(1)
        .max(50)
        .pattern(new RegExp('^[a-zA-Z\\s]+$'))
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        })
        .messages({
          'string.min': 'First name must be at least 1 character long',
          'string.max': 'First name cannot exceed 50 characters',
          'string.pattern.base': 'First name must only contain letters and spaces',
          'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED')
        }),
      lastName: Joi.string()
        .min(1)
        .max(50)
        .pattern(new RegExp('^[a-zA-Z\\s]+$'))
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        })
        .messages({
          'string.min': 'Last name must be at least 1 character long',
          'string.max': 'Last name cannot exceed 50 characters',
          'string.pattern.base': 'Last name must only contain letters and spaces',
          'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED')
        }),
      dateOfBirth: Joi.date()
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.validAge(value.toISOString(), minAge, maxAge)) {
            return helpers.error('business.ageInvalid', { minAge, maxAge });
          }
          return value;
        })
        .messages({
          'date.base': 'Date of birth must be a valid date',
          'business.ageInvalid': getLocalizedMessage('AGE_INVALID', 'en', { minAge, maxAge })
        }),
      phoneNumber: Joi.string()
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.validPhoneNumber(value)) {
            return helpers.error('business.phoneNumberInvalid');
          }
          return value;
        })
        .messages({
          'business.phoneNumberInvalid': getLocalizedMessage('PHONE_NUMBER_INVALID')
        })
    });
  },

  // Enhanced user profile with business rules
  userProfileWithBusinessRules: (options: { allowedEmailDomains?: string[] } = {}) => {
    const { allowedEmailDomains = [] } = options;
    
    return Joi.object({
      firstName: Joi.string()
        .min(1)
        .max(50)
        .pattern(new RegExp('^[a-zA-Z\\s]+$'))
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        })
        .messages({
          'string.min': 'First name must be at least 1 character long',
          'string.max': 'First name cannot exceed 50 characters',
          'string.pattern.base': 'First name must only contain letters and spaces',
          'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED')
        }),
      lastName: Joi.string()
        .min(1)
        .max(50)
        .pattern(new RegExp('^[a-zA-Z\\s]+$'))
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.noProfanity(value)) {
            return helpers.error('business.profanityDetected');
          }
          return value;
        })
        .messages({
          'string.min': 'Last name must be at least 1 character long',
          'string.max': 'Last name cannot exceed 50 characters',
          'string.pattern.base': 'Last name must only contain letters and spaces',
          'business.profanityDetected': getLocalizedMessage('PROFANITY_DETECTED')
        }),
      email: Joi.string()
        .email({ tlds: { allow: false } })
        .optional()
        .custom((value, helpers) => {
          if (value && allowedEmailDomains.length > 0) {
            const domain = value.split('@')[1]?.toLowerCase();
            if (!allowedEmailDomains.includes(domain)) {
              return helpers.error('business.emailDomainNotAllowed', { domain });
            }
          }
          return value;
        })
        .messages({
          'string.email': 'Please provide a valid email address',
          'business.emailDomainNotAllowed': getLocalizedMessage('EMAIL_DOMAIN_NOT_ALLOWED')
        }),
      phoneNumber: Joi.string()
        .optional()
        .custom((value, helpers) => {
          if (value && !businessRuleValidators.validPhoneNumber(value)) {
            return helpers.error('business.phoneNumberInvalid');
          }
          return value;
        })
        .messages({
          'business.phoneNumberInvalid': getLocalizedMessage('PHONE_NUMBER_INVALID')
        })
    });
  }
};

/**
 * Localized business rule validators with error codes
 */
export const localizedBusinessRuleValidators = {
  /**
   * Email domain validation with localized errors
   */
  allowedEmailDomain: (allowedDomains: string[] = []) => 
    createLocalizedValidator(businessRuleValidators.allowedEmailDomain, 'EMAIL_DOMAIN_NOT_ALLOWED', allowedDomains),

  /**
   * Common password validation with localized errors
   */
  notCommonPassword: () => 
    createLocalizedValidator(businessRuleValidators.notCommonPassword, 'PASSWORD_COMMON'),

  /**
   * Reserved username validation with localized errors
   */
  notReservedUsername: () => 
    createLocalizedValidator(businessRuleValidators.notReservedUsername, 'USERNAME_RESERVED'),

  /**
   * Profanity validation with localized errors
   */
  noProfanity: () => 
    createLocalizedValidator(businessRuleValidators.noProfanity, 'PROFANITY_DETECTED'),

  /**
   * Phone number validation with localized errors
   */
  validPhoneNumber: () => 
    createLocalizedValidator(businessRuleValidators.validPhoneNumber, 'FIELD_REQUIRED'),

  /**
   * Date range validation with localized errors
   */
  validDateRange: (minDate?: Date, maxDate?: Date) => 
    createLocalizedValidator(businessRuleValidators.validDateRange, 'FIELD_REQUIRED', minDate, maxDate),

  /**
   * Age validation with localized errors
   */
  validAge: (minAge: number = 13, maxAge: number = 120) => 
    createLocalizedValidator(businessRuleValidators.validAge, 'FIELD_REQUIRED', minAge, maxAge)
};

/**
 * Rate limiting validation
 */
export const rateLimitValidation = (limit: number, windowMs: number) => {
  const requestCounts = new Map<string, { count: number; resetTime: number }>();
  
  return (req: Request, res: Response, next: NextFunction) => {
    const identifier = req.ip || 'unknown';
    const now = Date.now();
    
    const record = requestCounts.get(identifier);
    
    if (!record || now > record.resetTime) {
      requestCounts.set(identifier, {
        count: 1,
        resetTime: now + windowMs
      });
      return next();
    }
    
    if (record.count >= limit) {
      logger.warn('Rate limit exceeded during validation', {
        ip: req.ip,
        path: req.path,
        count: record.count,
        limit
      });
      
      const language = detectLanguage(req);
      const retryAfter = Math.ceil((record.resetTime - now) / 1000);
      const errorObj = getLocalizedError('RATE_LIMIT_EXCEEDED', language, { retryAfter });
      
      return void res.status(429).json({
        error: 'Rate limit exceeded',
        message: errorObj.message,
        code: errorObj.code,
        severity: errorObj.severity,
        retryAfter,
        language,
        timestamp: new Date().toISOString()
      });
    }
    
    record.count++;
    next();
  };
};

/**
 * Comprehensive input validation with all security features
 */
export const comprehensiveValidation = (schema: Joi.ObjectSchema, options: ValidationOptions = {}) => {
  const enhancedOptions: ValidationOptions = {
    ...options,
    enableXSSDetection: true,
    enableSQLInjectionDetection: true,
    enablePasswordComplexity: true,
    customValidators: {
      ...businessRuleValidators,
      ...options.customValidators
    }
  };

  return [
    sanitizeInput(enhancedOptions.target),
    validate(schema, enhancedOptions)
  ];
};

export default {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateHeaders,
  sanitizeInput,
  validateAndSanitize,
  comprehensiveValidation,
  validationSchemas,
  enhancedValidationSchemas,
  businessRuleValidators,
  localizedBusinessRuleValidators,
  createLocalizedValidator,
  createCustomJoiValidators,
  createExtendedJoi,
  rateLimitValidation,
  isValidEmail,
  isStrongPassword
};