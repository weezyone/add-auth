/**
 * XSS Protection Middleware
 * Implements comprehensive Cross-Site Scripting (XSS) protection with sanitization
 */

import { Request, Response, NextFunction } from 'express';
import xss, { escapeAttrValue } from 'xss';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * XSS attack tracking for rate limiting
 */
const xssAttempts = new Map<string, { count: number; lastAttempt: number; blocked: boolean }>();

/**
 * Rate limiting for XSS attempts
 */
const XSS_RATE_LIMIT = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 minutes
  blockDuration: 60 * 60 * 1000 // 1 hour
};

/**
 * XSS Protection Configuration
 */
export interface XSSProtectionConfig {
  whiteList?: { [key: string]: string[] };
  stripIgnoreTag?: boolean;
  stripIgnoreTagBody?: string[] | boolean;
  css?: boolean | { [key: string]: boolean };
  allowCommentTag?: boolean;
  escapeHtml?: (html: string) => string;
  onIgnoreTag?: (tag: string, html: string, options: any) => string;
  onIgnoreTagAttr?: (tag: string, name: string, value: string, isWhiteAttr: boolean) => string;
  onTagAttr?: (tag: string, name: string, value: string, isWhiteAttr: boolean) => string;
  safeAttrValue?: (tag: string, name: string, value: string, cssFilter: any) => string;
}

/**
 * Default XSS protection configuration
 */
const defaultXSSConfig: XSSProtectionConfig = {
  whiteList: {
    // Allow basic formatting tags with limited attributes
    'b': [],
    'i': [],
    'em': [],
    'strong': [],
    'br': [],
    'p': ['class'],
    'span': ['class'],
    'div': ['class'],
    'h1': ['class'],
    'h2': ['class'],
    'h3': ['class'],
    'h4': ['class'],
    'h5': ['class'],
    'h6': ['class'],
    'ul': ['class'],
    'ol': ['class'],
    'li': ['class'],
    'a': ['href', 'title', 'target'],
    'img': ['src', 'alt', 'title', 'width', 'height']
  },
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'object', 'embed', 'iframe'],
  css: false,
  allowCommentTag: false,
  onIgnoreTag: (tag: string, html: string, options: any) => {
    // Log suspicious tags
    logger.warn('XSS: Ignored suspicious tag', { tag, html: html.substring(0, 100) });
    return '';
  },
  onIgnoreTagAttr: (tag: string, name: string, value: string, isWhiteAttr: boolean) => {
    // Log suspicious attributes
    if (!isWhiteAttr) {
      logger.warn('XSS: Ignored suspicious attribute', { tag, name, value: value.substring(0, 100) });
    }
    return '';
  },
  onTagAttr: (tag: string, name: string, value: string, isWhiteAttr: boolean) => {
    // Additional validation for href attributes
    if (name === 'href' && !isWhiteAttr) {
      // Only allow http, https, and mailto protocols
      if (!/^(https?:\/\/|mailto:)/i.test(value)) {
        logger.warn('XSS: Blocked suspicious href', { tag, name, value });
        return '';
      }
    }
    return `${name}="${escapeAttrValue(value)}"`;
  }
};

/**
 * Strict XSS configuration (no HTML allowed)
 */
const strictXSSConfig: XSSProtectionConfig = {
  whiteList: {}, // No tags allowed
  stripIgnoreTag: true,
  stripIgnoreTagBody: true,
  css: false,
  allowCommentTag: false
};

/**
 * Sanitize a string value using XSS protection
 */
export const sanitizeString = (input: string, config: XSSProtectionConfig = defaultXSSConfig): string => {
  if (typeof input !== 'string') {
    return input;
  }

  try {
    return xss(input, config);
  } catch (error) {
    logger.error('XSS sanitization failed:', error);
    // Fallback to basic escaping
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
};

/**
 * Sanitize object recursively
 */
export const sanitizeObject = (obj: any, config: XSSProtectionConfig = defaultXSSConfig): any => {
  if (typeof obj === 'string') {
    return sanitizeString(obj, config);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, config));
  }

  if (obj && typeof obj === 'object' && obj.constructor === Object) {
    const sanitized: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        // Sanitize both key and value
        const sanitizedKey = sanitizeString(key, strictXSSConfig);
        sanitized[sanitizedKey] = sanitizeObject(obj[key], config);
      }
    }
    return sanitized;
  }

  return obj;
};

/**
 * XSS protection middleware
 */
export const xssProtection = (config: XSSProtectionConfig = defaultXSSConfig) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body, config);
      }

      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query, config);
      }

      // Sanitize route parameters
      if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObject(req.params, config);
      }

      // Set XSS protection headers
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");

      next();
    } catch (error) {
      logger.error('XSS protection middleware failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'XSS protection failed'
      });
    }
  };
};

/**
 * Strict XSS protection middleware (no HTML allowed)
 */
export const strictXSSProtection = () => {
  return xssProtection(strictXSSConfig);
};

/**
 * XSS protection for specific fields
 */
export const xssProtectFields = (fields: string[], config: XSSProtectionConfig = defaultXSSConfig) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.body && typeof req.body === 'object') {
        for (const field of fields) {
          if (req.body[field] && typeof req.body[field] === 'string') {
            req.body[field] = sanitizeString(req.body[field], config);
          }
        }
      }

      if (req.query && typeof req.query === 'object') {
        for (const field of fields) {
          if (req.query[field] && typeof req.query[field] === 'string') {
            req.query[field] = sanitizeString(req.query[field] as string, config);
          }
        }
      }

      next();
    } catch (error) {
      logger.error('Field-specific XSS protection failed:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'XSS protection failed'
      });
    }
  };
};

/**
 * Content Security Policy (CSP) middleware
 */
export const contentSecurityPolicy = (customPolicy?: string) => {
  const defaultPolicy = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "object-src 'none'",
    "base-uri 'self'"
  ].join('; ');

  return (req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Content-Security-Policy', customPolicy || defaultPolicy);
    next();
  };
};

/**
 * HTML escaping utility
 */
export const escapeHtml = (text: string): string => {
  const map: { [key: string]: string } = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
  };

  return text.replace(/[&<>"'`=\/]/g, (s) => map[s]);
};

/**
 * URL validation and sanitization
 */
export const sanitizeUrl = (url: string): string => {
  if (typeof url !== 'string') {
    return '';
  }

  // Remove dangerous protocols
  const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:'];
  const lowerUrl = url.toLowerCase();
  
  for (const protocol of dangerousProtocols) {
    if (lowerUrl.includes(protocol)) {
      logger.warn('XSS: Blocked dangerous URL protocol', { url: url.substring(0, 100) });
      return '';
    }
  }

  // Only allow http, https, and mailto
  if (!/^(https?:\/\/|mailto:)/i.test(url)) {
    logger.warn('XSS: Blocked invalid URL protocol', { url: url.substring(0, 100) });
    return '';
  }

  return url;
};

/**
 * Safe JSON parsing with XSS protection
 */
export const safeJsonParse = (jsonString: string, config: XSSProtectionConfig = defaultXSSConfig): any => {
  try {
    const parsed = JSON.parse(jsonString);
    return sanitizeObject(parsed, config);
  } catch (error) {
    logger.error('Safe JSON parsing failed:', error);
    return null;
  }
};

/**
 * Extended XSS detection patterns
 */
const advancedXSSPatterns = [
  // Script tags
  /<script[^>]*>.*?<\/script>/gi,
  /<script[^>]*>/gi,
  /<\/script>/gi,
  
  // Event handlers
  /on\w+\s*=/gi,
  /onload=/gi,
  /onerror=/gi,
  /onclick=/gi,
  /onmouseover=/gi,
  /onfocus=/gi,
  /onblur=/gi,
  /onchange=/gi,
  /onsubmit=/gi,
  /onkeydown=/gi,
  /onkeyup=/gi,
  /onkeypress=/gi,
  /onmousedown=/gi,
  /onmouseup=/gi,
  /onmousemove=/gi,
  /onmouseout=/gi,
  /oncontextmenu=/gi,
  /ondblclick=/gi,
  /ondrag=/gi,
  /ondrop=/gi,
  /onwheel=/gi,
  /onscroll=/gi,
  
  // JavaScript protocols
  /javascript:/gi,
  /vbscript:/gi,
  /data:text\/html/gi,
  /data:text\/javascript/gi,
  /data:application\/javascript/gi,
  
  // Dangerous HTML elements
  /<iframe[^>]*>.*?<\/iframe>/gi,
  /<iframe[^>]*>/gi,
  /<object[^>]*>.*?<\/object>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<applet[^>]*>/gi,
  /<form[^>]*>/gi,
  /<input[^>]*>/gi,
  /<link[^>]*>/gi,
  /<meta[^>]*>/gi,
  /<style[^>]*>/gi,
  
  // DOM manipulation
  /document\.cookie/gi,
  /document\.write/gi,
  /document\.writeln/gi,
  /document\.createElement/gi,
  /document\.getElementById/gi,
  /document\.getElementsBy/gi,
  /document\.querySelector/gi,
  /window\.location/gi,
  /location\.href/gi,
  /location\.replace/gi,
  /location\.assign/gi,
  /window\.open/gi,
  /window\.close/gi,
  /window\.focus/gi,
  /window\.blur/gi,
  
  // Code execution
  /eval\(/gi,
  /setTimeout\(/gi,
  /setInterval\(/gi,
  /Function\(/gi,
  /new\s+Function/gi,
  /execScript/gi,
  /msWriteProfilerMark/gi,
  
  // Data extraction
  /XMLHttpRequest/gi,
  /ActiveXObject/gi,
  /fetch\(/gi,
  /\.ajax\(/gi,
  /\.get\(/gi,
  /\.post\(/gi,
  /\.load\(/gi,
  
  // URL encoding attempts
  /%3cscript/gi,
  /%3c\/script%3e/gi,
  /%3ciframe/gi,
  /%3c%2fscript%3e/gi,
  /%2522%253e/gi,
  /%27%3e/gi,
  
  // HTML entities
  /&lt;script/gi,
  /&gt;&lt;\/script&gt;/gi,
  /&#x3c;script/gi,
  /&#60;script/gi,
  
  // CSS injection
  /expression\(/gi,
  /-moz-binding/gi,
  /behavior:/gi,
  /\.htc/gi,
  /url\(/gi,
  /@import/gi,
  
  // SVG injection
  /<svg[^>]*>/gi,
  /<foreignObject[^>]*>/gi,
  /<use[^>]*>/gi,
  /<image[^>]*>/gi,
  
  // Advanced payloads
  /\\u[0-9a-fA-F]{4}/gi,
  /\\x[0-9a-fA-F]{2}/gi,
  /String\.fromCharCode/gi,
  /unescape\(/gi,
  /decodeURI/gi,
  /decodeURIComponent/gi,
  /escape\(/gi,
  /encodeURI/gi,
  /encodeURIComponent/gi,
  
  // Template injection
  /\{\{.*\}\}/gi,
  /\$\{.*\}/gi,
  /<%.*%>/gi,
  
  // Comment injection
  /<!--.*-->/gi,
  /\/\*.*\*\//gi,
  
  // Attribute injection
  /src\s*=\s*["']?data:/gi,
  /href\s*=\s*["']?data:/gi,
  /action\s*=\s*["']?data:/gi,
  /formaction\s*=\s*["']?data:/gi,
  
  // CDATA injection
  /<\!\[CDATA\[.*\]\]>/gi
];

/**
 * XSS detection utility with advanced patterns
 */
export const detectXSS = (input: string): { detected: boolean; patterns: string[]; severity: 'low' | 'medium' | 'high' | 'critical' } => {
  if (typeof input !== 'string' || input.length === 0) {
    return { detected: false, patterns: [], severity: 'low' };
  }

  const detectedPatterns: string[] = [];
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';

  // Decode common encodings first
  const decodedInputs = [
    input,
    (() => { try { return decodeURIComponent(input); } catch { return input; } })(),
    (() => { try { return Buffer.from(input, 'base64').toString('utf-8'); } catch { return input; } })(),
    input.replace(/\\u([0-9a-fA-F]{4})/g, (match, code) => String.fromCharCode(parseInt(code, 16))),
    input.replace(/\\x([0-9a-fA-F]{2})/g, (match, code) => String.fromCharCode(parseInt(code, 16))),
    input.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
  ];

  for (const decoded of decodedInputs) {
    if (typeof decoded === 'string') {
      for (const pattern of advancedXSSPatterns) {
        if (pattern.test(decoded)) {
          detectedPatterns.push(pattern.source);
          
          // Determine severity based on pattern type
          if (pattern.source.includes('script') || pattern.source.includes('eval') || pattern.source.includes('Function')) {
            severity = 'critical';
          } else if (pattern.source.includes('iframe') || pattern.source.includes('object') || pattern.source.includes('embed')) {
            if (severity !== 'critical') {
              severity = 'high';
            }
          } else if (pattern.source.includes('on\\w+') || pattern.source.includes('javascript:')) {
            if (severity === 'low') {
              severity = 'medium';
            }
          }
        }
      }
    }
  }

  return {
    detected: detectedPatterns.length > 0,
    patterns: [...new Set(detectedPatterns)], // Remove duplicates
    severity
  };
};

/**
 * Track XSS attempts for rate limiting
 */
const trackXSSAttempt = (identifier: string, severity: 'low' | 'medium' | 'high' | 'critical'): boolean => {
  const now = Date.now();
  const record = xssAttempts.get(identifier);
  
  if (!record) {
    xssAttempts.set(identifier, {
      count: 1,
      lastAttempt: now,
      blocked: false
    });
    return false;
  }
  
  // Reset count if outside window
  if (now - record.lastAttempt > XSS_RATE_LIMIT.windowMs) {
    record.count = 1;
    record.lastAttempt = now;
    record.blocked = false;
    return false;
  }
  
  // Check if still blocked
  if (record.blocked && now - record.lastAttempt < XSS_RATE_LIMIT.blockDuration) {
    return true;
  }
  
  // Increment count
  record.count++;
  record.lastAttempt = now;
  
  // Block if exceeded attempts
  if (record.count >= XSS_RATE_LIMIT.maxAttempts) {
    record.blocked = true;
    logger.error('XSS attack rate limit exceeded', {
      identifier,
      attempts: record.count,
      severity,
      blocked: true
    });
    return true;
  }
  
  return false;
};

/**
 * Generate CSP nonce for inline scripts
 */
export const generateCSPNonce = (): string => {
  return crypto.randomBytes(16).toString('base64');
};

/**
 * Enhanced XSS detection middleware with rate limiting
 */
export const xssDetection = (options: { blockOnDetection?: boolean; enableRateLimiting?: boolean } = {}) => {
  const { blockOnDetection = true, enableRateLimiting = true } = options;
  
  return (req: Request, res: Response, next: NextFunction) => {
    const identifier = req.ip || 'unknown';
    
    // Check if IP is currently blocked
    if (enableRateLimiting) {
      const record = xssAttempts.get(identifier);
      if (record?.blocked && Date.now() - record.lastAttempt < XSS_RATE_LIMIT.blockDuration) {
        logger.warn('Blocked XSS attempt from rate-limited IP', {
          ip: req.ip,
          userAgent: req.get('user-agent'),
          url: req.url,
          method: req.method
        });
        return res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'Too many malicious requests detected. Access temporarily blocked.'
        });
      }
    }
    
    const checkInput = (obj: any, path: string = '') => {
      if (typeof obj === 'string') {
        const detection = detectXSS(obj);
        if (detection.detected) {
          // Track the attempt
          if (enableRateLimiting) {
            const blocked = trackXSSAttempt(identifier, detection.severity);
            if (blocked) {
              return res.status(429).json({
                error: 'Rate limit exceeded',
                message: 'Too many malicious requests detected. Access temporarily blocked.'
              });
            }
          }
          
          logger.warn('XSS attack detected', {
            path,
            patterns: detection.patterns,
            severity: detection.severity,
            input: obj.substring(0, 200),
            ip: req.ip,
            userAgent: req.get('user-agent'),
            method: req.method,
            url: req.url,
            timestamp: new Date().toISOString()
          });
          
          // Block the request if enabled
          if (blockOnDetection) {
            return res.status(400).json({
              error: 'Malicious input detected',
              message: 'Request blocked due to potential XSS attack',
              severity: detection.severity
            });
          }
        }
      } else if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
          const result = checkInput(obj[i], `${path}[${i}]`);
          if (result) return result;
        }
      } else if (obj && typeof obj === 'object') {
        for (const key in obj) {
          if (obj.hasOwnProperty(key)) {
            const result = checkInput(obj[key], path ? `${path}.${key}` : key);
            if (result) return result;
          }
        }
      }
    };

    // Check body, query, and params
    const bodyResult = req.body ? checkInput(req.body, 'body') : null;
    if (bodyResult) return bodyResult;

    const queryResult = req.query ? checkInput(req.query, 'query') : null;
    if (queryResult) return queryResult;

    const paramsResult = req.params ? checkInput(req.params, 'params') : null;
    if (paramsResult) return paramsResult;

    next();
  };
};

/**
 * XSS attempt cleanup (run periodically)
 */
export const cleanupXSSAttempts = () => {
  const now = Date.now();
  const expiredEntries: string[] = [];
  
  for (const [identifier, record] of xssAttempts.entries()) {
    if (now - record.lastAttempt > XSS_RATE_LIMIT.blockDuration) {
      expiredEntries.push(identifier);
    }
  }
  
  expiredEntries.forEach(identifier => {
    xssAttempts.delete(identifier);
  });
  
  logger.info('XSS attempt cleanup completed', {
    cleaned: expiredEntries.length,
    remaining: xssAttempts.size
  });
};

/**
 * Get XSS attempt statistics
 */
export const getXSSStats = () => {
  const stats = {
    totalTracked: xssAttempts.size,
    currentlyBlocked: 0,
    topOffenders: [] as { identifier: string; count: number; lastAttempt: Date }[]
  };
  
  const now = Date.now();
  
  for (const [identifier, record] of xssAttempts.entries()) {
    if (record.blocked && now - record.lastAttempt < XSS_RATE_LIMIT.blockDuration) {
      stats.currentlyBlocked++;
    }
    
    stats.topOffenders.push({
      identifier,
      count: record.count,
      lastAttempt: new Date(record.lastAttempt)
    });
  }
  
  // Sort by count descending
  stats.topOffenders.sort((a, b) => b.count - a.count);
  stats.topOffenders = stats.topOffenders.slice(0, 10); // Top 10
  
  return stats;
};

/**
 * Advanced CSP middleware with nonce support
 */
export const advancedCSP = (options: { nonce?: string; reportUri?: string; enforceMode?: boolean } = {}) => {
  const { nonce, reportUri, enforceMode = true } = options;
  
  return (req: Request, res: Response, next: NextFunction) => {
    const cspNonce = nonce || generateCSPNonce();
    
    // Store nonce in request for use in templates
    (req as any).cspNonce = cspNonce;
    
    const directives = [
      "default-src 'self'",
      `script-src 'self' 'nonce-${cspNonce}' 'strict-dynamic'`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "upgrade-insecure-requests"
    ];
    
    if (reportUri) {
      directives.push(`report-uri ${reportUri}`);
    }
    
    const cspHeader = enforceMode ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
    const cspValue = directives.join('; ');
    
    res.setHeader(cspHeader, cspValue);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), screen-wake-lock=(), web-share=()');
    
    next();
  };
};

// Start cleanup timer
setInterval(cleanupXSSAttempts, 60 * 60 * 1000); // Every hour

export default {
  xssProtection,
  strictXSSProtection,
  xssProtectFields,
  contentSecurityPolicy,
  advancedCSP,
  sanitizeString,
  sanitizeObject,
  escapeHtml,
  sanitizeUrl,
  safeJsonParse,
  detectXSS,
  xssDetection,
  generateCSPNonce,
  cleanupXSSAttempts,
  getXSSStats
};