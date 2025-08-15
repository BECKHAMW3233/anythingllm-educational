// server/src/utils/logger.js
/**
 * Logger Utility for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in logs
 */
import winston from 'winston';
import { generateAnonymizedId } from './compliance.js';
import config from '../config/compliance.js';

// Create logger instance with compliance settings
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'anythingllm-educational' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    // File transport for errors
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    // File transport for all logs
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});

/**
 * Log compliance event with anonymized identifiers
 * @param {string} level - Log level
 * @param {string} message - Log message
 * @param {Object} meta - Additional metadata
 * @returns {void}
 */
export const logComplianceEvent = (level, message, meta = {}) => {
  try {
    // Sanitize meta data to remove PII
    const sanitizedMeta = { ...meta };
    
    // Remove potential PII from metadata
    const piiFields = ['userId', 'email', 'name', 'phone', 'address', 'ssn', 'studentId'];
    
    piiFields.forEach(field => {
      if (sanitizedMeta[field]) {
        delete sanitizedMeta[field];
      }
    });
    
    // Anonymize identifiers in metadata
    if (sanitizedMeta.userId) {
      sanitizedMeta.anonymizedUserId = generateAnonymizedId(sanitizedMeta.userId);
      delete sanitizedMeta.userId;
    }
    
    if (sanitizedMeta.user) {
      sanitizedMeta.anonymizedUser = generateAnonymizedId(sanitizedMeta.user);
      delete sanitizedMeta.user;
    }
    
    logger.log({
      level,
      message: sanitizeLogMessage(message),
      ...sanitizedMeta
    });
  } catch (error) {
    // Fallback logging if primary fails
    console.error('Failed to log compliance event:', error);
  }
};

/**
 * Sanitize log messages to remove PII
 * @param {string} message - Original log message
 * @returns {string} Sanitized log message
 */
export const sanitizeLogMessage = (message) => {
  if (typeof message !== 'string') return message;
  
  // Remove common PII patterns with placeholders
  let sanitizedMessage = message;
  
  // Replace email patterns
  sanitizedMessage = sanitizedMessage.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[EMAIL_REDACTED]');
  
  // Replace phone number patterns
  sanitizedMessage = sanitizedMessage.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_REDACTED]');
  
  // Replace SSN patterns
  sanitizedMessage = sanitizedMessage.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]');
  
  // Replace IP addresses with placeholder
  sanitizedMessage = sanitizedMessage.replace(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, '[IP_REDACTED]');
  
  return sanitizedMessage;
};

/**
 * Log authentication event
 * @param {string} action - Authentication action
 * @param {Object} details - Action details
 * @returns {void}
 */
export const logAuthEvent = (action, details = {}) => {
  logComplianceEvent('info', `Authentication: ${action}`, {
    action,
    ...details,
    userAgent: details.userAgent || 'unknown',
    ip: details.ip || 'unknown'
  });
};

/**
 * Log workspace event
 * @param {string} action - Workspace action
 * @param {Object} details - Action details
 * @returns {void}
 */
export const logWorkspaceEvent = (action, details = {}) => {
  logComplianceEvent('info', `Workspace: ${action}`, {
    action,
    ...details
  });
};

/**
 * Log system event
 * @param {string} action - System action
 * @param {Object} details - Action details
 * @returns {void}
 */
export const logSystemEvent = (action, details = {}) => {
  logComplianceEvent('info', `System: ${action}`, {
    action,
    ...details
  });
};

/**
 * Log error with compliance measures
 * @param {string} message - Error message
 * @param {Object} error - Error object
 * @param {Object} context - Additional context
 * @returns {void}
 */
export const logError = (message, error = {}, context = {}) => {
  // Sanitize error data to remove PII
  const sanitizedContext = { ...context };
  
  // Remove potential PII from context
  const piiFields = ['userId', 'email', 'name', 'phone', 'address', 'ssn'];
  
  piiFields.forEach(field => {
    if (sanitizedContext[field]) {
      delete sanitizedContext[field];
    }
  });
  
  logComplianceEvent('error', message, {
    error: error.message || error,
    stack: error.stack,
    ...sanitizedContext
  });
};

/**
 * Log security event
 * @param {string} action - Security action
 * @param {Object} details - Action details
 * @returns {void}
 */
export const logSecurityEvent = (action, details = {}) => {
  logComplianceEvent('warn', `Security: ${action}`, {
    action,
    ...details
  });
};

/**
 * Log compliance report generation
 * @param {Object} report - Compliance report data
 * @returns {void}
 */
export const logComplianceReport = (report) => {
  logComplianceEvent('info', 'Compliance report generated', {
    report: {
      timestamp: report.timestamp,
      system: report.system,
      complianceLevel: report.complianceLevel,
      feraCompliant: report.feraCompliant,
      coppaCompliant: report.coppaCompliant
    }
  });
};

/**
 * Get current logger instance
 * @returns {Object} Winston logger instance
 */
export const getLogger = () => {
  return logger;
};

// Export default logger for direct use
export default logger;

// Initialize compliance logging on startup
logger.info('Logger initialized with FERPA/COPPA compliance measures');
logger.info(`Compliance level: ${config.environment.complianceLevel}`);
