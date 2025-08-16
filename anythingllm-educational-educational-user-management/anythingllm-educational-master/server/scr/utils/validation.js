// server/src/utils/validation.js
/**
 * Input Validation Utilities for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in validation messages
 */
import { generateAnonymizedId } from './compliance.js';

/**
 * Validate user input for compliance requirements
 * @param {Object} userData - User data to validate
 * @returns {Object} Validation result
 */
export const validateUserInput = (userData) => {
  const result = {
    isValid: true,
    errors: [],
    warnings: []
  };
  
  const { username, password, role, email } = userData;
  
  // Validate required fields
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    result.isValid = false;
    result.errors.push('Username is required');
  }
  
  if (!password || password.length < 8) {
    result.isValid = false;
    result.errors.push('Password must be at least 8 characters long');
  }
  
  // Validate role
  const validRoles = ['student', 'instructor', 'admin', 'super_admin'];
  if (!role || !validRoles.includes(role)) {
    result.isValid = false;
    result.errors.push('Invalid user role specified');
  }
  
  // Validate email format (basic validation)
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    result.isValid = false;
    result.errors.push('Invalid email format');
  }
  
  // Validate username length and characters
  if (username && username.length > 50) {
    result.isValid = false;
    result.errors.push('Username too long');
  }
  
  // Username can only contain alphanumeric, underscore, and hyphen
  if (username && !/^[a-zA-Z0-9_-]+$/.test(username)) {
    result.isValid = false;
    result.errors.push('Username can only contain letters, numbers, underscores, and hyphens');
  }
  
  // Validate password strength
  if (password) {
    const checks = [
      { test: /(?=.*[a-z])/, message: 'Password must contain lowercase letter' },
      { test: /(?=.*[A-Z])/, message: 'Password must contain uppercase letter' },
      { test: /(?=.*\d)/, message: 'Password must contain number' },
      { test: /(?=.*[@$!%*?&])/, message: 'Password must contain special character' }
    ];
    
    checks.forEach(check => {
      if (!check.test.test(password)) {
        result.warnings.push(check.message);
      }
    });
  }
  
  return result;
};

/**
 * Validate workspace input for compliance requirements
 * @param {Object} workspaceData - Workspace data to validate
 * @returns {Object} Validation result
 */
export const validateWorkspaceInput = (workspaceData) => {
  const result = {
    isValid: true,
    errors: [],
    warnings: []
  };
  
  const { name, description } = workspaceData;
  
  // Validate required fields
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    result.isValid = false;
    result.errors.push('Workspace name is required');
  }
  
  // Validate name length
  if (name && name.length > 100) {
    result.isValid = false;
    result.errors.push('Workspace name too long');
  }
  
  // Validate description length
  if (description && description.length > 1000) {
    result.warnings.push('Description exceeds recommended length');
  }
  
  return result;
};

/**
 * Validate SSO input for compliance requirements
 * @param {Object} ssoData - SSO data to validate
 * @returns {Object} Validation result
 */
export const validateSSOInput = (ssoData) => {
  const result = {
    isValid: true,
    errors: []
  };
  
  const { token, provider } = ssoData;
  
  if (!token || typeof token !== 'string') {
    result.isValid = false;
    result.errors.push('Invalid SSO token');
  }
  
  if (!provider || typeof provider !== 'string') {
    result.isValid = false;
    result.errors.push('Invalid SSO provider');
  }
  
  // Validate provider is supported
  const validProviders = ['google', 'microsoft', 'ldap'];
  if (provider && !validProviders.includes(provider)) {
    result.isValid = false;
    result.errors.push('Unsupported SSO provider');
  }
  
  return result;
};

/**
 * Validate authentication input for compliance requirements
 * @param {Object} authData - Authentication data to validate
 * @returns {Object} Validation result
 */
export const validateAuthInput = (authData) => {
  const result = {
    isValid: true,
    errors: []
  };
  
  const { username, password } = authData;
  
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    result.isValid = false;
    result.errors.push('Username is required');
  }
  
  if (!password || typeof password !== 'string') {
    result.isValid = false;
    result.errors.push('Password is required');
  }
  
  // Validate username format
  if (username && username.length > 50) {
    result.isValid = false;
    result.errors.push('Username too long');
  }
  
  return result;
};

/**
 * Validate compliance data for educational requirements
 * @param {Object} data - Data to validate
 * @returns {Object} Validation result
 */
export const validateComplianceData = (data) => {
  const result = {
    isValid: true,
    errors: []
  };
  
  // Check for potential PII in data
  if (data && typeof data === 'object') {
    // Check for common PII fields that shouldn't be present
    const piiFields = ['name', 'email', 'phone', 'address', 'ssn', 'studentId', 'userId'];
    
    Object.keys(data).forEach(key => {
      if (piiFields.includes(key.toLowerCase())) {
        result.isValid = false;
        result.errors.push(`Field "${key}" contains potentially PII data and should be anonymized`);
      }
      
      // Check nested objects for PII
      if (data[key] && typeof data[key] === 'object' && !Array.isArray(data[key])) {
        const nestedResult = validateComplianceData(data[key]);
        if (!nestedResult.isValid) {
          result.isValid = false;
          result.errors.push(...nestedResult.errors);
        }
      }
    });
  }
  
  return result;
};

/**
 * Validate system configuration for compliance requirements
 * @param {Object} config - System configuration to validate
 * @returns {Object} Validation result
 */
export const validateSystemConfig = (config) => {
  const result = {
    isValid: true,
    errors: []
  };
  
  // Check required configuration values
  if (!process.env.JWT_SECRET) {
    result.isValid = false;
    result.errors.push('JWT_SECRET environment variable is required');
  }
  
  if (!process.env.NODE_ENV) {
    result.isValid = false;
    result.errors.push('NODE_ENV environment variable is required');
  }
  
  // Validate compliance settings
  if (config.compliance && config.compliance.requiresParentConsent !== undefined) {
    if (typeof config.compliance.requiresParentConsent !== 'boolean') {
      result.isValid = false;
      result.errors.push('requiresParentConsent must be a boolean value');
    }
  }
  
  return result;
};

/**
 * Validate data handling for educational requirements
 * @param {Object} data - Data to validate
 * @returns {Object} Validation result
 */
export const validateDataHandling = (data) => {
  const result = {
    isValid: true,
    errors: []
  };
  
  // In a real implementation, this would check against data handling policies
  // For now, we'll just return basic validation
  
  if (!data) {
    result.isValid = false;
    result.errors.push('Data is required');
  }
  
  return result;
};

/**
 * Sanitize input data to remove PII before processing
 * @param {Object} inputData - Input data to sanitize
 * @returns {Object} Sanitized data
 */
export const sanitizeInputData = (inputData) => {
  if (!inputData || typeof inputData !== 'object') {
    return inputData;
  }
  
  const sanitized = {};
  
  Object.keys(inputData).forEach(key => {
    // Skip PII fields and replace with anonymized versions
    if (['name', 'email', 'phone', 'address', 'ssn', 'studentId', 'userId'].includes(key.toLowerCase())) {
      // Replace with anonymized identifier
      sanitized[key] = `anonymized_${generateAnonymizedId(key)}`;
    } else if (inputData[key] && typeof inputData[key] === 'object' && !Array.isArray(inputData[key])) {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeInputData(inputData[key]);
    } else {
      sanitized[key] = inputData[key];
    }
  });
  
  return sanitized;
};

/**
 * Validate role hierarchy for access control
 * @param {string} userRole - User's current role
 * @param {string} requiredRole - Required role level
 * @returns {boolean} Permission status
 */
export const validateRoleHierarchy = (userRole, requiredRole) => {
  // Role hierarchy from lowest to highest
  const roleHierarchy = ['student', 'instructor', 'admin', 'super_admin'];
  
  const userLevel = roleHierarchy.indexOf(userRole);
  const requiredLevel = roleHierarchy.indexOf(requiredRole);
  
  return userLevel >= requiredLevel;
};

/**
 * Generate validation report for compliance monitoring
 * @param {Object} validationResults - Results from various validations
 * @returns {Object} Validation report
 */
export const generateValidationReport = (validationResults) => {
  const report = {
    timestamp: new Date().toISOString(),
    system: 'AnythingLLM Educational',
    version: process.env.npm_package_version || '1.0.0',
    validationStatus: 'completed',
    summary: {
      totalValidations: Object.keys(validationResults).length,
      passed: 0,
      failed: 0
    },
    details: {}
  };
  
  Object.keys(validationResults).forEach(key => {
    const result = validationResults[key];
    report.details[key] = result;
    
    if (result.isValid) {
      report.summary.passed++;
    } else {
      report.summary.failed++;
    }
  });
  
  return report;
};

export default {
  validateUserInput,
  validateWorkspaceInput,
  validateSSOInput,
  validateAuthInput,
  validateComplianceData,
  validateSystemConfig,
  validateDataHandling,
  sanitizeInputData,
  validateRoleHierarchy,
  generateValidationReport
};
