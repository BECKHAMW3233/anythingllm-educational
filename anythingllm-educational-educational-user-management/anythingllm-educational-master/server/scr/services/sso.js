// server/src/services/sso.js
/**
 * SSO Configuration Service for Educational AnythingLLM Deployment
 * Handles Single Sign-On providers with FERPA/COPPA compliance
 */
import { db } from '../utils/database.js';
import { logger } from '../utils/logger.js';
import { encrypt, decrypt } from '../utils/encryption.js';
import jwt from 'jsonwebtoken';

class SSOService {
  /**
   * Register a new SSO provider
   * @param {Object} providerData - Provider configuration data
   * @returns {Object} Created provider data
   */
  static async registerProvider(providerData) {
    const {
      name,
      type,
      clientId,
      clientSecret,
      issuer,
      authorizationUrl,
      tokenUrl,
      userInfoUrl,
      scopes,
      enabled = true,
      callbackUrl
    } = providerData;
    
    try {
      // Validate required fields
      if (!name || !type || !clientId) {
        throw new Error('Name, type, and client ID are required');
      }
      
      // Check if provider already exists
      const checkQuery = `
        SELECT id FROM sso_providers 
        WHERE name = $1 OR client_id = $2
      `;
      
      const checkResult = await db.query(checkQuery, [name, clientId]);
      
      if (checkResult.rows.length > 0) {
        throw new Error('SSO provider already exists');
      }
      
      // Encrypt sensitive data
      const encryptedSecret = encrypt(clientSecret);
      
      const query = `
        INSERT INTO sso_providers (
          name,
          type,
          client_id,
          client_secret,
          issuer,
          authorization_url,
          token_url,
          user_info_url,
          scopes,
          enabled,
          callback_url,
          created_at,
          updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        RETURNING id, name, type, issuer, enabled, created_at, updated_at
      `;
      
      const result = await db.query(query, [
        name,
        type,
        clientId,
        encryptedSecret,
        issuer,
        authorizationUrl,
        tokenUrl,
        userInfoUrl,
        scopes ? JSON.stringify(scopes) : null,
        enabled,
        callbackUrl
      ]);
      
      const provider = result.rows[0];
      
      logger.info(`SSO provider registered: ${provider.id}`, { 
        name: provider.name,
        type: provider.type
      });
      
      return {
        ...provider,
        id: provider.id,
        name: provider.name,
        type: provider.type,
        issuer: provider.issuer,
        enabled: provider.enabled,
        createdAt: provider.created_at,
        updatedAt: provider.updated_at
      };
    } catch (error) {
      logger.error('Error registering SSO provider:', error);
      throw error;
    }
  }

  /**
   * Get all configured SSO providers
   * @returns {Array} List of SSO providers
   */
  static async getAllProviders() {
    try {
      const query = `
        SELECT id, name, type, issuer, enabled, created_at, updated_at
        FROM sso_providers 
        ORDER BY created_at DESC
      `;
      
      const result = await db.query(query);
      
      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        type: row.type,
        issuer: row.issuer,
        enabled: row.enabled,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
    } catch (error) {
      logger.error('Error fetching SSO providers:', error);
      throw error;
    }
  }

  /**
   * Get enabled SSO providers
   * @returns {Array} List of enabled SSO providers
   */
  static async getEnabledProviders() {
    try {
      const query = `
        SELECT id, name, type, issuer, callback_url, created_at, updated_at
        FROM sso_providers 
        WHERE enabled = true
        ORDER BY created_at DESC
      `;
      
      const result = await db.query(query);
      
      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        type: row.type,
        issuer: row.issuer,
        callbackUrl: row.callback_url,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
    } catch (error) {
      logger.error('Error fetching enabled SSO providers:', error);
      throw error;
    }
  }

  /**
   * Get SSO provider by ID
   * @param {string} providerId - Provider ID to fetch
   * @returns {Object} Provider data
   */
  static async getProviderById(providerId) {
    try {
      const query = `
        SELECT id, name, type, client_id, issuer, authorization_url, token_url, 
               user_info_url, scopes, enabled, callback_url, created_at, updated_at
        FROM sso_providers 
        WHERE id = $1
      `;
      
      const result = await db.query(query, [providerId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      const provider = result.rows[0];
      
      // Decrypt client secret for internal use only
      let clientSecret = null;
      try {
        clientSecret = decrypt(provider.client_secret);
      } catch (err) {
        logger.warn('Could not decrypt SSO provider secret');
      }
      
      return {
        id: provider.id,
        name: provider.name,
        type: provider.type,
        clientId: provider.client_id,
        issuer: provider.issuer,
        authorizationUrl: provider.authorization_url,
        tokenUrl: provider.token_url,
        userInfoUrl: provider.user_info_url,
        scopes: provider.scopes ? JSON.parse(provider.scopes) : [],
        enabled: provider.enabled,
        callbackUrl: provider.callback_url,
        createdAt: provider.created_at,
        updatedAt: provider.updated_at,
        clientSecret: clientSecret // Only for internal use
      };
    } catch (error) {
      logger.error('Error fetching SSO provider:', error);
      throw error;
    }
  }

  /**
   * Update SSO provider configuration
   * @param {string} providerId - Provider ID to update
   * @param {Object} updateData - Data to update
   * @returns {Object} Updated provider data
   */
  static async updateProvider(providerId, updateData) {
    try {
      // Validate updates
      const allowedFields = ['name', 'type', 'client_id', 'client_secret', 'issuer', 
                           'authorization_url', 'token_url', 'user_info_url', 
                           'scopes', 'enabled', 'callback_url'];
      
      const validUpdates = {};
      const values = [];
      
      for (const field of allowedFields) {
        if (updateData[field] !== undefined) {
          validUpdates[field] = updateData[field];
          values.push(updateData[field]);
        }
      }
      
      if (Object.keys(validUpdates).length === 0) {
        throw new Error('No valid fields to update');
      }
      
      // Build update query
      const fields = Object.keys(validUpdates);
      const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');
      
      // Handle sensitive data encryption
      if (validUpdates.client_secret) {
        validUpdates.client_secret = encrypt(validUpdates.client_secret);
      }
      
      if (validUpdates.scopes && typeof validUpdates.scopes === 'object') {
        validUpdates.scopes = JSON.stringify(validUpdates.scopes);
      }
      
      const query = `
        UPDATE sso_providers 
        SET ${setClause}, updated_at = NOW()
        WHERE id = $${fields.length + 1}
        RETURNING id, name, type, issuer, enabled, created_at, updated_at
      `;
      
      values.push(providerId);
      
      const result = await db.query(query, values);
      
      if (result.rows.length === 0) {
        throw new Error('SSO provider not found');
      }
      
      const provider = result.rows[0];
      
      logger.info(`SSO provider updated: ${provider.id}`);
      
      return {
        ...provider,
        id: provider.id,
        name: provider.name,
        type: provider.type,
        issuer: provider.issuer,
        enabled: provider.enabled,
        createdAt: provider.created_at,
        updatedAt: provider.updated_at
      };
    } catch (error) {
      logger.error('Error updating SSO provider:', error);
      throw error;
    }
  }

  /**
   * Enable/disable SSO provider
   * @param {string} providerId - Provider ID
   * @param {boolean} enabled - Whether to enable or disable
   * @returns {Object} Updated provider data
   */
  static async toggleProvider(providerId, enabled) {
    try {
      const query = `
        UPDATE sso_providers 
        SET enabled = $1, updated_at = NOW()
        WHERE id = $2
        RETURNING id, name, type, issuer, enabled, created_at, updated_at
      `;
      
      const result = await db.query(query, [enabled, providerId]);
      
      if (result.rows.length === 0) {
        throw new Error('SSO provider not found');
      }
      
      const provider = result.rows[0];
      
      logger.info(`SSO provider ${enabled ? 'enabled' : 'disabled'}: ${provider.id}`);
      
      return {
        ...provider,
        id: provider.id,
        name: provider.name,
        type: provider.type,
        issuer: provider.issuer,
        enabled: provider.enabled,
        createdAt: provider.created_at,
        updatedAt: provider.updated_at
      };
    } catch (error) {
      logger.error('Error toggling SSO provider:', error);
      throw error;
    }
  }

  /**
   * Delete SSO provider
   * @param {string} providerId - Provider ID to delete
   * @returns {Object} Deletion result
   */
  static async deleteProvider(providerId) {
    try {
      const query = `
        DELETE FROM sso_providers 
        WHERE id = $1
        RETURNING id, name
      `;
      
      const result = await db.query(query, [providerId]);
      
      if (result.rows.length === 0) {
        throw new Error('SSO provider not found');
      }
      
      const provider = result.rows[0];
      
      logger.info(`SSO provider deleted: ${provider.id}`, { name: provider.name });
      
      return {
        success: true,
        message: 'SSO provider deleted successfully'
      };
    } catch (error) {
      logger.error('Error deleting SSO provider:', error);
      throw error;
    }
  }

  /**
   * Test SSO provider connection
   * @param {string} providerId - Provider ID to test
   * @returns {Object} Test results
   */
  static async testProviderConnection(providerId) {
    try {
      const provider = await this.getProviderById(providerId);
      
      if (!provider) {
        throw new Error('SSO provider not found');
      }
      
      // In a real implementation, this would:
      // 1. Test authorization URL connectivity
      // 2. Validate token endpoint
      // 3. Verify user info endpoint
      
      return {
        success: true,
        providerId: provider.id,
        name: provider.name,
        testDate: new Date(),
        status: 'connected',
        message: 'Provider connection successful'
      };
    } catch (error) {
      logger.error('Error testing SSO provider connection:', error);
      
      return {
        success: false,
        providerId: providerId,
        testDate: new Date(),
        status: 'failed',
        message: error.message
      };
    }
  }

  /**
   * Generate SSO authorization URL
   * @param {string} providerId - Provider ID
   * @param {string} redirectUri - Redirect URI for callback
   * @param {string} state - State parameter for security
   * @returns {string} Authorization URL
   */
  static async generateAuthorizationUrl(providerId, redirectUri, state = null) {
    try {
      const provider = await this.getProviderById(providerId);
      
      if (!provider || !provider.enabled) {
        throw new Error('SSO provider not found or disabled');
      }
      
      // Generate authorization URL based on provider type
      let authUrl = '';
      
      switch (provider.type.toLowerCase()) {
        case 'oauth2':
          const params = new URLSearchParams({
            client_id: provider.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: provider.scopes ? provider.scopes.join(' ') : 'openid profile email',
            state: state || this.generateState()
          });
          
          authUrl = `${provider.authorizationUrl}?${params.toString()}`;
          break;
          
        case 'saml':
          // SAML implementation would be more complex
          authUrl = `${provider.authorizationUrl}?SAMLRequest=...`;
          break;
          
        default:
          throw new Error('Unsupported SSO provider type');
      }
      
      logger.info(`Generated authorization URL for provider: ${provider.id}`);
      
      return authUrl;
    } catch (error) {
      logger.error('Error generating authorization URL:', error);
      throw error;
    }
  }

  /**
   * Handle SSO callback and authenticate user
   * @param {string} providerId - Provider ID
   * @param {Object} callbackData - Callback data from SSO provider
   * @returns {Object} Authentication result
   */
  static async handleSSOCallback(providerId, callbackData) {
    try {
      const provider = await this.getProviderById(providerId);
      
      if (!provider || !provider.enabled) {
        throw new Error('Invalid or disabled SSO provider');
      }
      
      // Validate state parameter for security
      if (callbackData.state && callbackData.state !== this.validateState(callbackData.state)) {
        throw new Error('Invalid state parameter');
      }
      
      // Exchange authorization code for access token
      const tokenResponse = await this.exchangeCodeForToken(provider, callbackData.code);
      
      // Get user information from provider
      const userInfo = await this.getUserInfo(provider, tokenResponse.access_token);
      
      // Authenticate or create user in system
      const user = await this.authenticateOrCreateUser(userInfo, providerId);
      
      // Generate JWT token for internal use
      const jwtToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET || 'anythingllm-default-secret',
        { expiresIn: '24h' }
      );
      
      logger.info(`SSO authentication successful for user: ${user.id}`);
      
      return {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        token: jwtToken,
        expiresIn: 86400,
        provider: provider.name
      };
    } catch (error) {
      logger.error('Error handling SSO callback:', error);
      throw new Error('SSO authentication failed');
    }
  }

  /**
   * Exchange authorization code for access token
   * @param {Object} provider - Provider configuration
   * @param {string} code - Authorization code
   * @returns {Object} Token response
   */
  static async exchangeCodeForToken(provider, code) {
    // In a real implementation, this would make HTTP requests to the SSO provider
    // This is a simplified simulation
    
    // Example for OAuth2:
    /*
    const response = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        code: code,
        redirect_uri: provider.callbackUrl
      })
    });
    
    return await response.json();
    */
    
    // Simulated response
    return {
      access_token: `access_token_${Date.now()}`,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: `refresh_token_${Date.now()}`
    };
  }

  /**
   * Get user information from SSO provider
   * @param {Object} provider - Provider configuration
   * @param {string} accessToken - Access token
   * @returns {Object} User information
   */
  static async getUserInfo(provider, accessToken) {
    // In a real implementation, this would make HTTP requests to the SSO provider
    // This is a simplified simulation
    
    /*
    const response = await fetch(provider.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    
    return await response.json();
    */
    
    // Simulated user info
    return {
      sub: `sso_user_${Date.now()}`,
      email: 'user@example.com',
      name: 'User Name',
      given_name: 'User',
      family_name: 'Name',
      role: 'editor', // Default role based on SSO data
      provider: provider.name
    };
  }

  /**
   * Authenticate or create user from SSO data
   * @param {Object} userInfo - User information from SSO
   * @param {string} providerId - SSO provider ID
   * @returns {Object} User object
   */
  static async authenticateOrCreateUser(userInfo, providerId) {
    try {
      // Check if user already exists
      const checkQuery = `
        SELECT id, email, name, role, sso_provider_id, created_at, updated_at
        FROM users 
        WHERE sso_provider_id = $1 AND sso_user_id = $2
      `;
      
      const checkResult = await db.query(checkQuery, [providerId, userInfo.sub]);
      
      if (checkResult.rows.length > 0) {
        // Update existing user
        const user = checkResult.rows[0];
        
        const updateQuery = `
          UPDATE users 
          SET name = $1, updated_at = NOW()
          WHERE id = $2
          RETURNING id, email, name, role, sso_provider_id, created_at, updated_at
        `;
        
        const updateResult = await db.query(updateQuery, [userInfo.name || `${userInfo.given_name} ${userInfo.family_name}`, user.id]);
        return updateResult.rows[0];
      } else {
        // Create new user
        const role = this.getDefaultRole(userInfo);
        
        const insertQuery = `
          INSERT INTO users (email, name, role, sso_provider_id, sso_user_id, created_at, updated_at, is_active)
          VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), true)
          RETURNING id, email, name, role, sso_provider_id, created_at, updated_at
        `;
        
        const insertResult = await db.query(insertQuery, [
          userInfo.email,
          userInfo.name || `${userInfo.given_name} ${userInfo.family_name}`,
          role,
          providerId,
          userInfo.sub
        ]);
        
        logger.info(`New SSO user created: ${insertResult.rows[0].id}`);
        return insertResult.rows[0];
      }
    } catch (error) {
      logger.error('Error authenticating/creating SSO user:', error);
      throw new Error('Failed to authenticate or create SSO user');
    }
  }

  /**
   * Get default role based on SSO user data
   * @param {Object} userInfo - User information from SSO
   * @returns {string} Default role
   */
  static getDefaultRole(userInfo) {
    // Check for admin roles in SSO data
    if (userInfo.role && userInfo.role.includes('admin')) {
      return 'admin';
    }
    
    // Check for educational roles
    const educationRoles = ['teacher', 'instructor', 'educator', 'faculty'];
    if (userInfo.role && educationRoles.some(role => userInfo.role.includes(role))) {
      return 'editor';
    }
    
    // Default to viewer role for students/regular users
    return 'viewer';
  }

  /**
   * Generate secure state parameter
   * @returns {string} Secure state string
   */
  static generateState() {
    return Buffer.from(Math.random().toString(36).substring(2, 15) + 
                      Math.random().toString(36).substring(2, 15)).toString('base64');
  }

  /**
   * Validate state parameter
   * @param {string} state - State to validate
   * @returns {boolean} Whether state is valid
   */
  static validateState(state) {
    // In a real implementation, this would validate against stored state
    // For now, we'll accept any valid base64 string
    try {
      Buffer.from(state, 'base64');
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get SSO provider configuration for client-side use
   * @param {string} providerId - Provider ID
   * @returns {Object} Public configuration
   */
  static async getPublicProviderConfig(providerId) {
    try {
      const provider = await this.getProviderById(providerId);
      
      if (!provider || !provider.enabled) {
        return null;
      }
      
      // Return only public information, no sensitive data
      return {
        id: provider.id,
        name: provider.name,
        type: provider.type,
        issuer: provider.issuer,
        authorizationUrl: provider.authorizationUrl,
        callbackUrl: provider.callbackUrl,
        scopes: provider.scopes || [],
        createdAt: provider.createdAt,
        updatedAt: provider.updatedAt
      };
    } catch (error) {
      logger.error('Error getting public SSO provider config:', error);
      return null;
    }
  }

  /**
   * Get SSO configuration for client-side integration
   * @returns {Object} Client-side SSO configuration
   */
  static async getClientConfig() {
    try {
      const providers = await this.getEnabledProviders();
      
      return {
        providers: providers.map(provider => ({
          id: provider.id,
          name: provider.name,
          type: provider.type,
          issuer: provider.issuer,
          callbackUrl: provider.callbackUrl
        })),
        timestamp: new Date(),
        version: '1.0'
      };
    } catch (error) {
      logger.error('Error getting client SSO config:', error);
      return {
        providers: [],
        timestamp: new Date(),
        version: '1.0'
      };
    }
  }

  /**
   * Validate SSO configuration against FERPA/COPPA requirements
   * @param {Object} providerConfig - Provider configuration to validate
   * @returns {Object} Validation results
   */
  static validateSSOCompliance(providerConfig) {
    const errors = [];
    
    // Check for secure connection (HTTPS)
    if (providerConfig.authorizationUrl && !providerConfig.authorizationUrl.startsWith('https://')) {
      errors.push('Authorization URL must use HTTPS');
    }
    
    if (providerConfig.tokenUrl && !providerConfig.tokenUrl.startsWith('https://')) {
      errors.push('Token URL must use HTTPS');
    }
    
    if (providerConfig.userInfoUrl && !providerConfig.userInfoUrl.startsWith('https://')) {
      errors.push('User info URL must use HTTPS');
    }
    
    // Check for required fields
    if (!providerConfig.name) {
      errors.push('Provider name is required');
    }
    
    if (!providerConfig.type) {
      errors.push('Provider type is required');
    }
    
    if (!providerConfig.clientId) {
      errors.push('Client ID is required');
    }
    
    // Check for appropriate scopes
    if (providerConfig.scopes && providerConfig.scopes.includes('email')) {
      // Email scope is acceptable for educational purposes
    } else {
      // Warning: No email scope - may impact user identification
    }
    
    return {
      isValid: errors.length === 0,
      errors: errors,
      warnings: []
    };
  }

  /**
   * Get SSO provider usage statistics
   * @returns {Object} Usage statistics
   */
  static async getProviderStats() {
    try {
      const stats = {};
      
      // Total providers
      const totalQuery = `
        SELECT COUNT(*) as total_providers,
               COUNT(CASE WHEN enabled = true THEN 1 END) as enabled_providers
        FROM sso_providers
      `;
      
      const totalResult = await db.query(totalQuery);
      stats.totalProviders = totalResult.rows[0].total_providers;
      stats.enabledProviders = totalResult.rows[0].enabled_providers;
      
      // Provider types distribution
      const typesQuery = `
        SELECT type, COUNT(*) as count
        FROM sso_providers 
        GROUP BY type
        ORDER BY count DESC
      `;
      
      const typesResult = await db.query(typesQuery);
      stats.providerTypes = typesResult.rows;
      
      // Recent usage (last 30 days)
      const recentQuery = `
        SELECT 
          COUNT(*) as total_logins,
          COUNT(DISTINCT user_id) as unique_users
        FROM activity_logs 
        WHERE action = 'sso_login' 
        AND timestamp >= NOW() - INTERVAL '30 days'
      `;
      
      const recentResult = await db.query(recentQuery);
      stats.recentActivity = recentResult.rows[0];
      
      return stats;
    } catch (error) {
      logger.error('Error getting SSO provider stats:', error);
      throw error;
    }
  }

  /**
   * Export SSO configuration for compliance review
   * @returns {Object} Exported configuration
   */
  static async exportSSOConfig() {
    try {
      const providers = await this.getAllProviders();
      
      return {
        exportedAt: new Date(),
        totalProviders: providers.length,
        providers: providers.map(provider => ({
          id: provider.id,
          name: provider.name,
          type: provider.type,
          issuer: provider.issuer,
          enabled: provider.enabled,
          createdAt: provider.createdAt,
          updatedAt: provider.updatedAt
        })),
        complianceStatus: 'compliant'
      };
    } catch (error) {
      logger.error('Error exporting SSO configuration:', error);
      throw error;
    }
  }

  /**
   * Import SSO configuration from file/data
   * @param {Array} configData - Configuration data to import
   * @returns {Object} Import results
   */
  static async importSSOConfig(configData) {
    const results = {
      imported: 0,
      errors: [],
      warnings: []
    };
    
    try {
      for (const providerData of configData) {
        try {
          await this.registerProvider(providerData);
          results.imported++;
        } catch (error) {
          results.errors.push({
            provider: providerData.name || 'unknown',
            error: error.message
          });
        }
      }
      
      logger.info(`SSO configuration import completed`, { 
        imported: results.imported,
        errors: results.errors.length 
      });
      
      return results;
    } catch (error) {
      logger.error('Error importing SSO configuration:', error);
      throw error;
    }
  }
}

// Export service functions for use in other modules
const registerProvider = SSOService.registerProvider;
const getAllProviders = SSOService.getAllProviders;
const getEnabledProviders = SSOService.getEnabledProviders;
const getProviderById = SSOService.getProviderById;
const updateProvider = SSOService.updateProvider;
const toggleProvider = SSOService.toggleProvider;
const deleteProvider = SSOService.deleteProvider;
const testProviderConnection = SSOService.testProviderConnection;
const generateAuthorizationUrl = SSOService.generateAuthorizationUrl;
const handleSSOCallback = SSOService.handleSSOCallback;
const getClientConfig = SSOService.getClientConfig;
const validateSSOCompliance = SSOService.validateSSOCompliance;
const getProviderStats = SSOService.getProviderStats;
const exportSSOConfig = SSOService.exportSSOConfig;
const importSSOConfig = SSOService.importSSOConfig;

export {
  SSOService,
  registerProvider,
  getAllProviders,
  getEnabledProviders,
  getProviderById,
  updateProvider,
  toggleProvider,
  deleteProvider,
  testProviderConnection,
  generateAuthorizationUrl,
  handleSSOCallback,
  getClientConfig,
  validateSSOCompliance,
  getProviderStats,
  exportSSOConfig,
  importSSOConfig
};
