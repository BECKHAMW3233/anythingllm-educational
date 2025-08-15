// server/src/app.js
/**
 * Main Application Entry Point for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in application setup
 */
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { fileURLToPath } from 'url';
import path from 'path';
import routes from './routes/index.js';
import { initializeSSO } from './services/sso.js';
import config from './config/compliance.js';

// Initialize SSO providers
const ssoProviders = initializeSSO();
console.log('[APP] SSO Providers initialized:', ssoProviders);

const app = express();

// Middleware setup
app.use(helmet()); // Security headers
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Logging middleware
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

app.use(compression()); // Compress responses
app.use(cookieParser()); // Parse cookies
app.use(express.json({ limit: '50mb' })); // Parse JSON bodies
app.use(express.urlencoded({ extended: true, limit: '50mb' })); // Parse URL-encoded bodies

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'AnythingLLM Educational',
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes
app.use('/api', routes);

// Serve static files (if needed)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, '../public')));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[APP] Unhandled error:', err);
  
  // Don't expose sensitive information in production
  const errorResponse = {
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  };
  
  if (process.env.NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
  }
  
  res.status(500).json(errorResponse);
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not found',
    message: 'The requested resource was not found'
  });
});

// Export app for testing and server startup
export default app;

// Initialize application on startup
const initializeApp = async () => {
  try {
    console.log('[APP] Initializing AnythingLLM Educational application...');
    
    // Validate configuration
    const configValidation = config.validate.settings();
    if (!configValidation.isValid) {
      console.error('[APP] Configuration validation failed:', configValidation.errors);
      throw new Error('Application configuration is invalid');
    }
    
    console.log('[APP] Application initialized successfully');
    console.log('[APP] SSO Providers enabled:', ssoProviders);
    
    return app;
  } catch (error) {
    console.error('[APP] Failed to initialize application:', error);
    throw error;
  }
};

// Export initialization function
export { initializeApp };
