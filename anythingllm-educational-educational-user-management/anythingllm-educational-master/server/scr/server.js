// server/src/server.js
/**
 * Server Entry Point for Educational AnythingLLM Deployment
 * Maintains FERPA/COPPA compliance by avoiding PII exposure in server configuration
 */
import app from './app.js';
import { initializeApp } from './app.js';
import { createServer } from 'http';
import { Server } from 'socket.io';
import config from './config/compliance.js';

// Get port from environment or default to 3000
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

// Create HTTP server
const server = createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true
  },
  // Secure WebSocket configuration
  transports: ['websocket', 'polling'],
  allowEIO3: false,
  cookie: {
    name: 'socket.io',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Store connected users with anonymized identifiers
const connectedUsers = new Map();

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('[SOCKET] New client connected:', socket.id);
  
  // Handle user authentication
  socket.on('authenticate', (authData) => {
    try {
      // In a real implementation, this would validate the auth token
      // For now, we'll just store the connection
      
      const userId = authData?.userId || 'anonymous';
      const anonymizedUserId = config.generateAnonymizedId(userId);
      
      connectedUsers.set(socket.id, {
        userId: anonymizedUserId,
        socketId: socket.id,
        connectedAt: new Date()
      });
      
      console.log('[SOCKET] User authenticated:', anonymizedUserId);
      socket.emit('authenticated', { success: true });
    } catch (error) {
      console.error('[SOCKET] Authentication error:', error);
      socket.emit('authentication_error', { error: 'Authentication failed' });
    }
  });
  
  // Handle user disconnection
  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      console.log('[SOCKET] User disconnected:', user.userId);
      connectedUsers.delete(socket.id);
    } else {
      console.log('[SOCKET] Anonymous user disconnected:', socket.id);
    }
  });
  
  // Handle workspace events
  socket.on('workspace:join', (data) => {
    try {
      const { workspaceId, userId } = data;
      const anonymizedWorkspaceId = config.generateAnonymizedId(workspaceId);
      const anonymizedUserId = config.generateAnonymizedId(userId);
      
      socket.join(`workspace_${anonymizedWorkspaceId}`);
      console.log('[SOCKET] User joined workspace:', anonymizedUserId, anonymizedWorkspaceId);
    } catch (error) {
      console.error('[SOCKET] Workspace join error:', error);
    }
  });
  
  // Handle chat events
  socket.on('chat:message', (data) => {
    try {
      const { workspaceId, message, userId } = data;
      
      // Broadcast to workspace room
      io.to(`workspace_${config.generateAnonymizedId(workspaceId)}`)
        .emit('chat:received', {
          message,
          userId: config.generateAnonymizedId(userId),
          timestamp: new Date().toISOString()
        });
    } catch (error) {
      console.error('[SOCKET] Chat message error:', error);
    }
  });
});

// Initialize application
const startServer = async () => {
  try {
    // Initialize the application
    await initializeApp();
    
    // Start server
    server.listen(PORT, HOST, () => {
      console.log(`[SERVER] AnythingLLM Educational server running on http://${HOST}:${PORT}`);
      console.log(`[SERVER] Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`[SERVER] Version: ${process.env.npm_package_version || '1.0.0'}`);
      
      // Log SSO configuration
      console.log('[SERVER] SSO Configuration:');
      console.log('  - Google SSO:', process.env.GOOGLE_SSO_ENABLED === 'true' ? 'Enabled' : 'Disabled');
      console.log('  - Microsoft SSO:', process.env.MICROSOFT_SSO_ENABLED === 'true' ? 'Enabled' : 'Disabled');
      console.log('  - LDAP SSO:', process.env.LDAP_SSO_ENABLED === 'true' ? 'Enabled' : 'Disabled');
    });
    
    // Handle server errors
    server.on('error', (error) => {
      console.error('[SERVER] Error starting server:', error);
      process.exit(1);
    });
    
  } catch (error) {
    console.error('[SERVER] Failed to start application:', error);
    process.exit(1);
  }
};

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('[SERVER] SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('[SERVER] Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('[SERVER] SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('[SERVER] Server closed');
    process.exit(0);
  });
});

// Export server and start function
export { server, io, startServer };

// Start the server if this file is run directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer();
}
