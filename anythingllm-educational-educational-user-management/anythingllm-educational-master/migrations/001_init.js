// Initial database schema for educational AnythingLLM deployment
module.exports = async (db, logger) => {
  // Create users table
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(255) PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'viewer',
      password_hash TEXT,
      sso_provider VARCHAR(100),
      sso_user_id VARCHAR(255),
      last_login TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    );
  `);
  
  // Create workspaces table
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      owner_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    );
  `);
  
  // Create workspace_users table (junction table for workspace membership)
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspace_users (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      user_id VARCHAR(255),
      role VARCHAR(50) DEFAULT 'viewer',
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(workspace_id, user_id)
    );
  `);
  
  // Create documents table
  await db.query(`
    CREATE TABLE IF NOT EXISTS documents (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      file_path TEXT,
      size INTEGER,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    );
  `);
  
  // Create workspace_documents table (junction table for document/workspace association)
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspace_documents (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      document_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
      UNIQUE(workspace_id, document_id)
    );
  `);
  
  // Create activity_logs table for audit trail
  await db.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(255),
      workspace_id VARCHAR(255),
      action VARCHAR(100),
      description TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL
    );
  `);
  
  // Create sso_providers table
  await db.query(`
    CREATE TABLE IF NOT EXISTS sso_providers (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) UNIQUE NOT NULL,
      type VARCHAR(50) NOT NULL,
      client_id VARCHAR(255) NOT NULL,
      client_secret TEXT NOT NULL,
      issuer VARCHAR(255),
      authorization_url TEXT,
      token_url TEXT,
      user_info_url TEXT,
      scopes TEXT,
      enabled BOOLEAN DEFAULT true,
      callback_url TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Create migrations table (for tracking migrations)
  await db.query(`
    CREATE TABLE IF NOT EXISTS migrations (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      version VARCHAR(50),
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      executed_at TIMESTAMP,
      rollback_script TEXT,
      description TEXT
    );
  `);
  
  // Create indexes for better performance
  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_sso_provider ON users(sso_provider);
    CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_users_user ON workspace_users(user_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_users_workspace ON workspace_users(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_activity_logs_workspace ON activity_logs(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_migrations_status ON migrations(status);
    CREATE INDEX IF NOT EXISTS idx_migrations_created_at ON migrations(created_at);
  `);
  
  logger.info('Initial database schema created successfully');
};
