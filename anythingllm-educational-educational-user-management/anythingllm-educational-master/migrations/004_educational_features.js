// Additional educational features and tables
module.exports = async (db, logger) => {
  // Create workspace_chats table for chat history
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspace_chats (
      id VARCHAR(255) PRIMARY KEY,
      workspace_id VARCHAR(255),
      user_id VARCHAR(255),
      title VARCHAR(255),
      messages JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);
  
  // Create system_settings table for configuration
  await db.query(`
    CREATE TABLE IF NOT EXISTS system_settings (
      id SERIAL PRIMARY KEY,
      key VARCHAR(255) UNIQUE NOT NULL,
      value TEXT,
      description TEXT,
      type VARCHAR(50) DEFAULT 'string',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  // Create welcome_messages table for onboarding
  await db.query(`
    CREATE TABLE IF NOT EXISTS welcome_messages (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      message TEXT,
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
    );
  `);
  
  // Create api_keys table for API access
  await db.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id VARCHAR(255) PRIMARY KEY,
      user_id VARCHAR(255),
      name VARCHAR(255),
      key_hash TEXT NOT NULL,
      permissions JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP,
      is_active BOOLEAN DEFAULT true,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
  
  // Create indexes for educational tables
  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_workspace_chats_workspace ON workspace_chats(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_chats_user ON workspace_chats(user_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_chats_created_at ON workspace_chats(created_at);
    CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(key);
    CREATE INDEX IF NOT EXISTS idx_welcome_messages_workspace ON welcome_messages(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
  `);
  
  // Insert default system settings
  await db.query(`
    INSERT INTO system_settings (key, value, description, type) 
    VALUES 
      ('max_workspace_members', '100', 'Maximum members per workspace', 'integer'),
      ('data_retention_days', '30', 'Data retention period in days', 'integer'),
      ('enable_sso', 'true', 'Enable Single Sign-On', 'boolean'),
      ('enable_vector_search', 'true', 'Enable vector search functionality', 'boolean')
    ON CONFLICT (key) DO NOTHING;
  `);
  
  logger.info('Educational features tables created successfully');
};
