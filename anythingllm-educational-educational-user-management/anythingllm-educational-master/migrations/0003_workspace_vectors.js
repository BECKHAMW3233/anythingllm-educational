// Vector database integration tables for educational content search
module.exports = async (db, logger) => {
  // Create vectors table for storing vector embeddings
  await db.query(`
    CREATE TABLE IF NOT EXISTS vectors (
      id VARCHAR(255) PRIMARY KEY,
      vector_type VARCHAR(50),
      embedding TEXT NOT NULL,
      size INTEGER,
      content TEXT,
      metadata JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    );
  `);
  
  // Create workspace_vectors table for linking vectors to workspaces
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspace_vectors (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      vector_id VARCHAR(255),
      document_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
      FOREIGN KEY (vector_id) REFERENCES vectors(id) ON DELETE CASCADE,
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL,
      UNIQUE(workspace_id, vector_id)
    );
  `);
  
  // Create workspace_user_vectors table for user-specific vector data
  await db.query(`
    CREATE TABLE IF NOT EXISTS workspace_user_vectors (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      user_id VARCHAR(255),
      vector_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (vector_id) REFERENCES vectors(id) ON DELETE CASCADE,
      UNIQUE(workspace_id, user_id, vector_id)
    );
  `);
  
  // Create vector_search_logs table for tracking search queries
  await db.query(`
    CREATE TABLE IF NOT EXISTS vector_search_logs (
      id SERIAL PRIMARY KEY,
      workspace_id VARCHAR(255),
      user_id VARCHAR(255),
      query_text TEXT,
      results_count INTEGER,
      execution_time_ms INTEGER,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);
  
  // Create indexes for vector tables
  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_vectors_type ON vectors(vector_type);
    CREATE INDEX IF NOT EXISTS idx_vectors_created_at ON vectors(created_at);
    CREATE INDEX IF NOT EXISTS idx_workspace_vectors_workspace ON workspace_vectors(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_vectors_vector ON workspace_vectors(vector_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_user_vectors_workspace ON workspace_user_vectors(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_workspace_user_vectors_user ON workspace_user_vectors(user_id);
    CREATE INDEX IF NOT EXISTS idx_vector_search_logs_workspace ON vector_search_logs(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_vector_search_logs_user ON vector_search_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_vector_search_logs_timestamp ON vector_search_logs(timestamp);
  `);
  
  logger.info('Vector database integration tables created successfully');
};
