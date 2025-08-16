// Compliance and audit logging tables for FERPA/COPPA compliance
module.exports = async (db, logger) => {
  // Create compliance_audit_logs table for detailed audit trail
  await db.query(`
    CREATE TABLE IF NOT EXISTS compliance_audit_logs (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(255),
      workspace_id VARCHAR(255),
      action VARCHAR(100),
      details TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      session_id VARCHAR(255),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL
    );
  `);
  
  // Create compliance_issues table for tracking compliance violations
  await db.query(`
    CREATE TABLE IF NOT EXISTS compliance_issues (
      id SERIAL PRIMARY KEY,
      issue_type VARCHAR(100),
      severity VARCHAR(20) DEFAULT 'medium',
      description TEXT,
      workspace_id VARCHAR(255),
      user_id VARCHAR(255),
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      resolved BOOLEAN DEFAULT false,
      resolution_notes TEXT,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);
  
  // Create security_events table for security monitoring
  await db.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id SERIAL PRIMARY KEY,
      event_type VARCHAR(100),
      description TEXT,
      user_id VARCHAR(255),
      workspace_id VARCHAR(255),
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      session_id VARCHAR(255),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL
    );
  `);
  
  // Create document_access_logs table for tracking document access
  await db.query(`
    CREATE TABLE IF NOT EXISTS document_access_logs (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(255),
      document_id VARCHAR(255),
      workspace_id VARCHAR(255),
      access_type VARCHAR(50) DEFAULT 'view',
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(45),
      user_agent TEXT,
      session_id VARCHAR(255),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL,
      FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL
    );
  `);
  
  // Create indexes for compliance tables
  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_user ON compliance_audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_workspace ON compliance_audit_logs(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_timestamp ON compliance_audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_compliance_issues_workspace ON compliance_issues(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_issues_user ON compliance_issues(user_id);
    CREATE INDEX IF NOT EXISTS idx_compliance_issues_timestamp ON compliance_issues(timestamp);
    CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_security_events_workspace ON security_events(workspace_id);
    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_document_access_logs_user ON document_access_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_document_access_logs_document ON document_access_logs(document_id);
    CREATE INDEX IF NOT EXISTS idx_document_access_logs_timestamp ON document_access_logs(timestamp);
  `);
  
  logger.info('Compliance and audit tables created successfully');
};
