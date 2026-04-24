-- Create the database
CREATE DATABASE IF NOT EXISTS intelligent_log_analysis;

-- Create the user for the application (allowing access from any host)
CREATE USER IF NOT EXISTS 'log_analyzer'@'%' IDENTIFIED BY 'LogAnalyzer@2026';

-- Grant all privileges
GRANT ALL PRIVILEGES ON intelligent_log_analysis.* TO 'log_analyzer'@'%';

-- Flush privileges to apply changes
FLUSH PRIVILEGES;

-- Verify
SHOW GRANTS FOR 'log_analyzer'@'%';
