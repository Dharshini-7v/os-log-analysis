"""Database integration for the Intelligent Log Analysis System."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from contextlib import asynccontextmanager
import logging

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

try:
    import aiomysql
    AIOMYSQL_AVAILABLE = True
except ImportError:
    AIOMYSQL_AVAILABLE = False

try:
    from influxdb_client import InfluxDBClient, Point
    from influxdb_client.client.write_api import SYNCHRONOUS
    INFLUXDB_AVAILABLE = True
except ImportError:
    INFLUXDB_AVAILABLE = False

from ..models.log_models import ParsedLog
from ..models.pattern_models import Pattern
from ..models.anomaly_models import Anomaly
from ..models.prediction_models import Prediction
from ..utils.logging import get_logger

logger = get_logger("database")


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pg_pool = None
        self.mysql_pool = None
        self.influx_client = None
        self.influx_write_api = None
        self.db_type = None  # 'postgresql', 'mysql', or None
        self._initialized = False
        
    async def initialize(self) -> None:
        """Initialize database connections."""
        logger.info("Initializing database connections...")
        
        try:
            # Try to initialize relational database (PostgreSQL or MySQL)
            await self._init_relational_database()
            
            # Initialize InfluxDB
            await self._init_influxdb()
            
            self._initialized = True
            logger.info("Database connections initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database connections: {e}")
            raise
    
    async def _init_relational_database(self) -> None:
        """Initialize relational database (PostgreSQL or MySQL)."""
        db_config = self.config.get("database", {})
        
        # Try PostgreSQL first
        if db_config.get("postgresql", {}).get("host"):
            await self._init_postgresql()
            if self.pg_pool:
                self.db_type = "postgresql"
                return
        
        # Try MySQL if PostgreSQL failed or not configured
        if db_config.get("mysql", {}).get("host"):
            await self._init_mysql()
            if self.mysql_pool:
                self.db_type = "mysql"
                return
        
        logger.info("No relational database configured or available")
    
    async def _init_mysql(self) -> None:
        """Initialize MySQL connection pool."""
        if not AIOMYSQL_AVAILABLE:
            logger.warning("aiomysql not available, MySQL features disabled")
            return
            
        mysql_config = self.config.get("database", {}).get("mysql", {})
        
        if not mysql_config.get("host"):
            logger.info("MySQL not configured, skipping initialization")
            return
            
        try:
            # Create connection pool
            self.mysql_pool = await aiomysql.create_pool(
                host=mysql_config.get("host", "localhost"),
                port=mysql_config.get("port", 3306),
                user=mysql_config.get("username", "root"),
                password=mysql_config.get("password", ""),
                db=mysql_config.get("database", "intelligent_log_analysis"),
                minsize=1,
                maxsize=mysql_config.get("connection_pool_size", 10),
                autocommit=True
            )
            
            # Create tables
            await self._create_mysql_tables()
            
            logger.info("MySQL connection pool created successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize MySQL: {e}")
            self.mysql_pool = None
    
    async def _init_postgresql(self) -> None:
        """Initialize PostgreSQL connection pool."""
        if not ASYNCPG_AVAILABLE:
            logger.warning("asyncpg not available, PostgreSQL features disabled")
            return
            
        pg_config = self.config.get("database", {}).get("postgresql", {})
        
        if not pg_config.get("host"):
            logger.info("PostgreSQL not configured, skipping initialization")
            return
            
        try:
            # Create connection pool
            self.pg_pool = await asyncpg.create_pool(
                host=pg_config.get("host", "localhost"),
                port=pg_config.get("port", 5432),
                database=pg_config.get("database", "intelligent_log_analysis"),
                user=pg_config.get("username", "postgres"),
                password=pg_config.get("password", ""),
                min_size=1,
                max_size=pg_config.get("connection_pool_size", 10),
                command_timeout=pg_config.get("query_timeout_seconds", 60)
            )
            
            # Create tables
            await self._create_postgresql_tables()
            
            logger.info("PostgreSQL connection pool created successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL: {e}")
            self.pg_pool = None
    
    async def _init_influxdb(self) -> None:
        """Initialize InfluxDB client."""
        if not INFLUXDB_AVAILABLE:
            logger.warning("influxdb-client not available, InfluxDB features disabled")
            return
            
        influx_config = self.config.get("database", {}).get("influxdb", {})
        
        if not influx_config.get("url"):
            logger.info("InfluxDB not configured, skipping initialization")
            return
            
        try:
            self.influx_client = InfluxDBClient(
                url=influx_config.get("url", "http://localhost:8086"),
                token=influx_config.get("token", ""),
                org=influx_config.get("org", "intelligent-log-analysis")
            )
            
            self.influx_write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            
            # Test connection
            health = self.influx_client.health()
            if health.status == "pass":
                logger.info("InfluxDB connection established successfully")
            else:
                logger.warning(f"InfluxDB health check failed: {health.message}")
                
        except Exception as e:
            logger.error(f"Failed to initialize InfluxDB: {e}")
            self.influx_client = None
            self.influx_write_api = None
    
    async def _create_postgresql_tables(self) -> None:
        """Create PostgreSQL tables if they don't exist."""
        if not self.pg_pool:
            return
            
        tables_sql = [
            # Users table
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            
            # Log templates table
            """
            CREATE TABLE IF NOT EXISTS log_templates (
                id SERIAL PRIMARY KEY,
                template_id VARCHAR(100) UNIQUE NOT NULL,
                template_text TEXT NOT NULL,
                parameter_count INTEGER DEFAULT 0,
                frequency INTEGER DEFAULT 1,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_level VARCHAR(20),
                source_pattern VARCHAR(255)
            )
            """,
            
            # Patterns table
            """
            CREATE TABLE IF NOT EXISTS patterns (
                id SERIAL PRIMARY KEY,
                pattern_id VARCHAR(100) UNIQUE NOT NULL,
                pattern_type VARCHAR(50) NOT NULL,
                sequence JSONB NOT NULL,
                frequency INTEGER DEFAULT 1,
                confidence FLOAT DEFAULT 0.0,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_anomalous BOOLEAN DEFAULT FALSE
            )
            """,
            
            # Anomalies table
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                id SERIAL PRIMARY KEY,
                anomaly_id VARCHAR(100) UNIQUE NOT NULL,
                anomaly_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                affected_sources JSONB,
                confidence FLOAT DEFAULT 0.0,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                status VARCHAR(20) DEFAULT 'open'
            )
            """,
            
            # Predictions table
            """
            CREATE TABLE IF NOT EXISTS predictions (
                id SERIAL PRIMARY KEY,
                prediction_id VARCHAR(100) UNIQUE NOT NULL,
                prediction_type VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                probability FLOAT NOT NULL,
                time_horizon INTERVAL NOT NULL,
                predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_time TIMESTAMP NOT NULL,
                model_version VARCHAR(50),
                features JSONB,
                status VARCHAR(20) DEFAULT 'pending'
            )
            """,
            
            # System metrics table
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id SERIAL PRIMARY KEY,
                metric_name VARCHAR(100) NOT NULL,
                metric_value FLOAT NOT NULL,
                metric_unit VARCHAR(20),
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags JSONB
            )
            """
        ]
        
        async with self.pg_pool.acquire() as conn:
            for sql in tables_sql:
                try:
                    await conn.execute(sql)
                    logger.debug(f"Table created/verified: {sql.split()[5]}")
                except Exception as e:
                    logger.error(f"Failed to create table: {e}")
                    
    async def _create_mysql_tables(self) -> None:
        """Create MySQL tables if they don't exist."""
        if not self.mysql_pool:
            return
            
        tables_sql = [
            # Users table
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            
            # Log templates table
            """
            CREATE TABLE IF NOT EXISTS log_templates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                template_id VARCHAR(100) UNIQUE NOT NULL,
                template_text TEXT NOT NULL,
                parameter_count INT DEFAULT 0,
                frequency INT DEFAULT 1,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_level VARCHAR(20),
                source_pattern VARCHAR(255)
            )
            """,
            
            # Patterns table
            """
            CREATE TABLE IF NOT EXISTS patterns (
                id INT AUTO_INCREMENT PRIMARY KEY,
                pattern_id VARCHAR(100) UNIQUE NOT NULL,
                pattern_type VARCHAR(50) NOT NULL,
                sequence JSON NOT NULL,
                frequency INT DEFAULT 1,
                confidence FLOAT DEFAULT 0.0,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_anomalous BOOLEAN DEFAULT FALSE
            )
            """,
            
            # Anomalies table
            """
            CREATE TABLE IF NOT EXISTS anomalies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                anomaly_id VARCHAR(100) UNIQUE NOT NULL,
                anomaly_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                affected_sources JSON,
                confidence FLOAT DEFAULT 0.0,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP NULL,
                status VARCHAR(20) DEFAULT 'open'
            )
            """,
            
            # Predictions table
            """
            CREATE TABLE IF NOT EXISTS predictions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                prediction_id VARCHAR(100) UNIQUE NOT NULL,
                prediction_type VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                probability FLOAT NOT NULL,
                time_horizon_seconds INT NOT NULL,
                predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_time TIMESTAMP NOT NULL,
                model_version VARCHAR(50),
                features JSON,
                status VARCHAR(20) DEFAULT 'pending'
            )
            """,
            
            # System metrics table
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                metric_name VARCHAR(100) NOT NULL,
                metric_value FLOAT NOT NULL,
                metric_unit VARCHAR(20),
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags JSON
            )
            """
        ]
        
        async with self.mysql_pool.acquire() as conn:
            async with conn.cursor() as cursor:
                for sql in tables_sql:
                    try:
                        await cursor.execute(sql)
                        table_name = sql.split()[5] if "CREATE TABLE" in sql else "unknown"
                        logger.debug(f"MySQL table created/verified: {table_name}")
                    except Exception as e:
                        logger.error(f"Failed to create MySQL table: {e}")
                        
        logger.info("MySQL tables created/verified successfully")
    
    async def close(self) -> None:
        """Close database connections."""
        logger.info("Closing database connections...")
        
        if self.pg_pool:
            await self.pg_pool.close()
            logger.info("PostgreSQL connection pool closed")
            
        if self.mysql_pool:
            self.mysql_pool.close()
            await self.mysql_pool.wait_closed()
            logger.info("MySQL connection pool closed")
            
        if self.influx_client:
            self.influx_client.close()
            logger.info("InfluxDB client closed")
    
    def _get_relational_pool(self):
        """Get the active relational database pool."""
        return self.pg_pool if self.db_type == "postgresql" else self.mysql_pool
    
    async def _execute_query(self, query: str, *args):
        """Execute a query on the active relational database."""
        pool = self._get_relational_pool()
        if not pool:
            return None
            
        if self.db_type == "postgresql":
            async with pool.acquire() as conn:
                return await conn.fetchval(query, *args)
        elif self.db_type == "mysql":
            async with pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(query, args)
                    return await cursor.fetchone()
        return None
    
    async def _execute_query_many(self, query: str, *args):
        """Execute a query and return multiple rows."""
        pool = self._get_relational_pool()
        if not pool:
            return []
            
        if self.db_type == "postgresql":
            async with pool.acquire() as conn:
                return await conn.fetch(query, *args)
        elif self.db_type == "mysql":
            async with pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cursor:
                    await cursor.execute(query, args)
                    return await cursor.fetchall()
        return []
    
    async def _execute_insert(self, query: str, *args):
        """Execute an insert query and return the inserted ID."""
        pool = self._get_relational_pool()
        if not pool:
            return None
            
        if self.db_type == "postgresql":
            async with pool.acquire() as conn:
                return await conn.fetchval(query, *args)
        elif self.db_type == "mysql":
            async with pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute(query, args)
                    return cursor.lastrowid
        return None
    
    # User management methods
    async def create_user(self, username: str, password_hash: str, email: str, 
                         full_name: str, role: str = "viewer") -> Optional[int]:
        """Create a new user in the database."""
        if not self._get_relational_pool():
            logger.warning("No relational database available, cannot create user")
            return None
            
        try:
            if self.db_type == "postgresql":
                query = """
                    INSERT INTO users (username, password_hash, email, full_name, role)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                """
                user_id = await self._execute_query(query, username, password_hash, email, full_name, role)
            elif self.db_type == "mysql":
                query = """
                    INSERT INTO users (username, password_hash, email, full_name, role)
                    VALUES (%s, %s, %s, %s, %s)
                """
                user_id = await self._execute_insert(query, username, password_hash, email, full_name, role)
            else:
                return None
                
            logger.info(f"User created: {username} (ID: {user_id})")
            return user_id
                
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            return None
    
    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        if not self._get_relational_pool():
            return None
            
        try:
            if self.db_type == "postgresql":
                query = "SELECT * FROM users WHERE username = $1 AND is_active = TRUE"
                rows = await self._execute_query_many(query, username)
                return dict(rows[0]) if rows else None
            elif self.db_type == "mysql":
                query = "SELECT * FROM users WHERE username = %s AND is_active = TRUE"
                rows = await self._execute_query_many(query, username)
                return rows[0] if rows else None
            return None
                
        except Exception as e:
            logger.error(f"Failed to get user {username}: {e}")
            return None
    
    async def update_user_login(self, username: str) -> None:
        """Update user's last login timestamp."""
        if not self._get_relational_pool():
            return
            
        try:
            if self.db_type == "postgresql":
                query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = $1"
                await self._execute_query(query, username)
            elif self.db_type == "mysql":
                query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = %s"
                await self._execute_query(query, username)
                
        except Exception as e:
            logger.error(f"Failed to update login for {username}: {e}")
    
    # Log storage methods
    async def store_log_entry(self, log_entry: ParsedLog) -> None:
        """Store a log entry in InfluxDB."""
        if not self.influx_write_api:
            return
            
        try:
            point = Point("log_entries") \
                .tag("level", log_entry.level.value) \
                .tag("source", log_entry.source) \
                .tag("template_id", log_entry.template_id or "unknown") \
                .field("message", log_entry.message) \
                .field("raw_log", log_entry.raw_log) \
                .time(log_entry.timestamp)
            
            # Add parameters as fields
            if log_entry.parameters:
                for key, value in log_entry.parameters.items():
                    point.field(f"param_{key}", str(value))
            
            self.influx_write_api.write(
                bucket=self.config.get("database", {}).get("influxdb", {}).get("bucket", "logs"),
                record=point
            )
            
        except Exception as e:
            logger.error(f"Failed to store log entry: {e}")
    
    async def store_pattern(self, pattern: Pattern) -> None:
        """Store a pattern in the relational database."""
        if not self._get_relational_pool():
            return
            
        try:
            if self.db_type == "postgresql":
                query = """
                    INSERT INTO patterns (pattern_id, pattern_type, sequence, frequency, confidence)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (pattern_id) DO UPDATE SET
                        frequency = patterns.frequency + 1,
                        confidence = $5,
                        last_detected = CURRENT_TIMESTAMP
                """
                await self._execute_query(query, pattern.id, pattern.pattern_type, 
                                        json.dumps(pattern.sequence), pattern.frequency, pattern.confidence)
            elif self.db_type == "mysql":
                query = """
                    INSERT INTO patterns (pattern_id, pattern_type, sequence, frequency, confidence)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        frequency = frequency + 1,
                        confidence = VALUES(confidence),
                        last_detected = CURRENT_TIMESTAMP
                """
                await self._execute_query(query, pattern.id, pattern.pattern_type, 
                                        json.dumps(pattern.sequence), pattern.frequency, pattern.confidence)
                
        except Exception as e:
            logger.error(f"Failed to store pattern {pattern.id}: {e}")
    
    async def store_anomaly(self, anomaly: Anomaly) -> None:
        """Store an anomaly in the relational database."""
        if not self._get_relational_pool():
            return
            
        try:
            if self.db_type == "postgresql":
                query = """
                    INSERT INTO anomalies (anomaly_id, anomaly_type, severity, title, 
                                         description, affected_sources, confidence)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """
                await self._execute_query(query, anomaly.id, anomaly.anomaly_type, anomaly.severity.value,
                                        anomaly.title, anomaly.description,
                                        json.dumps(anomaly.affected_sources), anomaly.confidence)
            elif self.db_type == "mysql":
                query = """
                    INSERT INTO anomalies (anomaly_id, anomaly_type, severity, title, 
                                         description, affected_sources, confidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                await self._execute_query(query, anomaly.id, anomaly.anomaly_type, anomaly.severity.value,
                                        anomaly.title, anomaly.description,
                                        json.dumps(anomaly.affected_sources), anomaly.confidence)
                
        except Exception as e:
            logger.error(f"Failed to store anomaly {anomaly.id}: {e}")
    
    async def store_prediction(self, prediction: Prediction) -> None:
        """Store a prediction in the relational database."""
        if not self._get_relational_pool():
            return
            
        try:
            target_time = prediction.predicted_at + timedelta(seconds=prediction.time_horizon_seconds)
            
            if self.db_type == "postgresql":
                query = """
                    INSERT INTO predictions (prediction_id, prediction_type, description,
                                           probability, time_horizon, target_time, features)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """
                await self._execute_query(query, prediction.id, prediction.prediction_type, prediction.description,
                                        prediction.probability, 
                                        timedelta(seconds=prediction.time_horizon_seconds),
                                        target_time, json.dumps(prediction.features or {}))
            elif self.db_type == "mysql":
                query = """
                    INSERT INTO predictions (prediction_id, prediction_type, description,
                                           probability, time_horizon_seconds, target_time, features)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                await self._execute_query(query, prediction.id, prediction.prediction_type, prediction.description,
                                        prediction.probability, prediction.time_horizon_seconds,
                                        target_time, json.dumps(prediction.features or {}))
                
        except Exception as e:
            logger.error(f"Failed to store prediction {prediction.id}: {e}")
    
    # Query methods
    async def get_recent_logs(self, limit: int = 100, 
                            level_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent log entries from InfluxDB."""
        if not self.influx_client:
            return []
            
        try:
            query_api = self.influx_client.query_api()
            
            level_filter_clause = ""
            if level_filter:
                level_filter_clause = f'|> filter(fn: (r) => r.level == "{level_filter}")'
            
            query = f'''
                from(bucket: "{self.config.get("database", {}).get("influxdb", {}).get("bucket", "logs")}")
                |> range(start: -1h)
                |> filter(fn: (r) => r._measurement == "log_entries")
                {level_filter_clause}
                |> sort(columns: ["_time"], desc: true)
                |> limit(n: {limit})
            '''
            
            result = query_api.query(query)
            
            logs = []
            for table in result:
                for record in table.records:
                    logs.append({
                        "timestamp": record.get_time().isoformat(),
                        "level": record.values.get("level", "INFO"),
                        "source": record.values.get("source", "unknown"),
                        "message": record.values.get("message", ""),
                        "template_id": record.values.get("template_id")
                    })
            
            return logs
            
        except Exception as e:
            logger.error(f"Failed to query recent logs: {e}")
            return []
    
    async def get_patterns(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get patterns from the relational database."""
        if not self._get_relational_pool():
            return []
            
        try:
            if self.db_type == "postgresql":
                query = """
                    SELECT pattern_id, pattern_type, sequence, frequency, confidence,
                           last_detected, is_anomalous
                    FROM patterns
                    ORDER BY last_detected DESC
                    LIMIT $1
                """
                rows = await self._execute_query_many(query, limit)
            elif self.db_type == "mysql":
                query = """
                    SELECT pattern_id, pattern_type, sequence, frequency, confidence,
                           last_detected, is_anomalous
                    FROM patterns
                    ORDER BY last_detected DESC
                    LIMIT %s
                """
                rows = await self._execute_query_many(query, limit)
            else:
                return []
                
            return [
                {
                    "id": row["pattern_id"],
                    "pattern_type": row["pattern_type"],
                    "sequence": json.loads(row["sequence"]),
                    "frequency": row["frequency"],
                    "confidence": row["confidence"],
                    "last_seen": row["last_detected"].isoformat() if hasattr(row["last_detected"], 'isoformat') else str(row["last_detected"]),
                    "is_anomalous": bool(row["is_anomalous"])
                }
                for row in rows
            ]
                
        except Exception as e:
            logger.error(f"Failed to query patterns: {e}")
            return []
    
    async def get_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get anomalies from the relational database."""
        if not self._get_relational_pool():
            return []
            
        try:
            if self.db_type == "postgresql":
                query = """
                    SELECT anomaly_id, anomaly_type, severity, title, description,
                           affected_sources, confidence, detected_at
                    FROM anomalies
                    WHERE status = 'open'
                    ORDER BY detected_at DESC
                    LIMIT $1
                """
                rows = await self._execute_query_many(query, limit)
            elif self.db_type == "mysql":
                query = """
                    SELECT anomaly_id, anomaly_type, severity, title, description,
                           affected_sources, confidence, detected_at
                    FROM anomalies
                    WHERE status = 'open'
                    ORDER BY detected_at DESC
                    LIMIT %s
                """
                rows = await self._execute_query_many(query, limit)
            else:
                return []
                
            return [
                {
                    "id": row["anomaly_id"],
                    "anomaly_type": row["anomaly_type"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "description": row["description"],
                    "affected_sources": json.loads(row["affected_sources"] or "[]"),
                    "confidence": row["confidence"],
                    "timestamp": row["detected_at"].isoformat() if hasattr(row["detected_at"], 'isoformat') else str(row["detected_at"])
                }
                for row in rows
            ]
                
        except Exception as e:
            logger.error(f"Failed to query anomalies: {e}")
            return []
    
    async def get_predictions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get predictions from the relational database."""
        if not self._get_relational_pool():
            return []
            
        try:
            if self.db_type == "postgresql":
                query = """
                    SELECT prediction_id, prediction_type, description, probability,
                           time_horizon, predicted_at, target_time
                    FROM predictions
                    WHERE status = 'pending' AND target_time > CURRENT_TIMESTAMP
                    ORDER BY predicted_at DESC
                    LIMIT $1
                """
                rows = await self._execute_query_many(query, limit)
            elif self.db_type == "mysql":
                query = """
                    SELECT prediction_id, prediction_type, description, probability,
                           time_horizon_seconds, predicted_at, target_time
                    FROM predictions
                    WHERE status = 'pending' AND target_time > CURRENT_TIMESTAMP
                    ORDER BY predicted_at DESC
                    LIMIT %s
                """
                rows = await self._execute_query_many(query, limit)
            else:
                return []
                
            return [
                {
                    "id": row["prediction_id"],
                    "type": row["prediction_type"],
                    "description": row["description"],
                    "probability": row["probability"],
                    "time_horizon": str(row.get("time_horizon", f"{row.get('time_horizon_seconds', 0)} seconds")),
                    "timestamp": row["predicted_at"].isoformat() if hasattr(row["predicted_at"], 'isoformat') else str(row["predicted_at"])
                }
                for row in rows
            ]
                
        except Exception as e:
            logger.error(f"Failed to query predictions: {e}")
            return []
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get system statistics from database."""
        stats = {
            "logs_processed": 0,
            "patterns_detected": 0,
            "anomalies_found": 0,
            "predictions_made": 0
        }
        
        if not self._get_relational_pool():
            return stats
            
        try:
            # Get pattern count
            if self.db_type == "postgresql":
                pattern_count = await self._execute_query("SELECT COUNT(*) FROM patterns")
                anomaly_count = await self._execute_query("SELECT COUNT(*) FROM anomalies")
                prediction_count = await self._execute_query("SELECT COUNT(*) FROM predictions")
                log_count = await self._execute_query("SELECT SUM(frequency) FROM log_templates")
            elif self.db_type == "mysql":
                pattern_count = await self._execute_query("SELECT COUNT(*) FROM patterns")
                anomaly_count = await self._execute_query("SELECT COUNT(*) FROM anomalies")
                prediction_count = await self._execute_query("SELECT COUNT(*) FROM predictions")
                log_count = await self._execute_query("SELECT SUM(frequency) FROM log_templates")
                
                # MySQL returns tuples, extract the count
                pattern_count = pattern_count[0] if pattern_count else 0
                anomaly_count = anomaly_count[0] if anomaly_count else 0
                prediction_count = prediction_count[0] if prediction_count else 0
                log_count = log_count[0] if log_count else 0
            
            stats["patterns_detected"] = pattern_count or 0
            stats["anomalies_found"] = anomaly_count or 0
            stats["predictions_made"] = prediction_count or 0
            stats["logs_processed"] = int(log_count or 0)
                
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
        
        # Get log count from InfluxDB if available - this will override the relational DB count if present
        if self.influx_client:
            try:
                query_api = self.influx_client.query_api()
                query = f'''
                    from(bucket: "{self.config.get("database", {}).get("influxdb", {}).get("bucket", "logs")}")
                    |> range(start: -24h)
                    |> filter(fn: (r) => r._measurement == "log_entries")
                    |> count()
                '''
                
                result = query_api.query(query)
                for table in result:
                    for record in table.records:
                        stats["logs_processed"] = record.get_value() or 0
                        break
                        
            except Exception as e:
                logger.error(f"Failed to get log count: {e}")
        
        return stats


# Global database manager instance
db_manager: Optional[DatabaseManager] = None


async def get_database() -> Optional[DatabaseManager]:
    """Get the global database manager instance."""
    return db_manager


async def initialize_database(config: Dict[str, Any]) -> DatabaseManager:
    """Initialize the global database manager."""
    global db_manager
    
    db_manager = DatabaseManager(config)
    await db_manager.initialize()
    
    return db_manager


async def close_database() -> None:
    """Close the global database manager."""
    global db_manager
    
    if db_manager:
        await db_manager.close()
        db_manager = None