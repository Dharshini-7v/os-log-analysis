"""Configuration data models."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator


class CollectorConfig(BaseModel):
    """Configuration for log collection."""
    
    # Log sources
    log_sources: List[Dict[str, Any]] = Field(default_factory=list, description="List of log sources to monitor")
    
    # Processing settings
    batch_size: int = Field(default=1000, gt=0, description="Number of log entries to process in a batch")
    processing_interval_seconds: float = Field(default=1.0, gt=0, description="Interval between processing cycles")
    max_file_size_mb: int = Field(default=100, gt=0, description="Maximum file size to process")
    
    # Retry settings
    retry_attempts: int = Field(default=3, ge=0, description="Number of retry attempts for failed operations")
    retry_backoff_base: float = Field(default=2.0, gt=1.0, description="Base for exponential backoff")
    retry_max_delay: int = Field(default=300, gt=0, description="Maximum retry delay in seconds")
    
    # Performance settings
    max_concurrent_files: int = Field(default=50, gt=0, description="Maximum number of files to process concurrently")
    buffer_size: int = Field(default=8192, gt=0, description="Buffer size for file reading")


class ParserConfig(BaseModel):
    """Configuration for log parsing."""
    
    # Drain algorithm parameters
    drain_depth: int = Field(default=4, gt=0, description="Depth of the Drain parsing tree")
    drain_similarity_threshold: float = Field(default=0.4, ge=0.0, le=1.0, description="Similarity threshold for template matching")
    drain_max_children: int = Field(default=100, gt=0, description="Maximum children per node in Drain tree")
    
    # Template extraction
    template_cache_size: int = Field(default=10000, gt=0, description="Size of template cache")
    parameter_extraction: bool = Field(default=True, description="Whether to extract parameters from log messages")
    
    # Format detection
    auto_detect_format: bool = Field(default=True, description="Whether to automatically detect log formats")
    supported_formats: List[str] = Field(default_factory=lambda: ["syslog", "json", "windows_event"], description="Supported log formats")


class PatternDetectorConfig(BaseModel):
    """Configuration for pattern detection."""
    
    # Analysis windows
    short_window_minutes: int = Field(default=5, gt=0, description="Short-term analysis window in minutes")
    long_window_hours: int = Field(default=24, gt=0, description="Long-term analysis window in hours")
    
    # Pattern classification
    frequency_threshold: int = Field(default=10, gt=0, description="Minimum frequency for pattern recognition")
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0, description="Minimum confidence for pattern classification")
    
    # Baseline establishment
    baseline_days: int = Field(default=7, gt=0, description="Number of days for baseline establishment")
    baseline_update_hours: int = Field(default=6, gt=0, description="Hours between baseline updates")
    
    # Sequence analysis
    max_sequence_length: int = Field(default=10, gt=0, description="Maximum length of sequence patterns")
    sequence_gap_tolerance: int = Field(default=5, ge=0, description="Tolerance for gaps in sequences")


class MLConfig(BaseModel):
    """Configuration for machine learning engine."""
    
    # Training settings
    training_data_days: int = Field(default=30, gt=0, description="Days of data to use for training")
    retrain_interval_hours: int = Field(default=24, gt=0, description="Hours between model retraining")
    min_training_samples: int = Field(default=1000, gt=0, description="Minimum samples required for training")
    
    # Prediction settings
    prediction_horizon_hours: int = Field(default=24, gt=0, description="Prediction time horizon in hours")
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0, description="Minimum confidence for predictions")
    
    # Model parameters
    ensemble_models: List[str] = Field(default_factory=lambda: ["random_forest", "isolation_forest"], description="Models to use in ensemble")
    
    # Feature extraction
    feature_window_minutes: int = Field(default=60, gt=0, description="Time window for feature extraction")
    max_features: int = Field(default=1000, gt=0, description="Maximum number of features to extract")
    
    # Model persistence
    model_save_path: str = Field(default="models/", description="Path to save trained models")
    model_versioning: bool = Field(default=True, description="Whether to version saved models")


class AnomalyDetectorConfig(BaseModel):
    """Configuration for anomaly detection."""
    
    # Detection methods
    statistical_threshold: float = Field(default=3.0, gt=0, description="Standard deviations for statistical anomaly detection")
    isolation_forest_contamination: float = Field(default=0.1, gt=0.0, lt=1.0, description="Expected contamination rate for isolation forest")
    
    # Severity scoring
    severity_thresholds: Dict[str, float] = Field(
        default_factory=lambda: {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 0.9},
        description="Thresholds for severity classification"
    )
    
    # Learning settings
    feedback_weight: float = Field(default=0.1, ge=0.0, le=1.0, description="Weight for incorporating feedback")
    baseline_update_rate: float = Field(default=0.05, ge=0.0, le=1.0, description="Rate for updating baselines")
    
    # Context analysis
    context_window_minutes: int = Field(default=30, gt=0, description="Context window for anomaly analysis")
    max_context_events: int = Field(default=100, gt=0, description="Maximum events to consider for context")


class AlertSystemConfig(BaseModel):
    """Configuration for alert system."""
    
    # Triggering thresholds
    prediction_confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence threshold for prediction alerts")
    anomaly_severity_threshold: float = Field(default=0.6, ge=0.0, le=1.0, description="Severity threshold for anomaly alerts")
    critical_alert_timeout_seconds: int = Field(default=30, gt=0, description="Timeout for critical alert delivery")
    
    # Rate limiting
    max_alerts_per_minute: int = Field(default=10, gt=0, description="Maximum alerts per minute")
    burst_window_minutes: int = Field(default=5, gt=0, description="Time window for burst detection")
    
    # Notification channels
    email_enabled: bool = Field(default=False, description="Whether email notifications are enabled")
    email_config: Dict[str, Any] = Field(default_factory=dict, description="Email configuration")
    
    webhook_enabled: bool = Field(default=False, description="Whether webhook notifications are enabled")
    webhook_config: Dict[str, Any] = Field(default_factory=dict, description="Webhook configuration")
    
    # Alert content
    include_context: bool = Field(default=True, description="Whether to include context in alerts")
    include_recommendations: bool = Field(default=True, description="Whether to include recommendations")
    max_context_lines: int = Field(default=20, gt=0, description="Maximum context lines in alerts")


class DatabaseConfig(BaseModel):
    """Configuration for database connections."""
    
    # InfluxDB settings
    influxdb_url: str = Field(default="http://localhost:8086", description="InfluxDB connection URL")
    influxdb_token: str = Field(default="", description="InfluxDB authentication token")
    influxdb_org: str = Field(default="intelligent-log-analysis", description="InfluxDB organization")
    influxdb_bucket: str = Field(default="logs", description="InfluxDB bucket name")
    
    # PostgreSQL settings
    postgresql_host: str = Field(default="localhost", description="PostgreSQL host")
    postgresql_port: int = Field(default=5432, gt=0, le=65535, description="PostgreSQL port")
    postgresql_database: str = Field(default="intelligent_log_analysis", description="PostgreSQL database name")
    postgresql_username: str = Field(default="postgres", description="PostgreSQL username")
    postgresql_password: str = Field(default="", description="PostgreSQL password")
    
    # Connection settings
    connection_pool_size: int = Field(default=10, gt=0, description="Database connection pool size")
    connection_timeout_seconds: int = Field(default=30, gt=0, description="Connection timeout in seconds")
    query_timeout_seconds: int = Field(default=60, gt=0, description="Query timeout in seconds")
    
    # Data retention
    retention_policies: Dict[str, int] = Field(
        default_factory=lambda: {
            "raw_logs_days": 30,
            "patterns_days": 90,
            "predictions_days": 365,
            "metrics_days": 30
        },
        description="Data retention policies in days"
    )


class PerformanceConfig(BaseModel):
    """Configuration for performance settings."""
    
    # Processing limits
    max_log_entries_per_second: int = Field(default=10000, gt=0, description="Maximum log entries to process per second")
    max_concurrent_files: int = Field(default=50, gt=0, description="Maximum files to process concurrently")
    max_memory_usage_mb: int = Field(default=2048, gt=0, description="Maximum memory usage in MB")
    
    # Auto-scaling
    enable_auto_scaling: bool = Field(default=True, description="Whether to enable auto-scaling")
    scale_up_threshold: float = Field(default=0.8, ge=0.0, le=1.0, description="Threshold for scaling up")
    scale_down_threshold: float = Field(default=0.3, ge=0.0, le=1.0, description="Threshold for scaling down")
    
    # Resource prioritization
    critical_sources_priority: int = Field(default=10, gt=0, description="Priority for critical log sources")
    high_severity_priority: int = Field(default=8, gt=0, description="Priority for high severity events")
    normal_priority: int = Field(default=5, gt=0, description="Priority for normal events")


class APIConfig(BaseModel):
    """Configuration for API server."""
    
    host: str = Field(default="0.0.0.0", description="API server host")
    port: int = Field(default=8700, gt=0, le=65535, description="API server port")
    workers: int = Field(default=4, gt=0, description="Number of worker processes")
    
    # Authentication
    enable_auth: bool = Field(default=False, description="Whether to enable authentication")
    jwt_secret: str = Field(default="change-this-secret", description="JWT secret key")
    token_expiry_hours: int = Field(default=24, gt=0, description="Token expiry time in hours")


class SystemConfig(BaseModel):
    """Main system configuration."""
    
    # System-wide settings
    log_level: str = Field(default="INFO", description="System log level")
    log_file: Optional[str] = Field(default=None, description="Log file path")
    metrics_retention_hours: int = Field(default=24, gt=0, description="Metrics retention time in hours")
    
    # Component configurations
    collector: CollectorConfig = Field(default_factory=CollectorConfig, description="Log collector configuration")
    parser: ParserConfig = Field(default_factory=ParserConfig, description="Log parser configuration")
    pattern_detector: PatternDetectorConfig = Field(default_factory=PatternDetectorConfig, description="Pattern detector configuration")
    ml_engine: MLConfig = Field(default_factory=MLConfig, description="ML engine configuration")
    anomaly_detector: AnomalyDetectorConfig = Field(default_factory=AnomalyDetectorConfig, description="Anomaly detector configuration")
    alert_system: AlertSystemConfig = Field(default_factory=AlertSystemConfig, description="Alert system configuration")
    database: DatabaseConfig = Field(default_factory=DatabaseConfig, description="Database configuration")
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig, description="Performance configuration")
    api: APIConfig = Field(default_factory=APIConfig, description="API configuration")
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()
    
    def get_component_config(self, component: str) -> BaseModel:
        """Get configuration for a specific component."""
        component_map = {
            "collector": self.collector,
            "parser": self.parser,
            "pattern_detector": self.pattern_detector,
            "ml_engine": self.ml_engine,
            "anomaly_detector": self.anomaly_detector,
            "alert_system": self.alert_system,
            "database": self.database,
            "performance": self.performance,
            "api": self.api
        }
        
        if component not in component_map:
            raise ValueError(f"Unknown component: {component}")
        
        return component_map[component]
