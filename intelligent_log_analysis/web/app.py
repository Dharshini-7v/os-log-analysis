"""FastAPI web application for the intelligent log analysis dashboard."""

import asyncio
import json
import re
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import jwt

from ..models.log_models import ParsedLog, LogLevel, LogSource
from ..models.anomaly_models import Anomaly, SeverityLevel
from ..models.pattern_models import Pattern
from ..models.prediction_models import Prediction
from ..models.config_models import CollectorConfig, ParserConfig
from ..core.collector import LogCollector
from ..core.parser import LogParser
from ..utils.logging import get_logger
from ..utils.config import ConfigManager
from ..storage.database import get_database, initialize_database, close_database

logger = get_logger("web")

# Global instances
config_manager: Optional[ConfigManager] = None
db_manager: Optional[Any] = None
log_parser: Optional[LogParser] = None
log_collector: Optional[LogCollector] = None
demo_generation_task: Optional[asyncio.Task] = None

# Security configuration
SECRET_KEY = "intelligent_log_analysis_secret_key_2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Demo users (in production, this would be in a database)
DEMO_USERS = {
    "admin": {"password": "admin123", "role": "administrator", "name": "System Administrator", "email": "admin@loganalysis.com"},
    "analyst": {"password": "analyst123", "role": "log_analyst", "name": "Log Analyst", "email": "analyst@loganalysis.com"},
    "demo": {"password": "demo", "role": "viewer", "name": "Demo User", "email": "demo@loganalysis.com"}
}

# User validation functions
def hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength."""
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username: str) -> tuple[bool, str]:
    """Validate username."""
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 20:
        return False, "Username must be less than 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    if username.lower() in DEMO_USERS:
        return False, "Username already exists"
    return True, "Username is valid"

def create_user(username: str, password: str, name: str, email: str, role: str = "viewer") -> bool:
    """Create a new user account."""
    try:
        # Hash the password
        hashed_password = hash_password(password)
        
        # Add user to DEMO_USERS (in production, this would be saved to database)
        DEMO_USERS[username.lower()] = {
            "password": hashed_password,
            "role": role,
            "name": name,
            "email": email,
            "created_at": datetime.now().isoformat(),
            "is_hashed": True  # Flag to indicate password is hashed
        }
        
        # Also try to save to database if available
        asyncio.create_task(save_user_to_database(username.lower(), hashed_password, email, name, role))
        
        return True
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

async def save_user_to_database(username: str, password_hash: str, email: str, name: str, role: str):
    """Save user to database if available."""
    try:
        db = await get_database()
        if db:
            await db.create_user(username, password_hash, email, name, role)
    except Exception as e:
        logger.error(f"Failed to save user to database: {e}")

app = FastAPI(title="Intelligent Log Analysis Dashboard", version="1.0.0")

# Lifecycle events
@app.on_event("startup")
async def startup_event():
    """Initialize system components on startup."""
    global config_manager, db_manager, log_parser, log_collector, demo_generation_task
    
    logger.info("Initializing Intelligent Log Analysis System...")
    
    try:
        # Load configuration
        config_path = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
        config_manager = ConfigManager(config_path)
        config = config_manager.get_all_config()
        
        # Reuse the database connection created by the main entrypoint when available.
        db_manager = await get_database()
        if db_manager is None:
            db_manager = await initialize_database(config)
            logger.info("Database initialized")
        else:
            logger.info("Using existing database connection")
        
        # Initialize log parser
        parser_config = ParserConfig(
            drain_depth=config.get("parser", {}).get("drain", {}).get("depth", 4),
            drain_similarity_threshold=config.get("parser", {}).get("drain", {}).get("similarity_threshold", 0.4),
            drain_max_children=config.get("parser", {}).get("drain", {}).get("max_children", 100),
            template_cache_size=config.get("parser", {}).get("template_cache_size", 10000),
            parameter_extraction=config.get("parser", {}).get("parameter_extraction", True)
        )
        log_parser = LogParser(parser_config)
        logger.info("Log parser initialized")
        
        # Initialize log collector
        collector_config = CollectorConfig(
            log_sources=config.get("collector", {}).get("log_sources", []),
            batch_size=config.get("collector", {}).get("batch_size", 1000),
            processing_interval_seconds=config.get("collector", {}).get("processing_interval_seconds", 1.0)
        )
        log_collector = LogCollector(collector_config)
        
        # Set callback for real-time processing
        log_collector.set_log_callback(log_processing_callback)
        
        # Start collector
        await log_collector.start()
        logger.info("Log collector started")
        
        # Start demo data generation as fallback/enrichment
        await seed_demo_patterns_if_empty()
        if demo_generation_task is None or demo_generation_task.done():
            demo_generation_task = asyncio.create_task(run_demo_generation())

    except Exception as e:
        logger.error(f"Error during startup: {e}")
        # In demo mode, we continue even if some components fail
        await seed_demo_patterns_if_empty()
        if demo_generation_task is None or demo_generation_task.done():
            demo_generation_task = asyncio.create_task(run_demo_generation())

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup components on shutdown."""
    global demo_generation_task

    logger.info("Shutting down system components...")

    if demo_generation_task and not demo_generation_task.done():
        demo_generation_task.cancel()
        try:
            await demo_generation_task
        except asyncio.CancelledError:
            pass
        demo_generation_task = None
    
    if log_collector:
        await log_collector.stop()
    
    await close_database()

def log_processing_callback(log_line: str, file_path: str, source_config: LogSource):
    """Callback for processing new log entries in real-time."""
    if not log_parser or not db_manager:
        return
        
    try:
        # Parse the log entry
        parsed_log = log_parser.parse_log_entry(log_line, file_path, source_config.format)
        
        # Store in database
        asyncio.create_task(db_manager.store_log_entry(parsed_log))
        
        # Broadcast to dashboard via WebSockets
        log_data = parsed_log.to_dict()
        asyncio.create_task(broadcast_update({
            "type": "new_log",
            "data": log_data
        }))
        
        # Also update demo data for fallback queries
        demo_data["logs"].append(log_data)
        demo_data["metrics"]["logs_processed"] += 1
        if len(demo_data["logs"]) > 1000:
            demo_data["logs"] = demo_data["logs"][-1000:]
            
    except Exception as e:
        logger.error(f"Error in log processing callback: {e}")

async def run_demo_generation():
    """Task for periodic demo data generation."""
    while True:
        try:
            # Generate demo log every few seconds
            await generate_demo_log()
            
            # Occasionally generate an anomaly or prediction
            import random
            if random.random() < 0.08:
                await generate_demo_pattern()
            if random.random() < 0.05:
                await generate_demo_anomaly()
            if random.random() < 0.03:
                await generate_demo_prediction()
                
            await asyncio.sleep(random.uniform(2, 10))
        except Exception as e:
            logger.error(f"Error in demo generation: {e}")
            await asyncio.sleep(10)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="intelligent_log_analysis/web/static"), name="static")
templates = Jinja2Templates(directory="intelligent_log_analysis/web/templates")

# Authentication functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None

def authenticate_user(username: str, password: str):
    if username in DEMO_USERS:
        user_data = DEMO_USERS[username]
        # Check if password is hashed
        if user_data.get("is_hashed", False):
            # Compare with hashed password
            if hash_password(password) == user_data["password"]:
                return user_data
        else:
            # Compare with plain text password (for demo accounts)
            if user_data["password"] == password:
                return user_data
    return None

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    username = verify_token(token)
    if not username or username not in DEMO_USERS:
        return None
    return {"username": username, **DEMO_USERS[username]}

# In-memory storage for demo (replace with database in production)
demo_data = {
    "logs": [],
    "patterns": [],
    "anomalies": [],
    "predictions": [],
    "metrics": {
        "logs_processed": 0,
        "patterns_detected": 0,
        "anomalies_found": 0,
        "predictions_made": 0
    }
}

# WebSocket connections for real-time updates
active_connections: List[WebSocket] = []


class DashboardStats(BaseModel):
    """Dashboard statistics model."""
    logs_processed: int
    patterns_detected: int
    anomalies_found: int
    predictions_made: int
    system_health: str
    processing_rate: float


class LogEntry(BaseModel):
    """Log entry for API responses."""
    timestamp: str
    level: str
    source: str
    message: str
    template_id: Optional[str] = None


class AnomalyAlert(BaseModel):
    """Anomaly alert for dashboard."""
    id: str
    timestamp: str
    severity: str
    title: str
    description: str
    affected_sources: List[str]


class PatternInfo(BaseModel):
    """Pattern information for dashboard."""
    id: str
    sequence: List[str]
    frequency: int
    confidence: float
    pattern_type: str
    last_seen: str
    is_anomalous: bool = False


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    """Container health endpoint used by Docker and local diagnostics."""
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intelligent Log Analysis - Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh; display: flex; align-items: center; justify-content: center;
            }
            .login-container {
                background: white; padding: 40px; border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                width: 400px; text-align: center;
            }
            .logo { font-size: 2.5em; margin-bottom: 10px; }
            h1 { color: #333; margin-bottom: 30px; font-size: 1.8em; }
            .subtitle { color: #666; margin-bottom: 30px; font-size: 0.9em; }
            .form-group { margin-bottom: 20px; text-align: left; }
            label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }
            input[type="text"], input[type="password"] {
                width: 100%; padding: 12px; border: 2px solid #ddd;
                border-radius: 8px; font-size: 16px; transition: border-color 0.3s;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none; border-color: #667eea;
            }
            .login-btn {
                width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; border: none; border-radius: 8px; font-size: 16px;
                cursor: pointer; transition: transform 0.2s; margin-bottom: 15px;
            }
            .login-btn:hover { transform: translateY(-2px); }
            .signup-link {
                display: block; text-align: center; color: #667eea; text-decoration: none;
                font-size: 14px; margin-top: 15px; transition: color 0.3s;
            }
            .signup-link:hover { color: #764ba2; }
            .demo-accounts {
                margin-top: 30px; padding: 20px; background: #f8f9fa;
                border-radius: 8px; text-align: left;
            }
            .demo-accounts h3 { color: #333; margin-bottom: 15px; font-size: 1.1em; }
            .account { margin-bottom: 10px; font-size: 0.9em; }
            .account strong { color: #667eea; }
            .error { color: #e74c3c; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">🧠</div>
            <h1>Intelligent Log Analysis</h1>
            <p class="subtitle">OS Log Analysis & Prediction using ML, DBMS, and Pattern Algorithms</p>
            
            <form method="post" action="/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="login-btn">Login to Dashboard</button>
            </form>
            
            <a href="/register" class="signup-link">Don't have an account? Create one here</a>
            
            <div class="demo-accounts">
                <h3>📋 Demo Accounts:</h3>
                <div class="account"><strong>admin</strong> / admin123 (Administrator)</div>
                <div class="account"><strong>analyst</strong> / analyst123 (Log Analyst)</div>
                <div class="account"><strong>demo</strong> / demo (Viewer)</div>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intelligent Log Analysis - Create Account</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; display: flex; align-items: center; justify-content: center;
                padding: 20px;
            }
            .register-container {
                background: white; padding: 40px; border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                width: 450px; text-align: center;
            }
            .logo { font-size: 2.5em; margin-bottom: 10px; }
            h1 { color: #333; margin-bottom: 30px; font-size: 1.8em; }
            .subtitle { color: #666; margin-bottom: 30px; font-size: 0.9em; }
            .form-group { margin-bottom: 20px; text-align: left; }
            label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }
            input[type="text"], input[type="password"], input[type="email"], select {
                width: 100%; padding: 12px; border: 2px solid #ddd;
                border-radius: 8px; font-size: 16px; transition: border-color 0.3s;
            }
            input[type="text"]:focus, input[type="password"]:focus, input[type="email"]:focus, select:focus {
                outline: none; border-color: #667eea;
            }
            .register-btn {
                width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; border: none; border-radius: 8px; font-size: 16px;
                cursor: pointer; transition: transform 0.2s; margin-bottom: 15px;
            }
            .register-btn:hover { transform: translateY(-2px); }
            .login-link {
                display: block; text-align: center; color: #667eea; text-decoration: none;
                font-size: 14px; margin-top: 15px; transition: color 0.3s;
            }
            .login-link:hover { color: #764ba2; }
            .requirements {
                margin-top: 20px; padding: 15px; background: #f8f9fa;
                border-radius: 8px; text-align: left; font-size: 0.85em;
            }
            .requirements h4 { color: #333; margin-bottom: 10px; }
            .requirements ul { margin-left: 20px; color: #666; }
            .requirements li { margin-bottom: 5px; }
            .error { color: #e74c3c; margin-top: 15px; font-size: 14px; }
            .success { color: #27ae60; margin-top: 15px; font-size: 14px; }
        </style>
        <script>
            function validateForm() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const confirmPassword = document.getElementById('confirm_password').value;
                const email = document.getElementById('email').value;
                const name = document.getElementById('name').value;
                
                // Basic validation
                if (username.length < 3) {
                    alert('Username must be at least 3 characters long');
                    return false;
                }
                
                if (password.length < 6) {
                    alert('Password must be at least 6 characters long');
                    return false;
                }
                
                if (password !== confirmPassword) {
                    alert('Passwords do not match');
                    return false;
                }
                
                if (!email.includes('@')) {
                    alert('Please enter a valid email address');
                    return false;
                }
                
                if (name.trim().length < 2) {
                    alert('Please enter your full name');
                    return false;
                }
                
                return true;
            }
        </script>
    </head>
    <body>
        <div class="register-container">
            <div class="logo">🧠</div>
            <h1>Create Account</h1>
            <p class="subtitle">Join the Intelligent Log Analysis System</p>
            
            <form method="post" action="/register" onsubmit="return validateForm()">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required minlength="3" maxlength="20">
                </div>
                
                <div class="form-group">
                    <label for="name">Full Name:</label>
                    <input type="text" id="name" name="name" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email Address:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label for="role">Role:</label>
                    <select id="role" name="role" required>
                        <option value="viewer">Viewer (Read-only access)</option>
                        <option value="log_analyst">Log Analyst (Analysis tools)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required minlength="6">
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit" class="register-btn">Create Account</button>
            </form>
            
            <a href="/" class="login-link">Already have an account? Login here</a>
            
            <div class="requirements">
                <h4>📋 Account Requirements:</h4>
                <ul>
                    <li>Username: 3-20 characters, letters, numbers, underscores only</li>
                    <li>Password: At least 6 characters with letters and numbers</li>
                    <li>Valid email address required</li>
                    <li>Administrator accounts require manual approval</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """


@app.post("/register")
async def register_user(
    username: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    role: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Handle user registration."""
    try:
        # Validate input
        errors = []
        
        # Username validation
        username_valid, username_msg = validate_username(username)
        if not username_valid:
            errors.append(username_msg)
        
        # Password validation
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        password_valid, password_msg = validate_password(password)
        if not password_valid:
            errors.append(password_msg)
        
        # Email validation
        if not validate_email(email):
            errors.append("Invalid email format")
        
        # Name validation
        if len(name.strip()) < 2:
            errors.append("Name must be at least 2 characters long")
        
        # Role validation
        if role not in ["viewer", "log_analyst"]:
            errors.append("Invalid role selected")
        
        # Check for existing email
        for existing_user, user_data in DEMO_USERS.items():
            if user_data.get("email", "").lower() == email.lower():
                errors.append("Email address already registered")
                break
        
        if errors:
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Registration Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                    .error-container {{ 
                        background: white; padding: 30px; border-radius: 10px; 
                        box-shadow: 0 5px 15px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto;
                    }}
                    .error-title {{ color: #e74c3c; font-size: 24px; margin-bottom: 20px; }}
                    .error-list {{ color: #666; margin-bottom: 20px; }}
                    .error-list li {{ margin-bottom: 10px; }}
                    .back-btn {{ 
                        background: #3498db; color: white; padding: 10px 20px; 
                        text-decoration: none; border-radius: 5px; display: inline-block;
                    }}
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h2 class="error-title">Registration Failed</h2>
                    <ul class="error-list">
                        {"".join(f"<li>{error}</li>" for error in errors)}
                    </ul>
                    <a href="/register" class="back-btn">← Back to Registration</a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=error_html)
        
        # Create the user
        if create_user(username.lower(), password, name.strip(), email.lower(), role):
            success_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Account Created Successfully</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                    .success-container {{ 
                        background: white; padding: 30px; border-radius: 10px; 
                        box-shadow: 0 5px 15px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto;
                        text-align: center;
                    }}
                    .success-title {{ color: #27ae60; font-size: 24px; margin-bottom: 20px; }}
                    .success-message {{ color: #666; margin-bottom: 20px; line-height: 1.6; }}
                    .user-info {{ 
                        background: #f8f9fa; padding: 15px; border-radius: 8px; 
                        margin: 20px 0; text-align: left;
                    }}
                    .login-btn {{ 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        color: white; padding: 12px 30px; text-decoration: none; 
                        border-radius: 8px; display: inline-block; margin-top: 20px;
                    }}
                    .login-btn:hover {{ transform: translateY(-2px); }}
                </style>
            </head>
            <body>
                <div class="success-container">
                    <h2 class="success-title">🎉 Account Created Successfully!</h2>
                    <p class="success-message">
                        Welcome to the Intelligent Log Analysis System! Your account has been created and is ready to use.
                    </p>
                    
                    <div class="user-info">
                        <strong>Account Details:</strong><br>
                        Username: {username.lower()}<br>
                        Name: {name.strip()}<br>
                        Email: {email.lower()}<br>
                        Role: {role.replace('_', ' ').title()}<br>
                        Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                    
                    <p class="success-message">
                        You can now login with your username and password to access the dashboard.
                    </p>
                    
                    <a href="/" class="login-btn">Login to Dashboard</a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=success_html)
        else:
            return HTMLResponse(content="""
                <script>
                    alert('Failed to create account. Please try again.');
                    window.location.href = '/register';
                </script>
            """)
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return HTMLResponse(content="""
            <script>
                alert('An error occurred during registration. Please try again.');
                window.location.href = '/register';
            </script>
        """)


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """Handle login form submission."""
    user = authenticate_user(username, password)
    if not user:
        return HTMLResponse(content="""
            <script>
                alert('Invalid username or password!');
                window.location.href = '/';
            </script>
        """)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username, "role": user["role"]}, 
        expires_delta=access_token_expires
    )
    
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page - requires authentication."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user
    })


@app.get("/logout")
async def logout():
    """Logout and clear session."""
    response = RedirectResponse(url="/")
    response.delete_cookie(key="access_token")
    return response


@app.get("/api/users")
async def get_users(request: Request) -> List[Dict[str, Any]]:
    """Get list of registered users - admin only."""
    user = get_current_user(request)
    if not user or user.get("role") != "administrator":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users_list = []
    for username, user_data in DEMO_USERS.items():
        users_list.append({
            "username": username,
            "name": user_data.get("name", ""),
            "email": user_data.get("email", ""),
            "role": user_data.get("role", ""),
            "created_at": user_data.get("created_at", "N/A"),
            "is_demo_account": not user_data.get("is_hashed", False)
        })
    
    return users_list


@app.get("/api/stats")
async def get_stats(request: Request) -> DashboardStats:
    """Get dashboard statistics - requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Try to get stats from database first
    db = await get_database()
    if db:
        try:
            db_stats = await db.get_stats()
            return DashboardStats(
                logs_processed=db_stats.get("logs_processed", 0),
                patterns_detected=db_stats.get("patterns_detected", 0),
                anomalies_found=db_stats.get("anomalies_found", 0),
                predictions_made=db_stats.get("predictions_made", 0),
                system_health="Healthy",
                processing_rate=calculate_processing_rate()
            )
        except Exception as e:
            logger.error(f"Failed to get stats from database: {e}")
    
    # Fallback to demo data
    return DashboardStats(
        logs_processed=demo_data["metrics"]["logs_processed"],
        patterns_detected=demo_data["metrics"]["patterns_detected"],
        anomalies_found=demo_data["metrics"]["anomalies_found"],
        predictions_made=demo_data["metrics"]["predictions_made"],
        system_health="Healthy",
        processing_rate=calculate_processing_rate()
    )


@app.get("/api/logs")
async def get_recent_logs(request: Request, limit: int = 100) -> List[LogEntry]:
    """Get recent log entries - requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Try to get logs from database first
    db = await get_database()
    if db:
        try:
            db_logs = await db.get_recent_logs(limit)
            if db_logs:
                return [
                    LogEntry(
                        timestamp=log.get("timestamp", ""),
                        level=log.get("level", "INFO"),
                        source=log.get("source", "unknown"),
                        message=log.get("message", ""),
                        template_id=log.get("template_id")
                    )
                    for log in db_logs
                ]
        except Exception as e:
            logger.error(f"Failed to get logs from database: {e}")
    
    # Fallback to demo data
    recent_logs = demo_data["logs"][-limit:]
    return [
        LogEntry(
            timestamp=log.get("timestamp", ""),
            level=log.get("level", "INFO"),
            source=log.get("source", "unknown"),
            message=log.get("message", ""),
            template_id=log.get("template_id")
        )
        for log in recent_logs
    ]


@app.get("/api/anomalies")
async def get_anomalies(request: Request, limit: int = 50) -> List[AnomalyAlert]:
    """Get recent anomalies - requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Try to get anomalies from database first
    db = await get_database()
    if db:
        try:
            db_anomalies = await db.get_anomalies(limit)
            if db_anomalies:
                return [
                    AnomalyAlert(
                        id=anomaly.get("id", ""),
                        timestamp=anomaly.get("timestamp", ""),
                        severity=anomaly.get("severity", "medium"),
                        title=anomaly.get("title", ""),
                        description=anomaly.get("description", ""),
                        affected_sources=anomaly.get("affected_sources", [])
                    )
                    for anomaly in db_anomalies
                ]
        except Exception as e:
            logger.error(f"Failed to get anomalies from database: {e}")
    
    # Fallback to demo data
    recent_anomalies = demo_data["anomalies"][-limit:]
    return [
        AnomalyAlert(
            id=anomaly.get("id", ""),
            timestamp=anomaly.get("timestamp", ""),
            severity=anomaly.get("severity", "medium"),
            title=anomaly.get("title", ""),
            description=anomaly.get("description", ""),
            affected_sources=anomaly.get("affected_sources", [])
        )
        for anomaly in recent_anomalies
    ]


@app.get("/api/patterns")
async def get_patterns(request: Request, limit: int = 20) -> List[PatternInfo]:
    """Get detected patterns - requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Try to get patterns from database first
    db = await get_database()
    if db:
        try:
            db_patterns = await db.get_patterns(limit)
            if db_patterns:
                return [
                    PatternInfo(
                        id=pattern.get("id", ""),
                        sequence=pattern.get("sequence", []),
                        frequency=pattern.get("frequency", 0),
                        confidence=pattern.get("confidence", 0.0),
                        pattern_type=pattern.get("pattern_type", "normal"),
                        last_seen=pattern.get("last_seen", ""),
                        is_anomalous=pattern.get("is_anomalous", False)
                    )
                    for pattern in db_patterns
                ]
        except Exception as e:
            logger.error(f"Failed to get patterns from database: {e}")
    
    # Fallback to demo data
    recent_patterns = demo_data["patterns"][-limit:]
    return [
        PatternInfo(
            id=pattern.get("id", ""),
            sequence=pattern.get("sequence", []),
            frequency=pattern.get("frequency", 0),
            confidence=pattern.get("confidence", 0.0),
            pattern_type=pattern.get("pattern_type", "normal"),
            last_seen=pattern.get("last_seen", ""),
            is_anomalous=pattern.get("is_anomalous", False)
        )
        for pattern in recent_patterns
    ]


@app.get("/api/predictions")
async def get_predictions(request: Request, limit: int = 10) -> List[Dict[str, Any]]:
    """Get ML predictions - requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Try to get predictions from database first
    db = await get_database()
    if db:
        try:
            db_predictions = await db.get_predictions(limit)
            if db_predictions:
                return db_predictions
        except Exception as e:
            logger.error(f"Failed to get predictions from database: {e}")
    
    # Fallback to demo data
    return demo_data["predictions"][-limit:]


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_update(data: Dict[str, Any]):
    """Broadcast updates to all connected WebSocket clients."""
    if active_connections:
        message = json.dumps(data)
        for connection in active_connections.copy():
            try:
                await connection.send_text(message)
            except:
                active_connections.remove(connection)


def calculate_processing_rate() -> float:
    """Calculate current log processing rate."""
    # Simple calculation for demo
    return len(demo_data["logs"]) / max(1, (datetime.now().hour + 1))


# Demo data generation functions (same as before)
async def generate_demo_log():
    """Generate a demo log entry."""
    import random
    
    levels = ["INFO", "WARNING", "ERROR", "DEBUG"]
    sources = ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log", "/var/log/mysql/error.log"]
    messages = [
        "User login successful for user{id}",
        "Failed authentication attempt from {ip}",
        "Database connection established",
        "High memory usage detected: {percent}%",
        "Service {service} started successfully",
        "Network timeout connecting to {host}",
        "Backup completed successfully",
        "Disk space warning: {percent}% full"
    ]
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "level": random.choice(levels),
        "source": random.choice(sources),
        "message": random.choice(messages).format(
            id=random.randint(100, 999),
            ip=f"192.168.1.{random.randint(1, 254)}",
            percent=random.randint(70, 95),
            service=random.choice(["nginx", "mysql", "redis"]),
            host=f"server{random.randint(1, 5)}.example.com"
        ),
        "template_id": f"template_{random.randint(1, 20)}"
    }
    
    demo_data["logs"].append(log_entry)
    demo_data["metrics"]["logs_processed"] += 1
    
    # Keep only last 1000 logs
    if len(demo_data["logs"]) > 1000:
        demo_data["logs"] = demo_data["logs"][-1000:]
    
    # Broadcast update
    await broadcast_update({
        "type": "new_log",
        "data": log_entry
    })


async def generate_demo_anomaly():
    """Generate a demo anomaly."""
    import random
    
    anomaly_types = [
        ("High Error Rate", "Unusual spike in error logs detected", "high"),
        ("Suspicious Login Pattern", "Multiple failed login attempts from same IP", "critical"),
        ("Performance Degradation", "Response times significantly increased", "medium"),
        ("Unusual Network Activity", "Abnormal network traffic patterns detected", "high"),
        ("Resource Exhaustion", "System resources approaching critical levels", "critical")
    ]
    
    title, description, severity = random.choice(anomaly_types)
    
    anomaly = {
        "id": f"anomaly_{len(demo_data['anomalies']) + 1}",
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "title": title,
        "description": description,
        "affected_sources": random.sample(["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log"], 
                                        random.randint(1, 2))
    }
    
    demo_data["anomalies"].append(anomaly)
    demo_data["metrics"]["anomalies_found"] += 1
    
    # Broadcast update
    await broadcast_update({
        "type": "new_anomaly",
        "data": anomaly
    })


async def generate_demo_pattern():
    """Generate a demo pattern."""
    import random
    
    pattern_sequences = [
        ["login_attempt", "authentication_success", "session_start"],
        ["database_connect", "query_execute", "connection_close"],
        ["http_request", "process_request", "send_response"],
        ["backup_start", "data_copy", "backup_complete"],
        ["service_stop", "cleanup", "service_start"]
    ]
    
    sequence = random.choice(pattern_sequences)
    
    pattern = {
        "id": f"pattern_{len(demo_data['patterns']) + 1}",
        "sequence": sequence,
        "frequency": random.randint(10, 100),
        "confidence": round(random.uniform(0.7, 1.0), 2),
        "pattern_type": random.choice(["normal", "frequent", "anomalous", "frequency", "temporal"]),
        "last_seen": datetime.now().isoformat()
    }
    pattern["is_anomalous"] = pattern["pattern_type"] == "anomalous"
    
    demo_data["patterns"].append(pattern)
    demo_data["metrics"]["patterns_detected"] += 1
    
    # Broadcast update
    await broadcast_update({
        "type": "new_pattern",
        "data": pattern
    })


async def generate_demo_prediction():
    """Generate a demo prediction."""
    import random
    
    predictions = [
        {
            "type": "system_failure",
            "description": "Potential disk space exhaustion in 4 hours",
            "probability": 0.85,
            "time_horizon": "4 hours"
        },
        {
            "type": "performance_degradation", 
            "description": "Database performance may degrade due to high load",
            "probability": 0.72,
            "time_horizon": "2 hours"
        },
        {
            "type": "security_incident",
            "description": "Possible brute force attack based on login patterns",
            "probability": 0.91,
            "time_horizon": "30 minutes"
        }
    ]
    
    pred = random.choice(predictions)
    prediction = {
        "id": f"prediction_{len(demo_data['predictions']) + 1}",
        "timestamp": datetime.now().isoformat(),
        **pred
    }
    
    demo_data["predictions"].append(prediction)
    demo_data["metrics"]["predictions_made"] += 1
    
    # Broadcast update
    await broadcast_update({
        "type": "new_prediction",
        "data": prediction
    })


async def seed_demo_patterns_if_empty() -> None:
    """Ensure the dashboard has baseline pattern data for charts."""
    if demo_data["patterns"]:
        return

    for _ in range(6):
        await generate_demo_pattern()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8700)
