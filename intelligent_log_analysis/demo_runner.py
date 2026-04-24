"""Demo runner for the intelligent log analysis system."""

import uvicorn
from pathlib import Path

from .web.app import app
from .utils.logging import setup_logging, get_logger

logger = get_logger("demo")


def run_demo():
    """Run the demo system with web interface."""
    setup_logging(level="INFO", log_file="logs/demo.log")

    logger.info("Starting Intelligent Log Analysis Demo...")

    Path("logs").mkdir(exist_ok=True)
    Path("intelligent_log_analysis/web/static").mkdir(parents=True, exist_ok=True)

    print("Intelligent Log Analysis System - Demo Mode")
    print("=" * 50)
    print("Starting web server...")
    print("Dashboard will be available at: http://localhost:8700")
    print("Demo data will be generated automatically")
    print("Real-time updates via WebSocket")
    print("=" * 50)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8700,
        log_level="info"
    )


if __name__ == "__main__":
    run_demo()
