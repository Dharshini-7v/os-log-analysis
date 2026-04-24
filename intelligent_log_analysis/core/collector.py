"""Log collection and file system monitoring."""

import asyncio
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from ..models.log_models import LogSource
from ..models.config_models import CollectorConfig
from ..utils.logging import get_logger
from ..utils.metrics import metrics

logger = get_logger("collector")


@dataclass
class LogFile:
    """Represents a monitored log file."""
    path: Path
    source_config: LogSource
    last_position: int = 0
    last_modified: float = 0.0
    inode: Optional[int] = None
    
    def __post_init__(self):
        """Initialize file metadata."""
        if self.path.exists():
            stat = self.path.stat()
            self.last_modified = stat.st_mtime
            self.inode = stat.st_ino


class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log files."""
    
    def __init__(self, collector: 'LogCollector', loop: asyncio.AbstractEventLoop):
        self.collector = collector
        self.loop = loop
        super().__init__()
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.collector._handle_file_event(event.src_path, 'modified'),
                self.loop
            )
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.collector._handle_file_event(event.src_path, 'created'),
                self.loop
            )
    
    def on_moved(self, event):
        """Handle file move events (log rotation)."""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.collector._handle_rotation(event.src_path, event.dest_path),
                self.loop
            )


class LogCollector:
    """Collects log entries from multiple sources with file system monitoring."""
    
    def __init__(self, config: CollectorConfig):
        self.config = config
        self.monitored_files: Dict[str, LogFile] = {}
        self.observers: List[Observer] = []
        self.running = False
        self.processing_queue = asyncio.Queue()
        self.log_callback: Optional[Callable[[str, str, LogSource], None]] = None
        
        # Statistics
        self.stats = {
            'files_monitored': 0,
            'entries_processed': 0,
            'errors': 0,
            'rotations_handled': 0
        }
    
    def set_log_callback(self, callback: Callable[[str, str, LogSource], None]) -> None:
        """Set callback function for processing log entries."""
        self.log_callback = callback
    
    async def start(self) -> None:
        """Start log collection and monitoring."""
        logger.info("Starting log collector...")
        self.running = True
        
        # Initialize log sources
        await self._initialize_sources()
        
        # Start file system monitoring
        self._start_file_monitoring()
        
        # Start processing task
        asyncio.create_task(self._process_queue())
        
        logger.info(f"Log collector started, monitoring {len(self.monitored_files)} files")
    
    async def stop(self) -> None:
        """Stop log collection and monitoring."""
        logger.info("Stopping log collector...")
        self.running = False
        
        # Stop file system observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
        logger.info("Log collector stopped")
    
    async def _initialize_sources(self) -> None:
        """Initialize log sources from configuration."""
        for source_data in self.config.log_sources:
            try:
                source = LogSource(**source_data)
                if source.enabled:
                    await self._add_log_source(source)
            except Exception as e:
                logger.error(f"Error initializing log source {source_data}: {e}")
                self.stats['errors'] += 1
    
    async def _add_log_source(self, source: LogSource) -> None:
        """Add a log source for monitoring."""
        source_path = Path(source.path)
        
        if source_path.is_file():
            # Single file
            await self._add_log_file(source_path, source)
        elif source_path.is_dir():
            # Directory - find matching files
            await self._add_directory_files(source_path, source)
        else:
            logger.warning(f"Log source path does not exist: {source.path}")
    
    async def _add_log_file(self, file_path: Path, source: LogSource) -> None:
        """Add a single log file for monitoring."""
        try:
            if self._should_monitor_file(file_path, source):
                log_file = LogFile(path=file_path, source_config=source)
                self.monitored_files[str(file_path)] = log_file
                self.stats['files_monitored'] += 1
                
                # Read existing content
                await self._read_existing_content(log_file)
                
                logger.debug(f"Added log file for monitoring: {file_path}")
        except Exception as e:
            logger.error(f"Error adding log file {file_path}: {e}")
            self.stats['errors'] += 1
    
    async def _add_directory_files(self, dir_path: Path, source: LogSource) -> None:
        """Add files from a directory based on patterns."""
        try:
            if source.recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            for file_path in dir_path.glob(pattern):
                if file_path.is_file() and self._should_monitor_file(file_path, source):
                    await self._add_log_file(file_path, source)
        except Exception as e:
            logger.error(f"Error scanning directory {dir_path}: {e}")
            self.stats['errors'] += 1
    
    def _should_monitor_file(self, file_path: Path, source: LogSource) -> bool:
        """Check if a file should be monitored based on patterns."""
        if not source.patterns:
            return True
        
        for pattern in source.patterns:
            if file_path.match(pattern):
                return True
        
        return False
    
    def _start_file_monitoring(self) -> None:
        """Start file system monitoring for all sources."""
        monitored_dirs: Set[str] = set()
        loop = asyncio.get_event_loop()
        
        for log_file in self.monitored_files.values():
            parent_dir = str(log_file.path.parent)
            if parent_dir not in monitored_dirs:
                observer = Observer()
                event_handler = LogFileHandler(self, loop)
                observer.schedule(event_handler, parent_dir, recursive=False)
                observer.start()
                
                self.observers.append(observer)
                monitored_dirs.add(parent_dir)
                
                logger.debug(f"Started monitoring directory: {parent_dir}")
    
    async def _read_existing_content(self, log_file: LogFile) -> None:
        """Read existing content from a log file."""
        try:
            if not log_file.path.exists():
                return
            
            # Start from end of file for new monitoring
            file_size = log_file.path.stat().st_size
            log_file.last_position = file_size
            
            logger.debug(f"Initialized file position for {log_file.path}: {file_size}")
        except Exception as e:
            logger.error(f"Error reading existing content from {log_file.path}: {e}")
            self.stats['errors'] += 1
    
    async def _handle_file_event(self, file_path: str, event_type: str) -> None:
        """Handle file system events."""
        if not self.running:
            return
        
        try:
            path_obj = Path(file_path)
            
            # Check if this is a monitored file
            if file_path in self.monitored_files:
                log_file = self.monitored_files[file_path]
                await self._process_file_changes(log_file)
            else:
                # Check if this is a new file that matches our patterns
                await self._check_new_file(path_obj)
                
        except Exception as e:
            logger.error(f"Error handling file event {event_type} for {file_path}: {e}")
            self.stats['errors'] += 1
    
    async def _process_file_changes(self, log_file: LogFile) -> None:
        """Process changes in a monitored log file."""
        try:
            if not log_file.path.exists():
                logger.warning(f"Monitored file no longer exists: {log_file.path}")
                return
            
            current_stat = log_file.path.stat()
            current_size = current_stat.st_size
            current_inode = current_stat.st_ino
            
            # Check for log rotation (inode changed)
            if log_file.inode and current_inode != log_file.inode:
                logger.info(f"Log rotation detected for {log_file.path}")
                await self._handle_log_rotation(log_file, current_inode)
                return
            
            # Check if file was truncated
            if current_size < log_file.last_position:
                logger.info(f"File truncation detected for {log_file.path}")
                log_file.last_position = 0
            
            # Read new content
            if current_size > log_file.last_position:
                await self._read_new_content(log_file, current_size)
            
            # Update file metadata
            log_file.last_modified = current_stat.st_mtime
            log_file.inode = current_inode
            
        except Exception as e:
            logger.error(f"Error processing file changes for {log_file.path}: {e}")
            self.stats['errors'] += 1
    
    async def _read_new_content(self, log_file: LogFile, current_size: int) -> None:
        """Read new content from a log file."""
        try:
            with open(log_file.path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(log_file.last_position)
                
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    line = line.rstrip('\n\r')
                    if line:  # Skip empty lines
                        await self.processing_queue.put((line, str(log_file.path), log_file.source_config))
                
                log_file.last_position = f.tell()
                
        except Exception as e:
            logger.error(f"Error reading new content from {log_file.path}: {e}")
            self.stats['errors'] += 1
    
    async def _handle_log_rotation(self, log_file: LogFile, new_inode: int) -> None:
        """Handle log file rotation."""
        try:
            # Update inode and reset position for new file
            log_file.inode = new_inode
            log_file.last_position = 0
            
            # Read any new content in the rotated file
            if log_file.path.exists():
                current_size = log_file.path.stat().st_size
                if current_size > 0:
                    await self._read_new_content(log_file, current_size)
            
            self.stats['rotations_handled'] += 1
            logger.info(f"Handled log rotation for {log_file.path}")
            
        except Exception as e:
            logger.error(f"Error handling log rotation for {log_file.path}: {e}")
            self.stats['errors'] += 1
    
    async def _handle_rotation(self, old_path: str, new_path: str) -> None:
        """Handle file move events (log rotation)."""
        try:
            if old_path in self.monitored_files:
                log_file = self.monitored_files[old_path]
                
                # Check if a new file was created at the old location
                old_path_obj = Path(old_path)
                if old_path_obj.exists():
                    # New file created, treat as rotation
                    await self._handle_log_rotation(log_file, old_path_obj.stat().st_ino)
                
                logger.info(f"Handled file rotation: {old_path} -> {new_path}")
                
        except Exception as e:
            logger.error(f"Error handling rotation {old_path} -> {new_path}: {e}")
            self.stats['errors'] += 1
    
    async def _check_new_file(self, file_path: Path) -> None:
        """Check if a new file should be monitored."""
        try:
            for log_file in self.monitored_files.values():
                source = log_file.source_config
                
                # Check if new file matches any monitored directory patterns
                if (file_path.parent == log_file.path.parent or 
                    (source.recursive and file_path.is_relative_to(log_file.path.parent))):
                    
                    if self._should_monitor_file(file_path, source):
                        await self._add_log_file(file_path, source)
                        break
                        
        except Exception as e:
            logger.error(f"Error checking new file {file_path}: {e}")
            self.stats['errors'] += 1
    
    async def _process_queue(self) -> None:
        """Process the log entry queue."""
        batch = []
        last_process_time = time.time()
        
        while self.running:
            try:
                # Collect entries for batch processing
                try:
                    # Wait for entries with timeout
                    entry = await asyncio.wait_for(
                        self.processing_queue.get(), 
                        timeout=self.config.processing_interval_seconds
                    )
                    batch.append(entry)
                except asyncio.TimeoutError:
                    # Process batch even if not full
                    pass
                
                # Process batch if it's full or enough time has passed
                current_time = time.time()
                if (len(batch) >= self.config.batch_size or 
                    (batch and current_time - last_process_time >= self.config.processing_interval_seconds)):
                    
                    await self._process_batch(batch)
                    batch.clear()
                    last_process_time = current_time
                
            except Exception as e:
                logger.error(f"Error in processing queue: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(1)  # Brief pause on error
    
    async def _process_batch(self, batch: List[tuple]) -> None:
        """Process a batch of log entries."""
        if not batch or not self.log_callback:
            return
        
        try:
            start_time = time.time()
            
            for log_line, file_path, source_config in batch:
                try:
                    self.log_callback(log_line, file_path, source_config)
                    self.stats['entries_processed'] += 1
                except Exception as e:
                    logger.error(f"Error processing log entry from {file_path}: {e}")
                    self.stats['errors'] += 1
            
            processing_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Record metrics
            metrics.record_metric("collector.batch_size", len(batch))
            metrics.record_metric("collector.processing_time_ms", processing_time)
            metrics.increment_counter("collector.entries_processed", len(batch))
            
            logger.debug(f"Processed batch of {len(batch)} entries in {processing_time:.2f}ms")
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
            self.stats['errors'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            **self.stats,
            'monitored_files': list(self.monitored_files.keys()),
            'queue_size': self.processing_queue.qsize() if hasattr(self.processing_queue, 'qsize') else 0
        }
    
    async def add_log_source(self, source: LogSource) -> None:
        """Dynamically add a new log source."""
        if self.running:
            await self._add_log_source(source)
            # Restart monitoring to include new directories
            self._start_file_monitoring()
    
    def remove_log_source(self, source_path: str) -> bool:
        """Remove a log source from monitoring."""
        if source_path in self.monitored_files:
            del self.monitored_files[source_path]
            self.stats['files_monitored'] -= 1
            logger.info(f"Removed log source: {source_path}")
            return True
        return False