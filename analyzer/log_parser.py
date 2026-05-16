"""
log_parser.py
Parses common log formats: Apache/Nginx combined, syslog, JSON logs.
"""

import re
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    raw: str
    source_file: str
    line_number: int
    timestamp: Optional[datetime] = None
    ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    message: Optional[str] = None
    level: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ─── Regex Patterns ───────────────────────────────────────────────────────────

# Apache / Nginx Combined Log Format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+'           # IP
    r'\S+\s+'                   # ident
    r'\S+\s+'                   # auth user
    r'\[(?P<time>[^\]]+)\]\s+'  # timestamp
    r'"(?P<method>\S+)\s+'      # HTTP method
    r'(?P<path>\S+)\s+'         # request path
    r'\S+"\s+'                  # HTTP version
    r'(?P<status>\d{3})\s+'     # status code
    r'(?P<size>\S+)'            # response size
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'  # optional referrer + user-agent
)

# Syslog format
# May 15 10:32:01 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
SYSLOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
)

# Generic timestamp patterns
TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache
    "%Y-%m-%dT%H:%M:%S%z",    # ISO 8601
    "%Y-%m-%d %H:%M:%S",      # Common
    "%b %d %H:%M:%S",         # Syslog (no year)
]

# IP address extractor
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


# ─── Parser ───────────────────────────────────────────────────────────────────

class LogParser:
    """Parses log files into structured LogEntry objects."""

    def __init__(self, source_file: str = ""):
        self.source_file = source_file
        self.parsed_count = 0
        self.failed_count = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_file(self, filepath: str):
        """Generator: yields LogEntry objects from a log file."""
        path = Path(filepath)
        self.source_file = path.name

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                if not line:
                    continue
                entry = self._parse_line(line, lineno)
                if entry:
                    self.parsed_count += 1
                    yield entry
                else:
                    self.failed_count += 1

    def parse_line(self, line: str, lineno: int = 0) -> Optional[LogEntry]:
        """Parse a single log line (public wrapper)."""
        return self._parse_line(line, lineno)

    # ── Internal Parsers ──────────────────────────────────────────────────────

    def _parse_line(self, line: str, lineno: int) -> Optional[LogEntry]:
        if not line.strip():
            return None
        entry = (
            self._try_combined(line, lineno) or
            self._try_json(line, lineno) or
            self._try_syslog(line, lineno) or
            self._try_generic(line, lineno)
        )
        return entry

    def _try_combined(self, line: str, lineno: int) -> Optional[LogEntry]:
        """Apache / Nginx combined log format."""
        m = COMBINED_LOG_RE.match(line)
        if not m:
            return None

        ts = self._parse_timestamp(m.group("time"))
        size_str = m.group("size")

        return LogEntry(
            raw=line,
            source_file=self.source_file,
            line_number=lineno,
            timestamp=ts,
            ip=m.group("ip"),
            method=m.group("method"),
            path=m.group("path"),
            status_code=int(m.group("status")),
            response_size=int(size_str) if size_str.isdigit() else None,
            user_agent=m.group("ua"),
        )

    def _try_json(self, line: str, lineno: int) -> Optional[LogEntry]:
        """JSON log lines (structured logging)."""
        if not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        ts_str = data.get("timestamp") or data.get("time") or data.get("@timestamp")
        ts = self._parse_timestamp(ts_str) if ts_str else None
        ip = data.get("ip") or data.get("remote_addr") or data.get("client_ip")

        return LogEntry(
            raw=line,
            source_file=self.source_file,
            line_number=lineno,
            timestamp=ts,
            ip=ip,
            method=data.get("method"),
            path=data.get("path") or data.get("uri"),
            status_code=data.get("status") or data.get("status_code"),
            message=data.get("message") or data.get("msg"),
            level=data.get("level") or data.get("severity"),
            extra=data,
        )

    def _try_syslog(self, line: str, lineno: int) -> Optional[LogEntry]:
        """Syslog format."""
        m = SYSLOG_RE.match(line)
        if not m:
            return None

        ts_str = f"{m.group('month')} {m.group('day')} {m.group('time')}"
        ts = self._parse_timestamp(ts_str)

        msg = m.group("message")
        ips = IP_RE.findall(msg)

        return LogEntry(
            raw=line,
            source_file=self.source_file,
            line_number=lineno,
            timestamp=ts,
            ip=ips[0] if ips else None,
            message=msg,
            extra={"host": m.group("host"), "process": m.group("process")},
        )

    def _try_generic(self, line: str, lineno: int) -> Optional[LogEntry]:
        """Fallback: extract whatever we can."""
        ips = IP_RE.findall(line)
        ts = None

        # Try ISO timestamp
        iso_match = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', line)
        if iso_match:
            ts = self._parse_timestamp(iso_match.group())

        level_match = re.search(
            r'\b(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|ALERT|FATAL)\b',
            line, re.IGNORECASE
        )

        return LogEntry(
            raw=line,
            source_file=self.source_file,
            line_number=lineno,
            timestamp=ts,
            ip=ips[0] if ips else None,
            message=line,
            level=level_match.group(1).upper() if level_match else None,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        for fmt in TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    def stats(self) -> dict:
        return {
            "parsed": self.parsed_count,
            "failed": self.failed_count,
            "success_rate": (
                round(self.parsed_count / (self.parsed_count + self.failed_count) * 100, 1)
                if (self.parsed_count + self.failed_count) > 0 else 0
            ),
        }
