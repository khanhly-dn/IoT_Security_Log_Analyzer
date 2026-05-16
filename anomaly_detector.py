from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import List, Dict, Optional, Tuple

from analyzer.log_parser import LogEntry


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class DetectorConfig:
    # High-frequency thresholds
    freq_window_minutes: int = 1          # sliding window size
    freq_req_threshold: int = 100         # requests per window → suspicious
    freq_req_critical: int = 500          # requests per window → critical

    # Error-rate thresholds
    error_rate_min_requests: int = 10     # ignore IPs with fewer requests
    error_rate_threshold: float = 0.40   # 40 % errors → suspicious
    error_rate_critical: float = 0.70    # 70 % errors → critical

    # Path-scan thresholds
    scan_distinct_paths: int = 50         # distinct paths → suspicious
    scan_distinct_paths_critical: int = 200

    # Auth-failure thresholds
    auth_fail_threshold: int = 5
    auth_fail_critical: int = 20

    # Off-hours definition
    business_hour_start: int = 8          # 08:00
    business_hour_end: int = 18           # 18:00
    off_hours_threshold: float = 0.80    # 80 %+ off-hours activity

    # User-agent churn
    ua_churn_threshold: int = 5           # distinct UAs from one IP

    # Burst window
    burst_window_seconds: int = 60
    burst_threshold: int = 50             # requests in burst window


# ─── Severity ─────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __lt__(self, other):
        return self.score < other.score


# ─── Anomaly types ────────────────────────────────────────────────────────────

class AnomalyType(str, Enum):
    HIGH_FREQUENCY   = "HIGH_FREQUENCY"
    ERROR_RATE       = "ERROR_RATE"
    PATH_SCAN        = "PATH_SCAN"
    AUTH_FAILURE     = "AUTH_FAILURE"
    OFF_HOURS        = "OFF_HOURS"
    UA_CHURN         = "UA_CHURN"
    BURST            = "BURST"


@dataclass
class Anomaly:
    ip: str
    anomaly_type: AnomalyType
    severity: Severity
    description: str
    evidence: dict = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def __str__(self) -> str:
        return (
            f"[{self.severity.value:<8}] {self.anomaly_type.value:<20} "
            f"IP={self.ip:<15} – {self.description}"
        )


# ─── Per-IP Statistics ────────────────────────────────────────────────────────

@dataclass
class IPStats:
    ip: str
    total_requests: int = 0
    error_count: int = 0          # 4xx + 5xx
    client_error_count: int = 0   # 4xx
    server_error_count: int = 0   # 5xx
    auth_failures: int = 0
    paths: set = field(default_factory=set)
    user_agents: set = field(default_factory=set)
    timestamps: list = field(default_factory=list)
    off_hours_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def record(self, entry: LogEntry, business_start: int, business_end: int):
        self.total_requests += 1

        if entry.timestamp:
            # Normalise to naive UTC to allow comparison across formats
            ts = entry.timestamp
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
            self.timestamps.append(ts)

            # Off-hours check
            hour = entry.timestamp.hour
            if not (business_start <= hour < business_end):
                self.off_hours_count += 1

        if entry.status_code:
            if entry.status_code >= 400:
                self.error_count += 1
            if 400 <= entry.status_code < 500:
                self.client_error_count += 1
            if entry.status_code >= 500:
                self.server_error_count += 1

        if entry.path:
            self.paths.add(entry.path)

        if entry.user_agent:
            self.user_agents.add(entry.user_agent)

        # Auth failure keywords
        if entry.message and any(
            kw in entry.message.lower()
            for kw in ("failed password", "authentication failure",
                       "invalid user", "failed login", "unauthorized",
                       "401", "403 forbidden")
        ):
            self.auth_failures += 1

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests

    @property
    def off_hours_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.off_hours_count / self.total_requests


# ─── Detector ─────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Processes LogEntry objects and emits Anomaly findings.

    Usage
    ─────
    detector = AnomalyDetector()
    detector.feed(entries)      # iterable of LogEntry
    anomalies = detector.detect()
    """

    # Private reserved ranges we ignore (RFC 1918 / loopback / link-local)
    _PRIVATE = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        ignore_private: bool = True,
        whitelist: Optional[List[str]] = None,
    ):
        self.config = config or DetectorConfig()
        self.ignore_private = ignore_private
        self.whitelist: set = set(whitelist or [])
        self._stats: Dict[str, IPStats] = {}
        self._total_entries = 0

    # ── Feed ──────────────────────────────────────────────────────────────────

    def feed(self, entries):
        """Ingest an iterable of LogEntry objects."""
        cfg = self.config
        for entry in entries:
            self._total_entries += 1
            ip = entry.ip
            if not ip or not self._is_interesting(ip):
                continue
            if ip not in self._stats:
                self._stats[ip] = IPStats(ip=ip)
            self._stats[ip].record(entry, cfg.business_hour_start, cfg.business_hour_end)

    # ── Detect ────────────────────────────────────────────────────────────────

    def detect(self) -> List[Anomaly]:
        """Run all detection strategies and return sorted anomalies."""
        anomalies: List[Anomaly] = []
        for ip, stats in self._stats.items():
            anomalies.extend(self._check_high_frequency(stats))
            anomalies.extend(self._check_error_rate(stats))
            anomalies.extend(self._check_path_scan(stats))
            anomalies.extend(self._check_auth_failure(stats))
            anomalies.extend(self._check_off_hours(stats))
            anomalies.extend(self._check_ua_churn(stats))
            anomalies.extend(self._check_burst(stats))

        # Sort: CRITICAL first, then by IP
        anomalies.sort(key=lambda a: (-a.severity.score, a.ip))
        return anomalies

    def stats_for(self, ip: str) -> Optional[IPStats]:
        return self._stats.get(ip)

    def all_stats(self) -> Dict[str, IPStats]:
        return dict(self._stats)

    def summary(self) -> dict:
        anomalies = self.detect()
        by_severity: Dict[str, int] = defaultdict(int)
        by_type: Dict[str, int] = defaultdict(int)
        for a in anomalies:
            by_severity[a.severity.value] += 1
            by_type[a.anomaly_type.value] += 1
        return {
            "total_entries_processed": self._total_entries,
            "unique_ips": len(self._stats),
            "total_anomalies": len(anomalies),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "top_offenders": self._top_offenders(anomalies, n=10),
        }

    # ── Detection Checks ──────────────────────────────────────────────────────

    def _check_high_frequency(self, stats: IPStats) -> List[Anomaly]:
        """Requests per minute exceeds threshold."""
        if not stats.timestamps or stats.total_requests < self.config.freq_req_threshold:
            return []

        window = timedelta(minutes=self.config.freq_window_minutes)
        sorted_ts = sorted(stats.timestamps)
        max_in_window = self._max_requests_in_window(sorted_ts, window)

        if max_in_window >= self.config.freq_req_critical:
            sev = Severity.CRITICAL
        elif max_in_window >= self.config.freq_req_threshold:
            sev = Severity.HIGH
        else:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.HIGH_FREQUENCY,
            severity=sev,
            description=(
                f"{max_in_window} requests in a {self.config.freq_window_minutes}-minute window"
            ),
            evidence={"max_requests_in_window": max_in_window, "total_requests": stats.total_requests},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_error_rate(self, stats: IPStats) -> List[Anomaly]:
        cfg = self.config
        if stats.total_requests < cfg.error_rate_min_requests:
            return []
        rate = stats.error_rate
        if rate >= cfg.error_rate_critical:
            sev = Severity.HIGH
        elif rate >= cfg.error_rate_threshold:
            sev = Severity.MEDIUM
        else:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.ERROR_RATE,
            severity=sev,
            description=(
                f"{rate*100:.1f}% error rate "
                f"({stats.error_count}/{stats.total_requests} requests)"
            ),
            evidence={
                "error_rate": round(rate, 4),
                "error_count": stats.error_count,
                "total_requests": stats.total_requests,
                "4xx": stats.client_error_count,
                "5xx": stats.server_error_count,
            },
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_path_scan(self, stats: IPStats) -> List[Anomaly]:
        cfg = self.config
        n = len(stats.paths)
        if n >= cfg.scan_distinct_paths_critical:
            sev = Severity.CRITICAL
        elif n >= cfg.scan_distinct_paths:
            sev = Severity.HIGH
        else:
            return []

        sample = sorted(stats.paths)[:10]
        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.PATH_SCAN,
            severity=sev,
            description=f"Accessed {n} distinct paths – possible scanner/enumerator",
            evidence={"distinct_paths": n, "sample_paths": sample},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_auth_failure(self, stats: IPStats) -> List[Anomaly]:
        cfg = self.config
        n = stats.auth_failures
        if n >= cfg.auth_fail_critical:
            sev = Severity.CRITICAL
        elif n >= cfg.auth_fail_threshold:
            sev = Severity.HIGH
        else:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.AUTH_FAILURE,
            severity=sev,
            description=f"{n} authentication failures detected",
            evidence={"auth_failures": n},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_off_hours(self, stats: IPStats) -> List[Anomaly]:
        cfg = self.config
        if stats.total_requests < cfg.error_rate_min_requests:
            return []
        rate = stats.off_hours_rate
        if rate < cfg.off_hours_threshold:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.OFF_HOURS,
            severity=Severity.MEDIUM,
            description=(
                f"{rate*100:.0f}% of activity outside business hours "
                f"({cfg.business_hour_start}:00–{cfg.business_hour_end}:00)"
            ),
            evidence={"off_hours_rate": round(rate, 4), "off_hours_count": stats.off_hours_count},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_ua_churn(self, stats: IPStats) -> List[Anomaly]:
        n = len(stats.user_agents)
        if n < self.config.ua_churn_threshold:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.UA_CHURN,
            severity=Severity.MEDIUM,
            description=f"Used {n} distinct User-Agent strings – possible evasion",
            evidence={"distinct_user_agents": n, "sample": list(stats.user_agents)[:5]},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    def _check_burst(self, stats: IPStats) -> List[Anomaly]:
        """Short burst: many requests in ≤60 seconds."""
        cfg = self.config
        if len(stats.timestamps) < cfg.burst_threshold:
            return []

        window = timedelta(seconds=cfg.burst_window_seconds)
        sorted_ts = sorted(stats.timestamps)
        max_in_window = self._max_requests_in_window(sorted_ts, window)

        if max_in_window < cfg.burst_threshold:
            return []

        return [Anomaly(
            ip=stats.ip,
            anomaly_type=AnomalyType.BURST,
            severity=Severity.HIGH,
            description=(
                f"{max_in_window} requests within {cfg.burst_window_seconds} seconds"
            ),
            evidence={"max_requests_in_burst": max_in_window},
            first_seen=stats.first_seen,
            last_seen=stats.last_seen,
        )]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_interesting(self, ip: str) -> bool:
        """Return False if IP should be skipped."""
        if ip in self.whitelist:
            return False
        if self.ignore_private:
            try:
                addr = ipaddress.ip_address(ip)
                for net in self._PRIVATE:
                    if addr in net:
                        return False
            except ValueError:
                return False
        return True

    @staticmethod
    def _max_requests_in_window(sorted_timestamps: list, window: timedelta) -> int:
        """Sliding window count – O(n) two-pointer."""
        if not sorted_timestamps:
            return 0
        max_count = 0
        left = 0
        for right, ts in enumerate(sorted_timestamps):
            while sorted_timestamps[right] - sorted_timestamps[left] > window:
                left += 1
            max_count = max(max_count, right - left + 1)
        return max_count

    @staticmethod
    def _top_offenders(anomalies: List[Anomaly], n: int = 10) -> List[dict]:
        """Rank IPs by cumulative severity score."""
        scores: Dict[str, int] = defaultdict(int)
        ip_anomalies: Dict[str, List[str]] = defaultdict(list)
        for a in anomalies:
            scores[a.ip] += a.severity.score
            ip_anomalies[a.ip].append(a.anomaly_type.value)

        ranked = sorted(scores.items(), key=lambda x: -x[1])[:n]
        return [
            {"ip": ip, "risk_score": score, "anomaly_types": ip_anomalies[ip]}
            for ip, score in ranked
        ]
