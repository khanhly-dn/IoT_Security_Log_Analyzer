import pytest
from datetime import datetime, timedelta
from analyzer.log_parser import LogParser, LogEntry
from analyzer.anomaly_detector import (
    AnomalyDetector, DetectorConfig, Severity, AnomalyType, IPStats
)
from analyzer.reporter import TextReporter, JSONReporter, CSVReporter, HTMLReporter
import json


# ─── Fixtures ─────────────────────────────────────────────────────────────────

APACHE_LINE = (
    '1.2.3.4 - frank [15/May/2024:10:00:00 +0700] '
    '"GET /index.html HTTP/1.1" 200 5432 '
    '"-" "Mozilla/5.0 (Windows NT 10.0)"'
)
SYSLOG_LINE = (
    "May 15 02:33:01 auth01 sshd[12345]: "
    "Failed password for root from 198.51.100.7 port 44321 ssh2"
)
JSON_LINE = json.dumps({
    "timestamp": "2024-05-15T10:00:00",
    "ip": "5.5.5.5",
    "method": "POST",
    "path": "/api/login",
    "status": 401,
    "message": "authentication failure",
})


# ─── LogParser Tests ──────────────────────────────────────────────────────────

class TestLogParser:
    def setup_method(self):
        self.parser = LogParser(source_file="test.log")

    def test_parse_apache_combined(self):
        entry = self.parser.parse_line(APACHE_LINE, lineno=1)
        assert entry is not None
        assert entry.ip == "1.2.3.4"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status_code == 200
        assert entry.response_size == 5432

    def test_parse_syslog(self):
        entry = self.parser.parse_line(SYSLOG_LINE, lineno=2)
        assert entry is not None
        assert entry.ip == "198.51.100.7"
        assert "Failed password" in entry.message

    def test_parse_json_log(self):
        entry = self.parser.parse_line(JSON_LINE, lineno=3)
        assert entry is not None
        assert entry.ip == "5.5.5.5"
        assert entry.status_code == 401
        assert entry.path == "/api/login"

    def test_parse_generic_fallback(self):
        line = "2024-05-15 11:22:33 ERROR Something went wrong from 9.9.9.9"
        entry = self.parser.parse_line(line, lineno=4)
        assert entry is not None
        assert entry.ip == "9.9.9.9"
        assert entry.level == "ERROR"

    def test_parse_empty_line_returns_none(self):
        assert self.parser.parse_line("", lineno=5) is None

    def test_ip_extraction_from_generic(self):
        line = "2024-01-01 00:00:00 connection from 203.0.113.99"
        entry = self.parser.parse_line(line, lineno=6)
        assert entry.ip == "203.0.113.99"

    def test_parse_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text(APACHE_LINE + "\n" + SYSLOG_LINE + "\n")
        parser = LogParser()
        entries = list(parser.parse_file(str(log_file)))
        assert len(entries) == 2

    def test_stats_tracking(self, tmp_path):
        log_file = tmp_path / "multi.log"
        lines = "\n".join([APACHE_LINE, SYSLOG_LINE, JSON_LINE])
        log_file.write_text(lines)
        parser = LogParser()
        list(parser.parse_file(str(log_file)))
        stats = parser.stats()
        assert stats["parsed"] == 3
        assert stats["success_rate"] == 100.0


# ─── AnomalyDetector Tests ────────────────────────────────────────────────────

def make_entry(ip, status=200, path="/", ts=None, ua=None, msg=None) -> LogEntry:
    return LogEntry(
        raw="", source_file="test.log", line_number=0,
        ip=ip, status_code=status, path=path,
        timestamp=ts or datetime(2024, 5, 15, 12, 0, 0),
        user_agent=ua,
        message=msg,
    )


class TestAnomalyDetector:

    def _detector(self, **kwargs) -> AnomalyDetector:
        cfg = DetectorConfig(**kwargs)
        return AnomalyDetector(config=cfg, ignore_private=False)

    # High-frequency
    def test_detects_high_frequency(self):
        det = self._detector(freq_req_threshold=10, freq_window_minutes=1)
        base = datetime(2024, 5, 15, 10, 0, 0)
        entries = [
            make_entry("1.2.3.4", ts=base + timedelta(seconds=i))
            for i in range(20)
        ]
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.HIGH_FREQUENCY in types

    def test_no_high_freq_below_threshold(self):
        det = self._detector(freq_req_threshold=100)
        base = datetime(2024, 5, 15, 10, 0, 0)
        entries = [make_entry("1.2.3.4", ts=base + timedelta(seconds=i)) for i in range(5)]
        det.feed(entries)
        anomalies = det.detect()
        assert not any(a.anomaly_type == AnomalyType.HIGH_FREQUENCY for a in anomalies)

    # Error rate
    def test_detects_high_error_rate(self):
        det = self._detector(error_rate_threshold=0.5, error_rate_min_requests=5)
        entries = (
            [make_entry("2.2.2.2", status=404) for _ in range(8)] +
            [make_entry("2.2.2.2", status=200) for _ in range(2)]
        )
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.ERROR_RATE in types

    def test_error_rate_ignores_small_samples(self):
        det = self._detector(error_rate_threshold=0.5, error_rate_min_requests=20)
        entries = [make_entry("3.3.3.3", status=500) for _ in range(5)]
        det.feed(entries)
        anomalies = det.detect()
        assert not any(a.anomaly_type == AnomalyType.ERROR_RATE for a in anomalies)

    # Path scan
    def test_detects_path_scanner(self):
        det = self._detector(scan_distinct_paths=10)
        entries = [make_entry("4.4.4.4", path=f"/scan/{i}") for i in range(15)]
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.PATH_SCAN in types

    # Auth failure
    def test_detects_auth_failures(self):
        det = self._detector(auth_fail_threshold=3)
        entries = [
            make_entry("5.5.5.5", msg="Failed password for root from 5.5.5.5 port 22 ssh2")
            for _ in range(5)
        ]
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.AUTH_FAILURE in types

    # UA churn
    def test_detects_ua_churn(self):
        det = self._detector(ua_churn_threshold=3)
        uas = ["Nikto/2.1", "sqlmap/1.7", "Nmap/7.94", "ZAP/2.14", "Burp/2023"]
        entries = [make_entry("6.6.6.6", ua=ua) for ua in uas]
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.UA_CHURN in types

    # Burst
    def test_detects_burst(self):
        det = self._detector(burst_threshold=20, burst_window_seconds=30)
        base = datetime(2024, 5, 15, 3, 0, 0)
        entries = [
            make_entry("7.7.7.7", ts=base + timedelta(seconds=i))
            for i in range(25)
        ]
        det.feed(entries)
        anomalies = det.detect()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.BURST in types

    # Whitelist
    def test_whitelist_skips_ip(self):
        det = AnomalyDetector(
            config=DetectorConfig(freq_req_threshold=5),
            ignore_private=False,
            whitelist=["8.8.8.8"],
        )
        entries = [make_entry("8.8.8.8", status=500) for _ in range(50)]
        det.feed(entries)
        assert det.detect() == []

    # Private IP filtering
    def test_ignores_private_ips_by_default(self):
        det = AnomalyDetector(config=DetectorConfig(error_rate_min_requests=1, error_rate_threshold=0.1))
        entries = [make_entry("192.168.1.100", status=500) for _ in range(20)]
        det.feed(entries)
        assert det.detect() == []

    # Severity ordering
    def test_anomalies_sorted_critical_first(self):
        det = self._detector(
            freq_req_threshold=5, freq_req_critical=15,
            scan_distinct_paths=3, scan_distinct_paths_critical=100,
        )
        base = datetime(2024, 5, 15, 10, 0, 0)
        # DoS (CRITICAL)
        for i in range(20):
            det.feed([make_entry("9.9.9.9", ts=base + timedelta(seconds=i))])
        # Scanner (HIGH)
        det.feed([make_entry("10.10.10.10", path=f"/{i}") for i in range(10)])
        anomalies = det.detect()
        scores = [a.severity.score for a in anomalies]
        assert scores == sorted(scores, reverse=True)

    # Summary
    def test_summary_structure(self):
        det = self._detector(error_rate_threshold=0.4, error_rate_min_requests=5)
        det.feed([make_entry("1.2.3.4", status=404) for _ in range(10)])
        s = det.summary()
        assert "total_entries_processed" in s
        assert "unique_ips" in s
        assert "total_anomalies" in s
        assert "by_severity" in s
        assert "top_offenders" in s


# ─── Reporter Tests ───────────────────────────────────────────────────────────

from analyzer.anomaly_detector import Anomaly

SAMPLE_ANOMALY = Anomaly(
    ip="198.51.100.7",
    anomaly_type=AnomalyType.AUTH_FAILURE,
    severity=Severity.CRITICAL,
    description="25 authentication failures detected",
    evidence={"auth_failures": 25},
    first_seen=datetime(2024, 5, 15, 2, 0, 0),
    last_seen=datetime(2024, 5, 15, 2, 30, 0),
)

SAMPLE_SUMMARY = {
    "total_entries_processed": 5000,
    "unique_ips": 45,
    "total_anomalies": 1,
    "by_severity": {"CRITICAL": 1},
    "by_type": {"AUTH_FAILURE": 1},
    "top_offenders": [{"ip": "198.51.100.7", "risk_score": 4, "anomaly_types": ["AUTH_FAILURE"]}],
}


class TestReporters:
    def test_text_reporter_contains_ip(self):
        r = TextReporter(use_colour=False)
        output = r.render([SAMPLE_ANOMALY], SAMPLE_SUMMARY)
        assert "198.51.100.7" in output
        assert "CRITICAL" in output

    def test_json_reporter_valid_json(self):
        r = JSONReporter()
        output = r.render([SAMPLE_ANOMALY], SAMPLE_SUMMARY)
        data = json.loads(output)
        assert data["summary"]["total_anomalies"] == 1
        assert data["anomalies"][0]["ip"] == "198.51.100.7"

    def test_csv_reporter_has_header(self):
        r = CSVReporter()
        output = r.render([SAMPLE_ANOMALY])
        assert "IP" in output
        assert "198.51.100.7" in output

    def test_html_reporter_valid_html(self):
        r = HTMLReporter()
        output = r.render([SAMPLE_ANOMALY], SAMPLE_SUMMARY, source_files=["access.log"])
        assert "<!DOCTYPE html>" in output
        assert "198.51.100.7" in output
        assert "CRITICAL" in output

    def test_empty_anomaly_list(self):
        r = TextReporter(use_colour=False)
        summary = {**SAMPLE_SUMMARY, "total_anomalies": 0}
        output = r.render([], summary)
        assert "No anomalies" in output

    def test_json_no_anomalies(self):
        r = JSONReporter()
        summary = {**SAMPLE_SUMMARY, "total_anomalies": 0}
        output = r.render([], summary)
        data = json.loads(output)
        assert data["anomalies"] == []


# ─── Integration Test ─────────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self, tmp_path):
        """Parse file → detect → report → no crash."""
        log_file = tmp_path / "access.log"
        lines = []

        # Normal traffic
        for i in range(50):
            lines.append(
                f'203.0.113.{i % 20} - - [15/May/2024:10:{i:02d}:00 +0700] '
                f'"GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
            )
        # DoS attacker
        for i in range(300):
            lines.append(
                f'198.51.100.99 - - [15/May/2024:10:01:{i % 60:02d} +0700] '
                f'"GET / HTTP/1.1" 200 500 "-" "python-requests/2.31.0"'
            )

        log_file.write_text("\n".join(lines))

        parser = LogParser()
        config = DetectorConfig(freq_req_threshold=50, freq_req_critical=200)
        detector = AnomalyDetector(config=config, ignore_private=False)
        detector.feed(parser.parse_file(str(log_file)))
        anomalies = detector.detect()
        summary = detector.summary()

        assert summary["total_entries_processed"] == 350
        assert any(a.ip == "198.51.100.99" for a in anomalies)
        assert any(a.severity in (Severity.HIGH, Severity.CRITICAL) for a in anomalies)

        # All reporters must not crash
        for Reporter in [TextReporter, JSONReporter, CSVReporter, HTMLReporter]:
            r = Reporter() if Reporter != TextReporter else TextReporter(use_colour=False)
            output = r.render(anomalies, summary, source_files=["access.log"])
            assert len(output) > 0
