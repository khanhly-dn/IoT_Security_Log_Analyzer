import argparse
import sys
import os
from pathlib import Path

from analyzer.log_parser import LogParser
from analyzer.anomaly_detector import AnomalyDetector, DetectorConfig
from analyzer.reporter import get_reporter, TextReporter


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="🔍  Security Log Analyzer – detects anomalous IP behaviour",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "files",
        nargs="+",
        metavar="LOG_FILE",
        help="One or more log files to analyse (Apache, Nginx, syslog, JSON)",
    )

    # Output
    p.add_argument(
        "-f", "--format",
        choices=["text", "json", "csv", "html"],
        default="text",
        help="Report format (default: text)",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save report to FILE instead of stdout",
    )

    # Filtering
    p.add_argument(
        "--whitelist",
        nargs="*",
        metavar="IP",
        default=[],
        help="IPs to exclude from analysis",
    )
    p.add_argument(
        "--include-private",
        action="store_true",
        help="Also analyse RFC-1918 / loopback addresses (skipped by default)",
    )
    p.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Only show anomalies at this severity or above",
    )

    # Thresholds
    thresh = p.add_argument_group("Detection thresholds")
    thresh.add_argument("--freq-threshold",  type=int, default=100,
                        help="Requests/minute to flag HIGH (default: 100)")
    thresh.add_argument("--freq-critical",   type=int, default=500,
                        help="Requests/minute to flag CRITICAL (default: 500)")
    thresh.add_argument("--error-rate",      type=float, default=0.40,
                        help="Error rate (0–1) to flag suspicious (default: 0.40)")
    thresh.add_argument("--scan-paths",      type=int, default=50,
                        help="Distinct paths to flag scanner (default: 50)")
    thresh.add_argument("--auth-fail",       type=int, default=5,
                        help="Auth failures to flag (default: 5)")

    # Display
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show per-IP statistics table",
    )
    p.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour output",
    )

    return p


# ─── Per-IP Stats Table ───────────────────────────────────────────────────────

def print_ip_stats(stats: dict):
    print("\n\033[1mPER-IP STATISTICS\033[0m")
    print(f"  {'IP':<18} {'Reqs':>7} {'Errors':>7} {'Err%':>6} {'Paths':>6} {'UAs':>4}")
    print(f"  {'─'*17} {'─'*7} {'─'*7} {'─'*6} {'─'*6} {'─'*4}")
    for ip, s in sorted(stats.items(), key=lambda x: -x[1].total_requests)[:30]:
        print(
            f"  {ip:<18} {s.total_requests:>7,} {s.error_count:>7,} "
            f"{s.error_rate*100:>5.1f}% {len(s.paths):>6,} {len(s.user_agents):>4}"
        )


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Validate files
    valid_files = []
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"⚠  File not found: {f}", file=sys.stderr)
        elif not p.is_file():
            print(f"⚠  Not a file: {f}", file=sys.stderr)
        else:
            valid_files.append(str(p))

    if not valid_files:
        print("❌  No valid log files provided.", file=sys.stderr)
        sys.exit(1)

    # Build config
    config = DetectorConfig(
        freq_req_threshold=args.freq_threshold,
        freq_req_critical=args.freq_critical,
        error_rate_threshold=args.error_rate,
        scan_distinct_paths=args.scan_paths,
        auth_fail_threshold=args.auth_fail,
    )

    detector = AnomalyDetector(
        config=config,
        ignore_private=not args.include_private,
        whitelist=args.whitelist,
    )

    # Parse & feed
    print(f"📂  Analysing {len(valid_files)} file(s)…", file=sys.stderr)
    parser_obj = LogParser()
    total_parsed = 0

    for filepath in valid_files:
        before = parser_obj.parsed_count
        detector.feed(parser_obj.parse_file(filepath))
        after = parser_obj.parsed_count
        n = after - before
        print(f"   ✓ {Path(filepath).name}: {n:,} entries", file=sys.stderr)

    print(f"   Total: {parser_obj.parsed_count:,} parsed, "
          f"{parser_obj.failed_count:,} unparseable", file=sys.stderr)

    # Detect
    anomalies = detector.detect()
    summary = detector.summary()

    # Filter by severity if requested
    if args.severity:
        from analyzer.anomaly_detector import Severity
        min_sev = Severity[args.severity]
        anomalies = [a for a in anomalies if a.severity.score >= min_sev.score]
        summary["total_anomalies"] = len(anomalies)

    # Verbose stats
    if args.verbose:
        print_ip_stats(detector.all_stats())

    # Render report
    reporter = get_reporter(args.format)
    if isinstance(reporter, TextReporter):
        reporter.use_colour = not args.no_colour

    report = reporter.render(
        anomalies=anomalies,
        summary=summary,
        stats=detector.all_stats(),
        source_files=[Path(f).name for f in valid_files],
    )

    # Output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"\n💾  Report saved to: {args.output}", file=sys.stderr)
    else:
        print(report)

    # Exit code: 1 if critical/high anomalies found (useful for CI/alerting)
    has_high = any(a.severity.score >= 3 for a in anomalies)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
