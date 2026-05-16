#!/usr/bin/env python3
import random
import os
from datetime import datetime, timedelta

# ─── Config ───────────────────────────────────────────────────────────────────

OUTPUT_DIR   = "sample_logs"
ACCESS_LOG   = os.path.join(OUTPUT_DIR, "access.log")
SYSLOG_LOG   = os.path.join(OUTPUT_DIR, "syslog.log")

NORMAL_IPS   = [f"203.0.113.{i}" for i in range(1, 40)]          # legit users
ATTACKER_IPS = {
    "198.51.100.7":  "brute_force",       # SSH brute-force
    "198.51.100.42": "scanner",           # path scanner
    "198.51.100.99": "dos",               # DoS / high-freq
    "198.51.100.13": "error_flood",       # error-rate abuser
    "198.51.100.55": "off_hours",         # off-hours actor
    "198.51.100.77": "ua_rotator",        # user-agent rotation
}

METHODS  = ["GET", "POST", "HEAD", "PUT", "DELETE"]
PATHS    = [
    "/", "/index.html", "/login", "/api/v1/users", "/api/v1/products",
    "/static/main.js", "/static/style.css", "/dashboard", "/logout",
    "/api/v1/orders", "/health", "/robots.txt",
]
SCAN_PATHS = [
    f"/{x}" for x in [
        "admin", "wp-login.php", "phpmyadmin", ".env", "config.php",
        "backup.zip", "shell.php", "cmd.php", ".git/config", "etc/passwd",
        "xmlrpc.php", "wp-admin/", "setup.php", "install.php", "readme.html",
        "wp-content/debug.log", ".htaccess", "server-status", "api/swagger",
        "actuator/env", "actuator/health", "debug/pprof", "console/",
        "adminer.php", "db.php", "database.php", "config/database.yml",
        "credentials.json", "secrets.yml", "appsettings.json",
        "web.config", "Global.asax", "crossdomain.xml", "clientaccesspolicy.xml",
        "sitemap.xml", "feed/", "rss/", "atom/", "xmlrpc", "cgi-bin/",
        "cgi-bin/test.cgi", "cgi-bin/printenv", "test.php", "info.php",
        "phpinfo.php", "check.php", "status.php", "monitor.php",
        "backup/", "old/", "tmp/", "temp/", "cache/",
        "logs/", "log/", "error_log", "access_log",
        "id_rsa", "id_dsa", "authorized_keys", ".bash_history",
        "proc/self/environ", "etc/shadow",
    ]
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Wget/1.21.4 (linux-gnu)",
]
ATTACKER_UAS = [
    "Nikto/2.1.6",
    "sqlmap/1.7.8#stable",
    "masscan/1.3.2",
    "Nmap Scripting Engine",
    "ZAP/2.14.0",
    "Burp Suite Professional",
    "dirbuster/1.0-RC1",
    "gobuster/3.6",
    "wfuzz/3.1.0",
    "nuclei/2.9.14",
]

SYSLOG_HOSTS    = ["web01", "db01", "auth01"]
SYSLOG_SERVICES = ["sshd", "sudo", "pam_unix", "kernel", "cron"]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def fmt_time_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0700")

def fmt_time_syslog(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")

def apache_line(ip, dt, method, path, status, size, ua, referrer="-"):
    return (
        f'{ip} - - [{fmt_time_apache(dt)}] '
        f'"{method} {path} HTTP/1.1" {status} {size} '
        f'"{referrer}" "{ua}"'
    )

def syslog_line(dt, host, service, pid, message):
    return f"{fmt_time_syslog(dt)} {host} {service}[{pid}]: {message}"

def rand_size(status):
    if status == 200:
        return random.randint(1_000, 50_000)
    if status in (301, 302):
        return random.randint(100, 500)
    return random.randint(50, 300)


# ─── Log Generation ───────────────────────────────────────────────────────────

def generate_access_log(start: datetime, hours: int = 24) -> list[str]:
    lines = []
    now = start

    # ── Normal traffic ────────────────────────────────────────────────────────
    for _ in range(3_000):
        dt = start + timedelta(
            hours=random.uniform(0, hours),
            minutes=random.uniform(0, 60),
        )
        ip  = random.choice(NORMAL_IPS)
        ua  = random.choice(USER_AGENTS)
        path   = random.choice(PATHS)
        method = random.choices(METHODS, weights=[60,20,5,10,5])[0]
        status = random.choices([200, 301, 304, 404, 500], weights=[75,5,5,12,3])[0]
        lines.append(apache_line(ip, dt, method, path, status, rand_size(status), ua))

    # ── Attack: DoS / High-frequency ──────────────────────────────────────────
    dos_ip = "198.51.100.99"
    burst_start = start + timedelta(hours=3, minutes=15)
    for i in range(800):
        dt = burst_start + timedelta(seconds=random.uniform(0, 90))
        lines.append(apache_line(
            dos_ip, dt, "GET", "/api/v1/users", 200, 4200,
            "python-requests/2.31.0"
        ))

    # ── Attack: Path scanner ──────────────────────────────────────────────────
    scanner_ip = "198.51.100.42"
    scan_start = start + timedelta(hours=1)
    for i, path in enumerate(SCAN_PATHS):
        dt = scan_start + timedelta(seconds=i * random.uniform(0.5, 3))
        status = random.choices([404, 403, 200], weights=[70, 20, 10])[0]
        ua = random.choice(ATTACKER_UAS[:3])
        lines.append(apache_line(scanner_ip, dt, "GET", path, status, rand_size(status), ua))

    # ── Attack: Error-rate abuser ─────────────────────────────────────────────
    err_ip = "198.51.100.13"
    for _ in range(200):
        dt = start + timedelta(hours=random.uniform(0, hours))
        status = random.choices([200, 401, 403, 404, 500], weights=[10,30,20,30,10])[0]
        path = random.choice(PATHS + ["/admin", "/login", "/api/secret"])
        lines.append(apache_line(err_ip, dt, "POST", path, status, rand_size(status),
                                 "Mozilla/5.0 (compatible; BadBot/1.0)"))

    # ── Attack: Off-hours actor ───────────────────────────────────────────────
    night_ip = "198.51.100.55"
    for _ in range(150):
        # 22:00 – 04:00
        hour = random.choice(list(range(22, 24)) + list(range(0, 5)))
        dt = start.replace(hour=hour, minute=random.randint(0, 59),
                           second=random.randint(0, 59))
        lines.append(apache_line(night_ip, dt, "GET",
                                 random.choice(PATHS), 200, rand_size(200),
                                 USER_AGENTS[0]))

    # ── Attack: User-Agent rotator ────────────────────────────────────────────
    ua_ip = "198.51.100.77"
    for i in range(120):
        dt = start + timedelta(hours=random.uniform(2, 10))
        ua = random.choice(ATTACKER_UAS)
        path = random.choice(PATHS)
        lines.append(apache_line(ua_ip, dt, "GET", path, 200, rand_size(200), ua))

    # Sort by timestamp (crude: lex sort on the timestamp portion)
    lines.sort(key=lambda l: l[l.index("[")+1 : l.index("]")])
    return lines


def generate_syslog(start: datetime, hours: int = 24) -> list[str]:
    lines = []

    # Normal syslog events
    for _ in range(500):
        dt = start + timedelta(hours=random.uniform(0, hours))
        host = random.choice(SYSLOG_HOSTS)
        svc  = random.choice(SYSLOG_SERVICES)
        pid  = random.randint(1000, 65000)
        msg  = random.choice([
            "session opened for user admin by (uid=0)",
            "session closed for user admin",
            "Accepted publickey for deploy from 203.0.113.5 port 55320 ssh2",
            "pam_unix(sshd:session): session opened for user www-data",
            "Cron job completed successfully",
            "Disk usage check: /dev/sda1 45% used",
        ])
        lines.append(syslog_line(dt, host, svc, pid, msg))

    # Brute-force SSH from attacker
    bf_ip = "198.51.100.7"
    bf_start = start + timedelta(hours=2)
    for i in range(80):
        dt = bf_start + timedelta(seconds=i * random.uniform(1, 5))
        pid  = random.randint(10000, 60000)
        user = random.choice(["root", "admin", "ubuntu", "pi", "oracle", "postgres"])
        msg  = f"Failed password for {user} from {bf_ip} port {random.randint(30000,65000)} ssh2"
        lines.append(syslog_line(dt, "auth01", "sshd", pid, msg))

    # A few successful logins mixed in
    for _ in range(5):
        dt = bf_start + timedelta(hours=random.uniform(0, 2))
        pid  = random.randint(10000, 60000)
        msg  = f"Accepted password for root from {bf_ip} port {random.randint(30000,65000)} ssh2"
        lines.append(syslog_line(dt, "auth01", "sshd", pid, msg))

    lines.sort()
    return lines


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    start = datetime(2024, 5, 15, 0, 0, 0)

    print(f"Generating {ACCESS_LOG} …")
    access_lines = generate_access_log(start, hours=24)
    with open(ACCESS_LOG, "w") as f:
        f.write("\n".join(access_lines) + "\n")
    print(f"  → {len(access_lines):,} lines written")

    print(f"Generating {SYSLOG_LOG} …")
    syslog_lines = generate_syslog(start, hours=24)
    with open(SYSLOG_LOG, "w") as f:
        f.write("\n".join(syslog_lines) + "\n")
    print(f"  → {len(syslog_lines):,} lines written")

    print("\n✅ Sample logs ready in ./sample_logs/")
    print("   Run: python main.py sample_logs/access.log sample_logs/syslog.log")


if __name__ == "__main__":
    main()
