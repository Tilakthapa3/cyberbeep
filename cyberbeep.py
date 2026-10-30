#!/usr/bin/env python3
"""CyberBeep — real-time SSH brute-force detection with audio alerts.

Watches an auth-style log (e.g. /var/log/auth.log) and/or a Wazuh
alerts file (/var/ossec/logs/alerts/alerts.json), flags brute-force
patterns, plays a severity beep, prints the alert, and records every
incident as one JSON object per line in incidents.jsonl.

With --dashboard it also serves a live page on http://127.0.0.1:8080/
showing recent incidents and per-IP counts. The page refreshes itself
every 5 seconds and never leaves the machine: it binds localhost only.

Standard library only. No network access, no credentials, nothing leaves
the machine it runs on.

Detection (steps 1-3) — one shared core, two event sources:
  - ssh_brute_force (HIGH): >= threshold failed logins from one IP inside
    the window, whether the failures arrive as syslog lines or as Wazuh
    alerts. One alert per IP per cooldown, so a sustained attack does
    not become a beep loop.
  - login_after_brute_force (CRITICAL): a successful login from an IP
    that was previously flagged. A brute force that suddenly succeeds is
    the incident that matters most.
  - wazuh_alert (level-mapped): any other Wazuh alert at or above
    --wazuh-min-level (default 10). Wazuh levels map to severities:
    >=13 CRITICAL, 10-12 HIGH, 7-9 MEDIUM, below that LOW.

Wazuh design notes (kept honest):
  - The code keys on rule *groups* and *level*, never on rule IDs, which
    vary between Wazuh versions and rulesets.
  - Alerts in the authentication-failure groups feed the shared
    brute-force counting only; they do not also emit a separate incident.
    Wazuh's own correlation rules (e.g. a "multiple authentication
    failures" rule) and CyberBeep's counting would otherwise double-beep
    for the same attack. A Wazuh alert's source IP is read from the
    top-level "srcip" field, falling back to "data.srcip".
  - Malformed JSON lines are skipped and counted, never fatal.

Sound is one notification channel, not the product: every alert is also
printed and logged, so a machine with no audio still works fine.

Usage:
  python cyberbeep.py --demo                       # replay both samples
  python cyberbeep.py --demo --dashboard           # replay, then keep the
                                                   # dashboard up to view it
  python cyberbeep.py /var/log/auth.log --dashboard
  python cyberbeep.py --wazuh /var/ossec/logs/alerts/alerts.json
  python cyberbeep.py /var/log/auth.log --wazuh /var/ossec/logs/alerts/alerts.json
  python cyberbeep.py --no-sound                   # print + log only

Only monitor logs you own or have permission to monitor.
"""

import argparse
import html as htmlmod
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import wave
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for \S+ from (\d+\.\d+\.\d+\.\d+)"
)
# Syslog lines start with "Oct 30 02:00:01" (no year).
TS_RE = re.compile(r"^(\w{3})\s+(\d+) (\d{2}):(\d{2}):(\d{2})")
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
# Wazuh timestamps look like "2019-10-15T19:07:57.741+0000".
WAZUH_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")

_ALERT_LOCK = threading.Lock()


def parse_ts(line, fallback):
    """Best-effort timestamp for a syslog line; falls back to wall clock."""
    m = TS_RE.match(line)
    if not m:
        return fallback
    month, day, hh, mm, ss = m.group(1), int(m.group(2)), *map(int, m.groups()[2:])
    try:
        return datetime(datetime.now().year, MONTHS[month], day, hh, mm, ss).timestamp()
    except (KeyError, ValueError):
        return fallback


def parse_wazuh_timestamp(value, fallback):
    """Best-effort timestamp for a Wazuh alert; falls back to wall clock."""
    if isinstance(value, str):
        for fmt in WAZUH_TS_FORMATS:
            try:
                return datetime.strptime(value, fmt).timestamp()
            except ValueError:
                continue
    return fallback


def fmt_ts(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- sound

def _write_tone(path, freq, ms):
    """Write a short sine-wave WAV with the standard library only."""
    rate = 44100
    frames = int(rate * ms / 1000)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        data = b"".join(
            struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate)))
            for i in range(frames)
        )
        w.writeframes(data)


class Beeper:
    """Severity beep patterns. Falls back to the terminal bell, then silence."""

    PATTERNS = {
        "LOW": [(660, 150)],
        "MEDIUM": [(660, 150), (660, 150)],
        "HIGH": [(880, 150)] * 3,
        "CRITICAL": [(880, 200), (660, 200)] * 3,
    }

    def __init__(self, enabled=True):
        self.enabled = enabled
        self._warned = False
        if sys.platform.startswith("win"):
            self._player = "winsound"
        else:
            self._player = (
                shutil.which("afplay")      # macOS
                or shutil.which("paplay")   # Linux (PulseAudio)
                or shutil.which("aplay")    # Linux (ALSA)
            )

    def beep(self, severity):
        if not self.enabled:
            return
        try:
            if self._player == "winsound":
                import winsound
                for freq, ms in self.PATTERNS[severity]:
                    winsound.Beep(freq, ms)
                    time.sleep(0.08)
                return
            for freq, ms in self.PATTERNS[severity]:
                if self._player:
                    with tempfile.NamedTemporaryFile(
                            suffix=".wav", delete=False) as f:
                        tmp = f.name
                    _write_tone(tmp, freq, ms)
                    subprocess.run([self._player, tmp],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    os.unlink(tmp)
                else:
                    sys.stdout.write("\a")
                    sys.stdout.flush()
                time.sleep(0.08)
        except Exception:
            if not self._warned:
                print("[sound unavailable — alerts will print and log only]",
                      file=sys.stderr)
                self._warned = True


# ------------------------------------------------------------- detection

class Detector:
    """Sliding-window brute-force detection, per source IP.

    Both event sources feed the same core: syslog lines are parsed into
    failed/accepted login observations, and Wazuh alerts call the same
    observation methods directly.
    """

    def __init__(self, threshold=5, window=300, cooldown=900):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.failures = defaultdict(deque)
        self.flagged = {}  # ip -> epoch of last HIGH alert
        self._lock = threading.Lock()

    def observe(self, line, now):
        with self._lock:
            return self._observe_locked(line, now)

    def _observe_locked(self, line, now):
        m = FAILED_RE.search(line)
        if m:
            return self._failed_locked(m.group(1), now)
        m = ACCEPTED_RE.search(line)
        if m:
            return self._accepted_locked(m.group(1), now)
        return None

    def observe_failed_login(self, ip, now):
        """Count one failed login from an outside caller (e.g. Wazuh)."""
        with self._lock:
            return self._failed_locked(ip, now)

    def _failed_locked(self, ip, now):
        dq = self.failures[ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if (len(dq) >= self.threshold
                and now - self.flagged.get(ip, 0) > self.cooldown):
            self.flagged[ip] = now
            return {"type": "ssh_brute_force", "severity": "HIGH",
                    "ip": ip, "count": len(dq),
                    "window_seconds": self.window}
        return None

    def observe_accepted_login(self, ip, now):
        with self._lock:
            return self._accepted_locked(ip, now)

    def _accepted_locked(self, ip, now):
        if ip in self.flagged:
            self.flagged.pop(ip, None)  # already escalated; re-arm for later
            return {"type": "login_after_brute_force", "severity": "CRITICAL",
                    "ip": ip,
                    "detail": "Successful login from a previously flagged IP"}
        return None

    def snapshot(self):
        """Copy of per-IP state for the dashboard (thread-safe)."""
        with self._lock:
            return {
                ip: {"failures_in_window": len(dq),
                     "flagged": ip in self.flagged}
                for ip, dq in self.failures.items()
            }


# ---------------------------------------------------------------- wazuh

def wazuh_srcip(alert):
    """Source IP: top-level "srcip" first, then "data.srcip"."""
    ip = alert.get("srcip")
    if ip:
        return ip
    data = alert.get("data")
    if isinstance(data, dict):
        return data.get("srcip")
    return None


def level_to_severity(level):
    if level >= 13:
        return "CRITICAL"
    if level >= 10:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    return "LOW"


def observe_wazuh(alert, now, detector, min_level):
    """Turn one parsed Wazuh alert into an incident dict, or None.

    Authentication-failure alerts feed the shared brute-force counting
    only. Everything else at or above min_level becomes its own incident.
    """
    if not isinstance(alert, dict):
        return None
    rule = alert.get("rule") or {}
    groups = [str(g).lower() for g in (rule.get("groups") or [])]
    ip = wazuh_srcip(alert)
    if ip and any("authentication_fail" in g for g in groups):
        return detector.observe_failed_login(ip, now)
    if ip and any("authentication_success" in g for g in groups):
        return detector.observe_accepted_login(ip, now)
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    if level < min_level:
        return None
    rule_id = str(rule.get("id", "?"))
    description = str(rule.get("description", ""))
    agent = alert.get("agent") or {}
    return {"type": "wazuh_alert",
            "severity": level_to_severity(level),
            "ip": ip or "n/a",
            "rule_id": rule_id,
            "rule_level": level,
            "agent": str(agent.get("name", "")),
            "detail": f"rule {rule_id} (level {level}): {description}"}


# ------------------------------------------------------------- dashboard

def _read_incidents(path, limit=50):
    try:
        with open(path) as f:
            rows = []
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return rows[-limit:][::-1]
    except FileNotFoundError:
        return []


def _render_page(watched, stats, snap, incidents):
    esc = htmlmod.escape
    sev_class = {"HIGH": "high", "CRITICAL": "critical",
                 "MEDIUM": "medium", "LOW": "low"}
    if incidents:
        rows = []
        for r in incidents:
            if r.get("type") == "ssh_brute_force":
                det = (f"{r.get('count')} failures in "
                       f"{r.get('window_seconds')}s")
            else:
                det = str(r.get("detail", ""))
            rows.append(
                "<tr><td>{ts}</td><td><span class='badge {cls}'>{sev}</span></td>"
                "<td>{typ}</td><td>{ip}</td><td>{det}</td></tr>".format(
                    ts=esc(str(r.get("timestamp", ""))),
                    cls=sev_class.get(r.get("severity"), ""),
                    sev=esc(str(r.get("severity", ""))),
                    typ=esc(str(r.get("type", ""))),
                    ip=esc(str(r.get("ip", ""))),
                    det=esc(det)))
        incident_rows = "".join(rows)
    else:
        incident_rows = ("<tr><td colspan='5'>No incidents yet — "
                         "alerts will appear here as they happen.</td></tr>")
    if snap:
        ip_rows = "".join(
            "<tr><td>{ip}</td><td>{n}</td><td>{flag}</td></tr>".format(
                ip=esc(ip),
                n=v["failures_in_window"],
                flag="yes" if v["flagged"] else "no")
            for ip, v in sorted(snap.items()))
    else:
        ip_rows = ("<tr><td colspan='3'>No failed logins seen yet.</td></tr>")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>CyberBeep Live</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2em; color: #111; }}
table {{ border-collapse: collapse; margin-bottom: 2em; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
.badge {{ padding: 2px 8px; border-radius: 10px; color: #fff; font-size: 0.85em; }}
.high {{ background: #e67e00; }} .critical {{ background: #c00; }}
.medium {{ background: #d4a017; }} .low {{ background: #2a7; }}
</style></head><body>
<h1>CyberBeep Live</h1>
<p>Watching: {esc(watched)} &nbsp;|&nbsp; Lines processed: {stats['lines']}
&nbsp;|&nbsp; Alerts: {stats['alerts']} &nbsp;|&nbsp; Auto-refreshes every 5s</p>
<h2>Recent incidents</h2>
<table><tr><th>Time</th><th>Severity</th><th>Type</th><th>IP</th><th>Detail</th></tr>
{incident_rows}</table>
<h2>Per-IP failures in window</h2>
<table><tr><th>IP</th><th>Failures</th><th>Flagged</th></tr>
{ip_rows}</table>
</body></html>"""


def _make_handler(detector, incident_file, stats, watched):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            page = _render_page(watched, stats, detector.snapshot(),
                                _read_incidents(incident_file))
            data = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def start_dashboard(detector, incident_file, stats, watched, port):
    """Start the localhost dashboard in a daemon thread (None if it fails)."""
    try:
        server = ThreadingHTTPServer(
            ("127.0.0.1", port),
            _make_handler(detector, incident_file, stats, watched))
    except OSError as e:
        print(f"[dashboard unavailable on port {port}: {e}]", file=sys.stderr)
        return None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Dashboard: http://127.0.0.1:{port}/")
    return server


# ------------------------------------------------------------------ main

def handle_alert(alert, now, beeper, incident_file, stats):
    # One lock: the syslog and Wazuh tails run in different threads, and
    # an alert must print, beep, and log as one indivisible unit.
    with _ALERT_LOCK:
        line = (f"[{alert['severity']}] {fmt_ts(now)} {alert['type']} "
                f"from {alert['ip']}")
        if alert["type"] == "ssh_brute_force":
            line += (f" ({alert['count']} failures "
                     f"in {alert['window_seconds']}s)")
        else:
            line += f" — {alert['detail']}"
        print(line, flush=True)
        beeper.beep(alert["severity"])
        record = {"timestamp": fmt_ts(now), "epoch": now, **alert}
        with open(incident_file, "a") as f:
            f.write(json.dumps(record) + "\n")
        stats["alerts"] += 1


def _tail_lines(path):
    """Yield new lines as they are appended; restarts on truncation."""
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.5)
                # Log rotated or truncated: start over instead of stalling.
                if os.path.getsize(path) < pos:
                    f.seek(0)
                else:
                    f.seek(pos)
                continue
            yield line


def run_demo(path, detector, beeper, incident_file, stats):
    print(f"Replaying {path} ...")
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            now = parse_ts(line, time.time())
            alert = detector.observe(line, now)
            stats["lines"] += 1
            if alert:
                handle_alert(alert, now, beeper, incident_file, stats)
            time.sleep(0.15)  # demo pace, so the "live" feel survives


def run_wazuh_demo(path, detector, beeper, incident_file, stats, min_level):
    print(f"Replaying {path} ...")
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            try:
                alert_json = json.loads(line)
            except json.JSONDecodeError:
                stats["skipped"] += 1
                continue
            now = parse_wazuh_timestamp(alert_json.get("timestamp"),
                                        time.time())
            alert = observe_wazuh(alert_json, now, detector, min_level)
            if alert:
                handle_alert(alert, now, beeper, incident_file, stats)
            time.sleep(0.15)


def run_tail(path, detector, beeper, incident_file, stats):
    print(f"Watching {path} (Ctrl+C to stop) ...")
    for line in _tail_lines(path):
        now = parse_ts(line, time.time())
        alert = detector.observe(line, now)
        stats["lines"] += 1
        if alert:
            handle_alert(alert, now, beeper, incident_file, stats)


def run_wazuh_tail(path, detector, beeper, incident_file, stats, min_level):
    print(f"Watching Wazuh alerts {path} (Ctrl+C to stop) ...")
    for line in _tail_lines(path):
        line = line.strip()
        if not line:
            continue
        stats["lines"] += 1
        try:
            alert_json = json.loads(line)
        except json.JSONDecodeError:
            stats["skipped"] += 1
            continue
        now = parse_wazuh_timestamp(alert_json.get("timestamp"), time.time())
        alert = observe_wazuh(alert_json, now, detector, min_level)
        if alert:
            handle_alert(alert, now, beeper, incident_file, stats)


def _require_file(path, label):
    if not os.path.exists(path):
        print(f"No such file: {path}", file=sys.stderr)
        return False
    return True


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", nargs="?",
                    help="auth-style log to watch (default: demo samples)")
    ap.add_argument("--demo", action="store_true",
                    help="replay the bundled samples instead of tailing")
    ap.add_argument("--dashboard", action="store_true",
                    help="serve the live dashboard on localhost")
    ap.add_argument("--port", type=int, default=8080,
                    help="dashboard port (default 8080)")
    ap.add_argument("--wazuh", metavar="FILE",
                    help="Wazuh alerts.json file to watch as well")
    ap.add_argument("--wazuh-min-level", type=int, default=10,
                    help="minimum Wazuh rule level that becomes its own "
                         "incident (default 10)")
    ap.add_argument("--threshold", type=int, default=5,
                    help="failed logins from one IP that trigger HIGH (default 5)")
    ap.add_argument("--window", type=int, default=5,
                    help="window in minutes for the threshold (default 5)")
    ap.add_argument("--cooldown", type=int, default=15,
                    help="minutes before the same IP can re-alert (default 15)")
    ap.add_argument("--no-sound", action="store_true",
                    help="print + log only, no beeps")
    ap.add_argument("--incidents", default="incidents.jsonl",
                    help="incident log file (default incidents.jsonl)")
    args = ap.parse_args()

    detector = Detector(threshold=args.threshold,
                        window=args.window * 60,
                        cooldown=args.cooldown * 60)
    beeper = Beeper(enabled=not args.no_sound)
    stats = {"lines": 0, "alerts": 0, "skipped": 0}

    demo = args.demo or (not args.logfile and not args.wazuh)
    watched = []
    try:
        if demo:
            syslog_sample = os.path.join(here, "examples", "sample_auth.log")
            wazuh_sample = os.path.join(
                here, "examples", "sample_wazuh_alerts.jsonl")
            watched = [syslog_sample + " (demo replay)",
                       wazuh_sample + " (demo replay)"]
            if args.dashboard:
                start_dashboard(detector, args.incidents, stats,
                                ", ".join(watched), args.port)
            run_demo(syslog_sample, detector, beeper, args.incidents, stats)
            run_wazuh_demo(wazuh_sample, detector, beeper, args.incidents,
                           stats, args.wazuh_min_level)
            if args.dashboard:
                # Keep serving the replay results until stopped.
                print("Dashboard still running — Ctrl+C to stop.")
                while True:
                    time.sleep(1)
        else:
            if args.wazuh and not _require_file(args.wazuh, "wazuh"):
                return 2
            if args.logfile and not _require_file(args.logfile, "logfile"):
                return 2
            if args.logfile:
                watched.append(args.logfile)
            if args.wazuh:
                watched.append(args.wazuh + " (Wazuh alerts)")
            if args.dashboard:
                start_dashboard(detector, args.incidents, stats,
                                ", ".join(watched), args.port)
            if args.wazuh and args.logfile:
                # Wazuh tail runs alongside the syslog tail.
                threading.Thread(
                    target=run_wazuh_tail,
                    args=(args.wazuh, detector, beeper, args.incidents,
                          stats, args.wazuh_min_level),
                    daemon=True).start()
                run_tail(args.logfile, detector, beeper, args.incidents, stats)
            elif args.wazuh:
                run_wazuh_tail(args.wazuh, detector, beeper, args.incidents,
                               stats, args.wazuh_min_level)
            else:
                run_tail(args.logfile, detector, beeper, args.incidents, stats)
    except KeyboardInterrupt:
        print()
    print(f"Done. {stats['lines']} lines processed, "
          f"{stats['alerts']} alert(s), {stats['skipped']} bad line(s) "
          f"skipped, in {args.incidents}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
