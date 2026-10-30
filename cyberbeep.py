#!/usr/bin/env python3
"""CyberBeep — real-time SSH brute-force detection with audio alerts.

Watches an auth-style log (e.g. /var/log/auth.log), flags brute-force
patterns, plays a severity beep, prints the alert, and records every
incident as one JSON object per line in incidents.jsonl.

Standard library only. No network access, no credentials, nothing leaves
the machine it runs on.

Rules (step 1):
  - ssh_brute_force (HIGH): >= threshold failed logins from one IP inside
    the window. One alert per IP per cooldown, so a sustained attack does
    not become a beep loop.
  - login_after_brute_force (CRITICAL): a successful login from an IP
    that was previously flagged. A brute force that suddenly succeeds is
    the incident that matters most.

Sound is one notification channel, not the product: every alert is also
printed and logged, so a machine with no audio still works fine.

Usage:
  python cyberbeep.py --demo            # replay the bundled sample log
  python cyberbeep.py /var/log/auth.log # watch a real log (needs read access)
  python cyberbeep.py --no-sound        # print + log only

Only monitor logs you own or have permission to monitor.
"""

import argparse
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import wave
from collections import defaultdict, deque
from datetime import datetime

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
    """Sliding-window brute-force detection, per source IP."""

    def __init__(self, threshold=5, window=300, cooldown=900):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.failures = defaultdict(deque)
        self.flagged = {}  # ip -> epoch of last HIGH alert

    def observe(self, line, now):
        m = FAILED_RE.search(line)
        if m:
            ip = m.group(1)
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
        m = ACCEPTED_RE.search(line)
        if m and m.group(1) in self.flagged:
            ip = m.group(1)
            self.flagged.pop(ip, None)  # already escalated; re-arm for later
            return {"type": "login_after_brute_force", "severity": "CRITICAL",
                    "ip": ip,
                    "detail": "Successful login from a previously flagged IP"}
        return None


# ------------------------------------------------------------------ main

def handle_alert(alert, now, beeper, incident_file, stats):
    line = (f"[{alert['severity']}] {fmt_ts(now)} {alert['type']} "
            f"from {alert['ip']}")
    if alert["type"] == "ssh_brute_force":
        line += f" ({alert['count']} failures in {alert['window_seconds']}s)"
    else:
        line += f" — {alert['detail']}"
    print(line, flush=True)
    beeper.beep(alert["severity"])
    record = {"timestamp": fmt_ts(now), "epoch": now, **alert}
    with open(incident_file, "a") as f:
        f.write(json.dumps(record) + "\n")
    stats["alerts"] += 1


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


def run_tail(path, detector, beeper, incident_file, stats):
    print(f"Watching {path} (Ctrl+C to stop) ...")
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
            now = parse_ts(line, time.time())
            alert = detector.observe(line, now)
            stats["lines"] += 1
            if alert:
                handle_alert(alert, now, beeper, incident_file, stats)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", nargs="?",
                    help="auth-style log to watch (default: demo sample)")
    ap.add_argument("--demo", action="store_true",
                    help="replay examples/sample_auth.log instead of tailing")
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
    stats = {"lines": 0, "alerts": 0}

    try:
        if args.demo or not args.logfile:
            sample = os.path.join(here, "examples", "sample_auth.log")
            run_demo(sample, detector, beeper, args.incidents, stats)
        else:
            if not os.path.exists(args.logfile):
                print(f"No such file: {args.logfile}", file=sys.stderr)
                return 2
            run_tail(args.logfile, detector, beeper, args.incidents, stats)
    except KeyboardInterrupt:
        print()
    print(f"Done. {stats['lines']} lines processed, "
          f"{stats['alerts']} alert(s) in {args.incidents}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
