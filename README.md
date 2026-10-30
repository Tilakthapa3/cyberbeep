# CyberBeep

Real-time SSH brute-force detection with severity audio alerts.

It watches an auth-style log, flags attack patterns, plays a beep
matching the severity, prints the alert, and records every incident as
JSON Lines. Standard library only — no dependencies, no network access,
nothing leaves the machine it runs on.

Sound is one notification channel, not the product: every alert is also
printed and logged, so a machine with no audio still works.

## Rules (steps 1–3)

| Alert | Severity | Trigger |
|---|---|---|
| `ssh_brute_force` | HIGH | 5+ failed logins from one IP within 5 minutes, from the syslog and/or Wazuh (one alert per IP per 15-minute cooldown, so a sustained attack doesn't become a beep loop) |
| `login_after_brute_force` | CRITICAL | A successful login from an IP that was previously flagged — a brute force that suddenly succeeds is the incident that matters most |
| `wazuh_alert` | From rule level | Any other Wazuh alert at or above `--wazuh-min-level` (default 10): level ≥13 CRITICAL, 10–12 HIGH, 7–9 MEDIUM, below that LOW |

Thresholds are flags: `--threshold`, `--window`, `--cooldown`.

## Wazuh input (step 3)

Point CyberBeep at a Wazuh manager's alert file and it tails it
alongside (or instead of) the syslog:

```bash
python cyberbeep.py --wazuh /var/ossec/logs/alerts/alerts.json
python cyberbeep.py /var/log/auth.log --wazuh /var/ossec/logs/alerts/alerts.json
```

How it works, honestly: it reads Wazuh's single-line JSON records from
`alerts.json` and keys on rule *groups* and *level*, never on rule IDs,
which vary between Wazuh versions and rulesets. Alerts in the
authentication-failure groups feed the same brute-force counting as the
syslog lines (a source IP is read from `srcip`, falling back to
`data.srcip`), so the same attack seen through both sources counts once
per IP — and Wazuh's own correlation rules don't double-beep. A
successful-login alert for a flagged IP escalates to CRITICAL the same
way. Anything else at or above `--wazuh-min-level` (default 10) becomes
its own `wazuh_alert` incident. Malformed JSON lines are skipped and
counted, never fatal.

`--demo` replays both bundled samples, including one malformed Wazuh
line that gets skipped.

## Try it in 30 seconds (no logs, no setup)

```bash
python cyberbeep.py --demo
```

This replays `examples/sample_auth.log`: an attacker IP fails 5 times
(HIGH beep), then logs in successfully (CRITICAL beep), while a second
IP with only 2 failures correctly stays silent. It then replays
`examples/sample_wazuh_alerts.jsonl`: five Wazuh auth-failure alerts
from one IP (HIGH beep) plus a level-10 Wazuh rule alert. Alerts land in
`incidents.jsonl`:

```json
{"timestamp": "2026-10-30 02:00:44", "type": "ssh_brute_force", "severity": "HIGH", "ip": "203.0.113.45", "count": 5, "window_seconds": 300}
{"timestamp": "2026-10-30 02:01:10", "type": "login_after_brute_force", "severity": "CRITICAL", "ip": "203.0.113.45", "detail": "Successful login from a previously flagged IP"}
```

## Watch a real log

```bash
python cyberbeep.py /var/log/auth.log        # Linux (Debian/Ubuntu)
python cyberbeep.py /var/log/secure           # Linux (RHEL/CentOS)
python cyberbeep.py --no-sound /var/log/auth.log  # print + log only
```

It tails the file, so new lines are checked as they arrive. If the log
rotates or shrinks, it restarts from the top instead of stalling.

## Live dashboard

Add `--dashboard` to serve a live page on http://127.0.0.1:8080/
(`--port` changes the port). It shows recent incidents and per-IP
failure counts, refreshes every 5 seconds, and binds localhost only —
nothing is exposed to the network.

```bash
python cyberbeep.py /var/log/auth.log --dashboard
python cyberbeep.py --demo --dashboard   # replay, then keep the page up
```

If the port is already taken, it prints a warning and keeps watching
without the dashboard instead of crashing.

## Sound

- Windows: built-in `winsound` beeps.
- macOS: generated tones played with `afplay`.
- Linux: generated tones played with `paplay` or `aplay`.
- No player available: falls back to the terminal bell, then prints only.
  Nothing crashes if audio is missing.

Beep patterns: HIGH is three beeps, CRITICAL is three alternating
high/low pairs.

## Testing

Tests use only the standard library (`unittest`):

```bash
python3 -m unittest discover -s tests -v
```

They cover the brute-force threshold and sliding window, the per-IP
cooldown, the login-after-flag CRITICAL rule, Wazuh counting vs.
standalone alerts (including the min-level cutoff and malformed-line
skipping), and the dashboard page rendering. No network, audio, or log
files are needed — the detector and parser are tested directly, and the
Wazuh demo path replays a temporary alerts file.

## Roadmap

- More rules (e.g. new-country logins, off-hours admin logins)
- Optional email/webhook notifications for CRITICAL alerts

## Disclaimer

Only monitor logs you own or have permission to monitor.
