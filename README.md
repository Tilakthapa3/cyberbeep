# CyberBeep

Real-time SSH brute-force detection with severity audio alerts.

It watches an auth-style log, flags attack patterns, plays a beep
matching the severity, prints the alert, and records every incident as
JSON Lines. Standard library only — no dependencies, no network access,
nothing leaves the machine it runs on.

Sound is one notification channel, not the product: every alert is also
printed and logged, so a machine with no audio still works.

## Rules (step 1)

| Alert | Severity | Trigger |
|---|---|---|
| `ssh_brute_force` | HIGH | 5+ failed logins from one IP within 5 minutes (one alert per IP per 15-minute cooldown, so a sustained attack doesn't become a beep loop) |
| `login_after_brute_force` | CRITICAL | A successful login from an IP that was previously flagged — a brute force that suddenly succeeds is the incident that matters most |

Thresholds are flags: `--threshold`, `--window`, `--cooldown`.

## Try it in 30 seconds (no logs, no setup)

```bash
python cyberbeep.py --demo
```

This replays `examples/sample_auth.log`: an attacker IP fails 5 times
(HIGH beep), then logs in successfully (CRITICAL beep), while a second
IP with only 2 failures correctly stays silent. Alerts land in
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

## Sound

- Windows: built-in `winsound` beeps.
- macOS: generated tones played with `afplay`.
- Linux: generated tones played with `paplay` or `aplay`.
- No player available: falls back to the terminal bell, then prints only.
  Nothing crashes if audio is missing.

Beep patterns: HIGH is three beeps, CRITICAL is three alternating
high/low pairs.

## Roadmap

- Live dashboard (incidents + per-IP counts, served locally)
- Wazuh alert-file input as a second event source
- More rules (e.g. new-country logins, off-hours admin logins)

## Disclaimer

Only monitor logs you own or have permission to monitor.
