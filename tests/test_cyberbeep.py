#!/usr/bin/env python3
"""Tests for CyberBeep. Standard library only (unittest).

Run from the repository root:

    python3 -m unittest discover -s tests -v

No network, audio, or real log files are needed: the detector and the
Wazuh parser are exercised directly, and the Wazuh demo path replays a
temporary alerts file. Sound is disabled via Beeper(enabled=False).
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cyberbeep as cb


FAILED_LINE = ("Oct 30 02:00:01 server sshd[100]: Failed password for root "
               "from {ip} port 51234 ssh2")
ACCEPTED_LINE = ("Oct 30 02:01:10 server sshd[101]: Accepted password for "
                 "root from {ip} port 51234 ssh2")


def wazuh_alert(ip=None, level=5, rule_id="5716", groups=None,
                description="SSHD authentication failed.", use_data=False):
    alert = {"timestamp": "2026-10-30T02:10:05.000+0000",
             "rule": {"level": level, "description": description,
                      "id": rule_id, "groups": groups or []},
             "agent": {"name": "linux-agent"}}
    if ip is not None:
        if use_data:
            alert["data"] = {"srcip": ip}
        else:
            alert["srcip"] = ip
    return alert


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.det = cb.Detector()  # threshold 5, window 300s, cooldown 900s

    def _failures(self, ip, start, count=5, step=1):
        results = [self.det.observe_failed_login(ip, start + i * step)
                   for i in range(count)]
        return results

    def test_four_failures_no_alert(self):
        results = self._failures("203.0.113.1", 1000, count=4)
        self.assertEqual(results, [None, None, None, None])

    def test_fifth_failure_fires_high(self):
        results = self._failures("203.0.113.1", 1000, count=5)
        self.assertEqual(results[:4], [None] * 4)
        alert = results[4]
        self.assertEqual(alert["type"], "ssh_brute_force")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["ip"], "203.0.113.1")
        self.assertEqual(alert["count"], 5)
        self.assertEqual(alert["window_seconds"], 300)

    def test_cooldown_suppresses_second_alert(self):
        self._failures("203.0.113.1", 1000, count=5)
        # Five more failures 100s later: inside the window, inside cooldown.
        results = self._failures("203.0.113.1", 1100, count=5)
        self.assertEqual(results, [None] * 5)

    def test_alert_fires_again_after_cooldown(self):
        self._failures("203.0.113.1", 1000, count=5)
        # Past both the 300s window and the 900s cooldown: a fresh burst.
        results = self._failures("203.0.113.1", 2000, count=5)
        self.assertEqual(results[:4], [None] * 4)
        self.assertEqual(results[4]["type"], "ssh_brute_force")

    def test_sliding_window_expiry(self):
        # Failures more than the window apart never accumulate to 5.
        for t in (0, 100, 200, 300, 400, 401):
            self.assertIsNone(self.det.observe_failed_login("203.0.113.1", t))

    def test_syslog_lines_drive_detection(self):
        ip = "203.0.113.45"
        for i in range(4):
            self.assertIsNone(
                self.det.observe(FAILED_LINE.format(ip=ip), 1000 + i))
        alert = self.det.observe(FAILED_LINE.format(ip=ip), 1004)
        self.assertEqual(alert["type"], "ssh_brute_force")
        self.assertEqual(alert["severity"], "HIGH")

    def test_login_after_flag_is_critical(self):
        ip = "203.0.113.45"
        self._failures(ip, 1000, count=5)
        alert = self.det.observe(ACCEPTED_LINE.format(ip=ip), 1010)
        self.assertEqual(alert["type"], "login_after_brute_force")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["ip"], ip)

    def test_accepted_without_flag_no_alert(self):
        self.assertIsNone(
            self.det.observe(ACCEPTED_LINE.format(ip="203.0.113.45"), 1000))

    def test_flag_rearms_after_critical(self):
        ip = "203.0.113.45"
        self._failures(ip, 1000, count=5)
        self.det.observe(ACCEPTED_LINE.format(ip=ip), 1010)
        # The flag is popped on escalation, and the pre-login failures are
        # still inside the window, so the very next failure re-fires HIGH
        # and the cooldown then suppresses the rest of the burst.
        results = self._failures(ip, 1020, count=5)
        self.assertEqual(results[0]["type"], "ssh_brute_force")
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertEqual(results[1:], [None] * 4)


class TestWazuh(unittest.TestCase):
    AUTH_GROUPS = ["syslog", "sshd", "authentication_failed"]

    def test_auth_failures_feed_counting_only(self):
        det = cb.Detector()
        results = [cb.observe_wazuh(
            wazuh_alert("198.51.100.23", groups=self.AUTH_GROUPS),
            1000 + i, det, 10) for i in range(5)]
        self.assertEqual(results[:4], [None] * 4)
        # The 5th is the shared brute-force alert, NOT a wazuh_alert.
        self.assertEqual(results[4]["type"], "ssh_brute_force")
        self.assertEqual(results[4]["severity"], "HIGH")

    def test_auth_failure_data_srcip_fallback(self):
        det = cb.Detector()
        self.assertEqual(cb.wazuh_srcip(
            wazuh_alert("198.51.100.23", use_data=True)), "198.51.100.23")
        results = [cb.observe_wazuh(
            wazuh_alert("198.51.100.23", groups=self.AUTH_GROUPS,
                        use_data=True),
            1000 + i, det, 10) for i in range(5)]
        self.assertEqual(results[4]["type"], "ssh_brute_force")

    def test_level10_non_auth_becomes_wazuh_alert(self):
        alert = cb.observe_wazuh(
            wazuh_alert("198.51.100.23", level=10, rule_id="5712",
                        groups=["syslog", "sshd", "attacks"],
                        description="SSHD brute force attack"),
            1000, cb.Detector(), 10)
        self.assertEqual(alert["type"], "wazuh_alert")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["rule_id"], "5712")
        self.assertIn("5712", alert["detail"])

    def test_level7_below_default_min_level(self):
        alert = wazuh_alert("198.51.100.23", level=7, rule_id="533",
                            groups=["syslog"],
                            description="Listened ports status changed")
        self.assertIsNone(cb.observe_wazuh(alert, 1000, cb.Detector(), 10))

    def test_level7_incident_at_min_level_7(self):
        alert = cb.observe_wazuh(
            wazuh_alert("198.51.100.23", level=7, rule_id="533",
                        groups=["syslog"],
                        description="Listened ports status changed"),
            1000, cb.Detector(), 7)
        self.assertEqual(alert["type"], "wazuh_alert")
        self.assertEqual(alert["severity"], "MEDIUM")

    def test_level13_maps_to_critical(self):
        alert = cb.observe_wazuh(
            wazuh_alert("198.51.100.23", level=13, rule_id="999",
                        groups=["syslog"], description="Severe attack"),
            1000, cb.Detector(), 10)
        self.assertEqual(alert["severity"], "CRITICAL")

    def test_auth_success_after_flag_is_critical(self):
        det = cb.Detector()
        for i in range(5):
            cb.observe_wazuh(
                wazuh_alert("9.9.9.9", groups=self.AUTH_GROUPS),
                1000 + i, det, 10)
        alert = cb.observe_wazuh(
            wazuh_alert("9.9.9.9", level=3, rule_id="5715",
                        groups=["syslog", "sshd", "authentication_success"],
                        description="sshd: authentication success"),
            1010, det, 10)
        self.assertEqual(alert["type"], "login_after_brute_force")
        self.assertEqual(alert["severity"], "CRITICAL")

    def test_non_dict_alert_returns_none(self):
        self.assertIsNone(cb.observe_wazuh("not a dict", 1000,
                                           cb.Detector(), 10))

    def test_malformed_json_lines_skipped_in_demo(self):
        lines = ["{this line is not JSON}"]
        for i in range(5):
            alert = wazuh_alert("198.51.100.23", groups=self.AUTH_GROUPS)
            alert["timestamp"] = "2026-10-30T02:10:%02d.000+0000" % (i * 10)
            lines.append(json.dumps(alert))
        lines.append("{also broken")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "alerts.jsonl")
            incidents = os.path.join(tmp, "incidents.jsonl")
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            stats = {"lines": 0, "alerts": 0, "skipped": 0}
            with contextlib.redirect_stdout(io.StringIO()):
                cb.run_wazuh_demo(path, cb.Detector(), cb.Beeper(enabled=False),
                                  incidents, stats, 10)
            self.assertEqual(stats["lines"], 7)
            self.assertEqual(stats["skipped"], 2)
            self.assertEqual(stats["alerts"], 1)
            with open(incidents) as f:
                records = [json.loads(line) for line in f]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["type"], "ssh_brute_force")


class TestDashboard(unittest.TestCase):
    def test_render_contains_incident_and_ip_table(self):
        incidents = [{"timestamp": "2026-10-30 02:00:44", "epoch": 1000.0,
                      "type": "ssh_brute_force", "severity": "HIGH",
                      "ip": "203.0.113.45", "count": 5,
                      "window_seconds": 300}]
        snap = {"203.0.113.45": {"failures_in_window": 5, "flagged": True}}
        page = cb._render_page("auth.log", {"lines": 11, "alerts": 1},
                               snap, incidents)
        self.assertIn("ssh_brute_force", page)
        self.assertIn("203.0.113.45", page)
        self.assertIn("HIGH", page)
        self.assertNotIn("No incidents yet", page)

    def test_render_empty_state(self):
        page = cb._render_page("auth.log", {"lines": 0, "alerts": 0}, {}, [])
        self.assertIn("No incidents yet", page)
        self.assertIn("No failed logins seen yet", page)

    def test_render_escapes_html(self):
        incidents = [{"timestamp": "2026-10-30 02:00:44", "epoch": 1000.0,
                      "type": "wazuh_alert", "severity": "HIGH",
                      "ip": "198.51.100.23",
                      "detail": "<script>alert(1)</script>"}]
        page = cb._render_page("alerts.json", {"lines": 1, "alerts": 1},
                               {}, incidents)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)


if __name__ == "__main__":
    unittest.main()
