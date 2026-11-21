import importlib.util
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "pilot_drive", Path(__file__).resolve().parent.parent / "scripts" / "pilot_drive.py")
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class FakePilot:
    """Minimal stand-in for the pilot control API, driven through run()'s api callable."""

    def __init__(self, state="enabled", attached=True, calls_per_event=1, alerts_file=None):
        self.state, self.attached, self.live_calls, self.per = state, attached, 0, calls_per_event
        self.log = []
        self.alerts_file = alerts_file   # when set, each alert appends a record like the real pilot

    def snapshot(self):
        return {"state": self.state, "live_calls": self.live_calls, "canary_leaks": 0,
                "results": {"alerted": self.live_calls}, "plugins_on_bus": ["audit"] if self.attached else [],
                "samples": {"jev_call": [.1], "event_to_alert": [.1], "event_to_result": [.1]}}

    def __call__(self, method, path):
        self.log.append((method, path))
        if path == "/pilot/state":
            return self.snapshot(), 0
        if path == "/metrics":
            return "auth_audit_pilot_enabled 1\n", 0
        if path == "/pilot/kill":
            self.state, self.attached = "killed", False
            return {"audit": "killed"}, 0
        if path == "/pilot/resume":
            self.state, self.attached = "enabled", True
            return {"audit": "enabled"}, 0
        scenario = path.split("scenario=")[1].split("&")[0]
        if self.attached:
            self.live_calls += self.per
            if self.alerts_file:
                with open(self.alerts_file, "a") as fh:
                    fh.write('{"scenario": "%s"}\n' % scenario)
        return {"scenario": scenario, "decision": D.EXPECTED[scenario], "alerted": self.attached}, 0


def args(**kw):
    base = dict(n=1, burst=2, state_dir=tempfile.gettempdir() + "/nonexistent-pilot-state", unit="u")
    return SimpleNamespace(**{**base, **kw})


def ok_journal(unit):
    return "clean", None


class BaseValidationTests(unittest.TestCase):
    def test_accepts_only_literal_loopback(self):
        for good in ("http://127.0.0.1:4021", "http://[::1]:4021", "http://127.0.0.2:1"):
            self.assertEqual(D.validate_base(good), good)
        for bad in ("http://example.com", "http://localhost:4021", "http://10.0.0.5:4021",
                    "https://127.0.0.1:4021", "http://127.0.0.1@evil.example", "http://u:p@127.0.0.1",
                    "ftp://127.0.0.1", "127.0.0.1:4021", "http://8.8.8.8"):
            with self.assertRaises(ValueError, msg=bad):
                D.validate_base(bad)

    def test_off_loopback_rejected_before_token_read_or_any_request(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(D.OPENER, "open") as opened, \
                mock.patch.object(Path, "read_text") as read_text:
            code = D.main(["--base", "http://203.0.113.9:4021", "--cfg", d, "--out", d + "/o.json"])
        self.assertEqual(code, 2)
        opened.assert_not_called()
        read_text.assert_not_called()

    def test_redirect_is_not_followed_and_token_not_forwarded(self):
        seen = []

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(("target", self.headers.get("Authorization")))
                self.send_response(200)
                self.end_headers()

            log_message = lambda *a: None  # noqa: E731

        target = HTTPServer(("127.0.0.1", 0), Target)

        class Redirector(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(("redirector", self.headers.get("Authorization")))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/x")
                self.end_headers()

            log_message = lambda *a: None  # noqa: E731

        redirector = HTTPServer(("127.0.0.1", 0), Redirector)
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (target, redirector)]
        for t in threads:
            t.start()
        try:
            with self.assertRaises(D.urllib.error.HTTPError) as ctx:
                D.call(f"http://127.0.0.1:{redirector.server_port}", "GET", "/pilot/state", "secret")
            self.assertEqual(ctx.exception.code, 302)
            ctx.exception.close()
        finally:
            for s in (target, redirector):
                s.shutdown()
                s.server_close()
        self.assertEqual([name for name, _ in seen], ["redirector"])


class RunVerdictTests(unittest.TestCase):
    def run_it(self, pilot, journal=ok_journal):
        return D.run(args(), pilot, journal=journal, sleep=lambda s: None)

    def test_healthy_run_passes_and_never_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            pilot = FakePilot(alerts_file=Path(d) / "alerts.jsonl")
            out, code = D.run(args(state_dir=d), pilot, journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 0, out["verdict"])
        self.assertTrue(all(out["verdict"].values()))
        self.assertNotIn(("POST", "/pilot/resume"), pilot.log)
        self.assertEqual(pilot.state, "killed")   # left for explicit operator resume
        self.assertTrue(out["rollback"]["left_killed_for_operator_resume"])

    def test_operator_kill_after_state_check_is_never_undone(self):
        class KilledDuringWait(FakePilot):
            def __call__(self, method, path):
                if path == "/pilot/kill":
                    super().__call__(method, path)
                    return {"audit": "killed"}, 0
                return super().__call__(method, path)

        pilot = KilledDuringWait()
        out, _ = self.run_it(pilot)
        # Whatever happens after the driver's own kill (including an operator kill during the
        # post-kill wait), the driver sends no resume, so the pilot cannot be re-enabled by it.
        self.assertNotIn(("POST", "/pilot/resume"), pilot.log)
        self.assertEqual(pilot.state, "killed")

    def test_empty_alerts_file_is_unavailable_when_alerts_expected(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_text("")
            out, code = D.run(args(state_dir=d), FakePilot(), journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertIn("alerts_file", out["privacy"]["surfaces_scanned"])   # readable bytes are still scanned

    def test_stale_alerts_from_prior_run_do_not_count(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_text('{"old": 1}\n{"old": 2}\n')
            out, code = D.run(args(state_dir=d), FakePilot(), journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])

    def test_disabled_start_refused_without_any_mutation(self):
        for pilot in (FakePilot(state="killed", attached=False), FakePilot(state="enabled", attached=False)):
            out, code = self.run_it(pilot)
            self.assertEqual(code, 2)
            self.assertFalse(out["verdict"]["precondition_enabled_and_attached"])
            self.assertEqual(pilot.log, [("GET", "/pilot/state")])   # no synthetic, kill or resume sent

    def test_killed_pilot_is_not_resumed(self):
        pilot = FakePilot(state="killed", attached=False)
        self.run_it(pilot)
        self.assertNotIn(("POST", "/pilot/resume"), pilot.log)
        self.assertEqual(pilot.state, "killed")

    def test_no_provider_call_during_run_fails_kill_switch_verdict(self):
        out, code = self.run_it(FakePilot(calls_per_event=0))
        self.assertEqual(code, 1)
        self.assertFalse(out["verdict"]["kill_switch_ok"])
        self.assertEqual(out["rollback"]["provider_calls_during_run"], 0)

    def test_operator_kill_mid_run_stays_killed(self):
        class KilledMidRun(FakePilot):
            def __call__(self, method, path):
                if path == "/pilot/state" and self.log and any("scenario=" in p for _, p in self.log) \
                        and self.live_calls >= 4 and self.attached:
                    self.state, self.attached = "killed", False   # operator kills during the burst drain
                return super().__call__(method, path)

        pilot = KilledMidRun()
        out, code = self.run_it(pilot)
        self.assertEqual(code, 1)
        self.assertEqual(pilot.state, "killed")
        self.assertNotIn(("POST", "/pilot/resume"), pilot.log)
        self.assertNotIn(("POST", "/pilot/kill"), pilot.log)
        self.assertTrue(out["rollback"]["skipped"])
        self.assertFalse(out["verdict"]["kill_switch_ok"])

    def test_missing_alerts_file_is_unavailable_when_alerts_expected(self):
        out, code = self.run_it(FakePilot())   # default state_dir does not exist; pilot alerted
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertNotIn("alerts_file", out["privacy"]["surfaces_scanned"])

    def test_missing_alerts_file_ok_when_no_alerts_expected(self):
        class NoAlerts(FakePilot):
            def __call__(self, method, path):
                body, t = super().__call__(method, path)
                if isinstance(body, dict) and "alerted" in body:
                    body["alerted"] = False
                if path == "/pilot/state":
                    body["results"] = {}
                return body, t

        out, code = self.run_it(NoAlerts())
        self.assertEqual(out["privacy"]["surfaces_unavailable"], [])
        self.assertTrue(out["privacy"]["pass"])

    def test_alerts_unreadable_at_startup_is_unavailable_and_run_still_rolls_back(self):
        # An existing file that cannot be read at startup must not become a zero baseline
        # (stale records would then look fresh); the run continues through rollback.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_text('{"old": 1}\n')
            real = Path.read_text

            def read_text(self, *a, **kw):
                if self.name == "alerts.jsonl":
                    raise PermissionError(13, "Permission denied", str(self))
                return real(self, *a, **kw)

            with mock.patch.object(Path, "read_text", read_text):
                out, code = D.run(args(state_dir=d), FakePilot(), journal=ok_journal, sleep=lambda s: None)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertIn("unreadable at run start", out["privacy"]["surfaces_unavailable"][0]["reason"])
        # Rollback still ran and is evaluated on its own evidence.
        self.assertNotIn("skipped", out["rollback"])
        self.assertTrue(out["verdict"]["kill_switch_ok"])
        self.assertEqual(code, 1)

    def test_alerts_unreadable_at_scan_time_is_unavailable_and_does_not_abort_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_text("")
            real = Path.read_text
            state = {"failed": False}

            def read_text(self, *a, **kw):
                # First read is the baseline (succeeds); the scan-time read fails.
                if self.name == "alerts.jsonl" and not state["failed"]:
                    state["failed"] = True
                    return real(self, *a, **kw)
                if self.name == "alerts.jsonl":
                    raise PermissionError(13, "Permission denied", str(self))
                return real(self, *a, **kw)

            with mock.patch.object(Path, "read_text", read_text):
                out, code = D.run(args(state_dir=d), FakePilot(), journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertIn("unreadable at scan time", out["privacy"]["surfaces_unavailable"][0]["reason"])
        self.assertNotIn("skipped", out["rollback"])          # reached rollback despite the read error
        self.assertTrue(out["verdict"]["kill_switch_ok"])

    def test_invalid_utf8_alerts_at_scan_time_is_unavailable_and_still_kills(self):
        class Corrupting(FakePilot):
            def __call__(self, method, path):
                if path == "/metrics":   # corrupt the file after the baseline read, before the scan
                    with open(self.alerts_file, "ab") as fh:
                        fh.write(b"\xff\xfe\n")
                return super().__call__(method, path)

        with tempfile.TemporaryDirectory() as d:
            pilot = Corrupting(alerts_file=Path(d) / "alerts.jsonl")
            out, code = D.run(args(state_dir=d), pilot, journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertIn("UnicodeDecodeError", out["privacy"]["surfaces_unavailable"][0]["reason"])
        self.assertIn(("POST", "/pilot/kill"), pilot.log)       # rollback still ran
        self.assertNotIn("skipped", out["rollback"])
        self.assertTrue(out["verdict"]["kill_switch_ok"])

    def test_invalid_utf8_alerts_at_startup_is_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_bytes(b"\xff\n")
            pilot = FakePilot(alerts_file=Path(d) / "alerts.jsonl")
            out, code = D.run(args(state_dir=d), pilot, journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertIn("unreadable at run start", out["privacy"]["surfaces_unavailable"][0]["reason"])
        self.assertIn(("POST", "/pilot/kill"), pilot.log)

    def test_canary_in_partial_alerts_file_is_reported_with_missing_records(self):
        class Partial(FakePilot):
            target = None

            def __call__(self, method, path):
                body, t = super().__call__(method, path)   # base writes nothing: alerts_file stays None
                if path.startswith("/pilot/synthetic") and self.live_calls == 1:
                    with open(self.target, "a") as fh:   # only one record, and it leaks
                        fh.write('{"user": "CANARY_USER_7f3a"}\n')
                return body, t

        with tempfile.TemporaryDirectory() as d:
            pilot = Partial()
            pilot.target = Path(d) / "alerts.jsonl"
            out, code = D.run(args(state_dir=d), pilot, journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual(out["privacy"]["canary_hits"], {"alerts_file": ["CANARY_USER_7f3a"]})
        self.assertEqual([u["surface"] for u in out["privacy"]["surfaces_unavailable"]], ["alerts_file"])
        self.assertIn("no new alert record", out["privacy"]["surfaces_unavailable"][0]["reason"])
        self.assertIn("alerts_file", out["privacy"]["surfaces_scanned"])

    def test_nonzero_starting_alert_count_unchanged_passes(self):
        # Pre-existing alerts from an earlier run must not require this run's file to grow.
        class PriorAlerts(FakePilot):
            def snapshot(self):
                snap = super().snapshot()
                snap["results"] = {"alerted": 5}   # cumulative counter; this run adds nothing
                return snap

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "alerts.jsonl").write_text("".join('{"old": %d}\n' % i for i in range(5)))
            out, code = D.run(args(state_dir=d), PriorAlerts(), journal=ok_journal, sleep=lambda s: None)
        self.assertEqual(code, 0, out["verdict"])
        self.assertTrue(out["privacy"]["pass"])
        self.assertEqual(out["privacy"]["surfaces_unavailable"], [])
        self.assertIn("alerts_file", out["privacy"]["surfaces_scanned"])

    def test_journal_read_failure_is_unavailable_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            out, code = D.run(args(state_dir=d), FakePilot(alerts_file=Path(d) / "alerts.jsonl"), sleep=lambda s: None,
                              journal=lambda unit: ("", "journalctl exited 1"))
        self.assertEqual(code, 1)
        self.assertFalse(out["privacy"]["pass"])
        self.assertEqual(out["privacy"]["surfaces_unavailable"], [{"surface": "journal", "reason": "journalctl exited 1"}])
        self.assertNotIn("journal", out["privacy"]["surfaces_scanned"])
        self.assertEqual(out["privacy"]["canary_hits"], {})

    def test_read_journal_checks_exit_status(self):
        failed = SimpleNamespace(returncode=1, stdout="", stderr="no access")
        with mock.patch.object(D.subprocess, "run", return_value=failed):
            self.assertEqual(D.read_journal("u"), ("", "journalctl exited 1"))
        with mock.patch.object(D.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIn("unavailable", D.read_journal("u")[1])
        good = SimpleNamespace(returncode=0, stdout="text", stderr="")
        with mock.patch.object(D.subprocess, "run", return_value=good):
            self.assertEqual(D.read_journal("u"), ("text", None))


if __name__ == "__main__":
    unittest.main()
