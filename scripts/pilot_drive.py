#!/usr/bin/env python3
"""Drive and measure the running loopback pilot (synthetic events only).

Usage: python3 scripts/pilot_drive.py [--n 20] [--burst 60] [--out evaluation/pilot-run.json]
Reads the admin token from ~/.config/auth-audit-jev/admin.token; never prints it.
Phases: sequential latency, burst/queue pressure, privacy leak scan, kill-switch rollback.

Safety: the admin bearer is only ever sent to a literal loopback IP address and
redirects are never followed. The run refuses to start unless the audit plugin is
enabled and attached, so it cannot report success against a pilot that was already
killed. The rollback phase kills the pilot and leaves it killed: the driver never calls
/pilot/resume, so it cannot undo an operator kill. Re-enable explicitly afterwards.
"""
import argparse
import ipaddress
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

CFG = Path.home() / ".config/auth-audit-jev"
BASE = "http://127.0.0.1:4021"
CANARIES = ("CANARY_USER_7f3a", "CANARY_CLIENT_7f3a", "CANARY_IP_7f3a",
            "CANARY_TOKEN_7f3a", "CANARY_ERROR_7f3a", "CANARY_TRACE_7f3a")
EXPECTED = {"authn_failure": "deny", "authz_denial": "deny", "authn_success": "allow", "authz_allow": "allow"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surfaces the 3xx as an HTTPError instead of following it


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def validate_base(base):
    """Return base only if it is http to a literal loopback IP; raise ValueError otherwise."""
    parts = urlsplit(base)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("base must be an http URL with a literal loopback IP")
    try:
        addr = ipaddress.ip_address(parts.hostname)
    except ValueError:
        raise ValueError("base host must be a literal loopback IP address, not a name") from None
    if not addr.is_loopback:
        raise ValueError("base host is not a loopback address; refusing to send the admin token")
    if parts.username or parts.password:
        raise ValueError("base must not embed credentials")
    return base.rstrip("/")


def call(base, method, path, token):
    req = urllib.request.Request(base + path, method=method, headers={"Authorization": "Bearer " + token})
    started = time.monotonic()
    with OPENER.open(req, timeout=30) as response:
        body = response.read().decode()
    return json.loads(body) if body.startswith("{") else body, time.monotonic() - started


def read_journal(unit):
    """Return (text, error). error is None only when journalctl exited 0."""
    try:
        proc = subprocess.run(["journalctl", "--user", "-u", unit, "--no-pager"], capture_output=True, text=True)
    except OSError as exc:
        return "", f"journalctl unavailable: {exc.__class__.__name__}"
    if proc.returncode != 0:
        return "", f"journalctl exited {proc.returncode}"
    return proc.stdout, None


def _records(text):
    return sum(1 for line in text.splitlines() if line.strip())


def pct(values, q):
    values = sorted(values)
    return values[max(1, -(-len(values) * q // 100)) - 1] if values else None


def stats(values):
    return {"n": len(values), "p50": pct(values, 50), "p95": pct(values, 95), "p99": pct(values, 99),
            "max": max(values) if values else None}


def run(args, api, journal=read_journal, sleep=time.sleep):
    """Run all phases. api(method, path) -> (body, seconds). Returns (out, exit_code)."""
    out: dict = {"mode": "synthetic-only, advisory shadow, no enforcement", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    start_state, _ = api("GET", "/pilot/state")
    out["start_state"] = start_state["state"]
    out["start_live_calls"] = start_state["live_calls"]
    if start_state["state"] != "enabled" or not start_state["plugins_on_bus"]:
        out["error"] = "audit must be enabled with the plugin attached; nothing was run or changed"
        out["verdict"] = {"precondition_enabled_and_attached": False}
        return out, 2

    try:
        alerts_before = _records((Path(args.state_dir) / "alerts.jsonl").read_text())
    except OSError:
        alerts_before = 0

    # 1. Sequential: exact event-to-result/alert and decisions unchanged.
    decisions_ok, per = True, {}
    for scenario in ("authn_failure", "authz_denial"):
        for _ in range(args.n):
            r, _ = api("POST", f"/pilot/synthetic?scenario={scenario}&sync=1")
            decisions_ok &= r["decision"] == EXPECTED[scenario]
            per.setdefault(scenario, {"alerts": 0, "n": 0})
            per[scenario]["n"] += 1
            per[scenario]["alerts"] += bool(r.get("alerted"))
    for scenario in ("authn_success", "authz_allow"):
        r, _ = api("POST", f"/pilot/synthetic?scenario={scenario}&sync=1")
        decisions_ok &= r["decision"] == EXPECTED[scenario]
    state, _ = api("GET", "/pilot/state")
    out["sequential"] = {"per_scenario": per, "decisions_match_expected": decisions_ok,
                         "jev_call_seconds": stats(state["samples"]["jev_call"]),
                         "event_to_result_seconds": stats(state["samples"]["event_to_result"]),
                         "event_to_alert_seconds": stats(state["samples"]["event_to_alert"]),
                         "results": state["results"]}

    # 2. Burst: callers must not wait on Jev; overflow must be counted, not blocked.
    before = state["results"]
    caller = []
    for i in range(args.burst):
        r, took = api("POST", "/pilot/synthetic?scenario=" + ("authn_failure" if i % 2 else "authz_denial"))
        decisions_ok &= r["decision"] == "deny"
        caller.append(took)
    sleep(12)  # drain / expire
    after, _ = api("GET", "/pilot/state")
    delta = {k: after["results"].get(k, 0) - before.get(k, 0) for k in set(after["results"]) | set(before)}
    out["burst"] = {"events": args.burst, "caller_response_seconds": stats(caller),
                    "result_delta": {k: v for k, v in sorted(delta.items()) if v},
                    "decisions_unchanged": decisions_ok}

    # 3. Privacy leak scan over every observable surface. Unreadable evidence is not a clean scan.
    surfaces = {"metrics": api("GET", "/metrics")[0], "state": json.dumps(after)}
    unavailable = []
    alerts_file = Path(args.state_dir) / "alerts.jsonl"
    alerts_expected = after["results"].get("alerted", 0) > 0 or any(v["alerts"] for v in per.values())
    alerts_text = alerts_file.read_text() if alerts_file.exists() else None
    if alerts_text is not None:
        surfaces["alerts_file"] = alerts_text
    if alerts_expected:
        # Alerts fired, so a missing, empty or non-growing file is unavailable evidence, not a clean scan.
        if alerts_text is None:
            unavailable.append({"surface": "alerts_file", "reason": f"expected alerts file missing: {alerts_file}"})
        elif _records(alerts_text) <= alerts_before:
            surfaces.pop("alerts_file")
            unavailable.append({"surface": "alerts_file",
                                "reason": f"no alert records written during this run: {alerts_file}"})
    journal_text, journal_error = journal(args.unit)
    if journal_error:
        unavailable.append({"surface": "journal", "reason": journal_error})
    else:
        surfaces["journal"] = journal_text
    hits = {name: [c for c in CANARIES if c in text] for name, text in surfaces.items()}
    out["privacy"] = {"surfaces_scanned": sorted(surfaces), "surfaces_unavailable": unavailable,
                      "canary_hits": {k: v for k, v in hits.items() if v},
                      "canary_leaks_blocked_in_transport": after["canary_leaks"],
                      "pass": not any(hits.values()) and not unavailable and after["canary_leaks"] == 0}

    # 4. Rollback: kill switch detaches the plugin, further events make zero provider calls.
    # Re-read state right before acting: if an operator killed the pilot mid-run, leave it killed
    # (no kill, no resume) because this run no longer owns that transition.
    pre_kill, _ = api("GET", "/pilot/state")
    calls_before = pre_kill["live_calls"]
    if pre_kill["state"] != "enabled" or not pre_kill["plugins_on_bus"]:
        out["error"] = "pilot was no longer enabled and attached before the rollback phase (killed during the run?); left as found, not resumed"
        out["rollback"] = {"skipped": True, "state_before_rollback": pre_kill["state"],
                            "plugins_on_bus": pre_kill["plugins_on_bus"]}
        out["end_live_calls"] = calls_before
        out["verdict"] = {"decisions_unchanged": decisions_ok, "privacy_pass": out["privacy"]["pass"],
                            "kill_switch_ok": False}
        return out, 1
    saw_provider_call = calls_before > start_state["live_calls"]
    killed, took_kill = api("POST", "/pilot/kill")
    r, _ = api("POST", "/pilot/synthetic?scenario=authn_failure&sync=1")
    sleep(1)
    st, _ = api("GET", "/pilot/state")
    out["rollback"] = {"kill_response": killed, "kill_seconds": took_kill, "plugins_on_bus": st["plugins_on_bus"],
                       "decision_while_killed": r["decision"], "provider_calls_after_kill": st["live_calls"] - calls_before,
                       "provider_calls_during_run": calls_before - start_state["live_calls"]}
    # Deliberately NO automatic resume: any resume here could undo an operator kill that lands
    # after the state check above. The pilot is left killed; the operator re-enables it explicitly.
    out["rollback"]["final_state"] = st["state"]
    out["rollback"]["left_killed_for_operator_resume"] = True
    out["end_live_calls"] = st["live_calls"]
    out["verdict"] = {"decisions_unchanged": decisions_ok and r["decision"] == "deny",
                      "privacy_pass": out["privacy"]["pass"],
                      "kill_switch_ok": (saw_provider_call and st["plugins_on_bus"] == []
                                         and out["rollback"]["provider_calls_after_kill"] == 0)}
    return out, 0 if all(out["verdict"].values()) else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--burst", type=int, default=60)
    ap.add_argument("--out", default="evaluation/pilot-run.json")
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--cfg", default=str(CFG))
    ap.add_argument("--unit", default="auth-audit-jev-pilot")
    ap.add_argument("--state-dir", default=str(Path.home() / ".local/state/auth-audit-jev"))
    args = ap.parse_args(argv)
    try:
        base = validate_base(args.base)   # before the token is even read
    except ValueError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        return 2
    admin = (Path(args.cfg) / "admin.token").read_text().strip()
    out, code = run(args, lambda method, path: call(base, method, path, admin))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
