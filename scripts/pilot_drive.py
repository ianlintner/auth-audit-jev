#!/usr/bin/env python3
"""Drive and measure the running loopback pilot (synthetic events only).

Usage: python3 scripts/pilot_drive.py [--n 20] [--burst 60] [--out evaluation/pilot-run.json]
Reads the admin token from ~/.config/auth-audit-jev/admin.token; never prints it.
Phases: sequential latency, burst/queue pressure, privacy leak scan, kill-switch rollback.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

CFG = Path.home() / ".config/auth-audit-jev"
BASE = "http://127.0.0.1:4021"
CANARIES = ("CANARY_USER_7f3a", "CANARY_CLIENT_7f3a", "CANARY_IP_7f3a",
            "CANARY_TOKEN_7f3a", "CANARY_ERROR_7f3a", "CANARY_TRACE_7f3a")
EXPECTED = {"authn_failure": "deny", "authz_denial": "deny", "authn_success": "allow", "authz_allow": "allow"}


def call(method, path, token):
    req = urllib.request.Request(BASE + path, method=method, headers={"Authorization": "Bearer " + token})
    started = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read().decode()
    return json.loads(body) if body.startswith("{") else body, time.monotonic() - started


def pct(values, q):
    values = sorted(values)
    return values[max(1, -(-len(values) * q // 100)) - 1] if values else None


def stats(values):
    return {"n": len(values), "p50": pct(values, 50), "p95": pct(values, 95), "p99": pct(values, 99),
            "max": max(values) if values else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--burst", type=int, default=60)
    ap.add_argument("--out", default="evaluation/pilot-run.json")
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--cfg", default=str(CFG))
    ap.add_argument("--unit", default="auth-audit-jev-pilot")
    ap.add_argument("--state-dir", default=str(Path.home() / ".local/state/auth-audit-jev"))
    args = ap.parse_args()
    globals()["BASE"] = args.base
    admin = (Path(args.cfg) / "admin.token").read_text().strip()
    out = {"mode": "synthetic-only, advisory shadow, no enforcement", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    start_state, _ = call("GET", "/pilot/state", admin)
    out["start_live_calls"] = start_state["live_calls"]

    # 1. Sequential: exact event-to-result/alert and decisions unchanged.
    decisions_ok, per = True, {}
    for scenario in ("authn_failure", "authz_denial"):
        for _ in range(args.n):
            r, _ = call("POST", f"/pilot/synthetic?scenario={scenario}&sync=1", admin)
            decisions_ok &= r["decision"] == EXPECTED[scenario]
            per.setdefault(scenario, {"alerts": 0, "n": 0})
            per[scenario]["n"] += 1
            per[scenario]["alerts"] += bool(r.get("alerted"))
    for scenario in ("authn_success", "authz_allow"):
        r, _ = call("POST", f"/pilot/synthetic?scenario={scenario}&sync=1", admin)
        decisions_ok &= r["decision"] == EXPECTED[scenario]
    state, _ = call("GET", "/pilot/state", admin)
    out["sequential"] = {"per_scenario": per, "decisions_match_expected": decisions_ok,
                         "jev_call_seconds": stats(state["samples"]["jev_call"]),
                         "event_to_result_seconds": stats(state["samples"]["event_to_result"]),
                         "event_to_alert_seconds": stats(state["samples"]["event_to_alert"]),
                         "results": state["results"]}

    # 2. Burst: callers must not wait on Jev; overflow must be counted, not blocked.
    before = state["results"]
    caller = []
    for i in range(args.burst):
        r, took = call("POST", "/pilot/synthetic?scenario=" + ("authn_failure" if i % 2 else "authz_denial"), admin)
        decisions_ok &= r["decision"] == "deny"
        caller.append(took)
    time.sleep(12)  # drain / expire
    after, _ = call("GET", "/pilot/state", admin)
    delta = {k: after["results"].get(k, 0) - before.get(k, 0) for k in set(after["results"]) | set(before)}
    out["burst"] = {"events": args.burst, "caller_response_seconds": stats(caller),
                    "result_delta": {k: v for k, v in sorted(delta.items()) if v},
                    "decisions_unchanged": decisions_ok}

    # 3. Privacy leak scan over every observable surface.
    surfaces = {"metrics": call("GET", "/metrics", admin)[0], "state": json.dumps(after)}
    alerts_file = Path(args.state_dir) / "alerts.jsonl"
    surfaces["alerts_file"] = alerts_file.read_text() if alerts_file.exists() else ""
    surfaces["journal"] = subprocess.run(["journalctl", "--user", "-u", args.unit, "--no-pager"],
                                         capture_output=True, text=True).stdout
    hits = {name: [c for c in CANARIES if c in text] for name, text in surfaces.items()}
    out["privacy"] = {"surfaces_scanned": sorted(surfaces), "canary_hits": {k: v for k, v in hits.items() if v},
                      "canary_leaks_blocked_in_transport": after["canary_leaks"],
                      "pass": not any(hits.values()) and after["canary_leaks"] == 0}

    # 4. Rollback: kill switch detaches the plugin, further events make zero provider calls.
    calls_before = after["live_calls"]
    killed, took_kill = call("POST", "/pilot/kill", admin)
    r, _ = call("POST", "/pilot/synthetic?scenario=authn_failure&sync=1", admin)
    time.sleep(1)
    st, _ = call("GET", "/pilot/state", admin)
    out["rollback"] = {"kill_response": killed, "kill_seconds": took_kill, "plugins_on_bus": st["plugins_on_bus"],
                       "decision_while_killed": r["decision"], "provider_calls_after_kill": st["live_calls"] - calls_before}
    resumed, _ = call("POST", "/pilot/resume", admin)
    out["rollback"]["resume_response"] = resumed
    out["end_live_calls"] = call("GET", "/pilot/state", admin)[0]["live_calls"]
    out["verdict"] = {"decisions_unchanged": decisions_ok and r["decision"] == "deny",
                      "privacy_pass": out["privacy"]["pass"],
                      "kill_switch_ok": st["plugins_on_bus"] == [] and out["rollback"]["provider_calls_after_kill"] == 0}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if all(out["verdict"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
