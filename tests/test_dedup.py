"""Tests for the bounded, local-only, per-tenant dedup layer."""

import threading
import unittest

from auth_audit_jev import (DECISION_EVALUATE, DECISION_SUPPRESS, DEDUP_COUNTERS,
                            DedupLayer)


def _signal(**overrides):
    signal = {
        "protocol": "oidc",
        "flow": "authorization_code",
        "failure_reason": "invalid_credentials",
        "client_config_category": "none",
        "authz_denial_category": None,
        "outcome": "failure",
        # Escalation-bearing fields are part of equivalence; the schema supplies
        # defaults so a normalized signal always carries them.
        "repeat_pattern": "not_repeated",
        "count_bucket": "1",
        "window_bucket": "under-1m",
    }
    signal.update(overrides)
    return signal


def _ctx(**parts):
    return {k: v for k, v in parts.items() if v is not None}


class DedupBasics(unittest.TestCase):
    def test_first_observation_is_evaluated_then_exact_repeat_suppressed(self):
        layer = DedupLayer()
        signal = _signal()
        ctx = _ctx(principal="alice", client="web")
        self.assertEqual(layer.decide(signal, tenant="t1", context=ctx, now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.decide(signal, tenant="t1", context=ctx, now=1.0),
                         DECISION_SUPPRESS)

    def test_changed_structured_reason_is_evaluated_not_suppressed(self):
        layer = DedupLayer()
        ctx = _ctx(principal="alice", client="web")
        layer.decide(_signal(failure_reason="invalid_credentials"),
                     tenant="t1", context=ctx, now=0.0)
        # A meaningful change in the reviewed reason must be re-assessed.
        self.assertEqual(
            layer.decide(_signal(failure_reason="account_locked"),
                         tenant="t1", context=ctx, now=1.0),
            DECISION_EVALUATE)

    def test_changed_scope_is_evaluated_not_suppressed(self):
        layer = DedupLayer()
        layer.decide(_signal(), tenant="t1", context=_ctx(principal="alice"), now=0.0)
        # A different principal under the same tenant and structured reason is
        # a different producer scope and must not be absorbed.
        self.assertEqual(
            layer.decide(_signal(), tenant="t1", context=_ctx(principal="bob"), now=1.0),
            DECISION_EVALUATE)

    def test_escalation_is_evaluated_not_suppressed(self):
        # A changed count_bucket / repeat_pattern / window_bucket encodes an
        # escalation (crossed threshold, burst, distributed pattern) and must
        # force a fresh assessment — never be suppressed as an exact repeat.
        layer = DedupLayer()
        ctx = _ctx(principal="alice", client="web")
        layer.decide(_signal(), tenant="t1", context=ctx, now=0.0)  # evaluate

        self.assertEqual(
            layer.decide(_signal(count_bucket="over-100"), tenant="t1",
                         context=ctx, now=1.0),
            DECISION_EVALUATE)
        self.assertEqual(
            layer.decide(_signal(repeat_pattern="repeated_same_principal_burst",
                                 count_bucket="over-100"), tenant="t1",
                         context=ctx, now=2.0),
            DECISION_EVALUATE)
        self.assertEqual(
            layer.decide(_signal(repeat_pattern="distributed_many_principals",
                                 count_bucket="over-100", window_bucket="5-60m"),
                         tenant="t1", context=ctx, now=3.0),
            DECISION_EVALUATE)
        self.assertEqual(layer.counters()["suppressed"], 0)


class DedupTenantIsolation(unittest.TestCase):
    def test_same_signal_across_tenants_never_collides(self):
        layer = DedupLayer()
        ctx = _ctx(principal="alice")
        signal = _signal()
        self.assertEqual(layer.decide(signal, tenant="a", context=ctx, now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.decide(signal, tenant="b", context=ctx, now=0.1),
                         DECISION_EVALUATE)

    def test_missing_tenant_abstains(self):
        layer = DedupLayer()
        signal = _signal()
        ctx = _ctx(principal="alice")
        self.assertEqual(layer.decide(signal, tenant="", context=ctx, now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.counters()["abstain_from_dedup"], 1)


class DedupAbstention(unittest.TestCase):
    def test_credential_reason_without_scope_abstains(self):
        # invalid_credentials is scope-needing; without a principal/client
        # fingerprint we must not merge unrelated principals.
        layer = DedupLayer()
        signal = _signal(failure_reason="invalid_credentials")
        for i in range(3):
            self.assertEqual(layer.decide(signal, tenant="t", context=None, now=float(i)),
                             DECISION_EVALUATE)
        self.assertGreaterEqual(layer.counters()["abstain_from_dedup"], 3)
        self.assertEqual(layer.counters()["suppressed"], 0)

    def test_credential_reason_with_client_only_abstains(self):
        # One OAuth client can serve unrelated principals. A client-only
        # fingerprint must not hide the second principal's failed login.
        layer = DedupLayer()
        ctx = _ctx(client="shared-web")
        self.assertEqual(layer.decide(_signal(), tenant="t", context=ctx, now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.decide(_signal(), tenant="t", context=ctx, now=1.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.counters()["abstain_from_dedup"], 2)

    def test_noncredential_client_only_or_empty_principal_abstains(self):
        layer = DedupLayer()
        signal = _signal(failure_reason="invalid_token")
        for ctx in (_ctx(client="shared-web"), _ctx(principal="", client="shared-web")):
            self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=0),
                             DECISION_EVALUATE)
            self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=1),
                             DECISION_EVALUATE)
        self.assertEqual(layer.counters()["abstain_from_dedup"], 4)

    def test_registry_key_does_not_hold_raw_tenant(self):
        layer = DedupLayer()
        layer.decide(_signal(), tenant="PRIVATE_TENANT", context=_ctx(principal="alice"))
        self.assertNotIn("PRIVATE_TENANT", repr(layer._registry))

    def test_scope_delimiter_injection_cannot_merge_principals(self):
        layer = DedupLayer()
        first = _ctx(principal="alice\x1fclient=bob")
        second = _ctx(principal="alice", client="bob")
        self.assertEqual(layer.decide(_signal(), tenant="t", context=first, now=0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.decide(_signal(), tenant="t", context=second, now=1),
                         DECISION_EVALUATE)

    def test_client_reason_without_client_scope_abstains(self):
        # A category is not a client ID; many unrelated clients share it.
        layer = DedupLayer()
        signal = _signal(failure_reason="other", client_config_category="unregistered_client")
        self.assertEqual(layer.decide(signal, tenant="t", context=None, now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.decide(signal, tenant="t", context=None, now=1.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.counters()["abstain_from_dedup"], 2)

    def test_unreviewed_reason_abstains_without_retaining_free_text(self):
        layer = DedupLayer()
        signal = _signal(failure_reason="private-user-identifier")
        self.assertEqual(layer.decide(signal, tenant="t", context=_ctx(principal="alice")),
                         DECISION_EVALUATE)
        self.assertEqual(layer.size, 0)
        self.assertNotIn("private-user-identifier", repr(layer._registry))

    def test_missing_structured_field_abstains(self):
        layer = DedupLayer()
        signal = _signal()
        del signal["flow"]
        self.assertEqual(layer.decide(signal, tenant="t",
                                      context=_ctx(principal="alice"), now=0.0),
                         DECISION_EVALUATE)
        self.assertEqual(layer.counters()["abstain_from_dedup"], 1)


class DedupBounds(unittest.TestCase):
    def test_capacity_evicts_oldest_and_counts(self):
        layer = DedupLayer(capacity=2)
        for principal in ("a", "b", "c"):
            layer.decide(_signal(), tenant="t", context=_ctx(principal=principal), now=0.0)
        self.assertEqual(layer.size, 2)
        self.assertGreaterEqual(layer.counters()["evicted"], 1)
        self.assertGreaterEqual(layer.counters()["potential_missed_signal"], 1)

    def test_extreme_signal_does_not_raise_or_block(self):
        # A hostile envelope (huge strings, weird types) must degrade to
        # evaluate/abstain, never throw or hang.
        layer = DedupLayer()
        signal = _signal()
        signal["failure_reason"] = ("x" * 1_000_000)  # not in closed enum
        self.assertEqual(layer.decide(signal, tenant="t", now=0.0), DECISION_EVALUATE)

    def test_oversized_scope_ingredient_is_dropped(self):
        layer = DedupLayer(max_scope_bytes=8)
        ctx = _ctx(principal="a" * 500)  # over the byte ceiling
        # principal ingredient dropped -> no fingerprint -> scope-needing reason
        # -> abstain (evaluate), never a crash.
        self.assertEqual(layer.decide(_signal(), tenant="t", context=ctx, now=0.0),
                         DECISION_EVALUATE)

    def test_malformed_context_type_abstains(self):
        layer = DedupLayer()
        self.assertEqual(layer.decide(_signal(), tenant="t", context="not-a-dict", now=0.0),
                         DECISION_EVALUATE)


class DedupTTL(unittest.TestCase):
    def test_entry_expires_after_ttl_without_repeat(self):
        layer = DedupLayer(ttl_seconds=10.0)
        ctx = _ctx(principal="alice")
        signal = _signal()
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=0.0),
                         DECISION_EVALUATE)
        # No repeat in between: the entry is quiescent, so it ages out and the
        # next observation is a fresh assessment.
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=11.0),
                         DECISION_EVALUATE)

    def test_continued_repetition_keeps_entry_alive_across_first_seen(self):
        # The entry must age out on *last activity*, not first_seen: a key that
        # keeps repeating within TTL must not be evicted by a frozen first_seen.
        layer = DedupLayer(ttl_seconds=10.0)
        ctx = _ctx(principal="alice")
        signal = _signal()
        layer.decide(signal, tenant="t", context=ctx, now=0.0)
        for t in (5.0, 9.0, 14.0, 19.0):
            # 9->14 is >10 since first_seen(0), but only 5 since last activity
            # (9), so it must still suppress.
            self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=t),
                             DECISION_SUPPRESS)

    def test_explicit_expire_returns_count(self):
        layer = DedupLayer(ttl_seconds=10.0)
        layer.decide(_signal(), tenant="t", context=_ctx(principal="a"), now=0.0)
        self.assertEqual(layer.expire(now=100.0), 1)
        self.assertEqual(layer.size, 0)


class DedupMilestone(unittest.TestCase):
    def test_milestone_refresh_forces_reevaluation(self):
        layer = DedupLayer(max_suppress_before_refresh=3)
        ctx = _ctx(principal="alice")
        signal = _signal()
        layer.decide(signal, tenant="t", context=ctx, now=0.0)  # evaluate
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=1.0),
                         DECISION_SUPPRESS)
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=2.0),
                         DECISION_SUPPRESS)
        # Third repeat crosses the threshold -> force a fresh assessment.
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=3.0),
                         DECISION_EVALUATE)
        self.assertGreaterEqual(layer.counters()["refreshed"], 1)


class DedupKillSwitch(unittest.TestCase):
    def test_kill_switch_forces_evaluate(self):
        layer = DedupLayer()
        ctx = _ctx(principal="alice")
        signal = _signal()
        layer.decide(signal, tenant="t", context=ctx, now=0.0)
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=1.0),
                         DECISION_SUPPRESS)
        layer.engage_kill_switch()
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=2.0),
                         DECISION_EVALUATE)
        layer.release_kill_switch()
        self.assertEqual(layer.decide(signal, tenant="t", context=ctx, now=3.0),
                         DECISION_SUPPRESS)


class DedupConcurrency(unittest.TestCase):
    def test_concurrent_decisions_do_not_raise_or_corrupt(self):
        layer = DedupLayer()
        signal = _signal()
        errors = []

        def worker(principal):
            try:
                for i in range(500):
                    layer.decide(signal, tenant="t",
                                 context=_ctx(principal=principal),
                                 now=float(i) / 1000.0)
            except Exception as exc:  # pragma: no cover - failure signal
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"p{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        # Counters must be internally consistent: observed == evaluate decisions
        # + suppressions tracked, and never negative.
        counts = layer.counters()
        self.assertGreaterEqual(counts["observed"], 8 * 500)
        for name in DEDUP_COUNTERS:
            self.assertGreaterEqual(counts[name], 0)


class DedupCounters(unittest.TestCase):
    def test_all_counter_names_are_present_and_zero_initially(self):
        layer = DedupLayer()
        self.assertEqual(set(layer.counters()), set(DEDUP_COUNTERS))
        self.assertTrue(all(v == 0 for v in layer.counters().values()))

    def test_suppressed_and_observed_advance(self):
        layer = DedupLayer()
        ctx = _ctx(principal="alice")
        signal = _signal()
        layer.decide(signal, tenant="t", context=ctx, now=0.0)
        layer.decide(signal, tenant="t", context=ctx, now=1.0)
        counts = layer.counters()
        self.assertEqual(counts["observed"], 2)
        self.assertEqual(counts["suppressed"], 1)


if __name__ == "__main__":
    unittest.main()
