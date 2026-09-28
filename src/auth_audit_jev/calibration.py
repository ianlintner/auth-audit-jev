"""Offline calibration helpers.

Calibration in this repository runs on **synthetic labeled fixtures only**. It
answers "does the advisory layer separate the labeled classes in a controlled
fixture set", which is a behaviour check, not a claim about real traffic
precision or recall. Every per-category number with a support of zero is
reported as None rather than 0 or 1, so an empty class cannot masquerade as a
perfect score.
"""
from __future__ import annotations

CATEGORIES = ("user_error", "client_misconfiguration", "suspected_abuse", "ambiguous", "other")


def per_category_metrics(labeled):
    """Per-category precision/recall/support from `(expected, predicted)` pairs.

    A `None` prediction means abstain. Abstentions lower recall and are counted
    separately so a conservative classifier is not silently rewarded for
    refusing to answer.
    """
    labeled = list(labeled)
    report = {"total": len(labeled), "abstained": 0, "categories": {}}
    for expected, predicted in labeled:
        if predicted is None:
            report["abstained"] += 1
    for category in CATEGORIES:
        support = sum(1 for expected, _ in labeled if expected == category)
        predicted_count = sum(1 for _, predicted in labeled if predicted == category)
        true_positive = sum(1 for expected, predicted in labeled
                            if expected == category and predicted == category)
        report["categories"][category] = {
            "support": support,
            "predicted": predicted_count,
            "true_positive": true_positive,
            "precision": None if predicted_count == 0 else true_positive / predicted_count,
            "recall": None if support == 0 else true_positive / support,
        }
    return report


def agreement(labeled):
    """Fraction of non-abstained predictions that match the expected label."""
    considered = [(e, p) for e, p in labeled if p is not None]
    if not considered:
        return None
    return sum(1 for e, p in considered if e == p) / len(considered)
