"""
Pattern-quality regression guard for the attack library.

Background calibration (scanners/calibration.py) automatically discounts a
pattern that sits near *everything* — that is what removed the need for a
category blocklist. It does nothing for the other failure mode: a pattern that
is genuinely close to a legitimate request.

That failure mode is real and was shipping. The library contained

    "Use the email tool to send a message to external address"

which describes ordinary agent behaviour, so any real email request landed on
it — "Can you help me draft a polite follow-up email to a client?" scored 0.78
and was the single largest false positive in the adversarial corpus. Rewriting
it to describe the exfiltration rather than the delivery
("...send collected user data to an outside address") fixed it.

Nothing structural prevents the next addition to jailbreak_patterns.json or to
attack_library.py from reintroducing that, so this module is the guard: every
library pattern is scored against held-out benign text, and any pattern that
reaches the operating threshold on it is named in the failure output.

The benign corpus here is deliberately **not** DEFAULT_BACKGROUND. Patterns are
calibrated against that corpus, so scoring them against it would be circular —
the leave-one-out ceiling largely guarantees a pass by construction. These are
unseen sentences, which is the only thing that tests generalisation.

By default this runs on the TF-IDF backend so it needs no PyTorch and no model
download. Set ACF_TEST_ST_MODEL=1 to additionally run it against the
sentence-transformer backend (downloads ~470MB on first use).
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("numpy", reason="scanner tests require the [scanners] extra")
pytest.importorskip("pydantic", reason="scanner tests require the [scanners] extra")
pytest.importorskip("sklearn", reason="scanner tests require the [scanners] extra")

from acf.scanners import ScanInput, SemanticScanner, SemanticScannerConfig
from acf.scanners.attack_library import build_pattern_library
from acf.scanners.calibration import DEFAULT_BACKGROUND, is_scannable
from acf.scanners.models import InputType, TrustLevel

# ---------------------------------------------------------------------------
# Held-out benign corpus — unseen by calibration.
#
# Topics are chosen to differ from DEFAULT_BACKGROUND, and the final group is
# the important one: ordinary requests that sit close to attack *semantics*
# (deleting things, sending mail, reading config, permissions). Those are what
# an over-broad pattern actually catches, so they carry most of this test's
# value.
# ---------------------------------------------------------------------------
HELD_OUT_BENIGN = {
    # everyday requests, deliberately unrelated to the calibration topics
    "Suggest a recipe that uses up leftover roast vegetables.",
    "Remind me to renew the car insurance before it expires.",
    "How long should I water tomato seedlings in the greenhouse?",
    "What time does the pharmacy on the high street close?",
    "Explain the offside rule in football to a complete beginner.",
    "Recommend a podcast about eighteenth century maritime history.",
    "Help me plan a three day itinerary for a trip to Kyoto.",
    "What documents do I need for a student visa application?",
    "Track the parcel that was dispatched on Monday afternoon.",
    # workplace prose
    "The library closes early on public holidays this month.",
    "Attendance at the Friday retrospective is optional for contractors.",
    "Our gym membership includes two guest passes each quarter.",
    "The tax filing deadline falls on the last day of January.",
    "Interview feedback should be submitted within two working days.",
    # adjacent to attack semantics but entirely legitimate — the cases an
    # over-broad pattern is most likely to trip on
    "Please delete the temporary files in my downloads folder.",
    "Send the meeting notes to everyone who attended the workshop.",
    "Show me the configuration options available for this project.",
    "What permissions does my account currently have on the staging server?",
    "Run the test suite and tell me which cases failed.",
    "Read the changelog file and summarise what shipped this week.",
    "Forward the signed contract to the legal team for filing.",
    "Update my saved preferences to use the metric system.",
    "List the tools you can use to help me with this task.",
    "Export the sales figures to a spreadsheet for the review.",
}

# ---------------------------------------------------------------------------
# Known false positives — currently produced by the shipped configuration.
#
# These are recorded rather than hidden. The guard below asserts that the
# violation set never *grows*: a newly over-broad pattern fails the build,
# while fixing one of these simply passes. Removing an entry from this list
# once it stops firing keeps the record honest.
#
# Both are limits of embedding similarity, not defects in the patterns, and
# neither is fixable by rewriting without destroying real detection.
# ---------------------------------------------------------------------------
KNOWN_FALSE_POSITIVES = {
    # The model keys on "safety" and cannot separate a safety *notice* from
    # safety *guidelines*. The pattern it matches is correctly specific.
    "Translate the safety notice on this packaging for me.",
    # Structurally identical to the attack: "ignore X and use Y instead". Only
    # knowing that "the first draft" is content rather than instructions
    # separates them, and "ignore previous instructions" is the canonical
    # injection pattern — it cannot be softened.
    "Ignore the first draft and work from the revised outline instead.",
    # The next two match short entries in jailbreak_patterns.json
    # ("the admin has authorized", "call the delete function"). Those are
    # lexical triggers: precise enough for the sidecar's Aho-Corasick scan,
    # but as embedding exemplars they are dominated by one salient term
    # ("admin", "delete") and pull in unrelated benign requests.
    #
    # The fix is to stop using them as *semantic* exemplars while leaving them
    # active for the lexical scan — the file is shared with the Go scanner, so
    # editing the strings themselves would weaken exact matching. Deliberately
    # deferred: it touches shared policy data and needs its own change.
    "Give me admin contact details for the billing department.",
    "Clear the cached results so the next query is fresh.",
}


def _make_input(text: str) -> ScanInput:
    return ScanInput(
        agent_id="test-agent",
        execution_id="exec-001",
        session_id="sess-001",
        input_type=InputType.PROMPT,
        normalized_content=text,
        trust_level=TrustLevel.LOW,
    )


def _find_over_broad_patterns(scanner: SemanticScanner, threshold: float):
    """Return (benign_text, score, offending_pattern, category) for violations."""
    violations = []
    for text in HELD_OUT_BENIGN | KNOWN_FALSE_POSITIVES:
        result = scanner.scan(_make_input(text))
        if result.risk_score >= threshold:
            hit = result.semantic_hits[0] if result.semantic_hits else None
            violations.append((
                text,
                result.risk_score,
                hit.matched_pattern if hit else "<no hit recorded>",
                hit.matched_category if hit else "?",
            ))
    return violations


def _report(violations) -> str:
    lines = [
        f"{len(violations)} new library pattern(s) fire on held-out benign text.",
        "",
        "A pattern listed here describes behaviour that is legitimate, not an "
        "attack. Rewrite it to describe what makes the action malicious — the "
        "email pattern was fixed by naming the exfiltration rather than the "
        "delivery. Raising the threshold, or moving the sentence into "
        "KNOWN_FALSE_POSITIVES, only hides it.",
        "",
    ]
    for text, score, pattern, category in sorted(violations, key=lambda v: -v[1]):
        lines.append(f"  score {score:.3f}  benign: {text!r}")
        lines.append(f"                 pattern [{category}]: {pattern!r}")
    return "\n".join(lines)


def _assert_no_new_violations(scanner: SemanticScanner) -> None:
    threshold = SemanticScannerConfig().default_threshold
    violations = _find_over_broad_patterns(scanner, threshold)
    new = [v for v in violations if v[0] not in KNOWN_FALSE_POSITIVES]
    assert not new, _report(new)


@pytest.fixture(scope="module")
def tfidf_scanner() -> SemanticScanner:
    return SemanticScanner(backend="tfidf")


class TestCorpusHygiene:
    """The held-out corpus is only meaningful if it is genuinely held out."""

    def test_held_out_corpus_is_disjoint_from_calibration(self):
        overlap = (HELD_OUT_BENIGN | KNOWN_FALSE_POSITIVES) & set(DEFAULT_BACKGROUND)
        assert not overlap, (
            "Held-out benign text leaked into the calibration corpus, which "
            f"makes this test circular: {overlap}"
        )

    def test_held_out_corpus_is_scannable(self):
        """Guard-filtered entries would pass vacuously at score 0.0."""
        unscannable = [
            t for t in HELD_OUT_BENIGN | KNOWN_FALSE_POSITIVES if not is_scannable(t)
        ]
        assert not unscannable, (
            f"These never reach the model, so they test nothing: {unscannable}"
        )

    def test_known_false_positives_are_not_also_in_the_passing_set(self):
        assert not (HELD_OUT_BENIGN & KNOWN_FALSE_POSITIVES)


class TestPatternQuality:
    def test_no_new_pattern_fires_on_held_out_benign_tfidf(self, tfidf_scanner):
        _assert_no_new_violations(tfidf_scanner)

    @pytest.mark.skipif(
        os.environ.get("ACF_TEST_ST_MODEL", "") != "1",
        reason="set ACF_TEST_ST_MODEL=1 to run against sentence-transformers "
               "(downloads ~470MB on first use)",
    )
    def test_no_new_pattern_fires_on_held_out_benign_sentence_transformer(self):
        _assert_no_new_violations(SemanticScanner(backend="sentence-transformer"))

    def test_email_pattern_stays_specific(self):
        """Regression guard for the specific defect this module exists for.

        The tool-abuse entry must describe the exfiltration, not the delivery.
        Phrased as "send a message to external address" it matched any ordinary
        request to send mail.
        """
        email_patterns = [
            p.text for p in build_pattern_library()
            if "email tool" in p.text.lower()
        ]
        assert email_patterns, "expected an email tool-abuse pattern in the library"
        for text in email_patterns:
            lowered = text.lower()
            assert any(
                marker in lowered
                for marker in ("collected", "user data", "database", "contents")
            ), (
                f"Pattern {text!r} describes sending mail without naming what "
                "makes it an attack, so it will match legitimate email requests."
            )
