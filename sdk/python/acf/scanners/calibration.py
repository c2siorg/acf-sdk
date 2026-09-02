"""Background calibration for the semantic scanner.

Why this exists
---------------
Raw cosine similarity is not comparable across models, libraries, or inputs.
Two properties of sentence embeddings break a fixed threshold:

1. **Anisotropy.** Embeddings occupy a narrow cone, so *everything* is somewhat
   similar to everything. Measured on the shipped library, the single character
   ``"x"`` scored 0.667 and ``"the"`` scored 0.674 — above several real attacks.

2. **Promiscuous patterns.** Some library entries sit near all short text.
   Literal-string entries like ``\\nSYSTEM:`` or a reversed-unicode blob are
   Aho-Corasick material; as embedding exemplars they produce a centroid that
   attracts unrelated input and dominates a max-similarity score.

Both were previously handled by hand-tuning one threshold per backend, which
has to be redone whenever the model or the pattern library changes.

What this does instead
----------------------
At startup each pattern is scored against a benign **background corpus**,
giving that pattern its own mean and spread. A pattern's contribution is then
its z-score — how unusual this input is *for that pattern* — so a promiscuous
pattern with a high background mean is discounted automatically and no
category blocklist is needed. Measured effect: the two backend/library
combinations that previously diverged (full vs filtered library) score
identically once z-scoring is applied.

The z-score is then mapped through a logistic onto ``[0.0, 1.0]``, centred on
the background ceiling, so that:

    score > 0.5  ⟺  more attack-like than anything in the background corpus

That makes ``0.5`` the meaningful default threshold for **every** backend and
model, which is what lets the model be swapped without recalibrating by hand.

Deployments with unusual traffic (heavy jargon, structured logs, a language mix
not represented here) should pass their own benign sample as ``background`` —
that is the supported way to adapt the scanner to a domain.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default background corpus — ordinary agent traffic across the four hooks.
#
# This is a *reference distribution*, not an allowlist: it defines "normal" so
# the scanner can measure distance from it. Entries are all scannable text —
# degenerate input is the content guard's job, and including it here would make
# it the extreme value in the leave-one-out ceiling. Non-English entries are
# included so a multilingual model does not treat every foreign string as
# anomalous.
#
# Coverage matters more than size: the ceiling is estimated leave-one-out, so a
# region of benign language with no representative here will look anomalous.
# ---------------------------------------------------------------------------
DEFAULT_BACKGROUND: tuple[str, ...] = (
    # natural-language requests
    "What is the weather forecast for tomorrow?",
    "Summarise this quarterly earnings report for me.",
    "How do I sort a list of dictionaries by key in Python?",
    "Please schedule a meeting with the design team on Thursday.",
    "Can you translate this paragraph into French?",
    "What were the main findings of the customer survey?",
    "Write a unit test for the parse_config function.",
    "Explain the difference between TCP and UDP.",
    "Find the invoice from last March and tell me the total.",
    "Draft a project update for the stakeholders.",
    "Review my pull request and suggest improvements.",
    "Convert this CSV file into a formatted table.",
    "Book a flight from Berlin to Lisbon next Tuesday.",
    "What is the capital of Australia and how large is it?",
    "Outline the main steps in the customer onboarding process.",
    "Suggest a title for this internal design document.",
    "Compare these two vendor proposals and list the trade-offs.",
    "What does this error message from the build log mean?",
    "Generate a weekly summary of the support ticket queue.",
    "Walk me through how the authentication flow works.",
    "Rewrite this paragraph to be clearer and shorter.",
    "Give me three options for the conference agenda.",
    # retrieved-document / context prose
    "Section 4 describes the deployment architecture in detail.",
    "Parking permits must be renewed before the end of the academic term.",
    "The database migration completed successfully at 03:14 UTC.",
    "The API rate limit is one thousand requests per hour.",
    "The organisation publishes a sustainability report each spring.",
    "Add a new column called created_at to the users table.",
    "This chapter introduces the core concepts before the examples.",
    "The maintenance window is scheduled for Sunday at midnight.",
    "The service returns a 429 status code once the quota is exhausted.",
    "Employees may carry over up to five unused vacation days.",
    # memory and tool-call values — realistic stored content
    "dark mode with compact spacing enabled",
    "the user's preferred language is British English",
    "quarterly revenue report for the northern region",
    "notification settings updated by the account owner",
    "/var/data/reports/q3-summary.csv",
    "weekly update for the platform team",
    # non-English benign, so foreign text is not inherently anomalous
    "¿Cuál es el clima en Madrid hoy y va a llover?",
    "Wie ist das Wetter in Berlin heute und morgen?",
    "今天北京的天气怎么样，需要带伞吗？",
    "आज दिल्ली में मौसम कैसा है और क्या बारिश होगी",
    "Quel temps fait-il à Paris aujourd'hui et demain ?",
    "Какая сегодня погода в Москве и будет ли дождь?",
    "ما هو الطقس في دبي اليوم وهل ستمطر؟",
    "Qual é a previsão do tempo para hoje e amanhã?",
    "今日の東京の天気はどうですか、傘は必要ですか？",
    "오늘 서울 날씨는 어떤가요, 우산이 필요할까요?",
    "Czy możesz streścić ten raport kwartalny?",
    "Puoi riassumere questo documento per favore?",
    "Kunt u dit rapport voor mij samenvatten?",
    "Bu raporu benim için özetleyebilir misiniz?",
    "คุณช่วยสรุปรายงานนี้ให้หน่อยได้ไหม",
    "bạn có thể tóm tắt báo cáo này không?",
    "האם תוכל לסכם את הדוח הזה עבורי?",
    "দয়া করে আগামীকালের সভার সময় নিশ্চিত করুন।",
    # Lower-resource languages need explicit representation: the model embeds
    # them further from the English-dominated centre, so without a benign
    # exemplar any text in them reads as anomalous. Swahili benign prose
    # false-positived at 0.71 when this group was absent.
    "Duka linafunguliwa saa ngapi kesho asubuhi?",
    "Anong oras magbubukas ang tindahan bukas ng umaga?",
    "நாளை காலை கடை எத்தனை மணிக்கு திறக்கும்?",
    "Xin vui lòng xác nhận thời gian cuộc họp ngày mai.",
    "Silakan konfirmasi jadwal rapat untuk besok pagi.",
)

# A "word" for guard purposes: two or more word characters, any script.
_WORD_RE = re.compile(r"\w{2,}", re.UNICODE)

# Scripts that do not delimit words with spaces, so word counting under-reports
# their length: CJK ideographs, kana, Hangul, Thai, Lao, Khmer, Myanmar.
_UNSPACED_SCRIPT_RE = re.compile(
    r"[぀-ヿ㐀-䶿一-鿿가-힯"
    r"฀-๿຀-໿ក-៿က-႟]"
)

#: Inputs with fewer real word tokens than this are not scannable. Embedding
#: similarity on one or two tokens reflects the model's anisotropy rather than
#: the content, so such inputs are reported as 0.0 instead of a spurious score.
MIN_SCANNABLE_WORDS = 3

#: Codepoint floor applied only to unspaced scripts, where a whole clause can
#: be a single word-token run. Roughly the length of a short CJK sentence.
MIN_SCANNABLE_UNSPACED_CHARS = 6


def count_words(text: str) -> int:
    """Number of word-like tokens, script-independent."""
    return len(_WORD_RE.findall(text)) if text else 0


def is_scannable(text: str, min_words: int = MIN_SCANNABLE_WORDS) -> bool:
    """Whether semantic similarity on this text carries any signal.

    Spaced scripts must clear ``min_words`` word tokens. Unspaced scripts
    (Chinese, Japanese, Korean, Thai …) can express a full clause in a single
    token run, so they fall back to a codepoint floor — otherwise the guard
    would silently exempt those languages from semantic scanning entirely.

    The fallback is deliberately *not* applied to spaced scripts: doing so let
    two-word English strings like "dark mode" through, and they scored 0.99.
    """
    if not text or not text.strip():
        return False
    if count_words(text) >= min_words:
        return True
    if _UNSPACED_SCRIPT_RE.search(text):
        return len(text.strip()) >= MIN_SCANNABLE_UNSPACED_CHARS
    return False


@dataclass(frozen=True)
class Calibration:
    """Per-pattern background statistics plus the derived operating point.

    Attributes
    ----------
    mu, sd :
        Per-pattern mean and standard deviation of cosine similarity against
        the background corpus. Shape ``(n_patterns,)``.
    z0 :
        Background ceiling in z units. An input scoring exactly ``z0`` maps to
        0.5, so ``score > 0.5`` means "less background-like than anything in
        the reference corpus".
    scale :
        Logistic steepness, in z units.
    """

    mu: np.ndarray
    sd: np.ndarray
    z0: float
    scale: float

    @classmethod
    def fit(
        cls,
        pattern_embeddings: np.ndarray,
        background_embeddings: np.ndarray,
        scale: Optional[float] = None,
    ) -> "Calibration":
        """Derive calibration from pattern and background embedding matrices."""
        sims = pattern_embeddings @ background_embeddings.T  # (n_pat, n_bg)
        n = sims.shape[1]
        mu = sims.mean(axis=1)
        # Floor the spread so a pattern with a near-constant background
        # similarity cannot produce an exploding z-score.
        sd = np.maximum(sims.std(axis=1), 1e-3)

        # Background ceiling, estimated leave-one-out.
        #
        # Scoring the background against statistics fitted on that same
        # background measures how unusual benign text looks *in sample*, which
        # is optimistic — real traffic is always unseen. The gap is small for
        # embedding backends, which generalise, and large for TF-IDF, where a
        # benign sentence sharing one rare term with a pattern spikes. Using
        # the in-sample max put ordinary prose ("The company was founded in
        # 2015...") at 0.93 under the TF-IDF backend.
        #
        # Each background document is instead scored against statistics fitted
        # on the *other* documents, so z0 estimates the ceiling for text the
        # calibration has never seen. Closed-form, no refitting:
        #     mu^(-j)  = (n*mu - x_j) / (n-1)
        #     var^(-j) = (n*(var + mu^2) - x_j^2) / (n-1) - (mu^(-j))^2
        if n >= 3:
            var = sims.var(axis=1)
            mu_loo = (n * mu[:, None] - sims) / (n - 1)
            second = (n * (var + mu ** 2)[:, None] - sims ** 2) / (n - 1)
            var_loo = np.maximum(second - mu_loo ** 2, 0.0)
            sd_loo = np.maximum(np.sqrt(var_loo), 1e-3)
            z_bg = ((sims - mu_loo) / sd_loo).max(axis=0)
        else:
            z_bg = ((sims - mu[:, None]) / sd[:, None]).max(axis=0)
        z0 = float(z_bg.max())

        if scale is None:
            # Spread of the background ceiling sets the transition width, so a
            # tight background gives a sharp boundary and a noisy one a soft
            # boundary. Floored to avoid a step function on small corpora.
            scale = float(max(z_bg.std(), 0.5))

        logger.info(
            "Semantic calibration: %d patterns vs %d background docs, "
            "z0=%.2f, scale=%.2f",
            pattern_embeddings.shape[0], background_embeddings.shape[0], z0, scale,
        )
        return cls(mu=mu, sd=sd, z0=z0, scale=scale)

    def z_scores(self, similarities: np.ndarray) -> np.ndarray:
        """Convert raw per-pattern similarities into per-pattern z-scores."""
        return (similarities - self.mu) / self.sd

    def to_score(self, z: float | np.ndarray) -> float | np.ndarray:
        """Map a z-score onto [0, 1] with 0.5 at the background ceiling."""
        return 1.0 / (1.0 + np.exp(-(z - self.z0) / self.scale))


def resolve_background(background: Optional[Sequence[str]]) -> List[str]:
    """Validate a caller-supplied background corpus, or fall back to default.

    Entries that would not survive the content guard are dropped. Calibration
    must model the distribution of text the scanner actually scores, and
    degenerate input never reaches scoring — the guard handles it. Leaving
    those entries in made them the extreme values in the leave-one-out ceiling,
    inflating z0 and suppressing detection on real text.
    """
    corpus = list(background) if background is not None else list(DEFAULT_BACKGROUND)
    scannable = [t for t in corpus if t and t.strip() and is_scannable(t)]

    if len(scannable) < 10:
        if background is not None:
            logger.warning(
                "Background corpus has only %d scannable entries (of %d); "
                "calibration is unreliable below ~10. Falling back to the "
                "built-in corpus.",
                len(scannable), len(corpus),
            )
            return resolve_background(None)
        raise ValueError(
            "Built-in background corpus has fewer than 10 scannable entries; "
            "this indicates a corrupt DEFAULT_BACKGROUND."
        )
    return scannable
