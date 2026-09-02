"""
Semantic fallback scanner for the ACF-SDK scan stage.

This module implements the embedding-based similarity detector that sits
after the lexical scanner in the PDP pipeline.  It only fires when the
lexical scan returns PROCEED — i.e. no known regex / Aho-Corasick pattern
was matched, but the input is still untrusted.

Architecture alignment (v0.2):
    scan stage = lexical · semantic fallback
    - Lexical  → deterministic, pattern-based, <1 ms
    - Semantic → embedding similarity, ~2-4 ms on CPU, catches novel /
                 paraphrased injections that lexical misses

Design decisions:
    1. Pluggable embedding backend — SentenceTransformer for production,
       TF-IDF for testing / lightweight environments.
    2. Pre-computed attack embeddings at startup → zero per-request
       encoding of the library.
    3. Cosine similarity via numpy dot product on L2-normalised vectors.
    4. Scores are **background-calibrated**, not raw cosine (see
       calibration.py). Each pattern is measured against its own distribution
       over a benign reference corpus, so a pattern that sits near all text is
       discounted automatically rather than excluded by hand. The result is
       comparable across backends and models, which is what lets one threshold
       (0.5, the background ceiling) serve every configuration instead of a
       hand-tuned constant per backend.
    5. A **content guard** rejects degenerate input before it reaches the
       model. Below a few word tokens cosine similarity reflects the embedding
       space's anisotropy rather than the content — "x" scored 0.667 and "the"
       0.674 against the shipped library. Since the zero-false-positive
       threshold is pinned to the highest-scoring benign input, that noise
       floor otherwise caps detection for every other input.
    6. Configurable thresholds per category — different attack types may
       need different sensitivity.
    7. Returns a risk_score + semantic_hits list that feeds into the risk
       aggregator, consistent with the signal-producer model.

Measured on the 47-attack / 11-benign adversarial corpus plus a 32-language
attack set, at the threshold where false positives are zero across all benign
text and degenerate probes:

    backend / model                          English   multilingual   p50
    paraphrase-multilingual-MiniLM-L12-v2    24/47     28/32          12.1ms
    all-mpnet-base-v2                        26/47      5/32          ~19ms
    tfidf                                    20/47      8/32           0.24ms

all-mpnet-base-v2 leads on English but collapses on non-English input, which
is why the multilingual model is the default.

Usage:
    # Production
    scanner = SemanticScanner(backend="sentence-transformer")

    # Lightweight / CI
    scanner = SemanticScanner(backend="tfidf")

    result = scanner.scan(scan_input)   # → SemanticScannerOutput
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
from pydantic import BaseModel, Field

from .attack_library import AttackPattern, build_pattern_library
from .backends import EmbeddingBackend, SentenceTransformerBackend, TfidfBackend
from .calibration import (
    MIN_SCANNABLE_WORDS,
    Calibration,
    is_scannable,
    resolve_background,
)
from .models import (
    ScanAction,
    ScanInput,
    SemanticHit,
    SemanticScannerOutput,
)

logger = logging.getLogger(__name__)


class SemanticScannerConfig(BaseModel):
    """Runtime configuration for the semantic scanner.

    Thresholds are expressed in **calibrated** score units, not raw cosine.
    Because calibration puts the benign background ceiling at 0.5 for every
    backend and model, these defaults do not need retuning when the model or
    the pattern library changes — which is what previously forced a separate
    hand-tuned threshold per backend.
    """

    model_name: str = Field(
        default="paraphrase-multilingual-MiniLM-L12-v2",
        description="Sentence-transformer model (used with sentence-transformer backend).",
    )
    default_threshold: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description=(
            "Calibrated score above which a hit is reported. 0.50 is the "
            "background ceiling — the point where an input is less "
            "background-like than any text in the calibration corpus."
        ),
    )
    block_threshold: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
        description="Calibrated score above which the scan SHORT_CIRCUIT_BLOCKs.",
    )
    category_thresholds: Dict[str, float] = Field(
        default_factory=dict,
        description="Per-category overrides for the default threshold.",
    )
    max_hits: int = Field(
        default=5,
        ge=1,
        description="Maximum number of semantic hits to return.",
    )
    background: Optional[List[str]] = Field(
        default=None,
        description=(
            "Benign reference corpus used to calibrate scores. Defaults to the "
            "built-in corpus. Supply a sample of your own benign traffic when "
            "your domain language differs markedly from ordinary agent text."
        ),
    )
    min_scannable_words: int = Field(
        default=MIN_SCANNABLE_WORDS,
        ge=1,
        description=(
            "Inputs with fewer word tokens are reported as 0.0 rather than "
            "scanned. Below a few tokens, cosine similarity reflects embedding "
            "anisotropy rather than content."
        ),
    )


class SemanticScanner:
    """
    Embedding-based semantic fallback scanner.

    On init: loads backend, encodes attack library into matrix.
    On scan: encodes input, computes cosine sims, returns hits + risk score.
    """

    def __init__(
        self,
        config: Optional[SemanticScannerConfig] = None,
        attack_patterns: Optional[List[AttackPattern]] = None,
        backend: Union[str, EmbeddingBackend] = "tfidf",
    ) -> None:
        self._config = config or SemanticScannerConfig()
        self._patterns = attack_patterns or build_pattern_library()
        self._pattern_texts = [p.text for p in self._patterns]
        self._pattern_categories = [p.category for p in self._patterns]
        self._background = resolve_background(self._config.background)

        if isinstance(backend, str):
            self._backend = self._create_backend(backend)
        else:
            self._backend = backend

        logger.info(
            "Encoding %d attack patterns with %s",
            len(self._patterns),
            type(self._backend).__name__,
        )
        self._embeddings: np.ndarray = self._backend.encode(self._pattern_texts)
        logger.info("Attack embedding matrix shape: %s", self._embeddings.shape)

        # Calibration is a startup cost (one batch encode of the background
        # corpus), never a per-request one.
        self._calibration = Calibration.fit(
            self._embeddings, self._backend.encode(self._background)
        )

    def _create_backend(self, name: str) -> EmbeddingBackend:
        if name == "sentence-transformer":
            return SentenceTransformerBackend(self._config.model_name)
        elif name == "tfidf":
            backend = TfidfBackend()
            # Vocabulary must span both corpora: background terms missing from
            # the vocabulary would vectorise to zero and make calibration blind
            # to the very text it is meant to model.
            backend.fit(self._pattern_texts + self._background)
            return backend
        else:
            raise ValueError(
                f"Unknown backend: {name!r}. Use 'sentence-transformer' or 'tfidf'."
            )

    def scan(self, inp: ScanInput) -> SemanticScannerOutput:
        """Run the semantic scan on a normalised input."""
        t0 = time.perf_counter()

        # Degenerate input never reaches the model. Below a few word tokens,
        # cosine similarity measures the embedding space's anisotropy rather
        # than the content — on the shipped library the bare string "x" scored
        # 0.667 and "the" 0.674, above several genuine attacks. Scoring those
        # would put the noise floor above the operating threshold and cap
        # detection for every other input.
        if not is_scannable(inp.normalized_content, self._config.min_scannable_words):
            return SemanticScannerOutput(
                action=ScanAction.PROCEED,
                risk_score=0.0,
                semantic_hits=[],
                processing_time_ms=round((time.perf_counter() - t0) * 1000, 2),
                reason=None,
            )

        input_vec: np.ndarray = self._backend.encode_single(inp.normalized_content)
        raw_similarities: np.ndarray = self._embeddings @ input_vec

        # Calibrate against each pattern's own background distribution, so a
        # pattern that sits near all short text is discounted automatically
        # rather than needing to be excluded by category.
        z = self._calibration.z_scores(raw_similarities)
        similarities: np.ndarray = np.asarray(self._calibration.to_score(z))

        hits: List[Tuple[int, float]] = []
        for idx, sim in enumerate(similarities):
            category = self._pattern_categories[idx]
            threshold = self._config.category_thresholds.get(
                category, self._config.default_threshold
            )
            if sim >= threshold:
                hits.append((idx, float(sim)))

        hits.sort(key=lambda x: x[1], reverse=True)
        hits = hits[: self._config.max_hits]

        semantic_hits = [
            SemanticHit(
                matched_category=self._pattern_categories[idx],
                similarity_score=round(sim, 4),
                matched_pattern=self._pattern_texts[idx],
                raw_similarity=round(float(raw_similarities[idx]), 4),
            )
            for idx, sim in hits
        ]

        max_similarity = float(np.max(similarities)) if len(similarities) > 0 else 0.0
        risk_score = round(max(max_similarity, 0.0), 4)

        action = ScanAction.PROCEED
        reason = None

        # Block check runs against all similarities, not just hits filtered by..
        # default_threshold / category_thresholds. Otherwise a pattern scoring
        # in [block_threshold, default_threshold) would be dropped before the
        # block check ever sees it.
        block_idx: Optional[int] = None
        block_sim: float = 0.0
        for idx, sim in enumerate(similarities):
            sim_f = float(sim)
            if sim_f >= self._config.block_threshold and sim_f > block_sim:
                block_idx = idx
                block_sim = sim_f

        if block_idx is not None:
            action = ScanAction.SHORT_CIRCUIT_BLOCK
            block_category = self._pattern_categories[block_idx]
            reason = (
                f"Calibrated semantic score {block_sim:.2f} "
                f"to known {block_category} pattern "
                f"exceeds block threshold {self._config.block_threshold}"
            )
            # If the blocking pattern wasn't already in the hits list (because it
            # fell below the default/category threshold), surface it so the caller
            # can see what triggered the block.
            if not any(idx == block_idx for idx, _ in hits):
                semantic_hits.insert(
                    0,
                    SemanticHit(
                        matched_category=block_category,
                        similarity_score=round(block_sim, 4),
                        matched_pattern=self._pattern_texts[block_idx],
                        raw_similarity=round(float(raw_similarities[block_idx]), 4),
                    ),
                )

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return SemanticScannerOutput(
            action=action,
            risk_score=risk_score,
            semantic_hits=semantic_hits,
            processing_time_ms=round(elapsed_ms, 2),
            reason=reason,
        )
