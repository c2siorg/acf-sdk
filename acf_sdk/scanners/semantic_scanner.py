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
       TF-IDF+SVD for testing / lightweight environments.
    2. Pre-computed attack embeddings at startup → zero per-request
       encoding of the library.
    3. Cosine similarity via numpy dot product on L2-normalised vectors.
    4. Configurable thresholds per category — different attack types may
       need different sensitivity.
    5. Returns a risk_score + semantic_hits list that feeds into the risk
       aggregator, consistent with the signal-producer model.

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
from .models import (
    ScanAction,
    ScanInput,
    SemanticHit,
    SemanticScannerOutput,
)

logger = logging.getLogger(__name__)


class SemanticScannerConfig(BaseModel):
    """Runtime configuration for the semantic scanner."""

    model_name: str = Field(
        default="all-MiniLM-L6-v2",
        description="Sentence-transformer model (used with sentence-transformer backend).",
    )
    default_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Cosine similarity threshold above which a hit is flagged.",
    )
    block_threshold: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
        description="Similarity above this triggers an immediate SHORT_CIRCUIT_BLOCK.",
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

    def _create_backend(self, name: str) -> EmbeddingBackend:
        if name == "sentence-transformer":
            return SentenceTransformerBackend(self._config.model_name)
        elif name == "tfidf":
            backend = TfidfBackend()
            backend.fit(self._pattern_texts)
            return backend
        else:
            raise ValueError(
                f"Unknown backend: {name!r}. Use 'sentence-transformer' or 'tfidf'."
            )

    def scan(self, inp: ScanInput) -> SemanticScannerOutput:
        """Run the semantic scan on a normalised input."""
        t0 = time.perf_counter()

        input_vec: np.ndarray = self._backend.encode_single(inp.normalized_content)
        similarities: np.ndarray = self._embeddings @ input_vec

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
            )
            for idx, sim in hits
        ]

        max_similarity = float(np.max(similarities)) if len(similarities) > 0 else 0.0
        risk_score = round(max(max_similarity, 0.0), 4)

        action = ScanAction.PROCEED
        reason = None
        if any(sim >= self._config.block_threshold for _, sim in hits):
            action = ScanAction.SHORT_CIRCUIT_BLOCK
            top_hit = semantic_hits[0]
            reason = (
                f"Semantic similarity {top_hit.similarity_score:.2f} "
                f"to known {top_hit.matched_category} pattern "
                f"exceeds block threshold {self._config.block_threshold}"
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return SemanticScannerOutput(
            action=action,
            risk_score=risk_score,
            semantic_hits=semantic_hits,
            processing_time_ms=round(elapsed_ms, 2),
            reason=reason,
        )
