"""
Embedding backends for the semantic scanner.

The scanner needs a function that maps text → normalised dense vector.
This module provides pluggable backends:

- SentenceTransformerBackend : production backend using paraphrase-multilingual-MiniLM-L12-v2
- TfidfBackend              : lightweight fallback using sklearn TF-IDF word n-grams

The backend interface is intentionally simple — any callable that takes
a list of strings and returns a numpy array of shape (n, dim) works.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List

import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingBackend(ABC):
    """Interface for embedding backends."""

    @abstractmethod
    def encode(self, texts: List[str]) -> np.ndarray:
        """
        Encode texts into L2-normalised dense vectors.

        Parameters
        ----------
        texts : list of str

        Returns
        -------
        np.ndarray of shape (len(texts), dim), L2-normalised rows.
        """
        ...

    @abstractmethod
    def encode_single(self, text: str) -> np.ndarray:
        """Encode a single text into an L2-normalised vector."""
        ...


class SentenceTransformerBackend(EmbeddingBackend):
    """
    Production backend using sentence-transformers.

    Recommended model: paraphrase-multilingual-MiniLM-L12-v2 (384d, ~117M params,
    50+ language coverage). Detects the same injection intent in 28 of 32
    languages at zero false positives; an English-only model of comparable
    quality (all-mpnet-base-v2) manages 5 of 32.
    """

    def __init__(self, model_name: str = "paraphrase-multilingual-MiniLM-L12-v2") -> None:
        from sentence_transformers import SentenceTransformer

        logger.info("Loading sentence-transformer model: %s", model_name)
        self._model = SentenceTransformer(model_name)

    def encode(self, texts: List[str]) -> np.ndarray:
        return self._model.encode(
            texts, normalize_embeddings=True, show_progress_bar=False
        )

    def encode_single(self, text: str) -> np.ndarray:
        return self._model.encode(
            text, normalize_embeddings=True, show_progress_bar=False
        )


class TfidfBackend(EmbeddingBackend):
    """
    Lightweight backend using TF-IDF over word n-grams.

    This is the fallback for environments where sentence-transformers or
    PyTorch are not available:
    - CI / testing without GPU or heavy deps
    - Quick prototyping
    - Resource-constrained deployments

    The backend fits on the attack library plus the calibration background at
    init and transforms new inputs into the same vector space.

    No dimensionality reduction
    ---------------------------
    Earlier revisions projected through TruncatedSVD(128). On a ~100-document
    attack library that projection is close to a no-op — sklearn requires
    ``n_components < min(n_samples, n_features)``, so it was already being
    clamped to ~101 — while still discarding information and costing time.
    Removing it measured strictly better on the adversarial corpus (29/47 vs
    25/47 detections at zero false positives) and ~30% faster (0.19ms vs
    0.28ms per scan). The vectors stay sparse-derived but dense-materialised;
    at this corpus size the matmul is a few hundred thousand flops.
    """

    def __init__(self, ngram_range: tuple = (1, 3), max_features: int = 5000) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            sublinear_tf=True,
        )
        self._fitted = False

    def fit(self, corpus: List[str]) -> None:
        """Fit the TF-IDF vocabulary.

        Pass the attack patterns *and* the calibration background together —
        terms absent from the vocabulary vectorise to zero, which would make
        background calibration blind to exactly the benign vocabulary it needs
        to model.
        """
        matrix = self._vectorizer.fit_transform(corpus)
        self._fitted = True
        logger.info(
            "TfidfBackend fitted: %d docs, %d features",
            matrix.shape[0], matrix.shape[1],
        )

    def encode(self, texts: List[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("TfidfBackend.fit() must be called first.")
        matrix = self._vectorizer.transform(texts)
        return self._l2_normalize(np.asarray(matrix.todense(), dtype=np.float64))

    def encode_single(self, text: str) -> np.ndarray:
        return self.encode([text])[0]

    @staticmethod
    def _l2_normalize(vectors: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-10)  # avoid division by zero
        return vectors / norms
