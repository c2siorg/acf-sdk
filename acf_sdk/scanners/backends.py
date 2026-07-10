"""
Embedding backends for the semantic scanner.

The scanner needs a function that maps text → normalised dense vector.
This module provides pluggable backends:

- SentenceTransformerBackend : production backend using all-MiniLM-L6-v2
- TfidfBackend              : lightweight fallback using sklearn TF-IDF + SVD

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

    Recommended model: all-MiniLM-L6-v2 (384d, ~22M params, fast CPU inference).
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
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
    Lightweight backend using TF-IDF + Truncated SVD.

    This is a fallback for environments where sentence-transformers or
    PyTorch are not available.  It produces lower-quality embeddings but
    is useful for:
    - CI / testing without GPU or heavy deps
    - Quick prototyping
    - Resource-constrained deployments

    The backend fits on the attack library at init and transforms new
    inputs into the same vector space.
    """

    def __init__(self, n_components: int = 128) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.decomposition import TruncatedSVD

        self._vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            sublinear_tf=True,
        )
        self._svd = TruncatedSVD(n_components=n_components, random_state=42)
        self._fitted = False
        self._n_components = n_components

    def fit(self, corpus: List[str]) -> None:
        """Fit the TF-IDF + SVD pipeline on the attack corpus."""
        tfidf_matrix = self._vectorizer.fit_transform(corpus)
        self._svd.fit(tfidf_matrix)
        self._fitted = True
        logger.info(
            "TfidfBackend fitted: %d docs, %d components",
            len(corpus),
            self._n_components,
        )

    def encode(self, texts: List[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("TfidfBackend.fit() must be called first.")
        tfidf_matrix = self._vectorizer.transform(texts)
        vectors = self._svd.transform(tfidf_matrix)
        return self._l2_normalize(vectors)

    def encode_single(self, text: str) -> np.ndarray:
        result = self.encode([text])
        return result[0]

    @staticmethod
    def _l2_normalize(vectors: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-10)  # avoid division by zero
        return vectors / norms
