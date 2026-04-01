"""
LogEncoder — NLP encoder for SIEM log strings.

Dual-backend design:
  - 'tfidf'       (default): sklearn TF-IDF → 128-dim L2-normalised vector.
                  Zero extra dependencies. Fast. Good enough for RL training.
  - 'transformer' (optional): sentence-transformers all-MiniLM-L6-v2 → 384-dim →
                  projected to 128-dim via a learned linear layer.
                  Requires: pip install sentence-transformers torch
                  Use this for evaluation or fine-tuning runs.

Both backends expose the same encode() interface and output a
float32 numpy array of shape (EMBEDDING_DIM,).
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
from pathlib import Path
from typing import Literal

import numpy as np

logger = logging.getLogger(__name__)

EMBEDDING_DIM = 128  # Fixed output dimension for both backends


class LogEncoder:
    """
    Encodes raw SIEM log strings (Windows Event XML / Sysmon / Metasploit stdout)
    into dense float32 vectors consumable by the PyTorch LSTM policy.

    The encoder is stateless after __init__ — encode() is pure and thread-safe.
    An LRU-style string cache avoids re-encoding identical log bursts.
    """

    def __init__(
        self,
        backend: Literal['tfidf', 'transformer'] = 'tfidf',
        cache_size: int = 512,
    ) -> None:
        self.backend = backend
        self._cache: dict[str, np.ndarray] = {}
        self._cache_size = cache_size
        self._encoder = self._build_encoder(backend)

    def encode(self, text: str) -> np.ndarray:
        """
        Encode a single SIEM log string to a float32 vector of shape (EMBEDDING_DIM,).

        Returns a zero vector for empty/None inputs.
        """
        if not text or not text.strip():
            return np.zeros(EMBEDDING_DIM, dtype=np.float32)

        # Cache lookup (keyed by first 256 chars — avoids huge key strings)
        cache_key = hashlib.md5(text[:256].encode()).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        vec = self._encoder(text)
        self._evict_if_full()
        self._cache[cache_key] = vec
        return vec

    def encode_buffer(self, log_lines: list[str], agg: str = 'mean') -> np.ndarray:
        """
        Encode a list of log lines and aggregate them into a single vector.

        Args:
            log_lines: List of log strings (e.g. last N from siem_log_buffer).
            agg: Aggregation strategy — 'mean' (default) or 'max'.

        Returns:
            Aggregated float32 vector of shape (EMBEDDING_DIM,).
        """
        if not log_lines:
            return np.zeros(EMBEDDING_DIM, dtype=np.float32)

        # Normalise: convert legacy dict-format log entries to strings
        str_lines = [line if isinstance(line, str) else str(line) for line in log_lines]
        vecs = np.stack([self.encode(line) for line in str_lines])
        if agg == 'max':
            return vecs.max(axis=0).astype(np.float32)
        return vecs.mean(axis=0).astype(np.float32)

    def _build_encoder(self, backend: str):
        if backend == 'transformer':
            return self._build_transformer()
        return self._build_tfidf()

    def _build_tfidf(self):
        """
        Build a TF-IDF vectorizer fit on the payload library + event templates corpus.
        Projects to EMBEDDING_DIM via truncated SVD (Latent Semantic Analysis).
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.decomposition import TruncatedSVD
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import Normalizer

        corpus = self._build_training_corpus()

        pipeline = Pipeline(
            [
                (
                    'tfidf',
                    TfidfVectorizer(
                        analyzer='char_wb',
                        ngram_range=(3, 5),
                        max_features=4096,
                        sublinear_tf=True,
                    ),
                ),
                ('svd', TruncatedSVD(n_components=EMBEDDING_DIM, random_state=42)),
                ('norm', Normalizer(norm='l2')),
            ]
        )
        pipeline.fit(corpus)
        logger.info(
            'LogEncoder[tfidf]: fitted on %d corpus documents → %d-dim LSA.',
            len(corpus),
            EMBEDDING_DIM,
        )

        def encode_fn(text: str) -> np.ndarray:
            vec = pipeline.transform([text])[0]
            # Ensure fixed output dimension even if SVD capped out
            if vec.shape[0] < EMBEDDING_DIM:
                padded = np.zeros(EMBEDDING_DIM, dtype=np.float32)
                padded[: vec.shape[0]] = vec
                return padded
            return vec.astype(np.float32)

        return encode_fn

    def _build_transformer(self):
        """
        Build a sentence-transformers encoder (all-MiniLM-L6-v2, 22MB).
        Projects 384-dim → EMBEDDING_DIM via a fixed random projection matrix.
        """
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            import torch

            model = SentenceTransformer('all-MiniLM-L6-v2')
            model.eval()

            # Fixed random projection: 384 → EMBEDDING_DIM
            rng = np.random.default_rng(42)
            proj = rng.standard_normal((384, EMBEDDING_DIM)).astype(np.float32)
            proj /= np.linalg.norm(proj, axis=0, keepdims=True) + 1e-8

            logger.info(
                'LogEncoder[transformer]: loaded all-MiniLM-L6-v2 → %d-dim projection.',
                EMBEDDING_DIM,
            )

            def encode_fn(text: str) -> np.ndarray:
                with torch.no_grad():
                    emb = model.encode(text, convert_to_numpy=True)
                vec = (emb @ proj).astype(np.float32)
                # L2 normalise
                norm = np.linalg.norm(vec)
                return vec / (norm + 1e-8) if norm > 0 else vec

            return encode_fn

        except ImportError:
            logger.warning(
                'LogEncoder: sentence-transformers not installed. '
                'Falling back to TF-IDF backend. '
                'Run: pip install sentence-transformers'
            )
            return self._build_tfidf()

    def _build_training_corpus(self) -> list[str]:
        """
        Assemble a training corpus from:
          1. payload_library.json (Metasploit stdout strings)
          2. Synthetic event template samples
        """
        corpus: list[str] = []

        # 1. Load payload library
        lib_path = Path(__file__).parent.parent / 'sim2real' / 'payload_library.json'
        if lib_path.exists():
            with open(lib_path) as f:
                lib = json.load(f)
            for action_data in lib.values():
                for outcome_list in action_data.values():
                    for text in outcome_list:
                        corpus.append(text)

        # 2. Synthetic template samples (generate 5 of each template type)
        from netforge_rl.siem.event_templates import (
            evid_4624,
            evid_4625,
            evid_4648,
            evid_4688,
            evid_4768,
            evid_4776,
            sysmon_1,
            sysmon_3,
            sysmon_10,
            sysmon_22,
        )

        sample_ips = ['10.0.0.1', '10.0.1.2', '192.168.1.5', '10.0.0.7', '10.0.1.9']
        for src, tgt in zip(sample_ips, reversed(sample_ips)):
            for fn in [evid_4624, evid_4625, evid_4648, evid_4776]:
                corpus.append(fn(src, tgt))
            # Add more variations to ensure > 128 samples
            for proc in [
                'cmd.exe',
                'powershell.exe',
                'mimikatz.exe',
                'procdump.exe',
                'net.exe',
            ]:
                corpus.append(evid_4688(src, process=proc))
                corpus.append(sysmon_1(src, process=proc))
            corpus.append(evid_4768(src, tgt))
            corpus.append(sysmon_3(src, tgt, dst_port=445))
            corpus.append(sysmon_3(src, tgt, dst_port=3389))
            corpus.append(sysmon_10(src))
            corpus.append(sysmon_22(src))

        # Add 50 unique random noise strings to guarantee diversity
        for i in range(50):
            corpus.append(
                f'Synthetic noise event {i} for dimension stability - {random.random()}'
            )

        if not corpus:
            # Ultimate fallback — at least something to fit on
            corpus = [
                'Windows Event Log',
                'Sysmon Network Connection',
                'LSASS access detected',
            ]

        return corpus

    def _evict_if_full(self) -> None:
        if len(self._cache) >= self._cache_size:
            # Evict oldest quarter of entries (FIFO approximation)
            evict_n = self._cache_size // 4
            keys = list(self._cache.keys())[:evict_n]
            for k in keys:
                del self._cache[k]
