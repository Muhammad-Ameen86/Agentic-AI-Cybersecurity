import hashlib
import logging
from sklearn.base import BaseEstimator, TransformerMixin

logger = logging.getLogger("sentinel.transformers")


class IPHasher(BaseEstimator, TransformerMixin):
    """
    Converts IP address strings to numeric hash values.
    MD5-based — consistent across train and test.
    Must live in an importable module (not __main__) so
    joblib can deserialize saved pipelines correctly.
    """
    def __init__(self, columns):
        self.columns = columns

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X = X.copy()
        for col in self.columns:
            if col in X.columns:
                X[col] = X[col].apply(self._hash_ip)
        return X

    @staticmethod
    def _hash_ip(ip):
        try:
            return int(
                hashlib.md5(str(ip).encode()).hexdigest(), 16
            ) % (10 ** 8)
        except Exception:
            return 0


class FullPipeline:
    """
    Wraps IPHasher + ColumnTransformer into one transform() call.

    CRITICAL: This class MUST live in this module file — not in a
    Jupyter notebook __main__ — so that joblib.load() can find it
    when the backend deserializes inference_registry.pkl.

    Used by:
        - ML notebook Cell 6 (fitting)
        - ML notebook Cell 9/10 (transform)
        - Backend model_registry.py (loading)
        - Backend prediction_service.py (inference)
    """
    def __init__(self, hasher, preprocessor, high_card_cols=None):
        self.hasher         = hasher
        self.preprocessor   = preprocessor
        self.high_card_cols = high_card_cols or []

    def transform(self, X):
        import pandas as pd
        X = self.hasher.transform(X)
        for col in self.high_card_cols:
            if col in X.columns:
                X[col] = pd.factorize(X[col])[0]
        return self.preprocessor.transform(X)

    def fit(self, X, y=None):
        return self