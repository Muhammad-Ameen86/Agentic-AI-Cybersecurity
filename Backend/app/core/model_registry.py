import sys
import json
import joblib
import logging
from pathlib import Path
from typing import List, Any, Dict

logger = logging.getLogger("sentinel.model_registry")

BASE_DIR = Path(__file__).resolve().parents[3]

# ── CRITICAL: Must import before any joblib.load() call ──────
# FullPipeline and IPHasher were defined in ML/preprocessing/custom_transformers.py
# joblib needs to find these classes when deserializing inference_registry.pkl
# Without this import, you get:
#   AttributeError: Can't get attribute 'FullPipeline' on <module '__main__'>
sys.path.insert(0, str(BASE_DIR))
try:
    from ML.preprocessing.custom_transformers import IPHasher, FullPipeline  # noqa: F401
    logger.info("[ModelRegistry] custom_transformers imported successfully")
except ImportError as e:
    logger.warning(
        f"[ModelRegistry] Could not import custom_transformers: {e}\n"
        "If inference_registry.pkl fails to load, run Cell 2→6→9→10→15 "
        "in sentinel_ml_gpu_final.ipynb to rebuild with correct class references."
    )

# ── New paths matching your ML folder structure ───────────────
INFERENCE_REGISTRY_PATH = BASE_DIR / "ML" / "inference_models" / "inference_registry.pkl"
UNSW_FEATURE_COLUMNS    = BASE_DIR / "ML" / "preprocessing" / "UNSW-NB15" / "feature_columns.joblib"
CIC_FEATURE_COLUMNS     = BASE_DIR / "ML" / "preprocessing" / "CIC-IDS-2017" / "feature_columns.joblib"
UNSW_METRICS_PATH       = BASE_DIR / "ML" / "evaluation" / "metrics" / "unsw_nb15_model_metrics.json"

# Fallback model accuracy if metrics file not found
FALLBACK_ACCURACY = {
    "random_forest":       0.9958,
    "xgboost":             0.9947,
    "logistic_regression": 0.9911,
}

# Default dataset to use for predictions
DEFAULT_DATASET = "unsw"  # "unsw" or "cic"


class ModelRegistry:
    """
    Loads and caches all trained models from inference_registry.pkl.
    Supports both UNSW-NB15 and CIC-IDS-2017 trained models.

    Registry keys:
        unsw_random_forest, unsw_xgboost, unsw_logistic_regression
        cic_random_forest,  cic_xgboost,  cic_logistic_regression
    """
    _registry: Dict[str, Any] = {}
    _feature_columns: Dict[str, List[str]] = {}
    _accuracy: Dict[str, float] = {}
    _loaded: bool = False

    # ── Preload ───────────────────────────────────────────────
    @classmethod
    def preload_all(cls):
        """
        Load inference registry once at startup.
        Raises RuntimeError if registry file not found.
        """
        if cls._loaded:
            return

        if not INFERENCE_REGISTRY_PATH.exists():
            raise RuntimeError(
                f"inference_registry.pkl not found at {INFERENCE_REGISTRY_PATH}\n"
                "Run Cell 15 of sentinel_ml_gpu_final.ipynb first."
            )

        logger.info(f"[ModelRegistry] Loading from {INFERENCE_REGISTRY_PATH}")
        cls._registry = joblib.load(INFERENCE_REGISTRY_PATH)
        logger.info(f"[ModelRegistry] Registry keys found: {sorted(list(cls._registry.keys()))}")
        
        # Log structure of each entry for diagnostics
        for key, entry in cls._registry.items():
            if isinstance(entry, dict):
                logger.info(f"[ModelRegistry] Entry: {key} -> {list(entry.keys())}")
            else:
                logger.info(f"[ModelRegistry] Entry: {key} -> type={type(entry).__name__}")

        # Load feature columns
        if UNSW_FEATURE_COLUMNS.exists():
            cls._feature_columns["unsw"] = joblib.load(UNSW_FEATURE_COLUMNS)
            logger.info(f"[ModelRegistry] UNSW features: {len(cls._feature_columns['unsw'])}")

        if CIC_FEATURE_COLUMNS.exists():
            cls._feature_columns["cic"] = joblib.load(CIC_FEATURE_COLUMNS)
            logger.info(f"[ModelRegistry] CIC features: {len(cls._feature_columns['cic'])}")

        cls._loaded = True

    # ── Available models ──────────────────────────────────────
    @classmethod
    def available_models(cls) -> List[str]:
        """Returns base model names (without dataset prefix)."""
        return ["random_forest", "xgboost", "logistic_regression"]

    @classmethod
    def available_datasets(cls) -> List[str]:
        """Returns which datasets have trained models."""
        datasets = set()
        for key in cls._registry:
            prefix = key.split("_")[0]
            datasets.add(prefix)
        return list(datasets)

    # ── Get model ─────────────────────────────────────────────
    @classmethod
    def get_model(cls, name: str, dataset: str = DEFAULT_DATASET) -> Any:
        """
        Get a trained model by name and dataset.
        dataset: "unsw" or "cic"
        name: "random_forest", "xgboost", "logistic_regression"
        """
        key = f"{dataset}_{name}"
        if key not in cls._registry:
            # Fallback: try other dataset
            fallback_key = f"{'cic' if dataset == 'unsw' else 'unsw'}_{name}"
            if fallback_key in cls._registry:
                logger.warning(
                    f"[ModelRegistry] {key} not found, using {fallback_key}"
                )
                key = fallback_key
            else:
                raise KeyError(
                    f"Model '{key}' not in registry. "
                    f"Available: {list(cls._registry.keys())}"
                )

        entry = cls._registry[key]
        # Registry entries are dicts: {"pipeline": ..., "model": ..., "dataset": ...}
        # Or sometimes {"pipeline": ..., "estimator": ...} depending on how it was saved
        if isinstance(entry, dict):
            # Try various common keys used for sub-models
            model_obj = entry.get("model") or entry.get("estimator")
            if model_obj:
                return model_obj
            # If no obvious key, return the first value if it's not a pipeline
            for k, v in entry.items():
                if k != "pipeline" and hasattr(v, "predict"):
                    return v
            return entry
        # Legacy: direct model object
        return entry

    # ── Get pipeline ─────────────────────────────────────────
    @classmethod
    def get_pipeline(cls, dataset: str = DEFAULT_DATASET):
        """Get the preprocessing pipeline for a dataset."""
        # Find first entry for this dataset
        for key, entry in cls._registry.items():
            if key.startswith(dataset) and isinstance(entry, dict):
                return entry["pipeline"]
        raise KeyError(f"No pipeline found for dataset '{dataset}'")

    # ── Get feature columns ───────────────────────────────────
    @classmethod
    def get_feature_columns(cls, dataset: str = DEFAULT_DATASET) -> List[str]:
        """Get feature column names for a dataset."""
        if dataset in cls._feature_columns:
            return cls._feature_columns[dataset]
        raise KeyError(
            f"Feature columns for '{dataset}' not loaded. "
            f"Available: {list(cls._feature_columns.keys())}"
        )

    # ── Get model accuracy ────────────────────────────────────
    @classmethod
    def get_model_accuracy(cls) -> Dict[str, float]:
        """
        Load actual measured accuracy from evaluation metrics.
        Falls back to hardcoded values if file missing.
        """
        if cls._accuracy:
            return cls._accuracy

        if UNSW_METRICS_PATH.exists():
            try:
                with open(UNSW_METRICS_PATH) as f:
                    metrics = json.load(f)
                cls._accuracy = {
                    name: data["accuracy"]
                    for name, data in metrics.items()
                }
                logger.info(f"[ModelRegistry] Accuracy loaded from metrics file")
                return cls._accuracy
            except Exception as e:
                logger.warning(f"[ModelRegistry] Could not load metrics: {e}")

        logger.warning("[ModelRegistry] Using fallback accuracy values")
        cls._accuracy = FALLBACK_ACCURACY
        return cls._accuracy