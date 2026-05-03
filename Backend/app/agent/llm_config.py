"""
=============================================================
  THE SENTINEL — LLM Provider Configuration

  Providers supported (configure via .env):
    - groq        → GROQ_API_KEY  / GROQ_LLM_MODEL
    - google      → GEMINI_API_KEY / GEMINI_LLM_MODEL
    - openrouter  → OPENROUTER_API_KEY / OPENROUTER_LLM_MODEL

  Hot-swap at runtime: call switch_active_provider(provider)
  or POST /evaluation/switch-model from the frontend Settings.
=============================================================
"""

import os
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("sentinel.llm_config")

# ── Default from .env ─────────────────────────────────────────
_ENV_PROVIDER = os.getenv("SENTINEL_LLM_PROVIDER", "groq").lower()

# ── Runtime active provider (hot-swappable without restart) ───
_active_provider: str = _ENV_PROVIDER

# Map each provider to its per-provider model env key
_PROVIDER_MODEL_ENVS = {
    "groq":       ("GROQ_LLM_MODEL",       "meta-llama/llama-4-scout-17b-16e-instruct"),
    "google":     ("GEMINI_LLM_MODEL",     "models/gemini-3-pro-preview"),
    "openrouter": ("OPENROUTER_LLM_MODEL", "anthropic/claude-3.7-sonnet"),
    "anthropic":  ("ANTHROPIC_LLM_MODEL",  "claude-3-5-sonnet-latest"),
}


def _model_for(provider: str) -> str:
    env_key, default = _PROVIDER_MODEL_ENVS.get(provider, ("SENTINEL_LLM_MODEL", "unknown"))
    return os.getenv(env_key, default)


def switch_active_provider(provider: str) -> dict:
    """
    Hot-swap the active LLM provider at runtime.
    Called when the user clicks a model card and saves in AI Core Settings.
    """
    global _active_provider
    provider = provider.lower()
    if provider not in _PROVIDER_MODEL_ENVS:
        raise ValueError(
            f"Unknown provider '{provider}'. Valid: {list(_PROVIDER_MODEL_ENVS.keys())}"
        )
    _active_provider = provider
    logger.info(f"[LLM] Runtime switch → {_active_provider} / {_model_for(_active_provider)}")
    return get_provider_info()


def get_llm(temperature: float = 0.0, max_tokens: int = 2048, provider: str = None):
    """
    Returns a configured LangChain LLM instance.

    Args:
        temperature: 0.0 = fully deterministic (default for security decisions).
        max_tokens:  max response length.
        provider:    override the active provider for this call only.
                     Leave None to use the current _active_provider.
    """
    use_provider = (provider or _active_provider).lower()

    if use_provider == "groq":
        try:
            from langchain_groq import ChatGroq
        except ImportError:
            raise RuntimeError("langchain-groq not installed. Run: pip install langchain-groq")
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set in .env")
        model_name = _model_for("groq")
        llm = ChatGroq(model=model_name, api_key=api_key, temperature=temperature, max_tokens=max_tokens)
        logger.info(f"[LLM] Using Groq: {model_name}")
        return llm

    elif use_provider == "google":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError:
            raise RuntimeError("langchain-google-genai not installed. Run: pip install langchain-google-genai")
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not set in .env")
        model_name = _model_for("google")
        llm = ChatGoogleGenerativeAI(model=model_name, google_api_key=api_key, temperature=temperature, max_output_tokens=max_tokens)
        logger.info(f"[LLM] Using Google Gemini: {model_name}")
        return llm

    elif use_provider == "openrouter":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise RuntimeError("langchain-openai not installed. Run: pip install langchain-openai")
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set in .env")
        model_name = _model_for("openrouter")
        llm = ChatOpenAI(model=model_name, api_key=api_key, base_url="https://openrouter.ai/api/v1", temperature=temperature, max_tokens=max_tokens)
        logger.info(f"[LLM] Using OpenRouter: {model_name}")
        return llm

    elif use_provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            raise RuntimeError("langchain-anthropic not installed. Run: pip install langchain-anthropic")
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set in .env")
        model_name = _model_for("anthropic")
        llm = ChatAnthropic(model=model_name, api_key=api_key, temperature=temperature, max_tokens=max_tokens)
        logger.info(f"[LLM] Using Anthropic Claude: {model_name}")
        return llm

    else:
        raise RuntimeError(
            f"Unknown provider '{use_provider}'. Valid: groq, google, openrouter, anthropic"
        )


def get_provider_info() -> dict:
    """Returns the currently active LLM provider info."""
    key_map = {
        "groq":       "GROQ_API_KEY",
        "google":     "GEMINI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "anthropic":  "ANTHROPIC_API_KEY",
    }
    return {
        "provider": _active_provider,
        "model":    _model_for(_active_provider),
        "ready":    bool(os.getenv(key_map.get(_active_provider, ""), "")),
    }