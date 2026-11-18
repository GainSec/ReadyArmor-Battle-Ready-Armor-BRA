"""Path settings for BRA head module.

Resolves paths to body directory containing:
- layer1/ - Governance layer (immutable during engagement): rules/, scripts/, hooks/, lib/
- layer2-templates/ - Methodology layer (grows)
- layer3-engagement/ - Engagement layer (per-engagement)
- .bra/ - Runtime state

Supports dynamic configuration via config file or set_bra_root().
"""

import json
import os
from pathlib import Path

from bra.debug_log import write_debug_log

# Branding
APP_NAME = "Battle Ready Armor"
APP_SHORT = "B.R.A."
APP_VERSION = "v15.0.0"
APP_COMPANY = "GainSec LLC."
APP_LICENSE = "1337"

# Config file location (in user's home directory)
CONFIG_FILE = Path.home() / ".bra-tui-config.json"

# Runtime defaults
DEFAULT_MODEL = None

# Head module root (this package)
HEAD_ROOT = Path(__file__).parent.parent.parent.resolve()  # head/

# Default BRA project root (parent of head)
_DEFAULT_BRA_ROOT = HEAD_ROOT.parent  # BRA/ or BRA-V13/

# Current BRA root (can be changed at runtime)
_bra_root: Path | None = None


_STALE_KEYS = {"provider", "litellm_base_url", "litellm_api_key_env", "openai_api_key_env"}
_DEFAULT_PROXY_CONTEXT_WINDOW = 32768
_DEFAULT_PROXY_MAX_COMPLETION_TOKENS = 8192


def _settings_debug(event: str, **fields) -> None:
    """Write settings debug logs without re-entering dynamic settings lookup."""
    root = _bra_root or _DEFAULT_BRA_ROOT
    bra_state = root / "body" / ".bra"
    write_debug_log(
        "settings",
        event,
        approvals_dir=bra_state / "approvals",
        logs_dir=bra_state / "logs",
        **fields,
    )


def _load_config() -> dict:
    """Load saved configuration, stripping stale provider fields."""
    _settings_debug("load_config_start", config_file=str(CONFIG_FILE), exists=CONFIG_FILE.exists())
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            stale = _STALE_KEYS & data.keys()
            if stale:
                for k in stale:
                    del data[k]
                CONFIG_FILE.write_text(json.dumps(data, indent=2))
                _settings_debug("load_config_pruned_stale", stale_keys=sorted(stale))
            _settings_debug("load_config_ok", keys=sorted(data.keys()))
            return data
        except (json.JSONDecodeError, IOError):
            _settings_debug("load_config_error", reason="json_or_io")
            pass
    _settings_debug("load_config_empty")
    return {}


def _save_config(config: dict) -> None:
    """Save configuration."""
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    _settings_debug("save_config", keys=sorted(config.keys()), config_file=str(CONFIG_FILE))


def _runtime_from_env() -> dict:
    """Read model override from environment."""
    runtime = {
        "model": (os.environ.get("BRA_MODEL") or "").strip() or None,
        "anthropic_api_key": (os.environ.get("ANTHROPIC_API_KEY") or "").strip() or None,
        "ui_profile": (os.environ.get("BRA_UI_PROFILE") or "").strip() or None,
        "ui_pack": (os.environ.get("BRA_UI_PACK") or "").strip() or None,
    }
    _settings_debug(
        "runtime_from_env",
        model_present=bool(runtime["model"]),
        anthropic_key_present=bool(runtime["anthropic_api_key"]),
        ui_profile=runtime["ui_profile"] or "",
        ui_pack=runtime["ui_pack"] or "",
    )
    return runtime


def get_ui_state_dir() -> Path:
    """Get the body-local UI runtime directory."""
    return _get_bra_state() / "ui"


def get_ui_config_path() -> Path:
    """Get body-local UI config path."""
    return get_ui_state_dir() / "config.json"


def _load_ui_config() -> dict:
    """Load body-local UI config."""
    path = get_ui_config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text())
            _settings_debug("load_ui_config_ok", path=str(path), keys=sorted(data.keys()))
            return data
        except (json.JSONDecodeError, IOError):
            _settings_debug("load_ui_config_error", path=str(path))
            pass
    _settings_debug("load_ui_config_empty", path=str(path))
    return {}


def _save_ui_config(config: dict) -> None:
    """Persist body-local UI config."""
    path = get_ui_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2))
    _settings_debug("save_ui_config", path=str(path), keys=sorted(config.keys()))


def get_ui_profiles_paths() -> list[Path]:
    """Get profile search paths in precedence order."""
    return [
        _get_layer3() / "UI" / "profiles",
        get_ui_state_dir() / "profiles",
        _get_layer2() / "ui" / "profiles",
        _DEFAULT_BRA_ROOT / "body" / "layer2-templates" / "ui" / "profiles",
    ]


def get_ui_packs_paths() -> list[Path]:
    """Get v2 UI pack search paths in precedence order."""
    return [
        _get_layer3() / "UI" / "packs",
        get_ui_state_dir() / "packs",
        _get_layer2() / "ui" / "packs",
        _DEFAULT_BRA_ROOT / "body" / "layer2-templates" / "ui" / "packs",
    ]


def get_ui_assets_paths() -> list[Path]:
    """Get asset search paths in precedence order."""
    return [
        _get_layer3() / "UI" / "assets",
        get_ui_state_dir() / "assets",
        _get_layer2() / "ui" / "assets",
        _DEFAULT_BRA_ROOT / "body" / "layer2-templates" / "ui" / "assets",
    ]


def get_runtime_config() -> dict:
    """Get runtime config from config file + env overrides."""
    cfg = _load_config()
    ui_cfg = _load_ui_config()
    ui_pack = ui_cfg.get("ui_pack") or ui_cfg.get("ui_profile") or "command-center"
    runtime = {
        "model": cfg.get("model") or DEFAULT_MODEL,
        "anthropic_api_key": (cfg.get("anthropic_api_key") or "").strip() or None,
        "ui_profile": ui_pack,
        "ui_pack": ui_pack,
    }

    env_runtime = _runtime_from_env()
    if env_runtime.get("model"):
        runtime["model"] = env_runtime["model"]
    if env_runtime.get("anthropic_api_key"):
        runtime["anthropic_api_key"] = env_runtime["anthropic_api_key"]
    if env_runtime.get("ui_profile"):
        runtime["ui_profile"] = env_runtime["ui_profile"]
        runtime["ui_pack"] = env_runtime["ui_profile"]
    if env_runtime.get("ui_pack"):
        runtime["ui_pack"] = env_runtime["ui_pack"]
        runtime["ui_profile"] = env_runtime["ui_pack"]
    _settings_debug(
        "get_runtime_config",
        source_model="env" if env_runtime.get("model") else ("config" if cfg.get("model") else "default"),
        source_key="env" if env_runtime.get("anthropic_api_key") else ("config" if cfg.get("anthropic_api_key") else "none"),
        model=runtime.get("model") or "",
        anthropic_key_present=bool(runtime.get("anthropic_api_key")),
        ui_profile=runtime.get("ui_profile") or "",
        ui_pack=runtime.get("ui_pack") or "",
    )
    return runtime


def get_anthropic_api_key() -> str | None:
    """Resolve Anthropic key from env first, then saved runtime config.

    Returns:
        Non-empty API key string if configured, otherwise None.
    """
    api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if api_key:
        _settings_debug("get_anthropic_api_key", source="env", present=True)
        return api_key

    runtime_key = (get_runtime_config().get("anthropic_api_key") or "").strip()
    if runtime_key:
        # Normalize env so downstream SDK paths see the same key source.
        os.environ["ANTHROPIC_API_KEY"] = runtime_key
        _settings_debug("get_anthropic_api_key", source="config", present=True)
        return runtime_key
    _settings_debug("get_anthropic_api_key", source="none", present=False)
    return None


def get_proxy_config() -> dict:
    """Resolve proxy configuration from env first, then config file.

    Returns dict with keys: proxy_enabled, proxy_port, proxy_backend_url,
    proxy_backend_api_key, proxy_model_map, proxy_context_window,
    proxy_max_completion_tokens.
    """
    cfg = _load_config()
    env_url = (os.environ.get("BRA_PROXY_BACKEND_URL") or "").strip()
    env_key = (os.environ.get("BRA_PROXY_BACKEND_API_KEY") or "").strip()
    env_port = os.environ.get("BRA_PROXY_PORT", "").strip()
    env_context_window = os.environ.get("BRA_PROXY_CONTEXT_WINDOW", "").strip()
    env_max_completion = os.environ.get("BRA_PROXY_MAX_COMPLETION_TOKENS", "").strip()

    backend_url = env_url or (cfg.get("proxy_backend_url") or "").strip()
    backend_key = env_key or (cfg.get("proxy_backend_api_key") or "").strip()
    port = int(env_port) if env_port.isdigit() else cfg.get("proxy_port", 4000)
    enabled = bool(backend_url) and cfg.get("proxy_enabled", False)
    model_map = cfg.get("proxy_model_map", {})
    context_window = (
        int(env_context_window)
        if env_context_window.isdigit()
        else int(cfg.get("proxy_context_window", _DEFAULT_PROXY_CONTEXT_WINDOW))
    )
    max_completion_tokens = (
        int(env_max_completion)
        if env_max_completion.isdigit()
        else int(cfg.get("proxy_max_completion_tokens", _DEFAULT_PROXY_MAX_COMPLETION_TOKENS))
    )

    # If env provides a URL, treat proxy as enabled
    if env_url:
        enabled = True

    return {
        "proxy_enabled": enabled,
        "proxy_port": port,
        "proxy_backend_url": backend_url,
        "proxy_backend_api_key": backend_key,
        "proxy_model_map": model_map if isinstance(model_map, dict) else {},
        "proxy_context_window": context_window,
        "proxy_max_completion_tokens": max_completion_tokens,
    }


def set_runtime_config(
    model: str | None = None,
    anthropic_api_key: str | None = None,
    ui_profile: str | None = None,
    persist: bool = False,
    ui_pack: str | None = None,
    proxy_enabled: bool | None = None,
    proxy_port: int | None = None,
    proxy_backend_url: str | None = None,
    proxy_backend_api_key: str | None = None,
    proxy_model_map: dict[str, str] | None = None,
    proxy_context_window: int | None = None,
    proxy_max_completion_tokens: int | None = None,
) -> None:
    """Set runtime config in environment; optionally persist to config file."""
    _settings_debug(
        "set_runtime_config_start",
        model=model or "",
        anthropic_key_present=bool(anthropic_api_key and anthropic_api_key.strip()),
        ui_profile=ui_profile or "",
        ui_pack=ui_pack or "",
        persist=persist,
    )
    if model is not None:
        os.environ["BRA_MODEL"] = model
    if anthropic_api_key is not None:
        cleaned_key = anthropic_api_key.strip()
        if cleaned_key:
            os.environ["ANTHROPIC_API_KEY"] = cleaned_key
        else:
            os.environ.pop("ANTHROPIC_API_KEY", None)
    effective_pack = ui_pack if ui_pack is not None else ui_profile
    if effective_pack is not None:
        os.environ["BRA_UI_PROFILE"] = effective_pack
        os.environ["BRA_UI_PACK"] = effective_pack

    if persist:
        cfg = _load_config()
        if model is not None:
            cfg["model"] = model
        if anthropic_api_key is not None:
            cleaned_key = anthropic_api_key.strip()
            if cleaned_key:
                cfg["anthropic_api_key"] = cleaned_key
            else:
                cfg.pop("anthropic_api_key", None)
        if proxy_enabled is not None:
            cfg["proxy_enabled"] = proxy_enabled
        if proxy_port is not None:
            cfg["proxy_port"] = proxy_port
        if proxy_backend_url is not None:
            cfg["proxy_backend_url"] = proxy_backend_url.strip()
        if proxy_backend_api_key is not None:
            cleaned = proxy_backend_api_key.strip()
            if cleaned:
                cfg["proxy_backend_api_key"] = cleaned
            else:
                cfg.pop("proxy_backend_api_key", None)
        if proxy_model_map is not None:
            cfg["proxy_model_map"] = proxy_model_map
        if proxy_context_window is not None:
            cfg["proxy_context_window"] = int(proxy_context_window)
        if proxy_max_completion_tokens is not None:
            cfg["proxy_max_completion_tokens"] = int(proxy_max_completion_tokens)
        _save_config(cfg)
        if effective_pack is not None:
            ui_cfg = _load_ui_config()
            ui_cfg["ui_profile"] = effective_pack
            ui_cfg["ui_pack"] = effective_pack
            _save_ui_config(ui_cfg)
    _settings_debug("set_runtime_config_done")


def get_bra_root() -> Path:
    """Get the current BRA root directory."""
    global _bra_root
    if _bra_root is not None:
        _settings_debug("get_bra_root_cached", bra_root=str(_bra_root))
        return _bra_root

    # Try loading from config file
    config = _load_config()
    if config.get("bra_dir"):
        path = Path(config["bra_dir"])
        if path.exists() and (path / "body").exists():
            _bra_root = path
            _settings_debug("get_bra_root_config", bra_root=str(_bra_root))
            return _bra_root

    # Fall back to default
    _settings_debug("get_bra_root_default", bra_root=str(_DEFAULT_BRA_ROOT))
    return _DEFAULT_BRA_ROOT


def set_bra_root(path: str | Path) -> bool:
    """Set the BRA root directory.

    Args:
        path: Path to BRA project root (containing body/ directory)

    Returns:
        True if valid and set, False if invalid
    """
    global _bra_root

    path = Path(path).expanduser().resolve()
    _settings_debug("set_bra_root_start", path=str(path))

    # Validate - must have body/ subdirectory
    if not path.exists():
        _settings_debug("set_bra_root_fail", reason="path_missing", path=str(path))
        return False
    if not (path / "body").exists():
        _settings_debug("set_bra_root_fail", reason="missing_body", path=str(path))
        return False

    _bra_root = path

    # Save to config
    config = _load_config()
    config["bra_dir"] = str(path)
    _save_config(config)

    _settings_debug("set_bra_root_ok", path=str(path))
    return True


def get_config_path() -> Path | None:
    """Get the currently configured BRA path from config file."""
    config = _load_config()
    if config.get("bra_dir"):
        out = Path(config["bra_dir"])
        _settings_debug("get_config_path", found=True, path=str(out))
        return out
    _settings_debug("get_config_path", found=False)
    return None


# Dynamic path properties
def _get_body_root() -> Path:
    return get_bra_root() / "body"

def _get_layer1() -> Path:
    return _get_body_root() / "layer1"

def _get_layer2() -> Path:
    return _get_body_root() / "layer2-templates"

def _get_layer3() -> Path:
    return _get_body_root() / "layer3-engagement"

def _get_bra_state() -> Path:
    return _get_body_root() / ".bra"


# For backwards compatibility, expose as module-level variables
# These are now dynamic via __getattr__
class _DynamicSettings:
    @property
    def BRA_ROOT(self) -> Path:
        return get_bra_root()

    @property
    def BODY_ROOT(self) -> Path:
        return _get_body_root()

    @property
    def SCRIPTS_DIR(self) -> Path:
        return _get_body_root() / "layer1" / "scripts"

    @property
    def HOOKS_DIR(self) -> Path:
        return _get_body_root() / "layer1" / "hooks"

    @property
    def LIB_DIR(self) -> Path:
        return _get_body_root() / "layer1" / "lib"

    @property
    def LAYER1(self) -> Path:
        return _get_layer1()

    @property
    def LAYER2(self) -> Path:
        return _get_layer2()

    @property
    def LAYER3(self) -> Path:
        return _get_layer3()

    @property
    def BRA_STATE(self) -> Path:
        return _get_bra_state()

    @property
    def APPROVALS_DIR(self) -> Path:
        return _get_bra_state() / "approvals"

    @property
    def LOGS_DIR(self) -> Path:
        return _get_bra_state() / "logs"

    @property
    def ARTIFACTS_DIR(self) -> Path:
        return _get_bra_state() / "artifacts"


_settings = _DynamicSettings()

# For direct access, use these functions or the _settings object
# Module-level access is handled by __getattr__ below
def __getattr__(name: str):
    """Allow module-level access to dynamic settings."""
    if hasattr(_settings, name):
        return getattr(_settings, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
