from __future__ import annotations
import json, os
from pathlib import Path
from typing import Any
try:
    from pydantic import BaseModel, Field, ConfigDict
    _PYDANTIC_AVAILABLE = True
except ImportError:
    _PYDANTIC_AVAILABLE = False
    class ConfigDict(dict):
        pass
    class _FieldSpec:
        def __init__(self, default=None, default_factory=None, **_kwargs):
            self.default = default
            self.default_factory = default_factory
    def Field(default=None, default_factory=None, **kwargs):
        return _FieldSpec(default, default_factory, **kwargs)
    class BaseModel:
        model_config = ConfigDict()
        def __init__(self, **kwargs):
            annotations = getattr(self, "__annotations__", {})
            for name in annotations:
                value = kwargs.get(name, None)
                if value is None:
                    spec = getattr(type(self), name, None)
                    if isinstance(spec, _FieldSpec):
                        value = spec.default_factory() if spec.default_factory else spec.default
                    elif hasattr(type(self), name):
                        value = getattr(type(self), name)
                if name == "scope" and isinstance(value, dict):
                    value = ScopeConfig(**value)
                setattr(self, name, value)
        @classmethod
        def model_validate(cls, data):
            return cls(**(data or {}))

class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra='ignore')
    include_domains: list[str] = Field(default_factory=list)
    include_paths: list[str] = Field(default_factory=list)
    include_regex: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

class RavenConfig(BaseModel):
    model_config = ConfigDict(extra='ignore')
    version: str = '6.6.6'
    user_agent: str = 'RavenEye/6.6.6'
    concurrency: int = Field(default=50, ge=1, le=1000)
    requests_per_second: float = Field(default=10.0, gt=0, le=10000)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    verify_tls: bool = True
    max_pages: int = Field(default=1000, ge=1)
    queue_size: int = Field(default=512, ge=32, le=100000)
    worker_count: int = Field(default=50, ge=1, le=1000)
    connection_limit: int = Field(default=200, ge=1, le=5000)
    max_response_bytes: int = Field(default=2_000_000, ge=1024, le=50_000_000)
    dedup_cache_size: int = Field(default=8192, ge=128, le=1_000_000)
    crawl_max_depth: int = Field(default=8, ge=0, le=128)
    retry_attempts: int = Field(default=2, ge=0, le=8)
    retry_backoff_seconds: float = Field(default=0.25, ge=0, le=60)
    adaptive_concurrency: bool = True
    cve_records_path: str | None = None
    multi_target_enabled: bool = False
    max_targets: int = Field(default=50, ge=1, le=500)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    output_dir: str = 'output'
    database_path: str = 'data/raveneye.db'
    log_path: str = 'output/raveneye.jsonl'
    model_config = ConfigDict(extra='ignore', env_prefix='RAVENEYE_')

def _load_file(p: Path) -> dict[str, Any]:
    if p.suffix.lower() in {'.yaml', '.yml'}:
        import yaml
        return yaml.safe_load(p.read_text(encoding='utf-8')) or {}
    if p.suffix.lower() == '.json':
        return json.loads(p.read_text(encoding='utf-8'))
    if p.suffix.lower() == '.toml':
        import tomllib
        return tomllib.loads(p.read_text(encoding='utf-8'))
    raise ValueError('Configuração deve ser YAML, TOML ou JSON')

def _env_overrides() -> dict[str, Any]:
    out: dict[str, Any] = {}
    mapping = {
        'RAVENEYE_CONCURRENCY':'concurrency','RAVENEYE_REQUESTS_PER_SECOND':'requests_per_second',
        'RAVENEYE_TIMEOUT_SECONDS':'timeout_seconds','RAVENEYE_MAX_PAGES':'max_pages','RAVENEYE_QUEUE_SIZE':'queue_size','RAVENEYE_WORKER_COUNT':'worker_count','RAVENEYE_CONNECTION_LIMIT':'connection_limit','RAVENEYE_MAX_RESPONSE_BYTES':'max_response_bytes','RAVENEYE_DEDUP_CACHE_SIZE':'dedup_cache_size',
        'RAVENEYE_OUTPUT_DIR':'output_dir','RAVENEYE_DATABASE_PATH':'database_path','RAVENEYE_LOG_PATH':'log_path',
        'RAVENEYE_MAX_TARGETS':'max_targets','RAVENEYE_CRAWL_MAX_DEPTH':'crawl_max_depth',
        'RAVENEYE_RETRY_ATTEMPTS':'retry_attempts','RAVENEYE_RETRY_BACKOFF_SECONDS':'retry_backoff_seconds',
        'RAVENEYE_CVE_RECORDS_PATH':'cve_records_path',
    }
    casts = {'concurrency':int,'requests_per_second':float,'timeout_seconds':float,'max_pages':int,'queue_size':int,'worker_count':int,'connection_limit':int,'max_response_bytes':int,'dedup_cache_size':int,'max_targets':int,'crawl_max_depth':int,'retry_attempts':int,'retry_backoff_seconds':float}
    for env,key in mapping.items():
        if env in os.environ:
            out[key] = casts.get(key, lambda x:x)(os.environ[env])
    if 'RAVENEYE_MULTI_TARGET_ENABLED' in os.environ:
        out['multi_target_enabled'] = os.environ['RAVENEYE_MULTI_TARGET_ENABLED'].lower() not in {'0','false','no','off'}
    if 'RAVENEYE_VERIFY_TLS' in os.environ:
        out['verify_tls'] = os.environ['RAVENEYE_VERIFY_TLS'].lower() not in {'0','false','no','off'}
    if 'RAVENEYE_ADAPTIVE_CONCURRENCY' in os.environ:
        out['adaptive_concurrency'] = os.environ['RAVENEYE_ADAPTIVE_CONCURRENCY'].lower() not in {'0','false','no','off'}
    return out

def load_config(path: str | Path | None = None) -> RavenConfig:
    data: dict[str, Any] = {}
    if path:
        p = Path(path)
        if p.exists(): data = _load_file(p)
    data.update(_env_overrides())
    # Never permit configuration files/env to silently change the public release line.
    data['version'] = '6.6.6'
    data.setdefault('user_agent', 'RavenEye/6.6.6')
    return RavenConfig.model_validate(data)
