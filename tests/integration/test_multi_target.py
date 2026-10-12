from pathlib import Path
import json
from raveneye.core.targets import normalize_target, normalize_targets
from raveneye.core.config import load_config

def test_normalize_target_and_batch():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target("ftp://example.com") == ""
    b = normalize_targets(["example.com", "https://EXAMPLE.com/", "https://two.example/", "https://two.example"], enabled=True, max_targets=5)
    assert b.urls == ("https://example.com", "https://two.example")
    b2 = normalize_targets(["a.example","b.example"], enabled=False)
    assert len(b2.urls) == 1

def test_target_canonicalization_preserves_query_and_removes_fragment():
    assert normalize_target("HTTPS://Example.com/path/?x=1#frag") == "https://example.com/path?x=1"
    assert normalize_target("http://example.com:80/") == "http://example.com"
    assert normalize_target("https://example.com:443/") == "https://example.com"

def test_legacy_default_has_multi_target_flag():
    from raveneye_pkg.constants import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["multi_target_enabled"] is False
    assert 1 <= DEFAULT_CONFIG["max_targets"] <= 500

def test_core_config_env(monkeypatch):
    monkeypatch.setenv("RAVENEYE_MULTI_TARGET_ENABLED", "true")
    monkeypatch.setenv("RAVENEYE_MAX_TARGETS", "7")
    cfg=load_config()
    assert cfg.multi_target_enabled is True
    assert cfg.max_targets == 7

import asyncio

def test_orchestrator_has_multi_target_method():
    from raveneye.core.orchestrator import RavenOrchestrator
    assert hasattr(RavenOrchestrator, 'full_passive_many')
