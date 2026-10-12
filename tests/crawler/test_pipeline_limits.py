from raveneye.core.config import RavenConfig
from raveneye.crawler.dedup import SimHashIndex


def test_pipeline_limits_defaults():
    c = RavenConfig()
    assert c.queue_size == 512
    assert c.connection_limit == 200
    assert c.max_response_bytes == 2_000_000
    assert c.dedup_cache_size == 8192


def test_simhash_index_is_bounded():
    idx = SimHashIndex(max_entries=128)
    for i in range(1000):
        idx.add(f'unique page {i}')
    assert len(idx._hashes) == 128
