import tempfile
from pathlib import Path
from raveneye.crawler.dedup import SimHashIndex
from raveneye.crawler.renderers import looks_like_spa
from raveneye.database.migrator import migrate
def test_simhash_near_duplicate():
    idx=SimHashIndex(max_distance=4); assert idx.add('alpha beta gamma delta') is False; assert idx.add('alpha beta gamma delta') is True
def test_spa_detection():
    assert looks_like_spa('<div id="root"></div><script src="app.js"></script>'); assert not looks_like_spa('<html><body>normal page</body></html>')
def test_migrations_are_idempotent():
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'db.sqlite'; assert migrate(str(p))>=1; assert migrate(str(p))==0
