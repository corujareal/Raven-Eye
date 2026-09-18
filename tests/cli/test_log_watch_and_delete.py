import asyncio
from pathlib import Path
import pytest
from raveneye.cli.log_viewer import safe_delete, watch


def test_safe_delete_requires_file_and_uses_unique_trash(tmp_path):
    f = tmp_path / 'a.log'
    f.write_text('x')
    trash = tmp_path / '.trash'
    out = safe_delete(str(f), str(trash), 'SIM')
    assert not f.exists()
    assert out.exists()
    assert out.parent == trash
    assert out.name.endswith('_a.log')


def test_safe_delete_rejects_directory_and_wrong_confirmation(tmp_path):
    d = tmp_path / 'dir'
    d.mkdir()
    with pytest.raises(PermissionError):
        safe_delete(str(d), str(tmp_path / '.trash'), 'NAO')
    with pytest.raises(IsADirectoryError):
        safe_delete(str(d), str(tmp_path / '.trash'), 'SIM')


def test_watch_rejects_non_positive_interval(tmp_path):
    f = tmp_path / 'x.log'
    f.write_text('x')
    with pytest.raises(ValueError):
        asyncio.run(asyncio.wait_for(watch(str(f), 0), timeout=.1))
