"""Keep scanner fixture persistence out of the developer's working database."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_scanner_database(tmp_path):
    from raveneye_pkg import database

    database.close()
    database.initialize({"database_path": str(tmp_path / "scanner-fixture.db")})
    try:
        yield
    finally:
        database.close()
