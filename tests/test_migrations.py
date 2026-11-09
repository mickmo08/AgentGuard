"""Migrations must produce exactly the schema the models describe."""
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from agentguard.server.db import Base
from agentguard.server.migrate import current_revision, migrate
from tests.conftest import PG_URL, _reset_postgres


def _check(url: str) -> None:
    engine = create_engine(url)
    migrate(engine)
    migrate(engine)  # idempotent
    assert current_revision(engine) is not None
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    engine.dispose()
    assert diff == [], f"models and migrations disagree: {diff}"


def test_sqlite_schema_matches_models(tmp_path):
    _check(f"sqlite:///{tmp_path}/m.db")


def test_postgres_schema_matches_models():
    import pytest

    if not PG_URL:
        pytest.skip("AGENTGUARD_TEST_POSTGRES_URL not set")
    _reset_postgres(PG_URL)
    _check(PG_URL)
