"""Schema migrations (Alembic), runnable programmatically or via `agentguard db upgrade`."""
from __future__ import annotations

from importlib import resources

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine


def _config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(resources.files("agentguard").joinpath("migrations")))
    return cfg


def migrate(engine: Engine, revision: str = "head") -> None:
    cfg = _config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, revision)


def current_revision(engine: Engine) -> str | None:
    from alembic.runtime.migration import MigrationContext

    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()
