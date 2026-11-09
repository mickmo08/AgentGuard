"""Alembic environment. The connection is passed in by agentguard.server.migrate."""
from alembic import context
from sqlalchemy import create_engine

from agentguard.server.db import Base

config = context.config
target_metadata = Base.metadata


def run() -> None:
    connection = config.attributes.get("connection")
    if connection is None:  # alembic CLI: use sqlalchemy.url from alembic.ini / -x url=...
        url = context.get_x_argument(as_dictionary=True).get("url") or config.get_main_option("sqlalchemy.url")
        with create_engine(url).connect() as conn:
            _migrate(conn)
            conn.commit()
    else:
        _migrate(connection)


def _migrate(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite needs table rebuilds for ALTER
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


run()
