"""Alembic migration verification — ensures `upgrade head` creates all expected tables."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sqlalchemy import create_engine, text

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestAlembicMigration:
    def test_initial_migration_applies(self, tmp_path: Path) -> None:
        # 1. Prepare a fresh sqlite DB path
        db_dir = tmp_path / "data"
        db_dir.mkdir()
        db_file = db_dir / "acme.db"
        db_url = f"sqlite:///{db_file}"

        # 2. Write a minimal alembic.ini that points at our temp database
        ini_content = f"""\
[alembic]
script_location = {PROJECT_ROOT}/alembic
prepend_sys_path = .
path_separator = os
sqlalchemy.url = {db_url}

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARNING
handlers = console
qualname =

[logger_sqlalchemy]
level = WARNING
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""  # noqa: E501
        ini_path = tmp_path / "alembic_test.ini"
        ini_path.write_text(ini_content, encoding="utf-8")

        # 3. Run alembic upgrade head in a subprocess pointing at our temp config
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        result = subprocess.run(
            [".venv/bin/alembic", "-c", str(ini_path), "upgrade", "head"],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}"
        )

        # 4. Verify that all expected tables were created by the migration
        engine = create_engine(db_url)
        try:
            with engine.connect() as conn:
                table_names = {
                    row[0]
                    for row in conn.execute(
                        text("SELECT name FROM sqlite_master WHERE type='table'")
                    )
                }
        finally:
            engine.dispose()

        expected_tables = {
            "alembic_version",
            "certificates",
            "events",
            "renewal_attempts",
            "webhook_configs",
        }
        assert expected_tables.issubset(table_names), (
            f"Missing tables {expected_tables - table_names}; found {table_names}"
        )
