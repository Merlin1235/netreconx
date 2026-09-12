from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class Database:
    """SQLite persistence layer for NetReconX."""

    def __init__(self, database_path: str | Path = "netreconx.db") -> None:
        self.database_path = Path(database_path)

    def connect(self) -> sqlite3.Connection:
        """Create a database connection."""

        connection = sqlite3.connect(self.database_path)

        connection.row_factory = sqlite3.Row

        return connection

    def initialize(self) -> None:
        """Create the NetReconX database schema."""

        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY (asset_id)
                        REFERENCES assets(id)
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    latency_ms REAL,
                    error TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES assessments(id)
                );

                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    product TEXT,
                    banner TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES assessments(id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    risk INTEGER NOT NULL,
                    evidence TEXT,
                    FOREIGN KEY (assessment_id)
                        REFERENCES assessments(id)
                );
                """
            )

    def execute(
        self,
        query: str,
        parameters: tuple[Any, ...] = (),
    ) -> sqlite3.Cursor:
        """Execute a database query."""

        with self.connect() as connection:
            cursor = connection.execute(query, parameters)
            connection.commit()
            return cursor

