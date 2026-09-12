from engine.services.database import Database


def test_database_initializes(tmp_path) -> None:
    database_path = tmp_path / "test.db"

    database = Database(database_path)
    database.initialize()

    with database.connect() as connection:
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

    table_names = {row["name"] for row in tables}

    assert "assets" in table_names
    assert "assessments" in table_names
    assert "scan_results" in table_names
    assert "services" in table_names
    assert "findings" in table_names
