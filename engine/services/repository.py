from __future__ import annotations

from datetime import datetime, timezone

from engine.assessment import Assessment
from engine.services.database import Database


class AssessmentRepository:
    """Persist NetReconX assessments."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def save(self, assessment: Assessment) -> int:
        """Save an assessment and return its database ID."""

        now = datetime.now(timezone.utc).isoformat()

        with self.database.connect() as connection:
            asset = connection.execute(
                """
                SELECT id
                FROM assets
                WHERE target = ?
                """,
                (assessment.target,),
            ).fetchone()

            if asset is None:
                cursor = connection.execute(
                    """
                    INSERT INTO assets (
                        target,
                        first_seen,
                        last_seen
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        assessment.target,
                        now,
                        now,
                    ),
                )

                asset_id = cursor.lastrowid
            else:
                asset_id = asset["id"]

                connection.execute(
                    """
                    UPDATE assets
                    SET last_seen = ?
                    WHERE id = ?
                    """,
                    (now, asset_id),
                )

            cursor = connection.execute(
                """
                INSERT INTO assessments (
                    asset_id,
                    started_at,
                    completed_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    asset_id,
                    assessment.started_at.isoformat(),
                    (
                        assessment.completed_at.isoformat()
                        if assessment.completed_at
                        else None
                    ),
                ),
            )

            assessment_id = cursor.lastrowid

            for result in assessment.scan_results:
                connection.execute(
                    """
                    INSERT INTO scan_results (
                        assessment_id,
                        port,
                        state,
                        latency_ms,
                        error
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        result.port,
                        result.state,
                        result.latency_ms,
                        result.error,
                    ),
                )

            for finding in assessment.findings:
                connection.execute(
                    """
                    INSERT INTO findings (
                        assessment_id,
                        port,
                        service,
                        title,
                        description,
                        risk,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        finding.port,
                        finding.service,
                        finding.title,
                        finding.description,
                        finding.risk,
                        finding.evidence,
                    ),
                )

            connection.commit()

        return int(assessment_id)
