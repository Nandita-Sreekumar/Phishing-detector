import logging
from datetime import datetime, timezone

import aiosqlite

from src.config import settings

logger = logging.getLogger(__name__)


async def init_database():
    """Initialize the database schema."""
    db_path = settings.database_url.replace("sqlite:///", "")

    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                raw_analysis TEXT NOT NULL
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                signal_name TEXT NOT NULL,
                signal_score REAL NOT NULL,
                signal_weight REAL NOT NULL,
                description TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ioc TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)

        await db.commit()

    logger.info(f"Database initialized at {db_path}")


async def save_scan_result(assessment: dict):
    """Save scan result to database."""
    db_path = settings.database_url.replace("sqlite:///", "")

    async with aiosqlite.connect(db_path) as db:
        # Save scan
        await db.execute(
            """
            INSERT INTO scans (scan_id, scan_type, timestamp, overall_score, risk_level, confidence, raw_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment["scan_id"],
                assessment["scan_type"],
                assessment["timestamp"],
                assessment["overall_score"],
                assessment["risk_level"],
                assessment["confidence"],
                str(assessment.get("raw_analysis", {}))
            )
        )

        # Save signals
        for signal in assessment.get("signals", []):
            await db.execute(
                """
                INSERT INTO signals (scan_id, signal_name, signal_score, signal_weight, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    assessment["scan_id"],
                    signal["name"],
                    signal["score"],
                    signal["weight"],
                    signal["description"]
                )
            )

        # Save IOCs
        for ioc in assessment.get("iocs", []):
            await db.execute(
                """
                INSERT INTO iocs (scan_id, ioc)
                VALUES (?, ?)
                """,
                (assessment["scan_id"], ioc)
            )

        await db.commit()


async def get_recent_scans(limit: int = 50) -> list[dict]:
    """Get recent scan results."""
    db_path = settings.database_url.replace("sqlite:///", "")

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            """
            SELECT * FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_dashboard_stats() -> dict:
    """Get statistics for dashboard."""
    db_path = settings.database_url.replace("sqlite:///", "")

    async with aiosqlite.connect(db_path) as db:
        # Total scans
        async with db.execute("SELECT COUNT(*) FROM scans") as cursor:
            total = (await cursor.fetchone())[0]

        # Scans by type
        async with db.execute(
            "SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type"
        ) as cursor:
            by_type = {row[0]: row[1] for row in await cursor.fetchall()}

        # Scans by risk
        async with db.execute(
            "SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level"
        ) as cursor:
            by_risk = {row[0]: row[1] for row in await cursor.fetchall()}

        # Average score
        async with db.execute("SELECT AVG(overall_score) FROM scans") as cursor:
            avg_score = (await cursor.fetchone())[0] or 0

        # Recent threats (last 7 days, high risk)
        seven_days_ago = datetime.now(timezone.utc).isoformat()
        async with db.execute(
            """
            SELECT COUNT(*) FROM scans
            WHERE risk_level IN ('phishing', 'likely_phishing')
            """,
        ) as cursor:
            recent_threats = (await cursor.fetchone())[0]

        return {
            "total_scans": total,
            "scans_by_type": by_type,
            "scans_by_risk": by_risk,
            "recent_threats": recent_threats,
            "avg_threat_score": round(avg_score, 1)
        }