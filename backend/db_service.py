import json
import sqlite3
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "scan_history.db"


def _get_connection():
    """Create a SQLite connection configured to return rows by column name."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


# Current schema version — bump this integer whenever a migration is added.
_SCHEMA_VERSION = 3


def _initialize_database():
    """Create and incrementally migrate all database tables.

    Migration history:
      v1  — initial: scans (id, target, timestamp, result_json, risk_score)
      v2  — async jobs: ADD COLUMN status, progress_text to scans
    """
    DATA_DIR.mkdir(exist_ok=True)
    with _get_connection() as connection:
        # Schema-version tracking table (created unconditionally)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

        # Determine the current applied version
        row = connection.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        current_version = row[0] or 0

        # --- v1 --- base scans table
        if current_version < 1:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    result_json TEXT,
                    risk_score REAL
                )
                """
            )
            connection.execute(
                "INSERT INTO schema_version (version) VALUES (1)"
            )

        # --- v2 --- async-job status columns
        if current_version < 2:
            existing_cols = {
                row[1]
                for row in connection.execute("PRAGMA table_info(scans)").fetchall()
            }
            if "status" not in existing_cols:
                connection.execute(
                    "ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"
                )
            if "progress_text" not in existing_cols:
                connection.execute(
                    "ALTER TABLE scans ADD COLUMN progress_text TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (2)"
            )

        # --- v3 --- drop NOT NULL constraint from result_json so pending scans
        #            (inserted before the background job finishes) can use NULL.
        #            SQLite has no ALTER COLUMN, so we recreate the table.
        if current_version < 3:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans_v3 (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    target          TEXT NOT NULL,
                    timestamp       TEXT NOT NULL,
                    result_json     TEXT,
                    risk_score      REAL,
                    status          TEXT NOT NULL DEFAULT 'completed',
                    progress_text   TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO scans_v3
                    (id, target, timestamp, result_json, risk_score, status, progress_text)
                SELECT  id, target, timestamp, result_json, risk_score, status, progress_text
                FROM    scans
                """
            )
            connection.execute("DROP TABLE scans")
            connection.execute("ALTER TABLE scans_v3 RENAME TO scans")
            connection.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (3)"
            )

        connection.commit()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def create_pending_scan(target: str, timestamp: str) -> int:
    """Insert a placeholder 'pending' row and return its id.

    Called by /start-scan before submitting the job to the background thread
    pool so the frontend gets an id to poll immediately.
    """
    with _get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (target, timestamp, result_json, status, progress_text)
            VALUES (?, ?, NULL, 'pending', 'Queued')
            """,
            (target, timestamp),
        )
        connection.commit()
        return int(cursor.lastrowid)


def save_scan(target: str, timestamp: str, result_json: dict, scan_id: int | None = None) -> int:
    """Persist a completed scan result.

    If *scan_id* is provided the existing row is updated (async path).
    Otherwise a new row is inserted (legacy synchronous path — kept for
    backward compatibility with tests and any direct callers).
    """
    risk_score = result_json.get("risk_score")
    payload = json.dumps(result_json)

    with _get_connection() as connection:
        if scan_id is not None:
            connection.execute(
                """
                UPDATE scans
                SET target = ?, timestamp = ?, result_json = ?, risk_score = ?,
                    status = 'completed', progress_text = 'Scan complete'
                WHERE id = ?
                """,
                (target, timestamp, payload, risk_score, scan_id),
            )
            connection.commit()
            return scan_id

        cursor = connection.execute(
            """
            INSERT INTO scans (target, timestamp, result_json, risk_score,
                               status, progress_text)
            VALUES (?, ?, ?, ?, 'completed', 'Scan complete')
            """,
            (target, timestamp, payload, risk_score),
        )
        connection.commit()
        return int(cursor.lastrowid)


def update_scan_status(scan_id: int, status: str, progress_text: str = "") -> None:
    """Update the job status and optional progress message for an in-flight scan."""
    with _get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET status = ?, progress_text = ?
            WHERE id = ?
            """,
            (status, progress_text, scan_id),
        )
        connection.commit()


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_scan_status(scan_id: int) -> dict | None:
    """Return the status row for a scan (id, status, progress_text, risk_score)."""
    with _get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, target, status, progress_text, risk_score
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
    return dict(row) if row else None


def get_all_scans() -> list[dict]:
    """Return scan history rows without the stored result payload."""
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, target, timestamp, risk_score, status
            FROM scans
            ORDER BY timestamp DESC, id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    """Return a single stored scan row with parsed JSON payload."""
    with _get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, target, timestamp, result_json, risk_score, status, progress_text
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    if result.get("result_json"):
        result["result_json"] = json.loads(result["result_json"])
    else:
        result["result_json"] = None
    return result


def get_scans_by_target(target: str) -> list[dict]:
    """Return all stored scans for a target, newest first, with parsed payloads."""
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, target, timestamp, result_json, risk_score, status
            FROM scans
            WHERE target = ?
            ORDER BY timestamp DESC, id DESC
            """,
            (target,),
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        if item.get("result_json"):
            item["result_json"] = json.loads(item["result_json"])
        else:
            item["result_json"] = None
        results.append(item)
    return results


def update_risk_score(scan_id: int, score: float) -> None:
    """Update the risk score for a previously stored scan row."""
    with _get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET risk_score = ?
            WHERE id = ?
            """,
            (score, scan_id),
        )
        connection.commit()


def _update_result_json(scan_id: int, result_json: dict) -> None:
    """Persist an updated scan payload for an existing scan row."""
    payload = json.dumps(result_json)
    with _get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET result_json = ?
            WHERE id = ?
            """,
            (payload, scan_id),
        )
        connection.commit()


_initialize_database()
