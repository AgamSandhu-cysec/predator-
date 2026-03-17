"""
brain/feedback_logger.py

SQLite-backed feedback store.  Records every exploit attempt with its feature
vector and outcome so the Adaptive ML Engine and RL Selector can learn.
"""
import sqlite3
import json
import hashlib
import datetime
import os
from utils.logger import get_logger
logger = get_logger('FeedbackLogger')
_SCHEMA = "\nCREATE TABLE IF NOT EXISTS exploit_attempts (\n    id            INTEGER PRIMARY KEY AUTOINCREMENT,\n    timestamp     TEXT    NOT NULL,\n    exploit_name  TEXT    NOT NULL,\n    feature_json  TEXT    NOT NULL,\n    success       INTEGER NOT NULL,\n    duration_sec  REAL    DEFAULT 0,\n    error_snippet TEXT    DEFAULT '',\n    target_hash   TEXT    DEFAULT ''\n);\n\nCREATE TABLE IF NOT EXISTS thompson_counts (\n    exploit_name  TEXT    PRIMARY KEY,\n    success_count INTEGER DEFAULT 0,\n    failure_count INTEGER DEFAULT 0,\n    last_updated  TEXT    DEFAULT ''\n);\n\nCREATE INDEX IF NOT EXISTS idx_exploit ON exploit_attempts(exploit_name);\nCREATE INDEX IF NOT EXISTS idx_success  ON exploit_attempts(success);\n"

class FeedbackLogger:
    """
    Logs exploit attempts to SQLite and maintains Thompson sampling counts.

    Thread-safe: uses a new connection per call (sqlite3's default isolation).
    """

    def __init__(self, db_path: str='brain/data/feedback.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def log(self, exploit_name: str, feature_vec: list, success: bool, duration: float=0.0, error: str='', target_id: str='') -> None:
        """
        Record one exploit attempt.

        Parameters
        ----------
        exploit_name : module name e.g. 'sudo_abuse'
        feature_vec  : ordered list matching brain.feature_schema.FEATURE_NAMES
        success      : True if uid=0 confirmed
        duration     : seconds elapsed
        error        : first portion of error output (will be truncated to 500 chars)
        target_id    : raw target identifier; stored only as a short hash
        """
        target_hash = hashlib.sha256(target_id.encode()).hexdigest()[:16]
        ts = datetime.datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute('INSERT INTO exploit_attempts (timestamp, exploit_name, feature_json, success, duration_sec, error_snippet, target_hash) VALUES (?, ?, ?, ?, ?, ?, ?)', (ts, exploit_name, json.dumps(feature_vec), 1 if success else 0, duration, error[:500], target_hash))
            if success:
                conn.execute('INSERT INTO thompson_counts(exploit_name, success_count, failure_count, last_updated)\n                       VALUES(?, 1, 0, ?)\n                       ON CONFLICT(exploit_name) DO UPDATE SET\n                           success_count = success_count + 1,\n                           last_updated  = excluded.last_updated', (exploit_name, ts))
            else:
                conn.execute('INSERT INTO thompson_counts(exploit_name, success_count, failure_count, last_updated)\n                       VALUES(?, 0, 1, ?)\n                       ON CONFLICT(exploit_name) DO UPDATE SET\n                           failure_count = failure_count + 1,\n                           last_updated  = excluded.last_updated', (exploit_name, ts))
        logger.info(f'Logged: {exploit_name} success={success} duration={duration:.1f}s')

    def get_thompson_counts(self) -> dict:
        """Return {exploit_name: (success_count, failure_count)}."""
        with self._conn() as conn:
            rows = conn.execute('SELECT exploit_name, success_count, failure_count FROM thompson_counts').fetchall()
        return {r[0]: (r[1], r[2]) for r in rows}

    def get_recent_attempts(self, n: int=500) -> list:
        """
        Return list of (exploit_name, feature_vec, success) for retraining.
        """
        with self._conn() as conn:
            rows = conn.execute('SELECT exploit_name, feature_json, success FROM exploit_attempts ORDER BY id DESC LIMIT ?', (n,)).fetchall()
        return [(r[0], json.loads(r[1]), bool(r[2])) for r in rows]

    def get_stats(self) -> dict:
        """Return aggregate success rate per exploit (for UI display)."""
        with self._conn() as conn:
            rows = conn.execute('SELECT exploit_name, SUM(success) as wins, COUNT(*) as total FROM exploit_attempts GROUP BY exploit_name').fetchall()
        return {r[0]: {'wins': r[1], 'total': r[2], 'rate': round(r[1] / r[2], 3) if r[2] else 0.0} for r in rows}

    def total_attempts(self) -> int:
        with self._conn() as conn:
            return conn.execute('SELECT COUNT(*) FROM exploit_attempts').fetchone()[0]

    def export_anonymised(self, n: int=200) -> list:
        """
        Export anonymised data for crowd-sharing.
        Strips target hash, keeps only feature_vec hash + outcome.
        """
        attempts = self.get_recent_attempts(n)
        result = []
        for exploit_name, fv, success in attempts:
            fv_hash = hashlib.sha256(json.dumps(fv, sort_keys=True).encode()).hexdigest()[:20]
            result.append({'exploit_name': exploit_name, 'success': int(success), 'feature_vec_hash': fv_hash})
        return result
