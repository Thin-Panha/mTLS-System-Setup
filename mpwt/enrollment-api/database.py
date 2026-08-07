"""
PostgreSQL connection pool using psycopg2.
All helpers return plain dicts / lists so routes stay DB-agnostic.
"""
import psycopg2
import psycopg2.extras
from psycopg2 import pool as pg_pool
import config

_pool: pg_pool.ThreadedConnectionPool | None = None


def init_pool(min_conn: int = 1, max_conn: int = 10) -> None:
    global _pool
    _pool = pg_pool.ThreadedConnectionPool(
        min_conn,
        max_conn,
        dsn=config.DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def get_conn():
    if _pool is None:
        raise RuntimeError("DB pool not initialised — call init_pool() first")
    return _pool.getconn()


def put_conn(conn) -> None:
    if _pool:
        _pool.putconn(conn)


# ── Context manager ────────────────────────────────────────────────────────────

class _DBConn:
    """with get_db() as db: db.execute(...)"""
    def __enter__(self):
        self._conn = get_conn()
        self._cur  = self._conn.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._conn.rollback()
        else:
            self._conn.commit()
        self._cur.close()
        put_conn(self._conn)

    def execute(self, sql: str, params=None):
        self._cur.execute(sql, params)

    def fetchone(self) -> dict | None:
        row = self._cur.fetchone()
        return dict(row) if row else None

    def fetchall(self) -> list[dict]:
        return [dict(r) for r in self._cur.fetchall()]

    def rowcount(self) -> int:
        return self._cur.rowcount


def get_db() -> _DBConn:
    return _DBConn()


# ── Convenience helpers ────────────────────────────────────────────────────────

def query_one(sql: str, params=None) -> dict | None:
    with get_db() as db:
        db.execute(sql, params)
        return db.fetchone()


def query_all(sql: str, params=None) -> list[dict]:
    with get_db() as db:
        db.execute(sql, params)
        return db.fetchall()


def execute_db(sql: str, params=None) -> int:
    """Run INSERT/UPDATE/DELETE, return rowcount."""
    with get_db() as db:
        db.execute(sql, params)
        return db.rowcount()


def execute_returning(sql: str, params=None) -> dict | None:
    """Run INSERT … RETURNING *, return the new row."""
    with get_db() as db:
        db.execute(sql, params)
        return db.fetchone()
