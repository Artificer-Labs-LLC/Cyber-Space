#!/usr/bin/env python3
"""Examiner gate 4 belt (ART-29): _log_name_conflict audit-trail hardening.

r4 (Examiner's 09:20 EDT block on 969a8f2): both failure cases now go
through the function's OWN code paths with real assertions —
cursor-patched, never table-dropped, never raw SQL outside the function.

1. OperationalError: one conflict INSERT in a three-record ingest batch is
   forced to fail with OperationalError (the cursor raises on that one
   INSERT; everything else delegates to the real DB). Asserts: the failure
   is logged, _name_conflict_error_count rises by exactly 1, the call does
   not raise, AND every other record in the batch is actually in the DB
   (the old version only proved the call didn't raise and left the
   "other records committed" claim as a comment).
2. IntegrityError: the early-return dedup check is spoofed to report "no
   existing row" while the real INSERT fires the UNIQUE constraint — so
   the function's OWN `except sqlite3.IntegrityError` branch executes.
   Asserts: no raise, counter untouched, still one row. (The old version
   returned early, then ran a raw INSERT outside the function — the branch
   under test never ran.)
"""
import io
import logging
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core


def make_conn():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE name_conflicts ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL, incumbent_pubkey TEXT NOT NULL,"
        " incumbent_issued_at TEXT NOT NULL,"
        " challenger_pubkey TEXT NOT NULL,"
        " challenger_issued_at TEXT NOT NULL,"
        " challenger_expires_at TEXT NOT NULL,"
        " reason TEXT NOT NULL, recorded_at TEXT NOT NULL,"
        " challenger_signature TEXT NOT NULL DEFAULT '',"
        " signed_payload BLOB,"
        " UNIQUE(name, challenger_pubkey))"
    )
    conn.execute(
        "CREATE TABLE name_conflict_overflow ("
        " name TEXT PRIMARY KEY,"
        " overflow_count INTEGER NOT NULL DEFAULT 0)"
    )
    return conn


def make_claim(pubkey, issued="2026-10-12T00:00:00+00:00"):
    return {
        "node_pubkey": pubkey,
        "issued_at": issued,
        "expires_at": "2027-10-12T00:00:00+00:00",
    }


class _ConnProxy:
    """Thin proxy over a sqlite3.Connection: the belt can intercept
    execute() without touching product code."""
    def __init__(self, real):
        self._real = real

    def _intercept(self, sql, params):
        return self._real.execute(sql, params)

    def execute(self, sql, params=()):
        return self._intercept(sql, params)

    def commit(self):
        return self._real.commit()

    def __getattr__(self, name):
        return getattr(self._real, name)


class _FailInsertOnce(_ConnProxy):
    """Raises OperationalError on the next INSERT INTO name_conflicts,
    then disarms. Everything else delegates to the real DB."""
    def __init__(self, real):
        super().__init__(real)
        self.armed = False

    def _intercept(self, sql, params):
        if self.armed and sql.lstrip().upper().startswith(
                "INSERT INTO NAME_CONFLICTS"):
            self.armed = False
            raise sqlite3.OperationalError(
                "simulated transient write failure")
        return self._real.execute(sql, params)


class _SpoofDedupMiss(_ConnProxy):
    """Reports 'no existing row' from the early-return dedup SELECT, so the
    INSERT below it runs against the real DB — where the UNIQUE constraint
    fires and the function's OWN except IntegrityError branch executes."""
    def _intercept(self, sql, params):
        if sql.lstrip().upper().startswith(
                "SELECT ID FROM NAME_CONFLICTS"):
            class _NoRow:
                def fetchone(self):
                    return None

                def fetchall(self):
                    return []
            return _NoRow()
        return self._real.execute(sql, params)


def test_operational_error_logged_counted_ingest_continues():
    real = make_conn()
    proxy = _FailInsertOnce(real)
    incumbent = make_claim("incumbent-pubkey")
    challengers = [make_claim(f"challenger-{i}") for i in range(3)]

    # Capture log output.
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    root_logger = logging.getLogger()
    old_level = root_logger.level
    root_logger.setLevel(logging.WARNING)
    root_logger.addHandler(handler)

    # Reset the counter.
    core._name_conflict_error_count = 0
    before = core._name_conflict_error_count

    # One ingest batch of three: first commits, second's INSERT fails
    # mid-function, third must still commit. None of the calls may raise.
    core._log_name_conflict(proxy, "batchname", incumbent, challengers[0],
                            "r0")
    proxy.armed = True
    core._log_name_conflict(proxy, "batchname", incumbent, challengers[1],
                            "r1")  # OperationalError inside; must not raise
    core._log_name_conflict(proxy, "batchname", incumbent, challengers[2],
                            "r2")

    root_logger.removeHandler(handler)
    root_logger.setLevel(old_level)
    log_output = log_stream.getvalue()

    # 1. The failure was logged.
    assert "name_conflict log failed" in log_output, (
        f"expected log message, got: {log_output!r}")
    assert "batchname" in log_output, (
        f"expected name in log message, got: {log_output!r}")

    # 2. Counter rose by exactly 1.
    after = core._name_conflict_error_count
    assert after - before == 1, (
        f"counter rose by {after - before}, expected 1")

    # 3. Every OTHER record in the batch is in the DB; the failed one is
    #    not (its INSERT raised). This is the real assertion the old
    #    version left as a comment.
    rows = {r[0] for r in real.execute(
        "SELECT challenger_pubkey FROM name_conflicts "
        "WHERE name='batchname'")}
    assert rows == {"challenger-0", "challenger-2"}, (
        f"other records must commit, failed one must not: {rows!r}")
    print("PASS: OperationalError logged, counter +1, batch others commit")


def test_integrity_error_silently_ignored():
    real = make_conn()
    proxy = _SpoofDedupMiss(real)
    incumbent = make_claim("incumbent-pubkey")
    challenger = make_claim("challenger-dup")

    core._name_conflict_error_count = 0
    before = core._name_conflict_error_count

    # First insert lands normally through the function.
    core._log_name_conflict(real, "dupname", incumbent, challenger, "r1")

    # Second: the dedup check is spoofed to miss, so the INSERT runs
    # against the real UNIQUE(name, challenger_pubkey) constraint and the
    # function's OWN `except sqlite3.IntegrityError` branch executes —
    # no early return, no raw SQL outside the function.
    core._log_name_conflict(proxy, "dupname", incumbent, challenger,
                            "r1")  # must not raise

    after = core._name_conflict_error_count
    assert after == before, (
        f"IntegrityError must not touch counter (before={before}, "
        f"after={after})")

    # Still exactly one row.
    n = real.execute(
        "SELECT COUNT(*) FROM name_conflicts WHERE name='dupname'"
    ).fetchone()[0]
    assert n == 1, f"expected 1 row, got {n}"
    print("PASS: function's own except IntegrityError branch, "
          "silently ignored, counter untouched")


if __name__ == "__main__":
    test_operational_error_logged_counted_ingest_continues()
    test_integrity_error_silently_ignored()
    print("Gate 4 belt: 2/2 green")
