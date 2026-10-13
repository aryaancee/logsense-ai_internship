"""Live engine: one background thread keeps every user's sources (cloud, URL, demo stream) flowing into that user's own database."""
import json, threading, time
from datetime import datetime, timezone
from . import auth, core, sources

KINDS = ("demo", "cloudwatch", "gcp", "s3", "file", "url")
_stop, _th, _due, _fails = threading.Event(), None, {}, {}


def _now(): return datetime.now(timezone.utc).strftime(core.ISO)
def _k(sid): return (core._path(), sid)


def add(kind, params, interval=15):
    if kind not in KINDS: raise ValueError(f"kind must be one of {KINDS}")
    c = core.db()
    cur = c.execute("INSERT INTO sources(kind,params,interval,enabled,status) VALUES(?,?,?,1,'starting')", (kind, json.dumps(params or {}), max(3, min(int(interval), 3600))))
    c.commit(); return cur.lastrowid


def listing():
    out = []
    for r in core.db().execute("SELECT * FROM sources ORDER BY id"):
        p = json.loads(r["params"]); secured = bool(p.pop("_enc", None))  # encrypted keys are never sent back to the browser
        out.append(dict(r, params=p, secured=secured))
    return out


def poll_one(sid, now=None):
    c = core.db(); r = c.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
    if not r: return False
    try:
        data, cursor = sources.poll(r["kind"], json.loads(r["params"]), r["cursor"], now)
        n = sum(core.ingest(lines, svc).get("ingested", 0) for svc, lines in data.items())
        c.execute("UPDATE sources SET cursor=?, last_run=?, status='running', error=NULL, total=total+? WHERE id=?", (cursor, _now(), n, sid)); _fails[_k(sid)] = 0
    except Exception as e:  # one failing source never stops the others; it backs off and shows its error
        _fails[_k(sid)] = _fails.get(_k(sid), 0) + 1
        c.execute("UPDATE sources SET last_run=?, status='error', error=? WHERE id=?", (_now(), f"{type(e).__name__}: {e}"[:300], sid))
    c.commit(); c.close(); return True


def toggle(sid, enabled):
    c = core.db(); c.execute("UPDATE sources SET enabled=?, status=? WHERE id=?", (int(enabled), "running" if enabled else "paused", sid)); c.commit(); _due.pop(_k(sid), None)


def remove(sid):
    c = core.db(); c.execute("DELETE FROM sources WHERE id=?", (sid,)); c.commit(); _due.pop(_k(sid), None); _fails.pop(_k(sid), None)


def _tick():
    for path in auth.poll_paths():
        tok = core.use_db(path)
        try:
            c = core.db(); rows = c.execute("SELECT id, interval FROM sources WHERE enabled=1").fetchall(); c.close()
            for r in rows:
                key = (path, r["id"])
                if time.time() >= _due.get(key, 0):
                    poll_one(r["id"])
                    f = _fails.get(key, 0)
                    _due[key] = time.time() + (min(r["interval"] * 2 ** f, 300) if f else r["interval"])
        finally:
            core._ctx.reset(tok)


def _loop():
    last_clean = 0
    while not _stop.wait(1.0):
        try:
            _tick()
            if time.time() - last_clean > 600: auth.cleanup(); last_clean = time.time()
        except Exception:
            pass


def start():
    global _th
    if not running():
        _stop.clear(); _th = threading.Thread(target=_loop, daemon=True, name="logsense-live"); _th.start()


def stop(): _stop.set()
def running(): return bool(_th and _th.is_alive() and not _stop.is_set())
