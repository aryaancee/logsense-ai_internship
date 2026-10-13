"""Accounts: PBKDF2 passwords, signed session cookies, guest demo accounts, one database file per user, AI usage limits, encryption of cloud keys."""
import base64, glob, hashlib, hmac, os, re, secrets, sqlite3, time
from contextlib import contextmanager
from datetime import date
from . import core

COOKIE = "ls_session"
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_att, _seen = {}, {}


class Throttled(ValueError):
    pass


def data_dir():
    d = os.getenv("LOGSENSE_DATA", "data"); os.makedirs(os.path.join(d, "users"), exist_ok=True); return d


def _adb():
    c = sqlite3.connect(os.path.join(data_dir(), "auth.db"), timeout=30); c.row_factory = sqlite3.Row
    c.executescript("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE, pw TEXT, guest INTEGER DEFAULT 0, created REAL, last_seen REAL);"
                    "CREATE TABLE IF NOT EXISTS usage(uid TEXT, day TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(uid, day));")
    return c


def secret():
    s = os.getenv("LOGSENSE_SECRET")
    if s: return s.encode()
    f = os.path.join(data_dir(), "secret.key")  # fallback for local use; on a server set LOGSENSE_SECRET
    if not os.path.exists(f):
        with open(f, "w") as h: h.write(secrets.token_hex(32))
    return open(f).read().strip().encode()


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt).split("$")[1], h)


_DUMMY = hash_pw("dummy-password-for-timing")


def user(uid):
    r = _adb().execute("SELECT id, email, guest FROM users WHERE id=?", (uid,)).fetchone()
    return dict(id=r["id"], email=r["email"], guest=bool(r["guest"])) if r else None


def signup(email, pw):
    email = (email or "").strip().lower()
    if not EMAIL.match(email): raise ValueError("Enter a valid email address")
    if len(pw or "") < 8: raise ValueError("Password must be at least 8 characters")
    uid, c, now = secrets.token_hex(8), _adb(), time.time()
    try:
        c.execute("INSERT INTO users(id,email,pw,guest,created,last_seen) VALUES(?,?,?,0,?,?)", (uid, email, hash_pw(pw), now, now)); c.commit()
    except sqlite3.IntegrityError:
        raise ValueError("That email is already registered")
    return user(uid)


def login(email, pw):
    r = _adb().execute("SELECT * FROM users WHERE email=? AND guest=0", ((email or "").strip().lower(),)).fetchone()
    ok = check_pw(pw or "", r["pw"] if r else _DUMMY)
    if not (r and ok): raise ValueError("Wrong email or password")
    return user(r["id"])


def guest():
    uid, now, c = "g" + secrets.token_hex(7), time.time(), _adb()
    c.execute("INSERT INTO users(id,email,pw,guest,created,last_seen) VALUES(?,?,?,1,?,?)", (uid, f"{uid}@guest.local", "", now, now)); c.commit()
    return user(uid)


def token(uid, days=14):
    msg = f"{uid}.{int(time.time()) + days * 86400}"
    return msg + "." + hmac.new(secret(), msg.encode(), hashlib.sha256).hexdigest()


def verify(tok):
    try:
        uid, exp, sig = tok.rsplit(".", 2)
        good = hmac.new(secret(), f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        return user(uid) if hmac.compare_digest(sig, good) and int(exp) > time.time() else None
    except (ValueError, AttributeError):
        return None


def touch(uid):
    if time.time() - _seen.get(uid, 0) > 60:
        c = _adb(); c.execute("UPDATE users SET last_seen=? WHERE id=?", (time.time(), uid)); c.commit(); _seen[uid] = time.time()


def db_path(uid):
    assert re.fullmatch(r"[0-9a-z]{8,32}", uid), "bad user id"
    return os.path.join(data_dir(), "users", uid + ".db")


@contextmanager
def using(uid):
    t = core.use_db(db_path(uid))
    try: yield
    finally: core._ctx.reset(t)


def throttle(key, limit=8, window=300):
    now = time.time(); q = [t for t in _att.get(key, []) if now - t < window]
    if len(q) >= limit: raise Throttled("Too many attempts. Please wait a few minutes and try again.")
    _att[key] = q + [now]


def ai_limit(u): return int(os.getenv("LOGSENSE_GUEST_AI_LIMIT", "10")) if u["guest"] else int(os.getenv("LOGSENSE_USER_AI_LIMIT", "50"))


def ai_left(u):
    r = _adb().execute("SELECT n FROM usage WHERE uid=? AND day=?", (u["id"], date.today().isoformat())).fetchone()
    return max(0, ai_limit(u) - (r["n"] if r else 0))


def take_ai(u):
    """Use one of today's AI questions (protects the shared AI key from abuse). False when the daily limit is reached."""
    c, day = _adb(), date.today().isoformat()
    c.execute("INSERT OR IGNORE INTO usage VALUES(?,?,0)", (u["id"], day))
    ok = c.execute("UPDATE usage SET n=n+1 WHERE uid=? AND day=? AND n<?", (u["id"], day, ai_limit(u))).rowcount == 1
    c.commit(); return ok


def _remove_files(uid):
    p = db_path(uid); core.forget(p)
    for f in glob.glob(p + "*"):
        try: os.remove(f)
        except OSError: pass


def delete_user(uid):
    c = _adb(); c.execute("DELETE FROM users WHERE id=?", (uid,)); c.execute("DELETE FROM usage WHERE uid=?", (uid,)); c.commit(); _remove_files(uid)


def cleanup(hours=24):
    """Delete guest demo accounts (and their data) that have been idle for a day."""
    c = _adb()
    for r in c.execute("SELECT id FROM users WHERE guest=1 AND last_seen<?", (time.time() - hours * 3600,)).fetchall():
        delete_user(r["id"])


def poll_paths():
    """Databases whose live sources should run: every registered user, guests only while recently active."""
    if os.getenv("LOGSENSE_AUTH", "on") == "off": return [core.default_path()]
    now = time.time()
    out = [db_path(r["id"]) for r in _adb().execute("SELECT id, guest, last_seen FROM users") if not r["guest"] or now - (r["last_seen"] or 0) < 900]
    return [p for p in out if os.path.exists(p)]


def _fernet():
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"creds|" + secret()).digest()))


def encrypt(text): return _fernet().encrypt(text.encode()).decode()
def decrypt(tok): return _fernet().decrypt(tok.encode()).decode()
