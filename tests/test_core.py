import io, json, os, sqlite3, sys, tempfile, time, types, urllib.error, urllib.request
os.environ["LOGSENSE_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["LOGSENSE_AUTH"] = "off"   # most tests run single-user; the account tests below switch auth on
os.environ["LOGSENSE_LIVE"] = "0"
for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST", "LOGSENSE_PROVIDER"):
    os.environ.pop(k, None)
import pytest
from fastapi.testclient import TestClient
from logsense import auth, core, llm, sources
from logsense.app import app

C = TestClient(app)
Q = "Why did payment-api fail between 2 and 3 AM?"


def demo(): C.post("/api/demo")


def fake_ai(monkeypatch, *replies):
    """Make the AI answer with the given replies in order; returns the list of prompts it received."""
    monkeypatch.setattr(core._llm, "enabled", lambda: True)
    prompts, it = [], iter(replies)
    monkeypatch.setattr(core, "llm", lambda p, n=500: (prompts.append(p), next(it, None))[1])
    return prompts


PLAN = '{"queries":[{"purpose":"count warnings","sql":"SELECT COUNT(*) AS n FROM logs WHERE level=\'WARNING\'"}],"keywords":["slow"]}'


def test_mask():
    m = core.mask("user a@b.com from 10.1.2.3 token=abc123 card 1234 5678 9012 3456")
    assert "<EMAIL>" in m and "<IP>" in m and "abc123" not in m and "<CARD>" in m


def test_parse_formats_and_traces():
    ev = core.parse_lines(['2026-08-14T02:00:00Z svc ERROR boom', 'Traceback (most recent call last):', '  File "x.py"',
                           '{"timestamp":"2026-08-14T02:00:01Z","level":"warn","message":"hi"}',
                           '1.2.3.4 - - [14/Aug/2026:02:00:02 +0000] "GET / HTTP/1.1" 502 0'])
    assert len(ev) == 3 and "Traceback" in ev[0]["msg"] and ev[1]["level"] == "WARNING" and ev[2]["level"] == "ERROR"


def test_template_mining():
    m = core.Miner([])
    a, _ = m.match("Timeout connecting to db after 30s"); b, new = m.match("Timeout connecting to db after 45s")
    assert a == b and not new


def test_pipeline_and_api():
    demo()
    s = C.get("/api/stats").json(); assert s["total"] > 500 and s["compression"] > 5
    inc = C.get("/api/incidents").json(); assert inc and "payment-api" in inc[0]["services"] and "Between" in inc[0]["summary"]
    a = C.post("/api/ask", json={"question": Q}).json()
    assert a["citations"] and "db" in a["answer"].lower() and a["answer"].startswith("I found")


def test_ids_are_chronological():
    demo()
    rows = core.search(limit=100000, asc=True)
    assert [r["id"] for r in rows] == list(range(1, len(rows) + 1))
    assert all(a["ts"] <= b["ts"] for a, b in zip(rows, rows[1:]))


def test_same_upload_twice_is_skipped():
    core.reset(); lines = ["2026-08-14T02:00:00Z svc ERROR boom", "2026-08-14T02:00:01Z svc INFO ok"]
    a = core.ingest(lines, "x"); b = core.ingest(lines, "x")
    assert a["ingested"] == 2 and b["duplicate"] and core.stats()["total"] == 2


def test_plain_text_cleaner():
    t = core.plain("**Hi** `x`\n<results>[{'a':1}]</results>\n## Title\n* item\n<logs>raw</logs>")
    assert "**" not in t and "<" not in t and "[{" not in t and "- item" in t and t.startswith("Hi x")


def test_level_counts_exact_and_demo_repeatable():
    demo(); demo()
    n = len(core.search(level="WARNING", exact=True, limit=100000))
    assert n > 0 and core.stats()["total"] < 2000
    assert core.ask("how many warning logs are there")["answer"].startswith(f"There are {n} warning-level")


def test_common_questions_are_answered_exactly_without_ai():
    demo()
    n = core.db().execute("SELECT COUNT(*) FROM logs WHERE level='WARNING'").fetchone()[0]
    for q in ("how many warning level are there", "how many number of warning logs are there", "how many warnings?"):
        r = core.ask(q); assert r["mode"] == "direct" and f"There are {n} warning-level" in r["answer"]
    last = core.db().execute("SELECT id, ts FROM logs WHERE level='WARNING' ORDER BY ts DESC, id DESC LIMIT 1").fetchone()
    assert f"log {last['id']}:" in core.ask("latest warning level log number")["answer"]
    top = core.db().execute("SELECT service FROM logs WHERE level IN ('ERROR','CRITICAL') GROUP BY service ORDER BY COUNT(*) DESC LIMIT 1").fetchone()[0]
    assert f"most is {top}" in core.ask("which service has the most errors?")["answer"]
    assert core.direct("why did checkout fail?") is None  # open questions go to the AI


def test_ai_blank_or_invented_numbers_are_rejected_and_retried(monkeypatch):
    demo()
    n = core.db().execute("SELECT COUNT(*) FROM logs WHERE level='ERROR'").fetchone()[0]
    fake_ai(monkeypatch, PLAN, "There are  logs of that kind.", f"There are {n} logs of that kind.")
    r = core.ask("describe warnings sorted nicely"); assert r["mode"] == "llm-sql" and "  " not in r["answer"] and str(n) in r["answer"]
    fake_ai(monkeypatch, PLAN, "Exactly 987654 of them.", "Still 987654 of them.")
    r = core.ask("describe warnings sorted nicely"); assert "987654" not in r["answer"]  # falls back to the exact data


def test_plain_keeps_a_number_the_model_wrapped_in_a_tag():
    assert core.plain("There are <results>238</results> warning-level logs.") == "There are 238 warning-level logs."


def test_lookup_by_id():
    demo()
    r = core.ask("GIVE 1059 ID LOG")
    assert r["mode"] == "lookup" and r["answer"].startswith("Log 1059 is a")
    assert core.ask("show log id: 99999")["answer"].startswith("There is no log number 99999")


def test_sql_sandbox_blocks_everything_but_select():
    demo()
    for bad in ("DROP TABLE logs", "SELECT 1; DELETE FROM logs", "SELECT * FROM sqlite_master", "SELECT * FROM feedback", "WITH x AS (SELECT 1) DELETE FROM logs"):
        with pytest.raises(Exception): core.run_sql(bad)
    assert core.run_sql("SELECT COUNT(*) FROM logs")[1][0][0] > 0


def test_ai_answer_is_plain_and_uses_history(monkeypatch):
    demo()
    prompts = fake_ai(monkeypatch, PLAN, "**There** are warning logs, mostly slow queries.")
    r = core.ask("and for db?", [{"q": "how many warnings?", "a": "156 warnings"}])
    assert r["mode"] == "llm-sql" and r["answer"] == "There are warning logs, mostly slow queries." and r["queries"][0]["rows"] == 1
    assert "156 warnings" in prompts[0]


def test_any_real_log_number_ok_but_invented_one_rejected(monkeypatch):
    demo()
    fake_ai(monkeypatch, '{"queries":[{"purpose":"x","sql":"SELECT * FROM logs WHERE id=1059"}],"keywords":[]}', "Log 1059 is a normal login failure.")
    assert core.ask("why was log 1059 a failure?")["mode"] == "llm-sql"
    fake_ai(monkeypatch, PLAN, "Log 999999 caused everything.")
    r = core.ask("why?"); assert r["mode"] == "extractive" and r["llm_error"]


def test_model_echoing_data_is_cleaned(monkeypatch):
    demo()
    fake_ai(monkeypatch, PLAN, "<results>[{'n': 1}]</results>\n<logs>x</logs>")
    r = core.ask("tell me about warnings sorted nicely")
    assert r["mode"] == "llm-sql" and "<" not in r["answer"] and "count warnings:" in r["answer"]


def test_broken_sql_is_repaired_once(monkeypatch):
    demo()
    bad = '{"queries":[{"purpose":"count","sql":"SELECT COUNT(*) FROM logs WHERE severity=\'WARNING\'"}],"keywords":[]}'
    good = '{"queries":[{"purpose":"count","sql":"SELECT COUNT(*) AS n FROM logs WHERE level=\'WARNING\'"}]}'
    fake_ai(monkeypatch, bad, good, "There are some warnings.")
    r = core.ask("what do the warnings look like?")
    assert r["mode"] == "llm-sql" and r["queries"][-1]["rows"] == 1 and not r["queries"][-1]["error"]


def test_ai_failure_falls_back_and_says_why(monkeypatch):
    demo()
    monkeypatch.setattr(core._llm, "enabled", lambda: True); monkeypatch.setattr(core, "llm", lambda *a, **k: None)
    monkeypatch.setattr(llm, "last_error", "RuntimeError: HTTP 429: quota")
    r = core.ask("what do warning logs look like?")
    assert r["mode"] == "extractive" and "429" in r["llm_error"]


def test_ask_works_without_sklearn(monkeypatch):
    demo()
    monkeypatch.setitem(sys.modules, "sklearn", None); monkeypatch.setitem(sys.modules, "sklearn.feature_extraction.text", None)
    assert core.ask(Q)["citations"]


def test_generic_and_custom_parsers(tmp_path, monkeypatch):
    e = core.parse_lines(["Aug host1 myapp[12]: 2026-08-14 02:00:00 ERROR disk full"])[0]
    assert e["level"] == "ERROR" and e["ts"].startswith("2026-08-14T02:00:00") and "disk full" in e["msg"]
    p = tmp_path / "p.json"
    p.write_text('[{"regex": "^(?P<ts>\\\\d{2}/\\\\d{2}/\\\\d{4}) (?P<level>\\\\w+) (?P<msg>.*)$", "ts_format": "%d/%m/%Y"}]')
    monkeypatch.setattr(core, "_custom", None); monkeypatch.setenv("LOGSENSE_PARSERS", str(p))
    e = core.parse_lines(["14/08/2026 FATAL kernel panic"])[0]
    assert e["level"] == "CRITICAL" and e["ts"].startswith("2026-08-14")
    monkeypatch.setattr(core, "_custom", None)


def test_provider_selection(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST", "LOGSENSE_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    assert llm.provider() is None and llm.complete("x") is None
    monkeypatch.setenv("GEMINI_API_KEY", "dummy"); assert llm.provider() == "gemini"
    monkeypatch.setenv("LOGSENSE_PROVIDER", "none"); assert not llm.enabled()


def test_env_last_line_wins(tmp_path, monkeypatch):
    f = tmp_path / ".env"; f.write_text("LOGSENSE_MODEL=first\nLOGSENSE_MODEL=second # note\nEMPTY=\n")
    monkeypatch.delenv("LOGSENSE_MODEL", raising=False); llm.load_env(str(f))
    assert os.environ["LOGSENSE_MODEL"] == "second"; monkeypatch.delenv("LOGSENSE_MODEL")


def test_http_errors_show_provider_message(monkeypatch):
    def boom(*a, **k): raise urllib.error.HTTPError("u", 400, "Bad", {}, io.BytesIO(b'{"error":{"message":"API key not valid"}}'))
    monkeypatch.setenv("GEMINI_API_KEY", "secret123"); monkeypatch.delenv("LOGSENSE_PROVIDER", raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert llm.complete("x") is None and "API key not valid" in llm.last_error and "secret123" not in llm.last_error


def test_retry_then_fallback_model(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "x"); monkeypatch.delenv("LOGSENSE_PROVIDER", raising=False); monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    seq = []
    def once(prompt, mt, m):
        seq.append(m)
        if len(seq) < 3:
            llm.last_error = "RuntimeError: HTTP 503: UNAVAILABLE"; return None
        llm.last_error = None; return "OK"
    monkeypatch.setattr(llm, "_once", once)
    assert llm.complete("x") == "OK" and len(seq) == 3 and seq[2] != seq[0]


def test_health_without_key():
    h = C.get("/api/health?test=1").json()
    assert h["provider"] is None and "working" not in h


def test_cloudwatch_pull_with_fake_client():
    class FakeCW:
        def filter_log_events(self, **kw):
            return {"events": [{"timestamp": 1786665600000, "message": "ERROR db timeout after 30s"}, {"timestamp": 1786665601000, "message": '{"level":"info","message":"ok"}'}]}
    data = sources.cloudwatch("/aws/lambda/pay", 1, client=FakeCW())
    assert list(data) == ["pay"] and len(data["pay"]) == 2
    core.reset(); core.ingest(data["pay"], "pay")
    assert core.search(level="ERROR", exact=True)[0]["msg"].startswith("ERROR db timeout")


def test_basic_answer_names_the_truly_first_error():
    demo()
    first = core.search(level="ERROR", limit=1, asc=True)[0]
    assert f"log {first['id']}:" in core.ask("what was the first error")["answer"]


from datetime import datetime
from logsense import live


def test_demo_stream_is_incremental():
    d1, c1 = sources.poll("demo", {}, None, datetime(2026, 8, 14, 2, 0, 0))
    assert sum(map(len, d1.values())) > 0 and c1 == "2026-08-14T02:00:00Z"
    d2, c2 = sources.poll("demo", {}, c1, datetime(2026, 8, 14, 2, 0, 30))
    assert sum(map(len, d2.values())) > 0 and c2 == "2026-08-14T02:00:30Z"
    assert sources.poll("demo", {}, c2, datetime(2026, 8, 14, 2, 0, 30))[0] == {}


def test_file_tail_is_incremental_and_sandboxed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSENSE_LOG_DIR", str(tmp_path))
    f = tmp_path / "app.log"; f.write_text("2026-08-14T02:00:00Z app ERROR boom\n2026-08-14T02:00:01Z app INFO ok\n")
    d, cur = sources.poll("file", {"file": "app.log"}, None)
    assert len(d["app"]) == 2
    f.write_text(f.read_text() + "2026-08-14T02:00:02Z app WARNING hmm\nhalf written line")
    d, cur = sources.poll("file", {"file": "app.log"}, cur)
    assert d == {"app": ["2026-08-14T02:00:02Z app WARNING hmm"]}
    for bad in ("../secret.txt", "/etc/passwd"):
        with pytest.raises(ValueError): sources.poll("file", {"file": bad}, None)


def test_private_urls_and_non_http_are_blocked():
    for bad in ("http://127.0.0.1/x", "http://169.254.169.254/latest", "file:///etc/passwd"):
        with pytest.raises(ValueError): sources.url(bad)


def test_cloudwatch_poll_only_asks_for_new_events():
    seen = []
    class CW:
        def filter_log_events(self, **kw):
            seen.append(kw["startTime"]); return {"events": [{"timestamp": 5000, "message": "ERROR x"}]}
    data, nxt = sources._cw(CW(), "/g/pay", 1000)
    assert seen == [1000] and nxt == 5001 and len(data["pay"]) == 1


def test_live_manager_alerts_and_errors(tmp_path, monkeypatch):
    core.reset(); monkeypatch.setenv("LOGSENSE_LOG_DIR", str(tmp_path))
    (tmp_path / "svc.log").write_text("2026-08-14T02:00:00Z svc CRITICAL Out of memory: killed\n")
    v0, a0 = core.version(), core.alert_seq()
    sid = live.add("file", {"file": "svc.log"}, 5); live.poll_one(sid)
    s = live.listing()[0]
    assert s["status"] == "running" and s["total"] == 1 and core.version() > v0 and core.alert_seq() > a0
    live.poll_one(sid); assert live.listing()[0]["total"] == 1  # nothing new -> nothing added
    live.toggle(sid, False); assert live.listing()[0]["enabled"] == 0
    live.remove(sid)
    bad = live.add("file", {"file": "missing.log"}, 5); live.poll_one(bad)
    assert live.listing()[0]["status"] == "error" and "FileNotFoundError" in live.listing()[0]["error"]
    live.remove(bad)


def test_sources_api(monkeypatch):
    r = C.post("/api/sources", json={"kind": "demo", "params": {}, "interval": 5}).json()
    assert r["ok"] and C.get("/api/sources").json()[0]["kind"] == "demo"
    C.post(f"/api/sources/{r['id']}/toggle"); assert C.get("/api/sources").json()[0]["enabled"] == 0
    C.delete(f"/api/sources/{r['id']}"); assert C.get("/api/sources").json() == []
    assert C.post("/api/sources", json={"kind": "nope"}).json()["ok"] is False


def test_page_headers_and_health():
    r = C.get("/")
    assert r.status_code == 200 and "LogSense AI" in r.text and r.headers["x-frame-options"] == "DENY" and "content-security-policy" in r.headers
    assert C.get("/healthz").json() == {"ok": True}


def test_upload_size_limit(monkeypatch):
    monkeypatch.setenv("LOGSENSE_MAX_UPLOAD_MB", "0.0001")
    assert C.post("/api/ingest?service=x", content=b"x" * 500).status_code == 413


def test_retention_cap(monkeypatch):
    monkeypatch.setenv("LOGSENSE_MAX_LOGS", "5"); core.reset()
    core.ingest([f"2026-08-14T02:00:{i:02d}Z svc INFO line {i}" for i in range(10)], "svc")
    rows = core.search(limit=100, asc=True)
    assert len(rows) == 5 and rows[-1]["msg"] == "line 9"


# ---------------- accounts, isolation, deployment safety ----------------
@pytest.fixture
def hosted(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSENSE_AUTH", "on"); monkeypatch.setenv("LOGSENSE_DATA", str(tmp_path)); monkeypatch.setenv("LOGSENSE_SECRET", "test-secret")
    auth._att.clear()
    return TestClient(app, headers={"x-requested-with": "logsense"})


def signup(c, email="a@x.com", pw="password1"):
    return c.post("/api/auth/signup", json={"email": email, "password": pw})


def test_signup_login_logout_and_data_isolation(hosted):
    a, b = hosted, TestClient(app, headers={"x-requested-with": "logsense"})
    assert a.get("/api/stats").status_code == 401
    assert signup(a).status_code == 200 and signup(b, "b@x.com", "password2").status_code == 200
    a.post("/api/demo")
    assert a.get("/api/stats").json()["total"] > 500 and b.get("/api/stats").json()["total"] == 0
    assert a.get("/api/me").json()["user"]["email"] == "a@x.com"
    assert a.post("/api/auth/logout").status_code == 200 and a.get("/api/stats").status_code == 401
    assert a.post("/api/auth/login", json={"email": "a@x.com", "password": "wrong"}).status_code == 401
    assert a.post("/api/auth/login", json={"email": "a@x.com", "password": "password1"}).status_code == 200
    assert a.get("/api/stats").json()["total"] > 500  # data survived logout


def test_signup_validation_and_login_throttle(hosted):
    assert signup(hosted, "not-an-email").status_code == 400 and signup(hosted, "a@x.com", "short").status_code == 400
    assert signup(hosted).status_code == 200 and signup(hosted).status_code == 400
    codes = [hosted.post("/api/auth/login", json={"email": "a@x.com", "password": "bad"}).status_code for _ in range(10)]
    assert 429 in codes and codes[0] == 401


def test_csrf_header_required(hosted):
    plain = TestClient(app)
    assert plain.post("/api/auth/signup", json={"email": "c@x.com", "password": "password3"}).status_code == 403
    signup(hosted, "c@x.com", "password3"); plain.cookies.update(hosted.cookies)
    assert plain.post("/api/reset").status_code == 403 and hosted.post("/api/reset").status_code == 200


def test_session_cookie_is_httponly_and_token_cannot_be_forged(hosted):
    assert "httponly" in signup(hosted).headers["set-cookie"].lower()
    u = auth.signup("t@x.com", "password5"); t = auth.token(u["id"])
    assert auth.verify(t)["email"] == "t@x.com" and auth.verify(t[:-2] + "00") is None and auth.verify("garbage") is None and auth.verify(auth.token(u["id"], days=-1)) is None


def test_guest_demo_account(hosted):
    r = hosted.post("/api/auth/guest"); assert r.status_code == 200 and r.json()["user"]["guest"]
    assert hosted.get("/api/stats").json()["total"] > 500 and hosted.get("/api/sources").json()[0]["kind"] == "demo"
    bad = hosted.post("/api/sources", json={"kind": "cloudwatch", "params": {"group": "/x"}}).json()
    assert bad["ok"] is False and "free account" in bad["error"].lower()


def test_idle_guest_accounts_are_cleaned_up(hosted):
    g = auth.guest()
    with auth.using(g["id"]): core.ingest(["2026-08-14T02:00:00Z s INFO x"], "s")
    with auth._tx() as c: c.execute("UPDATE users SET last_seen=? WHERE id=?", (time.time() - 99999, g["id"]))
    auth.cleanup()
    assert auth.user(g["id"]) is None and not os.path.exists(auth.db_path(g["id"]))


def test_cloud_keys_are_encrypted_and_user_supplied(hosted, monkeypatch):
    signup(hosted); calls = []
    class CW:
        def filter_log_events(self, **kw): return {"events": [{"timestamp": 5000, "message": "ERROR x"}]}
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda name, **kw: (calls.append(kw), CW())[1]))
    r = hosted.post("/api/sources", json={"kind": "cloudwatch", "params": {"group": "/g/pay", "region": "ap-south-1"}, "creds": {"aws_key": "AKIATEST", "aws_secret": "SUPERSECRET"}}).json()
    s = hosted.get("/api/sources").json()[0]
    assert r["ok"] and s["secured"] and "SUPERSECRET" not in json.dumps(s) and s["status"] == "running" and s["total"] == 1
    assert calls[0]["aws_access_key_id"] == "AKIATEST" and calls[0]["region_name"] == "ap-south-1"
    raw = sqlite3.connect(auth.db_path(auth.verify(hosted.cookies.get("ls_session"))["id"])).execute("SELECT params FROM sources").fetchone()[0]
    assert "SUPERSECRET" not in raw and "_enc" in raw


def test_hosted_mode_never_uses_the_servers_own_cloud_access(hosted, monkeypatch):
    monkeypatch.setenv("LOGSENSE_HOSTED", "1"); signup(hosted)
    assert hosted.post("/api/sources", json={"kind": "cloudwatch", "params": {"group": "/g"}}).json()["ok"]
    s = hosted.get("/api/sources").json()[0]
    assert s["status"] == "error" and "credentials are required" in s["error"].lower()
    assert hosted.post("/api/sources", json={"kind": "file", "params": {"file": "x"}}).json()["ok"] is False
    assert hosted.post("/api/sources", json={"kind": "url", "params": {"url": "http://169.254.169.254/"}}).json()["ok"]
    assert hosted.get("/api/sources").json()[-1]["status"] == "error"


def test_daily_ai_limit(hosted, monkeypatch):
    monkeypatch.setenv("LOGSENSE_USER_AI_LIMIT", "2"); u = auth.signup("q@x.com", "password4")
    assert [auth.take_ai(u) for _ in range(3)] == [True, True, False] and auth.ai_left(u) == 0


def test_delete_account_removes_all_data(hosted):
    signup(hosted); hosted.post("/api/demo")
    p = auth.db_path(auth.verify(hosted.cookies.get("ls_session"))["id"]); assert os.path.exists(p)
    assert hosted.delete("/api/me").status_code == 200 and not os.path.exists(p)
    assert hosted.post("/api/auth/login", json={"email": "a@x.com", "password": "password1"}).status_code == 401


def test_live_poller_serves_every_users_sources(hosted):
    from logsense import live
    u = auth.signup("p@x.com", "password6")
    with auth.using(u["id"]): live.add("demo", {}, 5)
    live._tick()
    with auth.using(u["id"]): assert live.listing()[0]["total"] > 0
