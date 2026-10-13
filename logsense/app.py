import asyncio, json, logging, os, re, time
from contextlib import asynccontextmanager
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from . import auth, core, gen, live, llm, sources

HOSTED = lambda: os.getenv("LOGSENSE_HOSTED") == "1"
AUTH_ON = lambda: os.getenv("LOGSENSE_AUTH", "on") != "off"
FILE_SRC = lambda: not HOSTED() or os.getenv("LOGSENSE_ALLOW_FILE_SOURCE") == "1"


@asynccontextmanager
async def lifespan(app):
    if os.getenv("LOGSENSE_LIVE", "1") != "0": live.start()  # background poller for everyone's live sources
    yield
    live.stop()


app = FastAPI(title="LogSense AI", lifespan=lifespan, docs_url=None if HOSTED() else "/docs", redoc_url=None, openapi_url=None if HOSTED() else "/openapi.json")
CSP = b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


class SecurityHeaders:
    """Pure ASGI middleware (keeps streaming and per-request context intact)."""
    def __init__(self, app): self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http": return await self.app(scope, receive, send)
        async def snd(m):
            if m["type"] == "http.response.start":
                h = [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"), (b"referrer-policy", b"same-origin"),
                     (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"), (b"content-security-policy", CSP)]
                if HOSTED(): h.append((b"strict-transport-security", b"max-age=31536000"))
                m = {**m, "headers": list(m.get("headers", [])) + h}
            await send(m)
        await self.app(scope, receive, snd)


app.add_middleware(SecurityHeaders)


def _xhr(request):  # extra CSRF defence: browsers cannot add this header cross-site
    if request.headers.get("x-requested-with") != "logsense": raise HTTPException(403, "Missing request header")


async def current_user(request: Request):
    """Runs before every /api call: identifies the user and points the whole request at THEIR database."""
    if not AUTH_ON():
        request.state.user = {"id": "local", "email": "local", "guest": False}; return request.state.user
    u = auth.verify(request.cookies.get(auth.COOKIE, ""))
    if not u: raise HTTPException(401, "Please log in")
    if request.method not in ("GET", "HEAD"): _xhr(request)
    auth.touch(u["id"]); core.use_db(auth.db_path(u["id"])); core._ai_ok.set(not u["guest"])
    request.state.user = u
    return u


def _u(request): return getattr(request.state, "user", None) or {"id": "local", "email": "local", "guest": False}
def _ip(request): return request.client.host if request.client else "?"


def _pub(u): return dict(email=u["email"], guest=bool(u["guest"]), ai_left=auth.ai_left(u) if AUTH_ON() else None)


def _session(u, request):
    r = JSONResponse({"ok": True, "user": _pub(u)})
    r.set_cookie(auth.COOKIE, auth.token(u["id"]), max_age=14 * 86400, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    return r


class Cred(BaseModel):
    email: str = ""
    password: str = ""


@app.get("/healthz")
def healthz(): return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    u = auth.verify(request.cookies.get(auth.COOKIE, "")) if AUTH_ON() else {"id": "local", "email": "local", "guest": False}
    return {"user": _pub(u) if u else None, "auth": AUTH_ON(), "author": os.getenv("LOGSENSE_AUTHOR", ""), "file_sources": FILE_SRC(), "ai": llm.enabled()}


@app.post("/api/auth/signup")
def signup(b: Cred, request: Request):
    _xhr(request)
    try:
        auth.throttle(f"s|{_ip(request)}", 10, 3600); u = auth.signup(b.email, b.password)
    except auth.Throttled as e: raise HTTPException(429, str(e))
    except ValueError as e: raise HTTPException(400, str(e))
    return _session(u, request)


@app.post("/api/auth/login")
def login(b: Cred, request: Request):
    _xhr(request)
    try:
        auth.throttle(f"l|{_ip(request)}|{b.email.lower()}", 8, 300); u = auth.login(b.email, b.password)
    except auth.Throttled as e: raise HTTPException(429, str(e))
    except ValueError as e: raise HTTPException(401, str(e))
    return _session(u, request)


@app.post("/api/auth/guest")
def guest(request: Request):
    """Instant demo account: sample data plus a live demo stream, deleted after 24 idle hours."""
    _xhr(request)
    try: auth.throttle(f"g|{_ip(request)}", 10, 3600)
    except auth.Throttled as e: raise HTTPException(429, str(e))
    u = auth.guest()
    with auth.using(u["id"]):
        for s, l in gen.generate().items(): core.ingest(l, s)
        live.poll_one(live.add("demo", {}, 5))
    return _session(u, request)


@app.post("/api/auth/logout")
def logout(request: Request):
    _xhr(request); r = JSONResponse({"ok": True}); r.delete_cookie(auth.COOKIE); return r


api = APIRouter(prefix="/api", dependencies=[Depends(current_user)])


class Q(BaseModel):
    question: str
    history: list[dict] = []


class FB(BaseModel):
    question: str
    answer: str
    helpful: bool


class Src(BaseModel):
    kind: str
    params: dict = {}
    creds: dict = {}
    interval: int = 15


@api.delete("/me")
def delete_me(request: Request):
    u = _u(request)
    if u["id"] != "local": auth.delete_user(u["id"])
    r = JSONResponse({"ok": True}); r.delete_cookie(auth.COOKIE); return r


@api.post("/ingest")
async def ingest(request: Request, service: str = "upload", host: str = "localhost"):
    """POST raw log text (any mix of plain/JSON/nginx; stack traces are merged). Size-limited."""
    cap, body = int(float(os.getenv("LOGSENSE_MAX_UPLOAD_MB", "10")) * 1_000_000), b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > cap: raise HTTPException(413, f"File too large (limit {cap // 1_000_000} MB)")
    svc = re.sub(r"[^\w.-]", "_", service)[:60] or "upload"
    return await run_in_threadpool(core.ingest, body.decode(errors="replace").splitlines(), svc, host[:60])


@api.post("/demo")
def demo():
    core.reset()
    return [dict(service=s, **core.ingest(l, s)) for s, l in gen.generate().items()]


@api.get("/stats")
def stats(): return core.stats()


@api.get("/logs")
def logs(q: str = None, service: str = None, level: str = None, since: str = None, until: str = None, limit: int = 100, asc: bool = False):
    return core.search(q, service, level, since, until, min(limit, 1000), asc)


@api.get("/templates")
def templates(): return core.templates()


@api.get("/incidents")
def incidents(): return core.incidents()


@api.post("/ask")
def ask(b: Q, request: Request):
    u = _u(request)
    use_ai = not (AUTH_ON() and llm.enabled()) or auth.take_ai(u)  # daily AI limit per account protects the shared AI key
    try:
        r = core.ask(b.question[:2000], b.history[-3:], ai=use_ai)
        if not use_ai: r["llm_error"] = "daily AI limit reached - this is a basic answer (limit resets tomorrow)"
        return r
    except Exception as e:
        logging.exception("ask failed")
        return dict(answer=f"Sorry, something failed: {type(e).__name__}: {e}", citations=[], mode="error", filters={}, queries=[])


@api.post("/feedback")
def feedback(b: FB): core.feedback(b.question[:500], b.answer[:2000], b.helpful); return {"ok": True}


@api.post("/reset")
def reset(): core.reset(); return {"ok": True}


def _deny(kind, u):
    if kind == "demo": return None
    if u.get("guest"): return "Demo accounts can only use the live demo stream. Create a free account to connect your own logs."
    if kind == "file" and not FILE_SRC(): return "Local file sources are disabled on this server."
    return None


@api.get("/sources")
def src_list(): return live.listing()


@api.post("/sources")
def src_add(b: Src, request: Request):
    try:
        u = _u(request)
        if b.kind not in live.KINDS: raise ValueError("Unknown source type")
        if (msg := _deny(b.kind, u)): raise ValueError(msg)
        if len(live.listing()) >= 5: raise ValueError("You can have at most 5 live sources")
        params = {k: str(v)[:300] for k, v in b.params.items() if k in ("group", "region", "project", "bucket", "prefix", "file", "url", "filter", "hours")}
        creds = {k: str(v)[:8000] for k, v in b.creds.items() if k in ("aws_key", "aws_secret", "gcp_json") and v}
        if creds: params["_enc"] = auth.encrypt(json.dumps(creds))
        sid = live.add(b.kind, params, b.interval); live.poll_one(sid)
        return {"ok": True, "id": sid}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}


@api.post("/sources/{sid}/run")
def src_run(sid: int): return {"ok": live.poll_one(sid)}


@api.post("/sources/{sid}/toggle")
def src_toggle(sid: int):
    cur = [x for x in live.listing() if x["id"] == sid]
    if cur: live.toggle(sid, not cur[0]["enabled"])
    return {"ok": bool(cur)}


@api.delete("/sources/{sid}")
def src_del(sid: int): live.remove(sid); return {"ok": True}


@api.get("/stream")
async def stream(request: Request):
    """Server-Sent Events: the dashboard updates the moment new logs arrive; new error patterns arrive as alerts."""
    path = core._path()
    async def events():
        seen, aseq, beat = -1, core.alert_seq(path), 0
        while not await request.is_disconnected():
            v, alerts = core.version(path), core.alerts_since(aseq, path)
            if v != seen or alerts:
                seen, aseq, beat = v, core.alert_seq(path), 0
                yield "data: " + json.dumps({"version": v, "alerts": alerts}) + "\n\n"
            elif beat >= 15:
                beat = 0; yield ": ping\n\n"
            await asyncio.sleep(1); beat += 1
    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


_hc = {"t": 0.0, "v": None}


@api.get("/health")
def health(request: Request, test: bool = False, fresh: bool = False):
    out = {**llm.status(), "logs": core.stats()["total"], "live": live.running()}
    if test and llm.enabled():  # live check, cached 10 min so page loads never burn AI quota
        if (fresh and not _u(request)["guest"]) or _hc["v"] is None or time.time() - _hc["t"] > 600:
            _hc["v"] = (llm.complete("Reply with the single word OK.", 20) is not None, llm.last_error); _hc["t"] = time.time()
        out["working"], out["last_error"] = _hc["v"]
    return out


app.include_router(api)


@app.get("/", response_class=HTMLResponse)
def home(): return PAGE


PAGE = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>LogSense AI - ask your server logs anything</title>
<meta name=description content="Live, AI-powered log analysis: connect your cloud logs, spot incidents the moment they start, and ask questions in plain English.">
<style>
:root{--bg:#0b1220;--panel:#111a2e;--line:#1f2a44;--fg:#e6edf7;--mut:#8aa0c0;--acc:#f5a524;--blue:#4cc2ff;--red:#ef5350;--green:#3ddc97}
[hidden]{display:none!important}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}.wrap{max-width:1100px;margin:auto;padding:18px}
h1{font-size:22px;margin:0}h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:26px 0 8px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.mut{color:var(--mut)}
.chip{padding:4px 12px;border-radius:99px;background:var(--panel);border:1px solid var(--line);color:var(--mut);font-size:12px;cursor:pointer;white-space:normal}.chip.ok{color:var(--green)}.chip.bad{color:var(--red)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.card b{font-size:24px;display:block}.card span{color:var(--mut);font-size:12px}
button,select,input,textarea{font:inherit;color:var(--fg);background:#1a2540;border:1px solid var(--line);border-radius:8px;padding:8px 12px}button{cursor:pointer}button.p{background:var(--acc);color:#1a1200;border:0;font-weight:600}button.g{background:transparent}button.big{padding:12px 20px;font-size:16px}input,textarea{flex:1;min-width:140px;width:100%}
.hero{padding:56px 0 24px;max-width:760px}.hero h1{font-size:44px;line-height:1.1;margin:14px 0}.hero p{font-size:18px;color:var(--mut)}.g4{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-top:30px}.g4 b{display:block;margin-bottom:4px}.g4 span{color:var(--mut);font-size:14px}
.steps{padding-left:20px;color:var(--mut)}.steps b{color:var(--fg)}footer{margin:40px 0 10px;color:var(--mut);font-size:13px;border-top:1px solid var(--line);padding-top:14px}
.lbl{display:flex;flex-direction:column;gap:4px;font-size:13px;flex:1;min-width:220px}.lbl small{color:var(--mut);font-size:12px}.fgrid{display:flex;flex-wrap:wrap;gap:12px;margin:10px 0}
.banner{background:#2a2410;border:1px solid #5a4a14;border-radius:10px;padding:10px 14px;margin:12px 0}
#chat{display:flex;flex-direction:column;gap:10px;max-height:480px;overflow:auto;padding:4px}.m{max-width:85%;padding:10px 14px;border-radius:14px;white-space:pre-wrap;word-wrap:break-word}.u{align-self:flex-end;background:#27406d}.b{align-self:flex-start;background:#18233d;border:1px solid var(--line)}
.meta{display:block;margin-top:6px;font-size:11px;color:var(--mut)}details{margin-top:4px;font-size:12px;color:var(--mut)}details pre{white-space:pre-wrap;margin:4px 0;font-family:ui-monospace,Consolas,monospace}.chips{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
#tl{display:flex;align-items:flex-end;gap:2px;height:90px}#tl i{flex:1;background:var(--blue);display:flex;align-items:flex-end;min-width:2px;border-radius:2px 2px 0 0}#tl u{background:var(--red);width:100%}
.inc{border-left:4px solid var(--red);margin-bottom:8px}.inc b{color:var(--red)}.tbl{overflow-x:auto}table{width:100%;border-collapse:collapse;font:12px ui-monospace,Consolas,monospace}td,th{padding:5px 8px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}td:last-child{white-space:normal}
.ERROR,.CRITICAL{color:var(--red)}.WARNING{color:var(--acc)}.src{padding:8px 0;border-bottom:1px solid var(--line)}.src button{margin-left:6px;padding:3px 10px;font-size:12px}.err{color:var(--red);font-size:13px;margin-top:4px}
#toasts{position:fixed;right:16px;top:16px;display:flex;flex-direction:column;gap:8px;z-index:9}.toast{max-width:360px;background:#2a1620;border:1px solid var(--red);padding:10px 14px;border-radius:10px;font-size:13px}
</style>
<div id=land hidden><div class=wrap>
<nav class=row style="justify-content:space-between"><b style="font-size:18px">🐝 LogSense AI</b><span class=row id=navbtns></span></nav>
<section class=hero><span class=chip>Live · AI-powered · for DevOps and support teams</span><h1>Ask your server logs anything.</h1>
<p>LogSense AI pulls logs from your cloud, turns thousands of lines into a few clear patterns, flags incidents the moment they start, and answers your questions in plain English.</p>
<div class=row id=cta></div><p id=gerr class=err></p></section>
<div id=authbox class=panel hidden style="max-width:420px"><div class=row><button id=m_login class=p onclick="mode('login')">Log in</button><button id=m_signup onclick="mode('signup')">Sign up</button></div>
<div class=fgrid><label class=lbl>Email<input id=em type=email autocomplete=email></label><label class=lbl>Password<input id=pw type=password autocomplete=current-password placeholder="at least 8 characters" onkeydown="if(event.key=='Enter')doAuth()"></label></div>
<div class=row><button class=p id=go onclick="doAuth()">Log in</button><button class=g onclick="$('authbox').hidden=true">Cancel</button></div><p id=aerr class=err></p>
<p class=mut style="margin:6px 0 0;font-size:13px">Just looking? <a href=# onclick="guest();return false" style="color:var(--acc)">Try the live demo - no sign-up</a></p></div>
<div class=g4><div class=panel><b>Live from your cloud</b><span>Connect AWS CloudWatch, S3, Google Cloud Logging or a log link. New logs stream in every few seconds.</span></div>
<div class=panel><b>Ask in plain English</b><span>No query language. Ask "why did checkout fail at 2 AM?" and get a clear answer based on your real data.</span></div>
<div class=panel><b>Incidents and alerts</b><span>Bursts of errors are grouped into incidents with a summary and likely cause. New error types pop up instantly.</span></div>
<div class=panel><b>Private by design</b><span>Emails, IPs and tokens are masked. Every account has its own data. Cloud keys are encrypted and read-only.</span></div></div>
<h2>How it works</h2><ol class=steps><li><b>Connect</b> a source, or load the sample data.</li><li><b>Clean up:</b> private data is masked and similar lines are grouped into patterns.</li><li><b>Watch</b> the live dashboard: activity, errors, incidents.</li><li><b>Ask</b> questions. The AI searches your logs and explains the real result.</li></ol>
<footer>Internship project at Beehive Systems Pvt. Ltd.<span id=author></span></footer></div></div>
<div id=app hidden><div class=wrap>
<header class=row style="justify-content:space-between"><h1>🐝 LogSense AI</h1><span class=row><span id=live class=chip>Live: connecting...</span><span id=ai class=chip title="Click to re-check the AI connection">AI: checking...</span><span id=who class=chip></span><button class=g onclick="showLand()">Home</button><button class=g onclick="logout()">Log out</button></span></header>
<div id=gb class="banner" hidden>You are in <b>demo mode</b>: sample data and a live demo stream are running, and everything is deleted after a day. <a href=# onclick="signupFromDemo();return false" style="color:var(--acc)">Create a free account</a> to connect your own cloud logs.</div>
<h2>Add logs</h2><div class=panel><div class=row><button class=p onclick="demo()">Load sample data</button><button onclick="clr()">Clear all</button>
<label class=chip>Upload log files<input type=file multiple hidden onchange="up(this.files)"></label><span id=msg class=chip style="display:none"></span></div>
<p class=mut style="margin:8px 0 0;font-size:12px">Upload any text log (one event per line, starting with a date and time). Max 10 MB per file.</p></div>
<h2>Live sources (auto-refresh)</h2><div class=panel>
<label class=lbl style="max-width:420px">Source type<select id=src onchange="renderForm()"></select></label>
<p id=shelp class=mut></p><div id=sform class=fgrid></div>
<div class=row><label class=lbl style="max-width:260px">Check every (seconds)<input id=iv type=number value=15 min=3><small>How often to look for new logs. 15 is a good start.</small></label><button class=p onclick="addSrc()">Start live</button></div>
<div id=srcs style="margin-top:12px"></div></div>
<h2>Overview</h2><div class=cards id=cards></div>
<h2>Ask your logs</h2><div class=panel><div id=chat></div><div class=chips id=chips></div>
<div class=row><input id=q placeholder="Ask anything about your logs, like you would ask a colleague..." onkeydown="if(event.key=='Enter')send()"><button class=p onclick="send()">Send</button></div><small class=mut id=aileft></small></div>
<h2>Activity (red = errors)</h2><div class=panel><div id=tl></div></div>
<h2>Incidents</h2><div id=inc></div>
<h2>Logs</h2><div class=row><input id=f placeholder="search text" onkeydown="if(event.key=='Enter')logs()"><select id=sv onchange="logs()"><option value="">all services</option></select>
<select id=lv onchange="logs()"><option value="">all levels</option><option>WARNING</option><option>ERROR</option><option>CRITICAL</option></select><select id=od onchange="logs()"><option value=0>newest first</option><option value=1>oldest first</option></select><button onclick="logs()">Search</button></div>
<div class="tbl panel" style="margin-top:8px"><table id=lg></table></div>
<p class=mut style="margin-top:30px;font-size:12px"><a href=# onclick="delAccount();return false" style="color:var(--mut)">Delete my account and data</a></p></div></div>
<div id=toasts></div>
<script>
const $=i=>document.getElementById(i);let ME=null,CFG={},hist=[],es=null;
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const H={'content-type':'application/json','x-requested-with':'logsense'};
const api=(p,o={})=>fetch('/api'+p,{...o,headers:H}).then(async r=>{if(r.status==401){ME=null;showLand();throw new Error('Please log in')}if(!r.ok){let m='Server error '+r.status;try{m=(await r.json()).detail||m}catch(e){}throw new Error(m)}return r.json()});
const authPost=async(p,b)=>{const r=await fetch('/api/auth/'+p,{method:'POST',headers:H,body:JSON.stringify(b||{})});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.detail||'Something went wrong');return j};
const say=t=>{const m=$('msg');m.style.display=t?'':'none';m.textContent=t};
window.onunhandledrejection=e=>say('Problem: '+(e.reason&&e.reason.message||e.reason));
const when=t=>String(t||'').replace('T',' ').replace('Z',' UTC');
/* ---------- landing + login ---------- */
let AM='login';
function showLand(){if(es){es.close();es=null}$('app').hidden=true;$('land').hidden=false;landCTA()}
function landCTA(){const g=ME&&ME.guest;
$('cta').innerHTML=!ME?`<button class="p big" onclick="guest()">Try the live demo - no sign-up</button><button class=big onclick="showAuth('signup')">Create a free account</button>`:g?`<button class="p big" onclick="showApp()">Back to my demo</button><button class=big onclick="signupFromDemo()">Create a free account</button>`:`<button class="p big" onclick="showApp()">Open my dashboard</button>`;
$('navbtns').innerHTML=!ME?`<button class=g onclick="guest()">Try demo</button><button class=g onclick="showAuth('login')">Log in</button>`:`<button onclick="showApp()">${g?'Back to my demo':'Open my dashboard'}</button>`}
function showAuth(m){$('authbox').hidden=false;mode(m);$('em').focus()}
function mode(m){AM=m;$('m_login').className=m=='login'?'p':'';$('m_signup').className=m=='signup'?'p':'';$('go').textContent=m=='login'?'Log in':'Create account';$('pw').autocomplete=m=='login'?'current-password':'new-password';$('aerr').textContent=''}
async function doAuth(){try{$('aerr').textContent='';await authPost(AM,{email:$('em').value,password:$('pw').value});await boot()}catch(e){$('aerr').textContent=e.message}}
async function guest(){try{$('gerr').textContent='Setting up your demo...';await authPost('guest');await boot()}catch(e){$('gerr').textContent=e.message}}
async function logout(){await authPost('logout');ME=null;hist=[];$('chat').innerHTML='';showLand()}
async function delAccount(){if(confirm('Permanently delete your account and all your data?')){await api('/me',{method:'DELETE'});ME=null;showLand()}}
function signupFromDemo(){logout().then(()=>showAuth('signup'))}
/* ---------- live source form ---------- */
const SRC={
demo:{name:'Live demo stream',help:'Creates realistic server logs every few seconds so you can watch live updates, incidents and alerts. Nothing to fill in.',fields:[]},
url:{name:'Web link to a text log file',help:'Reads a plain-text log file from a web address. Only lines added since the last check are loaded.',fields:[
 {k:'url',label:'Link to the log file',ph:'https://example.com/logs/app.log',help:'Must start with https:// and open as plain text (not a web page). Private or internal addresses are blocked.'}]},
cloudwatch:{name:'AWS CloudWatch Logs',help:'Reads logs from an AWS log group. In AWS, create an IAM user with the read-only permission CloudWatchLogsReadOnlyAccess, create an access key for it, and paste the key pair below. Keys are encrypted and only used to read your logs.',fields:[
 {k:'group',label:'Log group name',ph:'/aws/lambda/my-function',help:'AWS Console > CloudWatch > Log groups. Copy the name exactly, including the leading slash.'},
 {k:'region',label:'AWS region',ph:'ap-south-1',help:'Shown at the top right of the AWS console, for example us-east-1.'},
 {k:'aws_key',label:'Access key ID',ph:'AKIA...',help:'From IAM > Users > your user > Security credentials > Create access key.'},
 {k:'aws_secret',label:'Secret access key',secret:1,help:'Shown only once when the key is created.'},
 {k:'filter',label:'Filter',opt:1,ph:'ERROR',help:'Optional CloudWatch filter pattern. Leave empty to load everything.'}]},
gcp:{name:'Google Cloud Logging',help:'Reads logs from Google Cloud. In Google Cloud, create a service account with the role Logs Viewer, create a JSON key for it, and paste the whole JSON below. It is encrypted and only used to read your logs.',fields:[
 {k:'project',label:'Project ID',ph:'my-project-123456',help:'Use the project ID (not the name) from the project selector in the Google Cloud console.'},
 {k:'gcp_json',label:'Service account key (JSON)',area:1,secret:1,ph:'{ "type": "service_account", ... }',help:'Open the downloaded .json key file and paste its full contents.'},
 {k:'filter',label:'Filter',opt:1,ph:'severity>=WARNING',help:'Optional Google Logging query. Leave empty to load everything.'}]},
s3:{name:'AWS S3 bucket (log files)',help:'Reads new log files (plain text or .gz) from an S3 bucket. Use an IAM user with read-only access to that bucket.',fields:[
 {k:'bucket',label:'Bucket name',ph:'my-app-logs',help:'AWS Console > S3. Only the name, no s3:// prefix.'},
 {k:'prefix',label:'Folder prefix',opt:1,ph:'prod/2026/',help:'Optional. Only files whose path starts with this are read.'},
 {k:'region',label:'AWS region',opt:1,ph:'ap-south-1',help:'Optional. The region where the bucket lives.'},
 {k:'aws_key',label:'Access key ID',ph:'AKIA...',help:'From IAM > Users > your user > Security credentials.'},
 {k:'aws_secret',label:'Secret access key',secret:1,help:'Shown only once when the key is created.'}]},
file:{name:'Local log file (server folder)',help:'Reads a file from the server logs folder and picks up new lines as they are written.',fields:[
 {k:'file',label:'File name',ph:'sample-app.log',help:'A file inside the logs folder.'}]}};
const CREDK=['aws_key','aws_secret','gcp_json'];
function buildSelect(){const g=ME&&ME.guest;$('src').innerHTML=Object.entries(SRC).filter(([k])=>k!='file'||CFG.file_sources).map(([k,v])=>`<option value=${k} ${g&&k!='demo'?'disabled':''}>${esc(v.name)}${g&&k!='demo'?' (create an account to use)':''}</option>`).join('');renderForm()}
function renderForm(){const d=SRC[$('src').value];$('shelp').textContent=d.help;$('sform').innerHTML=d.fields.map(f=>`<label class=lbl>${esc(f.label)}${f.opt?' (optional)':' *'}${f.area?`<textarea id=f_${f.k} rows=4 placeholder="${esc(f.ph||'')}"></textarea>`:`<input id=f_${f.k} type=${f.secret?'password':'text'} placeholder="${esc(f.ph||'')}" autocomplete=off>`}<small>${esc(f.help||'')}</small></label>`).join('')}
async function addSrc(){const k=$('src').value,d=SRC[k],params={},creds={};
for(const f of d.fields){const v=$('f_'+f.k).value.trim();if(!v&&!f.opt){say('Please fill in: '+f.label);return}if(v)(CREDK.includes(f.k)?creds:params)[f.k]=v}
const r=await api('/sources',{method:'POST',body:JSON.stringify({kind:k,params,creds,interval:+$('iv').value||15})});
if(r.ok){d.fields.forEach(f=>{$('f_'+f.k).value=''});say('Live source started')}else say('Problem: '+r.error);await refresh()}
const ago=t=>{if(!t)return'never';const s=Math.max(0,Math.round((Date.now()-Date.parse(t))/1000));return s<60?s+'s ago':Math.round(s/60)+' min ago'};
function srcs(list){$('srcs').innerHTML=list.map(s=>{const p=s.params,name=p.group||p.project||p.bucket||p.file||p.url||'demo stream';
return `<div class=src><b>${esc(SRC[s.kind]?SRC[s.kind].name:s.kind)}</b> ${esc(name)} <span class=mut>· every ${s.interval}s · ${s.total} lines · last ${ago(s.last_run)}${s.secured?' · keys encrypted':''}</span> <span class="chip ${s.status=='error'?'bad':s.status=='running'?'ok':''}">${esc(s.status)}</span>
<button onclick="act(${s.id},'run')">Check now</button><button onclick="act(${s.id},'toggle')">${s.enabled?'Pause':'Resume'}</button><button onclick="act(${s.id},'del')">Remove</button>${s.error?`<div class=err>${esc(s.error)}</div>`:''}</div>`}).join('')||'<span class=mut>No live sources yet. Pick one above and click Start live.</span>'}
async function act(id,w){if(w=='del')await api('/sources/'+id,{method:'DELETE'});else await api('/sources/'+id+'/'+w,{method:'POST'});await refresh()}
/* ---------- chat ---------- */
const EX=['How many errors were there and which service had the most?','What was the first error?','Why did payment-api fail?','Summarize the incident for my manager','Were there any failed logins?','What happened right before the first error?'];
$('chips').innerHTML=EX.map(x=>`<span class=chip onclick="ask(this.textContent)">${esc(x)}</span>`).join('');
function bubble(c,h){const d=document.createElement('div');d.className='m '+c;d.innerHTML=h;$('chat').appendChild(d);$('chat').scrollTop=1e9;return d}
function send(){const q=$('q').value.trim();if(q){$('q').value='';ask(q)}}
async function ask(q){bubble('u',esc(q));const t=bubble('b','Thinking...');
try{const r=await api('/ask',{method:'POST',body:JSON.stringify({question:q,history:hist.slice(-3)})});
const how=(r.queries||[]).length?`<details><summary>How I found this</summary><pre>${esc(r.queries.map(x=>'- '+x.purpose+'\n  '+x.sql+'\n  -> '+(x.error?'error: '+x.error:x.rows+' rows')).join('\n'))}</pre></details>`:'';
const src=r.mode=='llm-sql'?'Answered by AI from your database':'Basic answer'+(r.llm_error?' (AI unavailable: '+esc(r.llm_error)+')':'');
t.innerHTML=esc(r.answer)+`<span class=meta>${src} · <a href=# onclick="fb(true);return false" style="color:inherit">helpful</a> · <a href=# onclick="fb(false);return false" style="color:inherit">not helpful</a></span>`+how;
hist.push({q,a:r.answer});window.last=[q,r.answer];me2()}catch(e){t.textContent='Problem: '+e.message}$('chat').scrollTop=1e9}
function fb(h){api('/feedback',{method:'POST',body:JSON.stringify({question:last[0],answer:last[1],helpful:h})});say('Thanks for the feedback');setTimeout(()=>say(''),2000)}
async function me2(){const m=await fetch('/api/me').then(r=>r.json());ME=m.user;$('aileft').textContent=ME&&ME.ai_left!=null&&CFG.ai?ME.ai_left+' AI questions left today':''}
/* ---------- dashboard ---------- */
async function load(){const s=await api('/stats');
$('cards').innerHTML=[['Log lines',s.total],['Patterns',s.templates],['Compression',s.compression+'x'],['Errors',s.errors]].map(([a,b])=>`<div class="panel card"><b>${esc(b)}</b><span>${a}</span></div>`).join('');
const mx=Math.max(1,...s.timeline.map(t=>t.n));$('tl').innerHTML=s.timeline.map(t=>`<i title="${esc(t.b)}: ${t.n} logs, ${t.e} errors" style="height:${t.n/mx*100}%"><u style="height:${t.e/t.n*100}%"></u></i>`).join('')||'<span class=mut>No data yet - load the sample data, upload a file or start a live source</span>';
const sv=$('sv'),cur=sv.value;sv.innerHTML='<option value="">all services</option>'+s.services.map(x=>`<option>${esc(x.k)}</option>`).join('');sv.value=cur;
srcs(await api('/sources'));const inc=await api('/incidents');$('inc').innerHTML=inc.map(i=>`<div class="panel inc"><b>#${i.id} ${esc(i.severity)}</b> · ${esc(when(i.start))} to ${esc(when(i.end))} · ${i.count} errors · ${esc(i.services.join(', '))}<br>${esc(i.summary)}</div>`).join('')||'<span class=mut>No incidents found</span>';logs()}
async function logs(){const p=new URLSearchParams({limit:80,q:$('f').value,service:$('sv').value,level:$('lv').value,asc:$('od').value=='1'});const r=await api('/logs?'+p);
$('lg').innerHTML='<tr><th>Log #<th>Time (UTC)<th>Service<th>Level<th>Category<th>Message</tr>'+r.map(x=>`<tr><td>${x.id}<td>${esc(when(x.ts))}<td>${esc(x.service)}<td class=${x.level}>${x.level}<td>${esc(x.category)}<td>${esc(x.msg.split('\n')[0])}</tr>`).join('')}
async function demo(){say('Loading sample data...');await api('/demo',{method:'POST'});say('Sample data loaded');hist=[];await load()}
async function clr(){if(confirm('Delete all stored logs?')){await api('/reset',{method:'POST'});say('Cleared');hist=[];await load()}}
async function up(fs){for(const f of fs){say('Uploading '+f.name+'...');const r=await fetch('/api/ingest?service='+encodeURIComponent(f.name.replace(/\.[^.]+$/,'')),{method:'POST',headers:{'x-requested-with':'logsense'},body:await f.text()}).then(async r=>{const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.detail||'Upload failed');return j}).catch(e=>({error:e.message}));
say(r.error?'Problem: '+r.error:r.duplicate?f.name+' was already loaded':'Uploaded '+f.name+' ('+r.ingested+' lines)')}await load()}
async function health(fresh){const h=await api('/health?test=1'+(fresh?'&fresh=true':''));const e=$('ai');e.className='chip '+(h.provider?(h.working?'ok':'bad'):'');
e.textContent=h.provider?(h.working?'AI connected':'AI problem: '+(h.last_error||'unknown')):'AI off - basic answers only'}
let busy=false,pend=false,pollTimer=null;
async function refresh(){if(busy){pend=true;return}busy=true;try{await load()}catch(e){say('Problem: '+e.message)}busy=false;if(pend){pend=false;setTimeout(refresh,1500)}}
function toast(a){const d=document.createElement('div');d.className='toast';d.textContent='New '+a.severity+' pattern in '+a.service+': '+a.template;$('toasts').appendChild(d);setTimeout(()=>d.remove(),9000)}
function setLive(on){const e=$('live');e.className='chip '+(on?'ok':'bad');e.textContent=on?'Live - updates instantly':'Reconnecting...';clearInterval(pollTimer);if(!on)pollTimer=setInterval(refresh,10000)}
function connect(){if(es)es.close();es=new EventSource('/api/stream');es.onopen=()=>setLive(true);es.onerror=()=>setLive(false);es.onmessage=e=>{const d=JSON.parse(e.data);(d.alerts||[]).forEach(toast);refresh()}}
$('ai').onclick=()=>health(true);
function showApp(){$('land').hidden=true;$('app').hidden=false;$('gb').hidden=!ME.guest;$('who').textContent=ME.guest?'Demo account':ME.email;buildSelect();me2();refresh();health();connect()}
async function boot(){const m=await fetch('/api/me').then(r=>r.json());CFG=m;ME=m.user;$('author').textContent=m.author?' · Built by '+m.author:'';if(ME)showApp();else showLand()}
boot();
</script>"""