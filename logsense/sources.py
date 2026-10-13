"""Pull logs from the cloud. Credentials come from YOUR machine's cloud login (aws configure / gcloud auth), never from this project."""
import gzip, ipaddress, json, os, socket, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone
from . import auth, core, gen


def to_line(ms, service, message, level=None):
    ts = datetime.fromtimestamp(ms / 1000, timezone.utc).strftime(core.ISO)
    try:
        d = json.loads(message)
        if isinstance(d, dict):
            d["timestamp"] = ts; d.setdefault("service", service)
            if level: d.setdefault("level", level)
            return json.dumps(d)
    except ValueError:
        pass
    m = core.GEN_LVL.search(message)
    return json.dumps(dict(timestamp=ts, service=service, level=level or (core.norm_level(m[1]) if m else "INFO"), message=message))


def _cw(client, group, start_ms, pattern="", max_events=20000, region=None, creds=None):
    if client is None:
        try:
            import boto3
        except ImportError:
            raise RuntimeError("Run: pip install boto3   then: aws configure")
        client = boto3.client("logs", region_name=region or None, **_aws_kw(creds))
    kw = dict(logGroupName=group, startTime=int(start_ms))
    if pattern: kw["filterPattern"] = pattern
    svc, lines, last = group.rstrip("/").split("/")[-1] or group, [], int(start_ms) - 1
    while len(lines) < max_events:
        r = client.filter_log_events(**kw)
        for e in r["events"]:
            lines.append(to_line(e["timestamp"], svc, e["message"].rstrip())); last = max(last, e["timestamp"])
        if not r.get("nextToken"): break
        kw["nextToken"] = r["nextToken"]
    return ({svc: lines} if lines else {}), last + 1


def cloudwatch(group, hours=1, region=None, pattern="", client=None, max_events=20000):
    return _cw(client, group, (datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000, pattern, max_events, region)[0]


GCP_TS = "%Y-%m-%dT%H:%M:%S.%fZ"


def _gcp(client, since, filter_="", max_events=20000):
    flt = f'timestamp>"{since}"' + (f" AND ({filter_})" if filter_ else "")
    out, last = {}, since
    for i, e in enumerate(client.list_entries(filter_=flt, order_by="timestamp asc")):
        if i >= max_events: break
        lab = getattr(e.resource, "labels", None) or {}
        svc = lab.get("service_name") or lab.get("function_name") or lab.get("container_name") or e.log_name.split("/")[-1]
        msg = e.payload if isinstance(e.payload, str) else json.dumps(e.payload, default=str)
        out.setdefault(svc, []).append(to_line(int(e.timestamp.timestamp() * 1000), svc, msg, core.norm_level(e.severity) if e.severity else None))
        last = max(last, e.timestamp.astimezone(timezone.utc).strftime(GCP_TS))
    return out, last


def _gcp_client(project, creds=None):
    try:
        import google.cloud.logging as gl
    except ImportError:
        raise RuntimeError("Run: pip install google-cloud-logging   then: gcloud auth application-default login")
    if creds and creds.get("gcp_json"):
        from google.oauth2 import service_account
        return gl.Client(project=project, credentials=service_account.Credentials.from_service_account_info(json.loads(creds["gcp_json"])))
    return gl.Client(project=project)


def gcp(project, hours=1, filter_="", client=None, max_events=20000):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(GCP_TS)
    return _gcp(client or _gcp_client(project), since, filter_, max_events)[0]


def _s3(client, bucket, prefix="", since=None, max_files=20):
    out, last = {}, since
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for o in sorted(page.get("Contents", []), key=lambda o: o["LastModified"]):
            if (since and o["LastModified"] <= since) or len(out) >= max_files: continue
            body = client.get_object(Bucket=bucket, Key=o["Key"])["Body"].read(20_000_000)
            if o["Key"].endswith(".gz"): body = gzip.decompress(body)
            out[o["Key"].rsplit("/", 1)[-1].split(".")[0] or "s3"] = body.decode("utf-8", "replace").splitlines()
            last = max(last, o["LastModified"]) if last else o["LastModified"]
    return out, last


def _s3_client(creds=None, region=None):
    try:
        import boto3
    except ImportError:
        raise RuntimeError("Run: pip install boto3   then: aws configure")
    return boto3.client("s3", region_name=region or None, **_aws_kw(creds))


def s3(bucket, prefix="", client=None, max_files=20):
    return _s3(client or _s3_client(), bucket, prefix, None, max_files)[0]


def _check_url(u):
    if not u.startswith(("http://", "https://")): raise ValueError("Only http(s) links are allowed")
    if os.getenv("LOGSENSE_ALLOW_PRIVATE_URLS") == "1": return
    for ai in socket.getaddrinfo(urllib.parse.urlparse(u).hostname or "", None):
        ip = ipaddress.ip_address(ai[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Private or internal addresses are blocked (set LOGSENSE_ALLOW_PRIVATE_URLS=1 to allow)")


def url(u):
    _check_url(u)
    text = urllib.request.urlopen(u, timeout=30).read(20_000_000).decode("utf-8", "replace")
    return {u.rstrip("/").rsplit("/", 1)[-1].split("?")[0] or "remote": text.splitlines()}


def _safe_path(name):
    base = os.path.realpath(os.getenv("LOGSENSE_LOG_DIR", "logs"))
    p = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, p]) != base: raise ValueError("The file must be inside the logs folder")
    return p


def file_tail(name, offset=0):
    """Only the lines added since byte `offset`; handles log rotation and ignores a half-written last line."""
    p = _safe_path(name)
    if os.path.getsize(p) < offset: offset = 0
    with open(p, "rb") as f:
        f.seek(offset); data = f.read(5_000_000)
    cut = data.rfind(b"\n") + 1
    lines = data[:cut].decode("utf-8", "replace").splitlines()
    return ({os.path.splitext(os.path.basename(p))[0]: lines} if lines else {}), str(offset + cut)


def _aws_kw(creds):
    return {"aws_access_key_id": creds["aws_key"], "aws_secret_access_key": creds["aws_secret"]} if creds and creds.get("aws_key") else {}


def _creds(p, kind):
    """Each user's own cloud keys (stored encrypted). On a hosted server the server's own cloud access is NEVER used."""
    creds = json.loads(auth.decrypt(p["_enc"])) if p.get("_enc") else None
    if not creds and os.getenv("LOGSENSE_HOSTED") == "1" and kind in ("cloudwatch", "gcp", "s3"):
        raise ValueError("Cloud credentials are required: add your own read-only access keys")
    return creds


def poll(kind, p, cursor, now=None):
    """One incremental fetch -> ({service: [new lines]}, new_cursor). Only events newer than the cursor are returned."""
    need = lambda k: p.get(k) or (_ for _ in ()).throw(ValueError(f"'{k}' is required for {kind}"))
    t1 = (now or datetime.now(timezone.utc)).replace(tzinfo=None, microsecond=0)
    if kind == "demo":
        t0 = datetime.strptime(cursor, core.ISO) if cursor else t1 - timedelta(seconds=60)
        return gen.stream(max(t0, t1 - timedelta(minutes=10)), t1), t1.strftime(core.ISO)
    if kind == "cloudwatch":
        start = int(cursor) if cursor else int((t1 - timedelta(hours=float(p.get("hours") or 0.1))).replace(tzinfo=timezone.utc).timestamp() * 1000)
        data, nxt = _cw(None, need("group"), start, p.get("filter", ""), region=p.get("region"), creds=_creds(p, kind))
        return data, str(nxt)
    if kind == "gcp":
        since = cursor or (t1 - timedelta(hours=float(p.get("hours") or 0.1))).strftime(GCP_TS)
        return _gcp(_gcp_client(need("project"), _creds(p, kind)), since, p.get("filter", ""))
    if kind == "s3":
        since = datetime.fromisoformat(cursor) if cursor else (datetime.now(timezone.utc) - timedelta(hours=float(p.get("hours") or 24)))
        data, last = _s3(_s3_client(_creds(p, kind), p.get("region")), need("bucket"), p.get("prefix", ""), since)
        return data, (last or since).isoformat()
    if kind == "file":
        if os.getenv("LOGSENSE_HOSTED") == "1" and os.getenv("LOGSENSE_ALLOW_FILE_SOURCE") != "1": raise ValueError("Local file sources are disabled on this server")
        return file_tail(need("file"), int(cursor or 0))
    if kind == "url":
        data = url(need("url")); name, lines = next(iter(data.items()))
        seen = int(cursor or 0); new = lines[seen:] if len(lines) >= seen else lines
        return ({name: new} if new else {}), str(len(lines))
    raise ValueError(f"unknown source '{kind}'")


def pull(source, p):
    """One-time pull (last N hours)."""
    need = lambda k: p.get(k) or (_ for _ in ()).throw(ValueError(f"'{k}' is required for {source}"))
    h = float(p.get("hours") or 1)
    if source == "cloudwatch": return cloudwatch(need("group"), h, p.get("region"), p.get("filter", ""))
    if source == "gcp": return gcp(need("project"), h, p.get("filter", ""))
    if source == "s3": return s3(need("bucket"), p.get("prefix", ""))
    if source == "url": return url(need("url"))
    raise ValueError(f"unknown source '{source}'")
