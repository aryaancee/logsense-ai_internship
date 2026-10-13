"""Provider-agnostic LLM client (stdlib only). Keys come from env vars or a local .env file - never from code."""
import json, os, re, time, urllib.error, urllib.request

FALLBACKS = {"gemini": "gemini-3.5-flash-lite"}  # tried last when the main model is overloaded (503/429)
DEFAULTS = {"gemini": "gemini-3.6-flash", "anthropic": "claude-haiku-5-5", "openai": "gpt-4o-mini", "ollama": "llama3.1"}
last_error = None


def load_env(path=None):
    """Read .env; if a key appears twice the LAST line wins. Real environment variables still take priority."""
    vals = {}
    try:
        for ln in open(path or os.getenv("LOGSENSE_ENV", ".env"), encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                v = v.split(" #")[0].strip().strip("\"'")
                if v: vals[k.strip()] = v
    except OSError:
        return
    for k, v in vals.items():
        os.environ.setdefault(k, v)


load_env()


def provider():
    p = os.getenv("LOGSENSE_PROVIDER", "auto").lower()
    if p != "auto":
        return None if p == "none" else p
    for name, envs in (("gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY")), ("anthropic", ("ANTHROPIC_API_KEY",)),
                       ("openai", ("OPENAI_API_KEY",)), ("ollama", ("OLLAMA_HOST",))):
        if any(os.getenv(e) for e in envs):
            return name
    return None


def enabled():
    return provider() is not None


def status():
    p = provider()
    return dict(provider=p, model=(os.getenv("LOGSENSE_MODEL") or DEFAULTS.get(p)) if p else None, last_error=last_error)


def _post(url, body, headers):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", "User-Agent": "LogSense/1.0", **headers})
    try:
        return json.load(urllib.request.urlopen(req, timeout=int(os.getenv("LOGSENSE_TIMEOUT", "30"))))
    except urllib.error.HTTPError as e:  # keep Google's/OpenAI's explanation, it says exactly what is wrong
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}") from None


def _once(prompt, max_tokens, m):
    """Text from the configured provider, or None (callers then fall back to rule-based logic)."""
    global last_error
    p = provider()
    if not p:
        return None
    msgs = [{"role": "user", "content": prompt}]
    try:
        if p == "gemini":
            key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            r = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                      {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": max(max_tokens, 2048), "temperature": 0}},
                      {"x-goog-api-key": key or ""})
            out = "".join(x.get("text", "") for x in r["candidates"][0]["content"]["parts"])
        elif p == "anthropic":
            r = _post("https://api.anthropic.com/v1/messages", {"model": m, "max_tokens": max_tokens, "messages": msgs},
                      {"x-api-key": os.getenv("ANTHROPIC_API_KEY", ""), "anthropic-version": "2023-06-01"})
            out = r["content"][0]["text"]
        elif p == "openai":  # also any OpenAI-compatible server via OPENAI_BASE_URL (Groq, OpenRouter, vLLM, LM Studio...)
            base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            r = _post(f"{base}/chat/completions", {"model": m, "max_tokens": max(max_tokens, 2048), "temperature": 0, "messages": msgs},
                      {"Authorization": "Bearer " + os.getenv("OPENAI_API_KEY", "")})
            out = r["choices"][0]["message"]["content"]
        elif p == "ollama":
            r = _post(os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/api/generate", {"model": m, "prompt": prompt, "stream": False}, {})
            out = r["response"]
        else:
            raise ValueError(f"unknown provider '{p}'")
        if not out.strip():
            raise ValueError("empty response")
        last_error = None
        return out
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        for env in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            if os.getenv(env):
                msg = msg.replace(os.getenv(env), "***")  # never show a key in the UI
        last_error = " ".join(msg.split())[:400]
        return None


def complete(prompt, max_tokens=500):
    """Text from the provider; retries overload errors (429/5xx/timeouts), then tries a fallback model."""
    p = provider()
    m = os.getenv("LOGSENSE_MODEL") or DEFAULTS.get(p)
    fb = os.getenv("LOGSENSE_FALLBACK_MODEL") or FALLBACKS.get(p)
    for i, model in enumerate([m, m, fb] if fb and fb != m else [m, m]):
        out = _once(prompt, max_tokens, model)
        if out or not last_error or not re.search(r"HTTP (5\d\d)|timed out", last_error):
            return out
        time.sleep(1.5 * (i + 1))
    return None
