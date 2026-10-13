"""Synthetic multi-format cloud logs with a DB outage (02:02-02:17) and an OOM, for demos/tests."""
import json, random
from collections import defaultdict
from datetime import datetime, timedelta

ISO = "%Y-%m-%dT%H:%M:%SZ"


def generate(minutes=180, seed=7, start=datetime(2026, 8, 14, 1, 0, 0)):
    r = random.Random(seed)
    users = ["asha@example.com", "ravi@example.org", "mei@example.net", "li@example.com"]
    ev = []
    def add(t, svc, *lines): ev.append((t, svc, list(lines)))
    for m in range(minutes):
        outage = 62 <= m < 77
        for _ in range(r.randint(4, 8)):
            t = start + timedelta(minutes=m, seconds=r.randint(0, 59)); ts = t.strftime(ISO); ip = f"10.0.{r.randint(0, 9)}.{r.randint(1, 250)}"
            u = r.choice(users); k = r.random()
            if outage and k < 0.55:
                add(t, "payment-api", f"{ts} payment-api ERROR Timeout connecting to db after {r.choice([30, 45])}s")
                if r.random() < .4: add(t, "payment-api", f"{ts} payment-api ERROR Connection pool exhausted (size=50, waiting={r.randint(5, 90)})")
                if r.random() < .15: add(t, "payment-api", f"{ts} payment-api ERROR Unhandled exception in checkout for {u}", "Traceback (most recent call last):", '  File "pay.py", line 88, in charge', "psycopg2.OperationalError: connection timed out")
                add(t, "checkout-web", f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "POST /checkout HTTP/1.1" {r.choice([502, 504])} 0')
                add(t, "auth-service", f"{ts} auth-service WARNING Slow login latency {r.randint(2000, 9000)}ms")
            elif k < .30: add(t, "payment-api", f"{ts} payment-api INFO Payment {r.randint(10**5, 10**6)} processed for {u} in {r.randint(40, 300)}ms")
            elif k < .50: add(t, "auth-service", f"{ts} auth-service INFO User {u} logged in from {ip}")
            elif k < .70: add(t, "checkout-web", f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /cart/{r.randint(1, 999)} HTTP/1.1" 200 {r.randint(200, 4000)}')
            elif k < .80: add(t, "db", f"{ts} db INFO checkpoint complete: wrote {r.randint(100, 900)} buffers")
            elif k < .88: add(t, "notification-svc", json.dumps(dict(timestamp=ts, level="info", service="notification-svc", message=f"Sent email to {u}")))
            elif k < .94: add(t, "db", f"{ts} db WARNING Slow query took {r.randint(800, 3000)}ms")
            else: add(t, "auth-service", f"{ts} auth-service WARNING Failed login for {u} from {ip} (attempt {r.randint(1, 6)})")
        if m == 150:
            t = start + timedelta(minutes=m, seconds=5)
            add(t, "worker", f"{t.strftime(ISO)} worker CRITICAL Out of memory: killed process worker-3 (pid {r.randint(1000, 9000)})")
    out = defaultdict(list)
    for _, svc, lines in sorted(ev, key=lambda x: x[0]): out[svc] += lines
    return dict(out)


def stream(t0, t1):
    """Realistic live logs for the window (t0, t1]. The last minute of every 6 is a database outage."""
    r = random.Random(int(t1.timestamp()))
    users = ["asha@example.com", "ravi@example.org", "mei@example.net", "li@example.com"]
    out = defaultdict(list)
    t = t0.replace(microsecond=0)
    while t < t1:
        t += timedelta(seconds=1)
        outage = (int(t.timestamp()) // 60) % 6 == 5
        for _ in range(r.randint(0, 2)):
            ts, k, u, ip = t.strftime(ISO), r.random(), r.choice(users), f"10.0.{r.randint(0, 9)}.{r.randint(1, 250)}"
            nx = lambda path, code: f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{path} HTTP/1.1" {code} {r.randint(0, 4000)}'
            if r.random() < 0.002:
                out["worker"].append(f"{ts} worker CRITICAL Out of memory: killed process worker-{r.randint(1, 5)} (pid {r.randint(1000, 9000)})")
            elif outage and k < .6:
                out["payment-api"].append(f"{ts} payment-api ERROR Timeout connecting to db after {r.choice([30, 45])}s")
                if r.random() < .3: out["payment-api"].append(f"{ts} payment-api ERROR Connection pool exhausted (size=50, waiting={r.randint(5, 90)})")
                out["checkout-web"].append(nx("POST /checkout", r.choice([502, 504])))
                out["auth-service"].append(f"{ts} auth-service WARNING Slow login latency {r.randint(2000, 9000)}ms")
            elif k < .3: out["payment-api"].append(f"{ts} payment-api INFO Payment {r.randint(10**5, 10**6)} processed for {u} in {r.randint(40, 300)}ms")
            elif k < .5: out["auth-service"].append(f"{ts} auth-service INFO User {u} logged in from {ip}")
            elif k < .7: out["checkout-web"].append(nx(f"GET /cart/{r.randint(1, 999)}", 200))
            elif k < .8: out["db"].append(f"{ts} db INFO checkpoint complete: wrote {r.randint(100, 900)} buffers")
            elif k < .88: out["notification-svc"].append(json.dumps(dict(timestamp=ts, level="info", service="notification-svc", message=f"Sent email to {u}")))
            elif k < .94: out["db"].append(f"{ts} db WARNING Slow query took {r.randint(800, 3000)}ms")
            else: out["auth-service"].append(f"{ts} auth-service WARNING Failed login for {u} from {ip} (attempt {r.randint(1, 6)})")
    return dict(out)
