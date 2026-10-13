"""Ship a log file to a running LogSense server.  python -m logsense.cli app.log --service payment-api [--follow]"""
import argparse, os, time, urllib.parse, urllib.request


def send(url, key, service, lines):
    q = urllib.parse.urlencode({"service": service})
    req = urllib.request.Request(f"{url.rstrip('/')}/api/ingest?{q}", "".join(lines).encode(), {"x-api-key": key or ""})
    return urllib.request.urlopen(req, timeout=60).read().decode()


def main():
    a = argparse.ArgumentParser()
    a.add_argument("file"); a.add_argument("--service", default="app"); a.add_argument("--url", default="http://localhost:8000")
    a.add_argument("--follow", action="store_true", help="keep watching the file (like tail -f)")
    a = a.parse_args(); key = os.getenv("LOGSENSE_API_KEY")
    with open(a.file, encoding="utf-8", errors="replace") as f:
        while True:
            lines = f.readlines(200_000)
            if lines:
                print(send(a.url, key, a.service, lines))
            elif a.follow:
                time.sleep(2)
            else:
                break


if __name__ == "__main__":
    main()
