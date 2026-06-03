#!/usr/bin/env python3
"""Tail honeypot logs and forward lines as JSON POSTs to the application webhook.

Simple, dependency-free implementation using polling and urllib.
"""
import os
import time
import json
from urllib import request as urlrequest
from urllib.error import URLError

ROOT = os.path.dirname(os.path.dirname(__file__))
LOG_DIR = os.path.join(ROOT, "logs")
WEBHOOK = os.environ.get("HONEYPOT_WEBHOOK", "http://web:8000/webhook/honeypot/")
POLL = float(os.environ.get("POLL_INTERVAL", "2"))


def iter_log_files(base_dir: str):
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".log") or True:
                yield os.path.join(root, f)


def tail_file(path: str):
    try:
        f = open(path, "r", encoding="utf-8", errors="ignore")
    except Exception:
        return
    f.seek(0, 2)
    return f


def post_line(line: str, source: str):
    payload = json.dumps({"source": source, "event": "log_line", "data": {"line": line}}).encode("utf-8")
    req = urlrequest.Request(WEBHOOK, data=payload, headers={"Content-Type": "application/json"})
    try:
        urlrequest.urlopen(req, timeout=2)
    except URLError:
        pass


def main():
    files = {}
    while True:
        for path in iter_log_files(LOG_DIR):
            if path not in files or files[path] is None:
                files[path] = tail_file(path)

            fh = files.get(path)
            if not fh:
                continue

            while True:
                line = fh.readline()
                if not line:
                    break
                source = os.path.basename(os.path.dirname(path)) or os.path.basename(path)
                post_line(line.strip(), source)

        time.sleep(POLL)


if __name__ == "__main__":
    main()
