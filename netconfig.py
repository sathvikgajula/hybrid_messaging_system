"""Relay URL loading. Public relays must be HTTPS/WSS; localhost may use HTTP."""
import json
import os
import sys
from urllib.parse import urlparse, urlunparse


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_dir(*parts):
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, *parts)


def _local_host(hostname):
    return hostname in ("127.0.0.1", "localhost", "::1")


def _derive_ws(http_url):
    parsed = urlparse(http_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse((scheme, parsed.netloc, "/ws", "", "", ""))


def assert_safe_urls(http_url, ws_url):
    http = urlparse(http_url)
    ws = urlparse(ws_url)
    if http.scheme not in ("http", "https") or ws.scheme not in ("ws", "wss"):
        raise ValueError("Relay URL is not http(s)/ws(s)")
    if not http.netloc or not ws.netloc:
        raise ValueError("Relay URL is missing a host")
    if http.username or http.password or ws.username or ws.password:
        raise ValueError("Relay URL must not contain credentials")
    if not _local_host(http.hostname):
        if http.scheme != "https" or ws.scheme != "wss":
            raise ValueError("A public relay must use https:// and wss://")
        if http.hostname != ws.hostname:
            raise ValueError("HTTP and WebSocket hosts must match")


def load_relay_urls():
    data = {}
    paths = [os.path.join(app_dir(), "sealed.json")]
    if getattr(sys, "frozen", False):
        paths.append(os.path.join(resource_dir(), "sealed.json"))
        paths.append(os.path.join(resource_dir(), "sealed.example.json"))
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            data = raw
            break
    http = (os.environ.get("SEALED_RELAY") or data.get("relay") or "http://127.0.0.1:8000").strip().rstrip("/")
    ws = (os.environ.get("SEALED_WS") or data.get("ws") or "").strip()
    if not ws:
        ws = _derive_ws(http)
    assert_safe_urls(http, ws)
    return http, ws
