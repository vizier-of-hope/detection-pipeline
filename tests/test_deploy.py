"""Exercise the deploy client against a local fake Splunk/Kibana API."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from dettools import convert, deploy


class FakeSiem(BaseHTTPRequestHandler):
    existing = {"SIGMA - Certutil Used To Download Remote File"}
    calls: list = []

    def log_message(self, *args):
        pass

    def _reply(self, code, body=None):
        payload = json.dumps(body or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        name = unquote(urlparse(self.path).path.rsplit("/", 1)[-1])
        self._reply(200 if name in self.existing else 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        path = urlparse(self.path).path
        self.calls.append((path, dict(self.headers), body))
        if path.endswith("/_import"):
            imported = [l for l in body.splitlines() if l.startswith("{")]
            self._reply(200, {"success_count": len(imported), "errors": []})
        else:
            self._reply(201)


@pytest.fixture
def fake_siem(monkeypatch):
    FakeSiem.calls = []
    server = HTTPServer(("127.0.0.1", 0), FakeSiem)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("SPLUNK_URL", url)
    monkeypatch.setenv("SPLUNK_TOKEN", "test-token")
    monkeypatch.setenv("KIBANA_URL", url)
    monkeypatch.setenv("KIBANA_API_KEY", "test-key")
    yield FakeSiem
    server.shutdown()


def test_deploy_upserts_and_respects_status(tmp_path, fake_siem):
    convert.main(["--out", str(tmp_path)])
    rc = deploy.main(["--target", "all", "--min-status", "test", "--build-dir", str(tmp_path)])
    assert rc == 0

    splunk_calls = [c for c in fake_siem.calls if "/saved/searches" in c[0]]
    paths = sorted(unquote(c[0]) for c in splunk_calls)
    # Existing rule is updated in place; new rule is created on the collection endpoint.
    assert paths == [
        "/servicesNS/nobody/search/saved/searches",
        "/servicesNS/nobody/search/saved/searches/SIGMA - Certutil Used To Download Remote File",
    ]
    create = next(c for c in splunk_calls if c[0].endswith("/saved/searches"))
    form = parse_qs(create[2])
    assert form["name"] == ["SIGMA - PowerShell Execution With Encoded Command"]
    assert form["search"][0].startswith('source="WinEventLog:Microsoft-Windows-Sysmon/Operational"')
    assert create[1]["Authorization"] == "Bearer test-token"

    (imp,) = [c for c in fake_siem.calls if c[0].endswith("/_import")]
    assert imp[1]["kbn-xsrf"] == "true"
    # experimental LSASS rule must not ship
    assert "1c4f8144-55a1-4bd3-89e6-8080f948f457" not in imp[2]
    assert "5f23f0aa-850c-44e8-a31d-7595ff0df60a" in imp[2]
