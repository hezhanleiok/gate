import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

import pytest

import vpngate

HEADER = (
    "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,"
    "TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64"
)


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def make_csv() -> str:
    tcp = b64("proto tcp\nremote 203.0.113.9 443\n")
    udp = b64("proto udp\nremote 203.0.113.10 1194\n")
    return "\n".join(
        [
            "*",
            HEADER,
            f"public-vpn-1,203.0.113.9,1000,12,1000000,Japan,JP,1,1,1,1,2weeks,op,,{tcp}",
            f"public-vpn-2,203.0.113.10,900,80,1000000,Japan,JP,1,1,1,1,2weeks,op,,{udp}",
            "*",
        ]
    )


CHECK_OK = {
    "success": True,
    "responseTime": 120,
    "colo": "NRT",
    "exit": {
        "ip": "198.51.100.7",
        "country": "Japan",
        "country_code": "JP",
        "city": "Tokyo",
        "continent": "AS",
        "asn": {"asn": 1234, "name": "NTT", "org": "NTT EAST"},
        "is_datacenter": False,
    },
}

CHECK_FAIL = {"success": False, "error": "sstp handshake timeout"}


def build_handler(csv_body: str, payload: dict) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server 接口
            path = urlsplit(self.path).path
            if path == "/api":
                body, ctype = csv_body.encode("utf-8"), "text/plain; charset=utf-8"
            elif path == "/check":
                body, ctype = json.dumps(payload).encode("utf-8"), "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: A003 - 静默
            pass

    return Handler


@pytest.fixture
def server():
    servers: list[HTTPServer] = []

    def start(csv_body: str, payload: dict) -> str:
        httpd = HTTPServer(("127.0.0.1", 0), build_handler(csv_body, payload))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def prepare_env(monkeypatch, base: str, public_dir, **extra):
    monkeypatch.setenv("VPNGATE_API", f"{base}/api")
    monkeypatch.setenv("CHECK_WORKER", f"{base}/check?sstp=vpn:vpn@")
    monkeypatch.setenv("PUBLIC_DIR", str(public_dir))
    monkeypatch.setenv("OPTIMAL_API", "")
    monkeypatch.setenv("EDGE_HOSTS", "edge.example.com:443")
    monkeypatch.setenv("CHECK_CONCURRENCY", "2")
    monkeypatch.setenv("CHECK_TIMEOUT", "5")
    monkeypatch.setenv("CHECK_DEADLINE", "60")
    monkeypatch.setenv("HTTP_TIMEOUT", "5")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    for key, value in extra.items():
        monkeypatch.setenv(key, value)
    for key in ("DOMAIN", "MAX_CHECK_NODES", "MIN_SUCCESS_RATIO"):
        if key not in extra:
            monkeypatch.delenv(key, raising=False)


def test_main_generates_all_artifacts(server, monkeypatch, tmp_path):
    base = server(make_csv(), CHECK_OK)
    prepare_env(monkeypatch, base, tmp_path / "public")

    vpngate.main()

    data = json.loads((tmp_path / "public" / "data.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["stats"]["raw_nodes"] == 2
    assert data["stats"]["sstp_nodes"] == 1
    assert data["stats"]["success"] == 1
    assert data["countries"]["JP"]["count"] == 1
    assert data["countries"]["JP"]["nodes"][0]["residential"] == "residential"
    assert data["worker_host"].startswith("127.0.0.1")

    nodes_text = (tmp_path / "public" / "nodes.txt").read_text(encoding="utf-8")
    assert nodes_text.strip() == (
        "edge.example.com:443#日本-住宅-01$sstp://vpn:vpn@public-vpn-1.opengw.net:443"
    )

    html = (tmp_path / "public" / "index.html").read_text(encoding="utf-8")
    assert "VPN Gate SSTP" in html


def test_main_refuses_to_publish_when_all_checks_fail(server, monkeypatch, tmp_path):
    base = server(make_csv(), CHECK_FAIL)
    public_dir = tmp_path / "public"
    prepare_env(monkeypatch, base, public_dir)

    with pytest.raises(SystemExit) as excinfo:
        vpngate.main()

    assert excinfo.value.code == 2
    assert not (public_dir / "data.json").exists()
    assert not (public_dir / "nodes.txt").exists()


def test_main_fails_fast_without_worker_config(server, monkeypatch, tmp_path):
    base = server(make_csv(), CHECK_OK)
    prepare_env(monkeypatch, base, tmp_path / "public")
    monkeypatch.delenv("CHECK_WORKER", raising=False)

    with pytest.raises(SystemExit) as excinfo:
        vpngate.main()

    assert excinfo.value.code == 2
    assert not (tmp_path / "public").exists()


def test_derive_nodes_url_uses_github_repository(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "someone/gate")
    monkeypatch.delenv("NODES_URL", raising=False)
    assert vpngate.derive_nodes_url() == "https://someone.github.io/gate/nodes.txt"
