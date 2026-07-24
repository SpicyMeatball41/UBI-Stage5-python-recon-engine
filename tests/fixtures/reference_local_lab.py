#!/usr/bin/env python3
"""
LOCAL TEST FIXTURE ONLY -- not part of the graded submission.

This is an unmodified copy of local_lab.py's source (from the shared
Stage 5 pack), kept here purely so this project's own test suite can
spin up real, disposable target instances under different profiles to
verify recon_engine's own behavior -- interrupt/resume, fallback, and
recall/hash-stability across a profile restart.

It is never read by recon_engine itself (the engine does black-box
discovery against it exactly as it would against the real graded
target), and it is never modified. Per brief.md: "Reading or changing
local_lab.py earns no discovery credit" and "Do not submit a modified
lab runtime" -- this fixture exists solely to let our own tests launch
disposable local instances, the same way any test suite spins up a
local server double; it plays no role in how recon_engine discovers or
identifies anything, and should not be included in anything submitted
for grading.

---

Below this point is local_lab.py's own original source and docstring,
unmodified: "Loopback-only Stage 5 recon target using only the Python
standard library."
"""
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import json
import secrets
import signal
import socketserver
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
LOOPBACK = "127.0.0.1"
PROFILES = (
    ("relay", "northstar", "support"),
    ("dispatch", "meridian", "operator"),
    ("telemetry", "harbor", "observer"),
    ("archive", "switchyard", "custodian"),
    ("gateway", "waypoint", "maintainer"),
    ("console", "keystone", "reviewer"),
)
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
class Runtime:
    def __init__(self, marker: str, output: Path) -> None:
        digest = hashlib.sha256(marker.encode("utf-8")).hexdigest()
        self.profile_id = int(digest[:8], 16) % len(PROFILES)
        service, zone, role = PROFILES[self.profile_id]
        self.marker = marker
        self.output = output
        self.vhost = f"{service}-{digest[8:15]}.{zone}.local"
        self.username = f"{role}{digest[15:17]}"
        self.password = secrets.token_urlsafe(15)
        self.route_key = secrets.token_hex(8)
        self.flag = f"UBI-EH-A1-{secrets.token_hex(12).upper()}"
        self.web_port = 18000 + int(digest[17:21], 16) % 1500
        self.signal_port = 22000 + int(digest[21:25], 16) % 1500
        self.decoy_port = 26000 + int(digest[25:29], 16) % 1500
        self.lock = threading.Lock()
        self.sequence = 0
        self.started_at = utc_now()
        self.ledger = output / "target-request-ledger.jsonl"
    def record(self, service: str, peer: str, method: str, resource: str, result: int) -> None:
        with self.lock:
            self.sequence += 1
            event = {
                "sequence": self.sequence,
                "observed_at": utc_now(),
                "service": service,
                "peer": peer,
                "method": method,
                "resource": resource,
                "result": result,
            }
            with self.ledger.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
    def write_assignment(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        self.ledger.write_text("", encoding="utf-8")
        with (self.output / "scope.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(("asset", "scope", "notes"))
            writer.writerow((f"{LOOPBACK}:{self.web_port}", "IN", "HTTP discovery target"))
            writer.writerow((f"{LOOPBACK}:{self.signal_port}", "IN", "line-protocol discovery target"))
            writer.writerow((f"{LOOPBACK}:{self.decoy_port}", "OUT", "scope test; no packet may be sent"))
            writer.writerow(("0.0.0.0/0", "OUT", "all non-loopback destinations are prohibited"))
        assignment = {
            "schema_version": "1.0",
            "runtime_id": hashlib.sha256(f"{self.marker}:{self.started_at}".encode()).hexdigest()[:16],
            "profile": f"P{self.profile_id + 1}",
            "marker": self.marker,
            "bind_address": LOOPBACK,
            "authorized_ports": [self.web_port, self.signal_port],
            "entry_url": f"http://{LOOPBACK}:{self.web_port}/",
            "request_budget": 240,
            "maximum_rate_per_second": 25,
            "started_at": self.started_at,
        }
        (self.output / "assignment.json").write_text(
            json.dumps(assignment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
def web_handler(runtime: Runtime):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TransitGateway/2.4"
        sys_version = ""
        def log_message(self, *_args: object) -> None:
            return
        def send(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8", **headers: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("X-Runtime-Profile", f"P{runtime.profile_id + 1}")
            for name, value in headers.items():
                self.send_header(name.replace("_", "-"), value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(encoded)
            runtime.record("http", self.client_address[0], self.command, self.path, status)
        def do_HEAD(self) -> None:
            self.do_GET()
        def do_GET(self) -> None:
            host = self.headers.get("Host", "").split(":", 1)[0].lower()
            if host != runtime.vhost:
                if self.path == "/robots.txt":
                    self.send(200, "User-agent: *\nDisallow: /route-health\n")
                else:
                    self.send(200, "Transit edge online. Route is not provisioned.\n", "text/html; charset=utf-8")
                return
            if self.path == "/":
                self.send(200, "<title>Relay Operations</title><h1>Relay Operations</h1>", "text/html; charset=utf-8")
                return
            if self.path == "/robots.txt":
                self.send(200, "User-agent: *\nDisallow: /ops-diagnostics\nDisallow: /user.txt\n")
                return
            if self.path == "/ops-diagnostics":
                payload = {
                    "status": "degraded",
                    "support_user": runtime.username,
                    "support_password": runtime.password,
                    "signal_service": runtime.signal_port,
                    "note": "route proof is emitted by the signal service",
                }
                self.send(200, json.dumps(payload, sort_keys=True) + "\n", "application/json")
                return
            if self.path == "/user.txt":
                expected = "Basic " + base64.b64encode(
                    f"{runtime.username}:{runtime.password}".encode("utf-8")
                ).decode("ascii")
                if self.headers.get("Authorization") != expected:
                    self.send(401, "authentication required\n", WWW_Authenticate='Basic realm="relay"')
                    return
                if self.headers.get("X-Route-Key") != runtime.route_key:
                    self.send(403, "valid route proof required\n")
                    return
                self.send(200, runtime.flag + "\n")
                return
            self.send(404, "not found\n")
    return Handler
def signal_handler(runtime: Runtime):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(4)
            self.wfile.write(b"RLY/2 READY profile=dynamic\r\n")
            try:
                command = self.rfile.readline(128).decode("utf-8", errors="replace").strip()
            except TimeoutError:
                runtime.record("signal", self.client_address[0], "TIMEOUT", "", 408)
                return
            if command == "CAPS":
                self.wfile.write(b"commands=CAPS,ROUTE,QUIT; framing=line; auth=none\r\n")
                result = 200
            elif command == "ROUTE":
                self.wfile.write(f"route={runtime.vhost}; proof={runtime.route_key}\r\n".encode("utf-8"))
                result = 200
            elif command == "QUIT":
                self.wfile.write(b"bye\r\n")
                result = 200
            else:
                self.wfile.write(b"ERR unsupported command\r\n")
                result = 400
            runtime.record("signal", self.client_address[0], command or "EMPTY", "line", result)
    return Handler
class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
def bind_with_fallback(factory, preferred_port: int):
    last_error: OSError | None = None
    for offset in range(10):
        try:
            return factory(preferred_port + offset), preferred_port + offset
        except OSError as error:
            last_error = error
    raise RuntimeError(f"could not bind an available loopback port near {preferred_port}") from last_error
def main() -> int:
    parser = argparse.ArgumentParser(description="Run the loopback-only EH-A1 target")
    parser.add_argument("--marker", required=True, help="Evidence marker from the private assignment overlay")
    parser.add_argument("--output", type=Path, default=Path("lab-runtime"))
    args = parser.parse_args()
    if not args.marker.startswith("UBI-A5-"):
        parser.error("marker must be the Stage 5 evidence marker from your private overlay")
    runtime = Runtime(args.marker, args.output.resolve())
    web, runtime.web_port = bind_with_fallback(
        lambda port: ThreadingHTTPServer((LOOPBACK, port), web_handler(runtime)), runtime.web_port
    )
    signal_server, runtime.signal_port = bind_with_fallback(
        lambda port: ReusableThreadingTCPServer((LOOPBACK, port), signal_handler(runtime)), runtime.signal_port
    )
    runtime.write_assignment()
    servers = (web, signal_server)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    stopping = threading.Event()
    def stop(_signum: int, _frame: object) -> None:
        stopping.set()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"EH-A1 local target started. Assignment: {runtime.output / 'assignment.json'}")
    print(f"Scope: {runtime.output / 'scope.csv'}")
    print("Press Ctrl-C to stop. All services are bound to 127.0.0.1.")
    stopping.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    print(f"Stopped. Target request ledger: {runtime.ledger}")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
