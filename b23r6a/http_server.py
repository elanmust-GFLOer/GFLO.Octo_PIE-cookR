"""Loopback test server; no network Auth client, database client, or mutation dispatch."""
import argparse
import json
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .contracts import Request, Decision, Outcome, Reason
from .gateway import Gateway, Adapters
from .adapters.offline import OfflinePrimary

def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out
    def invalid(value):
        raise ValueError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)

class Server(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    def __init__(self, address, gateway):
        if address[0] != "127.0.0.1":
            raise ValueError("R6A is loopback-only")
        self.gateway = gateway
        self.worker_slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(2)
        return sock, addr

    def process_request(self, request, client_address):
        if not self.worker_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        def abort():
            try: request.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            request.close()
        # Absolute connection lifetime, including slowly trickled headers/body.
        timer=threading.Timer(3,abort)
        timer.daemon=True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            timer.join(.1)
            self.worker_slots.release()

    def handle_error(self, request, client_address):
        # Never print request/header/exception strings.
        pass

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "R6A-Lab"
    sys_version = ""

    def log_message(self, *args):
        pass

    def reply(self, body, code=200):
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def deny(self, code=400):
        decision=Decision(Outcome.DENY, Reason.INVALID_REQUEST, str(uuid.uuid4()), str(uuid.uuid4()))
        try:
            self.server.gateway.events.commit(self.server.gateway.events.event(decision,"unknown"))
        except Exception:
            pass  # No protected data is available on this path.
        self.reply(decision.as_dict(), code)

    def headers_valid(self):
        host = f"127.0.0.1:{self.server.server_port}"
        return (sum(len(k) + len(v) for k,v in self.headers.items()) <= 16384
                and self.headers.get_all("Host", []) == [host]
                and self.headers.get("Origin") in (None, "http://" + host)
                and "Transfer-Encoding" not in self.headers
                and len(self.headers.get_all("Authorization", [])) <= 1)

    def do_GET(self):
        if not self.headers_valid():
            return self.deny()
        if self.path == "/healthz":
            request = {"operation": "system.health.read", "request_id": str(uuid.uuid4()), "payload": {}}
            return self.server.gateway.handle(request, deliver=self.reply)
        if self.path != "/v1/audit/summary":
            return self.deny(404)
        if "Cookie" in self.headers:
            return self.deny()
        rid = self.headers.get("X-Request-ID", str(uuid.uuid4()))
        request = {"operation": "audit.summary.read", "request_id": rid, "payload": {}}
        def delivery(body):
            code = 200 if body["decision"] == "ALLOW" else 503 if body["decision"] == "QUARANTINE" else 401 if body["reason_code"].startswith("AUTH_") else 403
            self.reply(body, code)
        return self.server.gateway.handle(request, self.token(), include_data=True, deliver=delivery)

    def token(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def do_POST(self):
        if not self.headers_valid() or self.path != "/v1/decisions" or "Cookie" in self.headers:
            return self.deny()
        if self.headers.get("Content-Type") != "application/json":
            return self.deny(415)
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            return self.deny()
        length = int(lengths[0])
        if length > 16384:
            return self.deny(413)
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.deny()
            value = strict_json(raw)
        except (ValueError, UnicodeError, RecursionError, socket.timeout):
            return self.deny()
        return self.server.gateway.handle(value, self.token(), deliver=self.reply)

    def do_DELETE(self): self.deny(405)
    def do_PUT(self): self.deny(405)
    def do_PATCH(self): self.deny(405)
    def do_OPTIONS(self): self.deny(405)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    # Health works; protected requests fail closed without injected test adapters.
    with Server(("127.0.0.1", args.port), Gateway(Adapters(), OfflinePrimary())) as server:
        server.serve_forever(poll_interval=.1)

if __name__ == "__main__":
    main()
