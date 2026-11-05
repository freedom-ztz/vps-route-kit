"""Temporary controlled HTTPS/UDP fixture; never a subscription or proxy server."""

import argparse
import http.server
import json
import socket
import ssl
import threading
import urllib.parse
import time


class ProbeServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(
        self,
        address,
        context,
        *,
        handshake_timeout=10,
        idle_timeout=120,
        download_bytes=25_000_000,
        upload_bytes=8_000_000,
        stream_seconds=31,
    ):
        self.context = context
        self.handshake_timeout = handshake_timeout
        self.idle_timeout = idle_timeout
        self.download_bytes = download_bytes
        self.upload_bytes = upload_bytes
        self.stream_seconds = stream_seconds
        super().__init__(address, Handler)

    def process_request_thread(self, request, address):
        try:
            request.settimeout(self.handshake_timeout)
            wrapped = self.context.wrap_socket(request, server_side=True)
            wrapped.settimeout(self.idle_timeout)
        except (ssl.SSLError, OSError):
            request.close()
            return
        super().process_request_thread(wrapped, address)

    def handle_error(self, request, address):
        # Disconnects are evidence on the client; do not log request bodies or URLs.
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, data=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            self.reply(204)
        elif path == "/metadata":
            self.reply(
                200,
                json.dumps(
                    {
                        "schema_version": 1,
                        "handshake_timeout": self.server.handshake_timeout,
                        "idle_timeout": self.server.idle_timeout,
                        "download_bytes": self.server.download_bytes,
                        "upload_bytes": self.server.upload_bytes,
                        "stream_seconds": self.server.stream_seconds,
                    }
                ).encode(),
            )
        elif path == "/egress":
            self.reply(200, json.dumps({"ip": self.client_address[0]}).encode())
        elif path == "/down":
            self.send_response(200)
            self.send_header("Content-Length", str(self.server.download_bytes))
            self.end_headers()
            remaining = self.server.download_bytes
            while remaining:
                size = min(65536, remaining)
                self.wfile.write(b"0" * size)
                remaining -= size
        elif path == "/stream":
            count = max(2, int(self.server.stream_seconds) + 1)
            self.send_response(200)
            self.send_header("Content-Length", str(count))
            self.end_headers()
            for index in range(count):
                self.wfile.write(b".")
                self.wfile.flush()
                if index < count - 1:
                    time.sleep(self.server.stream_seconds / (count - 1))
        else:
            self.reply(404)

    def do_POST(self):
        if self.path != "/up":
            self.close_connection = True
            self.reply(404)
            return
        try:
            remaining = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            remaining = -1
        if not 0 <= remaining <= self.server.upload_bytes:
            self.close_connection = True
            self.reply(413 if remaining > self.server.upload_bytes else 400)
            return
        while remaining:
            data = self.rfile.read(min(65536, remaining))
            if not data:
                self.close_connection = True
                return
            remaining -= len(data)
        self.reply(204)


def udp_echo(sock, stop):
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(4096)
            sock.sendto(data, peer)
        except socket.timeout:
            continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18446)
    parser.add_argument("--udp-port", type=int, default=18445)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.listen, args.udp_port))
        sock.settimeout(0.5)
        udp = threading.Thread(target=udp_echo, args=(sock, stop), daemon=True)
        udp.start()
        try:
            with ProbeServer((args.listen, args.port), context) as server:
                server.serve_forever()
        finally:
            stop.set()
            udp.join(timeout=2)


if __name__ == "__main__":
    main()
