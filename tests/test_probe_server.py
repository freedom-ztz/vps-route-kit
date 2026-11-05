import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from vrk.probe_server import ProbeServer, udp_echo


class ProbeServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        (root / "openssl.cnf").write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
            "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                str(root / "openssl.cnf"),
                "-keyout",
                str(root / "key.pem"),
                "-out",
                str(root / "cert.pem"),
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "cert.pem", root / "key.pem")
        cls.server = ProbeServer(
            ("127.0.0.1", 0),
            context,
            handshake_timeout=0.2,
            idle_timeout=2,
            download_bytes=4096,
            upload_bytes=1024,
            stream_seconds=0.1,
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client_context = ssl.create_default_context(cafile=str(root / "cert.pem"))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def connect(self):
        return http.client.HTTPSConnection(
            "localhost",
            self.server.server_port,
            context=self.client_context,
            timeout=2,
        )

    def test_udp_readiness_and_exact_nonce_echo(self):
        stop = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(0.1)
            worker = threading.Thread(target=udp_echo, args=(server, stop))
            worker.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(1)
                    nonce = b"controlled-test" * 80
                    client.sendto(nonce, server.getsockname())
                    self.assertEqual(client.recv(4096), nonce)
            finally:
                stop.set()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())

    def test_stalled_tls_client_does_not_block_another_client(self):
        stalled = socket.create_connection(self.server.server_address)
        conn = self.connect()
        try:
            conn.request("GET", "/health")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 204)
        finally:
            conn.close()
            stalled.close()

    def test_handshake_deadline_is_not_reused_for_idle_or_post_upload(self):
        conn = self.connect()
        try:
            conn.request("POST", "/up", body=b"test")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 204)
            original = conn.sock
            time.sleep(0.4)
            conn.request("GET", "/health")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 204)
            self.assertIs(conn.sock, original)
        finally:
            conn.close()

    def test_metadata_and_transfer_lengths_are_explicit(self):
        conn = self.connect()
        try:
            conn.request("GET", "/metadata")
            meta = json.loads(conn.getresponse().read())
            self.assertEqual(meta["idle_timeout"], 2)
            self.assertEqual(meta["download_bytes"], 4096)
            conn.request("GET", "/down")
            self.assertEqual(len(conn.getresponse().read()), 4096)
            conn.request("POST", "/up", body=b"x" * 1025)
            response = conn.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            conn.close()

    def test_partial_upload_does_not_spin_or_block_other_requests(self):
        conn = self.connect()
        conn.request("POST", "/up", body=b"x", headers={"Content-Length": "10"})
        conn.close()
        control = self.connect()
        try:
            control.request("GET", "/health")
            response = control.getresponse()
            response.read()
            self.assertEqual(response.status, 204)
        finally:
            control.close()
