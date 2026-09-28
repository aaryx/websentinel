"""Run against an installed wheel, from outside the repository working directory."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
import sys
import tempfile
import threading


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>release fixture</html>")


def main():
    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as cwd:
                proc = subprocess.run([sys.executable, "-m", "websentinel", "scan", "-u",
                    f"http://127.0.0.1:{server.server_port}/?access_token=release-secret",
                    "--allow-private", "--checks", "cookies", "--fail-on-incomplete", "--format", "json"],
                    cwd=cwd, capture_output=True, text=True, timeout=20)
                assert proc.returncode == 0, proc.stderr
                result = json.loads(proc.stdout)
                assert result["scan"]["completion"] == "complete"
                assert result["scan"]["requests_made"] == 1
                assert "release-secret" not in proc.stdout + proc.stderr
        finally:
            server.shutdown()
            thread.join(timeout=2)
    print("Installed wheel: CLI, local HTTP, completion status, redaction PASS")


if __name__ == "__main__":
    main()
