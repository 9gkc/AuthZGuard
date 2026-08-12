"""Local-only training service. It contains no production credentials or real data."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class TrainingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        if self.path == "/v1/admin":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"message":"authorization boundary enforced"}')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        return


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), TrainingHandler).serve_forever()

