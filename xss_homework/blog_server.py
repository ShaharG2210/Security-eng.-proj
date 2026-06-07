"""
blog_server.py — שרת בלוג פגיע ל־XSS
הדגמה חינוכית בלבד, לריצה מקומית בלבד.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus
import os

PORT = 8000
COMMENTS_FILE = "comments.txt"


def load_comments():
    """טוען את כל התגובות מהקובץ ומחזיר רשימה."""
    if not os.path.exists(COMMENTS_FILE):
        open(COMMENTS_FILE, "w").close()
        return []
    with open(COMMENTS_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    # מסנן שורות ריקות
    return [line for line in lines if line.strip()]


def save_comment(comment):
    """שומר תגובה חדשה לקובץ."""
    with open(COMMENTS_FILE, "a", encoding="utf-8") as f:
        f.write(comment + "\n")


def build_page(comments):
    """בונה את דף ה־HTML של הבלוג.

    שימו לב: התגובות מוצגות כ־raw HTML ללא escaping — זו החולשה המכוונת.
    """
    # בונה את רשימת התגובות כ־HTML גולמי
    comments_html = ""
    for c in comments:
        # ⚠️  אין html.escape — התגובה מוצגת כמו שהיא, כולל תגיות HTML/JS
        comments_html += f"<li>{c}</li>\n"

    return f"""<!DOCTYPE html>
<html lang="he">
<head>
  <meta charset="UTF-8">
  <title>Vulnerable Blog</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; }}
    h1   {{ color: #c0392b; }}
    textarea {{ width: 100%; height: 80px; }}
    button {{ margin-top: 8px; padding: 6px 18px; cursor: pointer; }}
    ul   {{ background: #f9f9f9; padding: 16px 32px; border-radius: 6px; }}
    .warn {{ background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; margin-bottom: 16px; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>Vulnerable Blog</h1>
  <div class="warn">⚠️ אתר זה פגיע ל־XSS בכוונה, לצורכי הדגמה חינוכית בלבד.</div>

  <h2>הוסף תגובה</h2>
  <form method="POST" action="/">
    <textarea name="comment" placeholder="כתוב תגובה כאן..."></textarea><br>
    <button type="submit">שלח תגובה</button>
  </form>

  <h2>תגובות</h2>
  <ul>
    {comments_html if comments_html else "<li>אין תגובות עדיין.</li>"}
  </ul>

  <hr>
  <small>פרויקט הדגמה — Cybersecurity Course | localhost only</small>
</body>
</html>"""


class BlogHandler(BaseHTTPRequestHandler):

    def _set_common_headers(self, status=200, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # ⚠️  ללא HttpOnly — כדי ש־document.cookie יוכל לקרוא את ה־cookie (חלק מההדגמה)
        self.send_header("Set-Cookie", "session_id=abc123; Path=/")
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            comments = load_comments()
            page = build_page(comments)
            self._set_common_headers()
            self.wfile.write(page.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        if self.path == "/":
            # קריאת גוף הבקשה
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            # פענוח הפרמטר מהטופס
            params = parse_qs(body)
            comment = params.get("comment", [""])[0]
            comment = unquote_plus(comment)

            if comment.strip():
                # ⚠️  שמירה ללא sanitize — זו החולשה
                save_comment(comment)

            # PRG — Post/Redirect/Get: מונע שליחה כפולה עם רענון
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session_id=abc123; Path=/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # הדפסה נקייה לטרמינל
        print(f"[Blog] {self.address_string()} — {format % args}")


if __name__ == "__main__":
    # יצירת קובץ תגובות אם לא קיים
    if not os.path.exists(COMMENTS_FILE):
        open(COMMENTS_FILE, "w").close()

    server = HTTPServer(("localhost", PORT), BlogHandler)
    print("=" * 50)
    print("  📝  Blog Server (VULNERABLE — educational only)")
    print(f"  Running at: http://localhost:{PORT}")
    print("  Press Ctrl+C to stop.")
    print("=" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Blog] Server stopped.")
