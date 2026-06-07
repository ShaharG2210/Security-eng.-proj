"""
blog_server.py — Vulnerable blog server for XSS demonstration
Educational purposes only, run locally only.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus, urlparse
import os

PORT = 8000
COMMENTS_FILE = "comments.txt"


def load_comments():
    """Loads all comments from file and returns a list."""
    if not os.path.exists(COMMENTS_FILE):
        open(COMMENTS_FILE, "w").close()
        return []
    with open(COMMENTS_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    # Filter empty lines
    return [line for line in lines if line.strip()]


def save_comment(comment):
    """Saves a new comment to file."""
    with open(COMMENTS_FILE, "a", encoding="utf-8") as f:
        f.write(comment + "\n")


def build_page(comments, show_success=False):
    """Builds the HTML page of the blog.

    Note: Comments are displayed as raw HTML without escaping — this is the intentional vulnerability.
    """
    # Build the comments list as raw HTML
    comments_html = ""
    for c in comments:
        # ⚠️  No html.escape — the comment is displayed as-is, including HTML/JS tags
        comments_html += f"<li>{c}</li>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
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
    .success {{ background: #d4edda; border: 1px solid #28a745; color: #155724; padding: 10px 16px; border-radius: 4px; margin-bottom: 16px; font-size: 0.95em; }}
  </style>
</head>
<body>
  <h1>Vulnerable Blog</h1>

  {"<div class='success'>✅ Your comment was added successfully!</div><script>history.replaceState(null,'','/');</script>" if show_success else ""}

  <h2>Add a Comment</h2>
  <form method="POST" action="/">
    <textarea name="comment" placeholder="Write a comment here..."></textarea><br>
    <button type="submit">Submit Comment</button>
  </form>

  <h2>Comments</h2>
  <ul>
    {comments_html if comments_html else "<li>No comments yet.</li>"}
  </ul>

</body>
</html>"""


class BlogHandler(BaseHTTPRequestHandler):

    def _set_common_headers(self, status=200, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # ⚠️  No HttpOnly — so that document.cookie can read the cookie (part of the demo)
        self.send_header("Set-Cookie", "session_id=abc123; Path=/")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            show_success = "success=1" in (parsed.query or "")
            comments = load_comments()
            page = build_page(comments, show_success=show_success)
            self._set_common_headers()
            self.wfile.write(page.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        if self.path == "/":
            # Read the request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            # Decode the form parameter
            params = parse_qs(body)
            comment = params.get("comment", [""])[0]
            comment = unquote_plus(comment)

            if comment.strip():
                # ⚠️  Saving without sanitization — this is the vulnerability
                save_comment(comment)

            # PRG — Post/Redirect/Get: prevents duplicate submission on refresh
            # ?success=1 מציג הודעת אישור בדף
            self.send_response(303)
            self.send_header("Location", "/?success=1")
            self.send_header("Set-Cookie", "session_id=abc123; Path=/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Clean output to terminal
        print(f"[Blog] {self.address_string()} — {format % args}")


if __name__ == "__main__":
    # Create comments file if it doesn't exist
    if not os.path.exists(COMMENTS_FILE):
        open(COMMENTS_FILE, "w").close()

    server = HTTPServer(("localhost", PORT), BlogHandler)
    print("=" * 50)
    print("  📝  Blog Server (VULNERABLE)")    
    print(f"  Running at: http://localhost:{PORT}")
    print("  Press Ctrl+C to stop.")
    print("=" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Blog] Server stopped.")
