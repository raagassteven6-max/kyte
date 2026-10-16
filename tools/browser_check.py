"""Dev tool (needs `pip install playwright` + `playwright install chromium`).
Run: python tools/browser_check.py [screenshot_dir]

Browser check of the Kyte UI against a stdlib stand-in for the FastAPI app.

Uses the REAL modules (sources, service, store, views) and the REAL static files
and CSP string from app.py; only the HTTP layer is a stand-in.
"""
import ast, json, re, sys, tempfile, threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
SHOTS = Path(sys.argv[1] if len(sys.argv) > 1 else "shots")
SHOTS.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "src"))
from kyte.emails import parse_message
from kyte.service import list_cards
from kyte.sources import MockSource
from kyte.store import DismissedStore
from kyte.views import FILTER_MODES

STATIC = ROOT / "src/kyte/static"
tree = ast.parse((ROOT / "src/kyte/app.py").read_text())
HEADERS = next(ast.literal_eval(n.value) for n in tree.body
               if isinstance(n, ast.Assign) and n.targets[0].id == "SECURITY_HEADERS")

NOW = datetime.now(UTC)
HOSTILE = {
    "id": "evil1", "threadId": "evil1", "labelIds": ["INBOX", "UNREAD"],
    "snippet": "&lt;script&gt;window.__xss=1&lt;/script&gt; <img src=x onerror=window.__xss=1>",
    "internalDate": str(int((NOW.timestamp() - 60) * 1000)),
    "payload": {"headers": [
        {"name": "From", "value": '"<b>Bold</b>" <x@y.example>'},
        {"name": "Subject", "value": "<img src=x onerror=window.__xss=1>"}]},
}

class Src:
    def fetch_recent(self):
        return [parse_message(HOSTILE)] + MockSource(now=NOW).fetch_recent()

store = DismissedStore(Path(tempfile.mkdtemp()) / "k.db")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b"", ctype="text/plain", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items(): self.send_header(k, v)
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if u.path.startswith("/static/"):
            f = STATIC / u.path[len("/static/"):]
            if f.is_file():
                ct = {".css": "text/css", ".js": "text/javascript"}.get(f.suffix, "text/plain")
                return self._send(200, f.read_bytes(), ct)
        if u.path == "/api/emails":
            mode = parse_qs(u.query).get("filter", ["all"])[0]
            if mode not in FILTER_MODES: return self._send(422)
            cards = list_cards(Src(), mode=mode, now=NOW, tz=ZoneInfo("UTC"),
                               owner_email="me@example.com", dismissed=store.dismissed_ids())
            return self._send(200, json.dumps(cards).encode(), "application/json", {"Cache-Control": "no-store"})
        self._send(404)
    def do_POST(self):
        m = re.fullmatch(r"/api/emails/([A-Za-z0-9_-]{1,64})/dismiss", urlparse(self.path).path)
        if not m: return self._send(422)
        store.dismiss(m.group(1)); self._send(204)

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"

from playwright.sync_api import expect, sync_playwright
results = []
def check(name, ok, detail=""):
    results.append((name, ok)); print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    console = []
    page.on("console", lambda m: console.append((m.type, m.text)))
    page.on("pageerror", lambda e: console.append(("pageerror", str(e))))
    page.goto(BASE + "/"); page.wait_for_selector("#cards li")
    page.wait_for_timeout(300)
    page.screenshot(path=str(SHOTS / "desktop.png"), full_page=True)

    n = page.locator("#cards > li").count()
    check("renders 11 cards (10 mock + 1 hostile)", n == 11, str(n))
    check("status announces count", page.inner_text("#status").startswith("11 emails"), page.inner_text("#status"))
    check("hostile subject shown as literal text",
          page.locator("#cards li").first.locator(".subject").inner_text() == "<img src=x onerror=window.__xss=1>")
    check("no script executed from email content", page.evaluate("window.__xss") is None)
    check("no injected <img>/<b> elements in cards", page.locator("#cards img, #cards b").count() == 0)
    check("spoofed sender shows real address",
          "evil@scam.example" in page.locator("#cards").inner_text())
    check("open-in-gmail links are https gmail only",
          all(h.startswith("https://mail.google.com/") for h in page.eval_on_selector_all("#cards a.link", "els=>els.map(e=>e.href)")))
    check("links open safely", page.eval_on_selector_all("#cards a.link", "els=>els.every(e=>e.rel.includes('noopener')&&e.target==='_blank')"))

    tops = page.eval_on_selector_all("#cards > li", "els => els.map(e => Math.round(e.getBoundingClientRect().top))")
    check("visual order follows DOM (newest-first) order, row by row",
          all(b >= a for a, b in zip(tops, tops[1:])), str(tops))
    page.click('[data-filter="unread"]'); expect(page.locator('#status')).to_contain_text('Unread')
    unread = page.locator("#cards > li").count()
    check("unread filter pressed state", page.get_attribute('[data-filter="unread"]', "aria-pressed") == "true"
          and page.get_attribute('[data-filter="all"]', "aria-pressed") == "false")
    check("unread filter shows only unread", page.locator("#cards > li:not(.is-unread)").count() == 0 and 0 < unread < 11, str(unread))
    page.click('[data-filter="today"]'); expect(page.locator('#status')).to_contain_text('Today')
    check("today filter shows fewer than all", 0 < page.locator("#cards > li").count() < 11)
    page.click('[data-filter="all"]'); expect(page.locator('#status')).to_contain_text('All')

    first_id = page.locator("#cards > li .subject").nth(1).get_attribute("id")
    page.locator("#cards > li .dismiss").first.click()
    expect(page.locator('#status')).to_have_text(re.compile(r'^Dismissed'))
    check("dismiss removes card and announces", page.locator("#cards > li").count() == 10, page.inner_text("#status"))
    check("focus moves to a neighbouring dismiss button", page.evaluate("document.activeElement.classList.contains('dismiss')"))
    page.reload(); page.wait_for_selector("#cards li")
    check("dismissal persists across reload", page.locator("#cards > li").count() == 10)

    pre_error_console = list(console)
    # error and retry
    page.route("**/api/emails*", lambda r: r.fulfill(status=500, body="boom"))
    page.click("#refresh"); page.wait_for_selector("#error:not([hidden])")
    page.screenshot(path=str(SHOTS / "error.png"))
    check("error state shown with alert role", page.get_attribute("#error", "role") == "alert" and page.locator("#cards").is_hidden())
    page.unroute("**/api/emails*")
    page.click("#retry"); page.wait_for_selector("#cards li")
    check("retry recovers", page.locator("#cards > li").count() == 10)

    # empty
    page.route("**/api/emails*", lambda r: r.fulfill(status=200, content_type="application/json", body="[]"))
    page.click("#refresh"); page.wait_for_selector("#empty:not([hidden])")
    page.screenshot(path=str(SHOTS / "empty.png"))
    check("empty state shown", page.inner_text("#empty-text") != "")
    page.unroute("**/api/emails*")

    # keyboard: skip link
    page.reload(); page.wait_for_selector("#cards li")
    page.keyboard.press("Tab")
    check("first Tab stop is the skip link", page.evaluate("document.activeElement.className") == "skip")
    page.keyboard.press("Enter")
    check("skip link moves focus to main", page.evaluate("document.activeElement.id") == "main")

    errs = [c for c in pre_error_console if c[0] in ("error", "pageerror") and "fonts.g" not in c[1] and "ERR_" not in c[1]
            and "Failed to load resource" not in c[1]]
    csp = [c for c in console if "Content Security Policy" in c[1] and "fonts" not in c[1]]
    check("no console/page errors (offline font fetches ignored)", not errs, str(errs)[:200])
    check("no CSP violations from the app's own files", not csp, str(csp)[:200])

    # mobile
    m = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    mp = m.new_page(); mp.goto(BASE + "/"); mp.wait_for_selector("#cards li"); mp.wait_for_timeout(300)
    mp.screenshot(path=str(SHOTS / "mobile.png"), full_page=False)
    mp.screenshot(path=str(SHOTS / "mobile_full.png"), full_page=True)
    check("no horizontal scroll on a 390px phone", mp.evaluate("document.documentElement.scrollWidth <= window.innerWidth"),
          str(mp.evaluate("document.documentElement.scrollWidth")))
    small = mp.evaluate("""() => [...document.querySelectorAll('button, a.link')].filter(e => e.offsetParent)
        .map(e => e.getBoundingClientRect()).filter(r => r.height < 44 && r.height>0).length""")
    names = mp.evaluate("""() => [...new Set([...document.querySelectorAll('button, a.link')].filter(e => e.offsetParent)
        .filter(e => e.getBoundingClientRect().height < 44).map(e => e.tagName + '.' + e.className))]""")
    check("buttons are at least 44px tall on mobile", small == 0, f"{small} smaller: {names}")
    b.close()

bad = [n for n, ok in results if not ok]
print(f"\n{len(results)-len(bad)}/{len(results)} checks passed"); sys.exit(1 if bad else 0)
