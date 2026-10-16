"""Smoke-check kyte/app.py wiring against a tiny FAKE of FastAPI (not the real thing)."""
import sys, types, tempfile
from datetime import UTC, datetime
from pathlib import Path as P
from urllib.parse import parse_qs, urlparse

ROOT = P(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

class HTTPException(Exception):
    def __init__(self, status_code, detail=None): self.status_code, self.detail = status_code, detail
class Dep:
    def __init__(self, dependency): self.dependency = dependency
class Response:
    def __init__(self, content=None, status_code=200, **kw):
        self.status_code, self.headers, self.cookies, self.deleted = status_code, {}, {}, []
    def set_cookie(self, name, value, **kw): self.cookies[name] = (value, kw)
    def delete_cookie(self, name, **kw): self.deleted.append((name, kw))
class RedirectResponse(Response):
    def __init__(self, url, status_code=307): super().__init__(status_code=status_code); self.url = url
class FileResponse(Response):
    def __init__(self, path, **kw): super().__init__(); self.path = path
class FastAPI:
    def __init__(self, **kw): self.routes, self.state = {}, types.SimpleNamespace()
    def _reg(self, method):
        def deco(path, **kw):
            def inner(fn): self.routes[(method, path)] = (fn, kw); return fn
            return inner
        return deco
    def __getattr__(self, name):
        if name in ("get", "post"): return self._reg(name)
        raise AttributeError(name)
    def middleware(self, kind): return lambda fn: fn
    def mount(self, *a, **k): pass
fa = types.ModuleType("fastapi")
fa.Depends, fa.FastAPI, fa.HTTPException, fa.Request, fa.Response = Dep, FastAPI, HTTPException, object, Response
fa.Path = lambda *a, **k: None; fa.Query = lambda *a, **k: None
fr = types.ModuleType("fastapi.responses"); fr.FileResponse, fr.RedirectResponse = FileResponse, RedirectResponse
fs = types.ModuleType("fastapi.staticfiles"); fs.StaticFiles = lambda **k: None
sys.modules.update({"fastapi": fa, "fastapi.responses": fr, "fastapi.staticfiles": fs})

from kyte.app import create_app, SESSION_COOKIE, FLOW_COOKIE
from kyte.auth import AuthService
from kyte.config import Settings
from kyte.credentials import CredentialStore
from kyte.security import TokenVault
from kyte.sources import MockSource
from kyte.store import DismissedStore
from tests.test_auth import FakeGoogle, GMAIL
from kyte.oauth import Tokens
from tests.test_auth import id_token

NOW = datetime(2026, 10, 13, 15, 0, tzinfo=UTC)
class Req:
    def __init__(self, cookies=None, headers=None, query=None):
        self.cookies, self._h, self.query_params = cookies or {}, {k.lower(): v for k, v in (headers or {}).items()}, query or {}
        self.headers = types.SimpleNamespace(get=lambda k, d=None: self._h.get(k.lower(), d))

results = []
def check(name, ok): results.append(ok); print(("PASS " if ok else "FAIL ") + name)
def raises(status, fn, *a, **k):
    try: fn(*a, **k)
    except HTTPException as e: return e.status_code == status
    return False

tmp = P(tempfile.mkdtemp()) / "k.db"
env = {"KYTE_SECRET_KEY": "k"*40, "KYTE_OWNER_EMAIL": "me@example.com", "KYTE_BASE_URL": "https://kyte.example.com",
       "KYTE_MOCK": "0", "GOOGLE_CLIENT_ID": "client-123.apps.googleusercontent.com", "GOOGLE_CLIENT_SECRET": "cs", "KYTE_DB_PATH": str(tmp)}
settings = Settings.from_env(env)
google = FakeGoogle(); creds = CredentialStore(tmp, TokenVault(settings.secret_key))
auth = AuthService(settings, google, creds); store = DismissedStore(tmp)
app = create_app(settings, source=MockSource(now=NOW), store=store, clock=lambda: NOW, auth=auth, creds=creds)
R = lambda m, p: app.routes[(m, p)]

# guards
owner_dep = R("get", "/api/emails")[1]["dependencies"][0].dependency
dismiss_deps = [d.dependency for d in R("post", "/api/emails/{email_id}/dismiss")[1]["dependencies"]]
origin_dep = dismiss_deps[1]
check("no cookie -> 401", raises(401, owner_dep, Req()))
check("forged cookie -> 401", raises(401, owner_dep, Req({SESSION_COOKIE: "forged"})))
check("stranger session -> 401", raises(401, owner_dep, Req({SESSION_COOKIE: auth.issue_session("x@evil.example")})))
good = auth.issue_session("me@example.com")
check("owner session accepted", owner_dep(Req({SESSION_COOKIE: good})) == "me@example.com")
check("missing Origin -> 403", raises(403, origin_dep, Req()))
check("evil Origin -> 403", raises(403, origin_dep, Req(headers={"Origin": "https://evil.example"})))
check("own Origin accepted", origin_dep(Req(headers={"Origin": "https://kyte.example.com"})) is None)

# sign-in
r = R("get", "/auth/login")[0]()
check("login -> 302 to Google", r.status_code == 302 and r.url.startswith("https://accounts.google.com/o/oauth2/v2/auth?"))
val, kw = r.cookies[FLOW_COOKIE]
check("flow cookie flags", kw["httponly"] and kw["secure"] and kw["samesite"] == "lax" and kw["path"] == "/auth" and kw["max_age"] == 600)
q = {k: v[0] for k, v in parse_qs(urlparse(r.url).query).items()}; google.nonce = q["nonce"]
cb = R("get", "/auth/callback")[0]
ok = cb(Req({FLOW_COOKIE: val}, query={"state": q["state"], "code": "c"}))
sv, skw = ok.cookies.get(SESSION_COOKIE, (None, {}))
check("callback success -> 303 '/' + session cookie", ok.status_code == 303 and ok.url == "/" and sv is not None)
check("session cookie flags", skw.get("httponly") and skw.get("secure") and skw.get("samesite") == "lax" and skw.get("max_age") == 7*86400)
check("flow cookie cleared after callback", any(n == FLOW_COOKIE for n, _ in ok.deleted))
check("session from callback works", owner_dep(Req({SESSION_COOKIE: sv})) == "me@example.com")
bad = cb(Req({FLOW_COOKIE: val}, query={"state": "forged", "code": "c"}))
check("bad state -> /?auth_error=invalid, no session", bad.url == "/?auth_error=invalid" and SESSION_COOKIE not in bad.cookies)
check("no flow cookie -> expired", cb(Req(query={"state": "x", "code": "c"})).url == "/?auth_error=expired")

# api
info = R("get", "/api/session")[0]
check("session info signed out", info(Req()) == {"mock": False, "authenticated": False, "connected": False, "owner": None})
creds_ok = creds.is_connected()
check("session info signed in+connected", info(Req({SESSION_COOKIE: sv}))["connected"] is creds_ok is True)
cards = R("get", "/api/emails")[0](mode="unread")
check("list emails returns unread cards", cards and all(c["unread"] for c in cards))
dis = R("post", "/api/emails/{email_id}/dismiss")[0]
check("dismiss -> 204 and stored", dis("m01").status_code == 204 and "m01" in store.dismissed_ids())
check("dismiss bad id -> 422", raises(422, dis, "bad id!"))
check("dismissed card disappears", "m01" not in [c["id"] for c in R("get", "/api/emails")[0](mode="all")])

# disconnect / logout
d = R("post", "/auth/disconnect")[0]()
check("disconnect -> 204, revoked, forgotten, cookie cleared",
      d.status_code == 204 and google.revoked and not creds.is_connected() and any(n == SESSION_COOKIE for n, _ in d.deleted))
lo = R("post", "/auth/logout")[0]()
check("logout -> 204 + cookie cleared", lo.status_code == 204 and any(n == SESSION_COOKIE for n, _ in lo.deleted))

# mock mode
menv = {**env, "KYTE_MOCK": "1"}; menv.pop("GOOGLE_CLIENT_ID"); menv.pop("GOOGLE_CLIENT_SECRET")
mapp = create_app(Settings.from_env(menv), source=MockSource(now=NOW), store=store, clock=lambda: NOW)
check("mock mode: /auth/login -> 404", raises(404, mapp.routes[("get", "/auth/login")][0]))
mdep = mapp.routes[("get", "/api/emails")][1]["dependencies"][0].dependency
check("mock mode: no login needed", mdep(Req()) == "me@example.com")
check("mock mode: session info says mock", mapp.routes[("get", "/api/session")][0](Req())["mock"] is True)
# mail errors -> HTTP status codes
from kyte.gmail import MailUnavailable, NotConnected, ReconnectRequired
class Boom:
    def __init__(self, exc): self.exc = exc
    def fetch_recent(self): raise self.exc
def outcome(application):
    try: application.routes[("get", "/api/emails")][0](mode="all")
    except HTTPException as e: return e.status_code, e.detail
for exc, want in ((NotConnected(), (409, "not_connected")), (ReconnectRequired(), (409, "reconnect_required")),
                  (MailUnavailable(), (502, "mail_unavailable"))):
    boom_app = create_app(settings, source=Boom(exc), store=store, clock=lambda: NOW, auth=auth, creds=creds)
    check(f"{want[1]} -> HTTP {want[0]}", outcome(boom_app) == want)

# default real-mode app (no injected source/auth): uses the Gmail source; nothing connected -> 409, no network
tmp2 = P(tempfile.mkdtemp()) / "k2.db"
real_app = create_app(Settings.from_env({**env, "KYTE_DB_PATH": str(tmp2)}), store=DismissedStore(tmp2))
check("default real-mode app builds and reports not_connected (409)", outcome(real_app) == (409, "not_connected"))
print(f"\n{sum(results)}/{len(results)} wiring checks passed (against a FAKE FastAPI)")
sys.exit(0 if all(results) else 1)
