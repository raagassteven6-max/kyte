"""FastAPI application factory.

Routes stay thin: the decisions live in ``auth``, ``oauth``, ``service`` and
friends, which are tested without a web server.
"""

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path as FsPath
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from kyte.auth import (
    FLOW_SECONDS, SESSION_SECONDS, AuthService, origin_allowed,
)
from kyte.config import Settings
from kyte.credentials import CredentialStore
from kyte.gmail import MailError
from kyte.oauth import AuthError, GoogleOAuth
from kyte.security import TokenVault
from kyte.service import list_cards
from kyte.sources import MailSource, build_source
from kyte.store import DismissedStore, InvalidEmailId
from kyte.views import FilterMode

log = logging.getLogger("kyte.auth")

ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
STATIC_DIR = FsPath(__file__).parent / "static"
SESSION_COOKIE = "kyte_session"
FLOW_COOKIE = "kyte_flow"

# Scripts and styles only from this origin (plus Google Fonts). No inline
# script or style is used, so none is allowed.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app(
    settings: Settings,
    *,
    source: MailSource | None = None,
    store: DismissedStore | None = None,
    clock: Callable[[], datetime] | None = None,
    auth: AuthService | None = None,
    creds: CredentialStore | None = None,
) -> FastAPI:
    """Create the Kyte web application.

    In mock mode there is no login: only fake mail is served. Otherwise every
    API call needs the owner's session cookie, and state-changing requests
    must also come from this app's own origin.

    Interactive API docs are disabled: the deployed URL is public, so there
    is no reason to advertise the API surface.
    """
    app = FastAPI(title="Kyte", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    dismissed = store or DismissedStore(settings.db_path)
    now = clock or (lambda: datetime.now(UTC))
    secure_cookies = settings.base_url.startswith("https://")

    creds_store: CredentialStore | None = None
    auth_service: AuthService | None = None
    google: GoogleOAuth | None = None
    if not settings.mock_mode:
        creds_store = creds or CredentialStore(
            settings.db_path, TokenVault(settings.secret_key)
        )
        google = GoogleOAuth(
            settings.google_client_id or "", settings.google_client_secret or ""
        )
        auth_service = auth or AuthService(settings, google, creds_store)
    mail = source or build_source(settings, creds=creds_store, google=google)

    def need_auth() -> AuthService:
        if auth_service is None:
            raise HTTPException(status_code=404)  # mock mode has no sign-in
        return auth_service

    def require_owner(request: Request) -> str:
        if auth_service is None:
            return settings.owner_email
        owner = auth_service.owner_from_session(request.cookies.get(SESSION_COOKIE))
        if owner is None:
            raise HTTPException(status_code=401, detail="Not signed in.")
        return owner

    def require_same_origin(request: Request) -> None:
        if auth_service is None:
            return  # mock mode: no sessions, so nothing to forge
        if not origin_allowed(request.headers.get("origin"), settings.base_url):
            raise HTTPException(status_code=403, detail="Cross-origin request refused.")

    def set_cookie(
        response: Response, name: str, value: str, max_age: int, path: str = "/"
    ) -> None:
        # Lax (not Strict): the sign-in redirect back from Google is a
        # cross-site navigation and must carry the flow cookie.
        response.set_cookie(
            name, value, max_age=max_age, httponly=True,
            secure=secure_cookies, samesite="lax", path=path,
        )

    @app.middleware("http")
    async def add_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith(("/api/", "/auth/")):
            response.headers["Cache-Control"] = "no-store"  # mail never cached
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.get("/api/session")
    def session_info(request: Request) -> dict[str, Any]:
        if auth_service is None or creds_store is None:
            return {"mock": True, "authenticated": True, "connected": True,
                    "owner": settings.owner_email}
        owner = auth_service.owner_from_session(request.cookies.get(SESSION_COOKIE))
        return {
            "mock": False,
            "authenticated": owner is not None,
            "connected": owner is not None and creds_store.is_connected(),
            "owner": owner,
        }

    @app.get("/api/emails", dependencies=[Depends(require_owner)])
    def list_emails(
        mode: FilterMode = Query("all", alias="filter"),
    ) -> list[dict[str, Any]]:
        try:
            return list_cards(
                mail,
                mode=mode,
                now=now(),
                tz=settings.timezone,
                owner_email=settings.owner_email,
                dismissed=dismissed.dismissed_ids(),
            )
        except MailError as exc:
            log.warning("mail unavailable: %s", exc.code)
            # 409: the owner must act (connect or reconnect). 502: try again.
            action = exc.code in ("not_connected", "reconnect_required")
            raise HTTPException(
                status_code=409 if action else 502, detail=exc.code
            ) from exc

    @app.post(
        "/api/emails/{email_id}/dismiss",
        status_code=204,
        dependencies=[Depends(require_owner), Depends(require_same_origin)],
    )
    def dismiss_email(email_id: str = Path(pattern=ID_PATTERN)) -> Response:
        try:
            dismissed.dismiss(email_id)
        except InvalidEmailId as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return Response(status_code=204)

    @app.get("/auth/login", include_in_schema=False)
    def login() -> Response:
        start = need_auth().start_login()
        response = RedirectResponse(start.url, status_code=302)
        set_cookie(response, FLOW_COOKIE, start.flow_cookie, FLOW_SECONDS, "/auth")
        return response

    @app.get("/auth/callback", include_in_schema=False)
    def callback(request: Request) -> Response:
        service = need_auth()
        try:
            session = service.finish_login(
                dict(request.query_params), request.cookies.get(FLOW_COOKIE)
            )
        except AuthError as exc:
            log.warning("sign-in refused: %s", exc.reason)  # reason only, no details
            response = RedirectResponse(f"/?auth_error={exc.reason}", status_code=303)
        else:
            response = RedirectResponse("/", status_code=303)
            set_cookie(response, SESSION_COOKIE, session, SESSION_SECONDS)
        response.delete_cookie(FLOW_COOKIE, path="/auth")
        return response

    @app.post(
        "/auth/logout", status_code=204, dependencies=[Depends(require_same_origin)]
    )
    def logout() -> Response:
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.post(
        "/auth/disconnect",
        status_code=204,
        dependencies=[Depends(require_owner), Depends(require_same_origin)],
    )
    def disconnect() -> Response:
        need_auth().disconnect()
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
