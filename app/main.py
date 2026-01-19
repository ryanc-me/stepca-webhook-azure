import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import ssl
import threading
import time
from typing import Any, Dict, Optional

import requests
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

load_dotenv(os.getenv("ENV_FILE", ".env"))

logging.basicConfig(level=os.getenv("APP_LOG_LEVEL", "info").upper())
logger = logging.getLogger("stepca-webhook-azure")

app = FastAPI(title="stepca-webhook-azure")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    logger.warning(
        "http_error path=%s status=%s detail=%s",
        request.url.path,
        exc.status_code,
        exc.detail,
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled_error path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


class TokenCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._expires_at: float = 0.0

    def get(self) -> Optional[str]:
        with self._lock:
            if self._token and time.time() < self._expires_at:
                return self._token
        return None

    def set(self, token: str, expires_in: int) -> None:
        with self._lock:
            self._token = token
            self._expires_at = time.time() + max(0, expires_in - 60)


token_cache = TokenCache()


def _get_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _bool_env(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _get_by_path(data: Dict[str, Any], path: str) -> Optional[Any]:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _get_graph_token() -> str:
    cached = token_cache.get()
    if cached:
        return cached

    tenant_id = _get_env("AZURE_TENANT_ID")
    client_id = _get_env("AZURE_CLIENT_ID")
    client_secret = _get_env("AZURE_CLIENT_SECRET")
    scope = os.getenv("AZURE_GRAPH_SCOPE", "https://graph.microsoft.com/.default")
    token_endpoint = os.getenv(
        "AZURE_TOKEN_ENDPOINT",
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    )

    response = requests.post(
        token_endpoint,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        },
        timeout=10,
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Azure token request failed: {response.status_code}",
        )

    payload = response.json()
    access_token = payload.get("access_token")
    expires_in = int(payload.get("expires_in", 3600))
    if not access_token:
        raise HTTPException(
            status_code=502, detail="Azure token response missing access_token"
        )

    token_cache.set(access_token, expires_in)
    return access_token


def _fetch_group_ids(user_object_id: str) -> list[str]:
    graph_base = os.getenv("AZURE_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
    security_only = _bool_env("AZURE_GROUPS_SECURITY_ONLY", "false")
    url = f"{graph_base}/users/{user_object_id}/getMemberGroups"

    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {_get_graph_token()}"},
        json={"securityEnabledOnly": security_only},
        timeout=10,
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Azure Graph request failed: {response.status_code}",
        )

    payload = response.json()
    values = payload.get("value", [])
    if not isinstance(values, list):
        raise HTTPException(
            status_code=502, detail="Azure Graph response missing value list"
        )
    return values


def _resolve_user_object_id(user_email: str) -> str:
    graph_base = os.getenv("AZURE_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
    url = f"{graph_base}/users/{user_email}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {_get_graph_token()}"},
        params={"$select": "id"},
        timeout=10,
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Azure Graph user lookup failed: {response.status_code}",
        )
    payload = response.json()
    user_id = payload.get("id")
    if not user_id:
        raise HTTPException(
            status_code=502, detail="Azure Graph user lookup missing id"
        )
    return str(user_id)


def _extract_user_email(request_body: Dict[str, Any]) -> str:
    email_path = os.getenv("WEBHOOK_EMAIL_PATH", "sshCertificateRequest.keyID")
    email_value = _get_by_path(request_body, email_path)
    if isinstance(email_value, str) and "@" in email_value:
        return email_value
    raise HTTPException(
        status_code=400, detail=f"Missing user email at path: {email_path}"
    )


@app.get("/healthz")
def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/ssh/enrich")
async def webhook(request: Request) -> Dict[str, Any]:
    raw_body = await request.body()
    _verify_stepca_signature(request, raw_body)

    request_body = json.loads(raw_body.decode("utf-8"))
    if not isinstance(request_body, dict):
        raise HTTPException(
            status_code=400, detail="Request body must be a JSON object"
        )

    user_email = _extract_user_email(request_body)
    user_object_id = _resolve_user_object_id(user_email)
    group_ids = _fetch_group_ids(user_object_id)
    logger.info(
        "azure_enrich user_email=%s user_id=%s group_count=%s group_ids=[%s]",
        user_email,
        user_object_id,
        len(group_ids),
        ", ".join(group_ids),
    )

    output_claim = os.getenv("AZURE_GROUPS_CLAIM_NAME", "azure_group_ids")
    return {
        "allow": True,
        "data": {
            output_claim: group_ids,
            f"{output_claim}_count": len(group_ids),
        },
    }


def _verify_stepca_signature(request: Request, raw_body: bytes) -> None:
    secret = os.getenv("STEPCA_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise HTTPException(status_code=500, detail="Missing STEPCA_WEBHOOK_SECRET")

    signature = request.headers.get("X-Smallstep-Signature", "").strip()
    if not signature:
        raise HTTPException(status_code=401, detail="Missing X-Smallstep-Signature")

    if signature.startswith("sha256="):
        signature = signature[len("sha256=") :]

    try:
        secret_bytes = base64.b64decode(secret, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=500, detail="Invalid STEPCA_WEBHOOK_SECRET base64"
        ) from exc

    digest = hmac.new(secret_bytes, raw_body, hashlib.sha256).digest()
    expected_hex = digest.hex()
    expected_b64 = base64.b64encode(digest).decode("utf-8")

    if not (
        hmac.compare_digest(signature, expected_hex)
        or hmac.compare_digest(signature, expected_b64)
    ):
        logger.warning(
            "invalid_signature webhook_id=%s signature=%s expected_hex=%s expected_b64=%s body_len=%s",
            request.headers.get("X-Smallstep-Webhook-ID"),
            signature,
            expected_hex,
            expected_b64,
            len(raw_body),
        )
        raise HTTPException(status_code=401, detail="Invalid X-Smallstep-Signature")

    expected_id = os.getenv("STEPCA_WEBHOOK_ID")
    if expected_id:
        webhook_id = request.headers.get("X-Smallstep-Webhook-ID")
        if not webhook_id or webhook_id != expected_id:
            raise HTTPException(
                status_code=401, detail="Invalid X-Smallstep-Webhook-ID"
            )


def main() -> None:
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "5000"))
    log_level = os.getenv("APP_LOG_LEVEL", "info")

    tls_cert = os.getenv("TLS_CERT_FILE")
    tls_key = os.getenv("TLS_KEY_FILE")
    tls_ca = os.getenv("TLS_CLIENT_CA_FILE")
    tls_require_client_cert = _bool_env("TLS_REQUIRE_CLIENT_CERT", "false")

    ssl_kwargs: Dict[str, Any] = {}
    if tls_cert and tls_key:
        ssl_kwargs["ssl_certfile"] = tls_cert
        ssl_kwargs["ssl_keyfile"] = tls_key
        if tls_ca:
            ssl_kwargs["ssl_ca_certs"] = tls_ca
            if tls_require_client_cert:
                ssl_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED

    uvicorn.run("main:app", host=host, port=port, log_level=log_level, **ssl_kwargs)


if __name__ == "__main__":
    main()
