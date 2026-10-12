"""ART-29 item (b), Villhaze ruling 50876294 (confirmed 3c65ab2b): minimal
legacy migrate-route stub.

The legacy /api/v1/agents/migrate* path is replaced by window_open. Every
legacy migrate route answers HTTP 409 with a fixed JSON body; nothing is
read or written.
"""
from fastapi import APIRouter
from starlette.responses import JSONResponse

router = APIRouter()

LEGACY_MIGRATE_PATHS = (
    ("POST", "/api/v1/agents/migrate"),
    ("GET", "/api/v1/agents/migrate"),
    ("POST", "/api/v1/agents/migrate/cancel"),
    ("POST", "/api/v1/agents/migrate/withdraw"),
)

GONE_BODY = {
    "error": "legacy_migrate_replaced",
    "detail": "The legacy migrate path has been replaced by window_open.",
    "replaced_by": "window_open",
}


def _gone():
    return JSONResponse(status_code=409, content=GONE_BODY)


for _m, _p in LEGACY_MIGRATE_PATHS:
    router.add_api_route(_p, _gone, methods=[_m], include_in_schema=False)
