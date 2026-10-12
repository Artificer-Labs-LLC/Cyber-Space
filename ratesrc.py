"""Per-source rate buckets for the legacy-migration routes (Bulwark Gate 1
#2): every global bucket gets a per-source bucket in front of it, so one
source cannot drain a route for everyone.

  src:auth:<source>   routes that burn a challenge (withdraw, import);
                      shared with challenge/login once the RC lands
  src:read:<source>   public reads (head, proof, witnessed, observe)

The source is core.request_source() when the client-source code (trusted
proxies, X-Forwarded-For, IPv6 /64) is present, and the direct peer address
until then. This module only adapts; it adds nothing to core.

ART-40 C1: ported together with core.client_source. Alone, source() falls
back to request.client.host and every client behind Caddy shares one bucket.
The legacy routes charge their own per-IP / per-log buckets (see
routes_legacy_witness); they do not use auth() for import-legacy, because
that bucket is shared across challenge-burning routes and a 1x global.
"""
from fastapi import Request

import core

SOURCE_AUTH_LIMIT = getattr(core, "SOURCE_AUTH_LIMIT", 60)
SOURCE_READ_LIMIT = 120


def source(request: Request) -> str:
    rs = getattr(core, "request_source", None)
    if rs is not None:
        return rs(request)
    return request.client.host if request.client else "unknown"


def auth(request: Request) -> None:
    core._check_rate(f"src:auth:{source(request)}", limit=SOURCE_AUTH_LIMIT)


def read(request: Request) -> None:
    core._check_rate(f"src:read:{source(request)}", limit=SOURCE_READ_LIMIT)
