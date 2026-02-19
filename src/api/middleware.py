from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from src.config import get_config


class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ['/health']:
            return await call_next(request)

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        token = auth_header[7:]
        cfg = get_config()
        admin_token = cfg.api.get('admin_token', '')

        if not admin_token or token != admin_token:
            raise HTTPException(status_code=403, detail="Invalid admin token")

        return await call_next(request)
