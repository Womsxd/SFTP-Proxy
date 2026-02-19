from typing import Optional
from fastapi import Header, HTTPException
from src.config import get_config

async def verify_admin_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization[7:]
    cfg = get_config()
    admin_token = cfg.api.get('admin_token', '')

    if not admin_token or token != admin_token:
        raise HTTPException(status_code=403, detail="Invalid admin token")

    return token
