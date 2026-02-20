from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from src.api.dependencies import verify_admin_token
from src.redis_client import TokenStore, generate_token
from src.config import get_config
from src.logger import api_log

router = APIRouter()


class CreateTokenRequest(BaseModel):
    paths: list[str]
    expire: Optional[int] = None
    download_limits: Optional[dict] = None
    rate_limit: Optional[int] = None
    auth_type: str = "token"


class TokenResponse(BaseModel):
    token: str
    expires_at: float
    paths: list[str]
    download_limits: Optional[dict]
    rate_limit: Optional[int]


@router.post("", response_model=TokenResponse)
async def create_token(
    request: CreateTokenRequest,
    admin_token: str = Depends(verify_admin_token)
):
    cfg = get_config()

    if request.auth_type == "token":
        token = generate_token()
        token_store = TokenStore()
        result = token_store.create_token(
            token=token,
            paths=request.paths,
            download_limits=request.download_limits,
            expire=request.expire,
            rate_limit=request.rate_limit
        )
        api_log("CREATE_TOKEN", f"token={token[:8]}... paths={request.paths} expire={request.expire} rate_limit={request.rate_limit}")
        return TokenResponse(**result)

    elif request.auth_type == "jwt":
        from src.auth.jwt_auth import JWTAuth
        jwt_auth = JWTAuth()
        token = jwt_auth.create_token(
            paths=request.paths,
            download_limits=request.download_limits,
            expire=request.expire or cfg.token.get('default_expire', 600),
            rate_limit=request.rate_limit
        )
        api_log("CREATE_TOKEN", f"jwt_token created paths={request.paths} expire={request.expire} rate_limit={request.rate_limit}")
        return TokenResponse(
            token=token,
            expires_at=0,
            paths=request.paths,
            download_limits=request.download_limits,
            rate_limit=request.rate_limit
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid auth_type. Use 'token' or 'jwt'")


@router.get("/{token}")
async def get_token(
    token: str,
    admin_token: str = Depends(verify_admin_token)
):
    cfg = get_config()
    auth_type = cfg.auth.get('type', 'token')

    if auth_type == 'token':
        token_store = TokenStore()
        data = token_store.get_token(token)
    elif auth_type == 'jwt':
        from src.auth.jwt_auth import JWTAuth
        jwt_auth = JWTAuth()
        try:
            import jwt as pyjwt
            payload = pyjwt.decode(token, jwt_auth._secret, algorithms=[jwt_auth._algorithm], options={"verify_exp": False})
            data = {
                'paths': payload.get('paths', []),
                'download_limits': payload.get('download_limits', {}),
                'expires_at': payload.get('exp', 0),
                'rate_limit': payload.get('rate_limit')
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JWT: {str(e)}")
    else:
        raise HTTPException(status_code=400, detail=f"Token query not supported for auth type: {auth_type}")

    if not data:
        raise HTTPException(status_code=404, detail="Token not found or expired")

    return data


@router.delete("/{token}")
async def delete_token(
    token: str,
    admin_token: str = Depends(verify_admin_token)
):
    cfg = get_config()
    auth_type = cfg.auth.get('type', 'token')

    success = False
    if auth_type == 'token':
        token_store = TokenStore()
        success = token_store.delete_token(token)
    elif auth_type == 'jwt':
        from src.auth.jwt_auth import JWTAuth
        jwt_auth = JWTAuth()
        success = jwt_auth.revoke_token(token)

    if not success:
        raise HTTPException(status_code=404, detail="Token not found")

    api_log("REVOKE_TOKEN", f"token={token[:8]}...")
    return {"message": "Token revoked successfully"}


@router.get("/{token}/downloads")
async def get_downloads(
    token: str,
    admin_token: str = Depends(verify_admin_token)
):
    cfg = get_config()
    auth_type = cfg.auth.get('type', 'token')

    if auth_type == 'token':
        token_store = TokenStore()
        data = token_store.get_token(token)
    elif auth_type == 'jwt':
        from src.auth.jwt_auth import JWTAuth
        jwt_auth = JWTAuth()
        try:
            import jwt as pyjwt
            payload = pyjwt.decode(token, jwt_auth._secret, algorithms=[jwt_auth._algorithm], options={"verify_exp": False})
            data = {
                'paths': payload.get('paths', []),
                'download_limits': payload.get('download_limits', {}),
                'rate_limit': payload.get('rate_limit')
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JWT: {str(e)}")
    else:
        data = {'paths': [], 'download_limits': {}}

    if not data:
        raise HTTPException(status_code=404, detail="Token not found or expired")

    return {
        "token": token[:8] + "..." if len(token) > 16 else token,
        "paths": data.get('paths', []),
        "download_limits": data.get('download_limits', {}),
        "downloads": data.get('downloads', {}),
        "rate_limit": data.get('rate_limit')
    }
