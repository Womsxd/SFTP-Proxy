from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routes import tokens, admin

app = FastAPI(title="SFTP Proxy API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tokens.router, prefix="/api/tokens", tags=["tokens"])
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])

@app.get("/health")
async def health_check():
    from src.redis_client import RedisClient
    redis = RedisClient()
    return {
        "status": "ok",
        "redis": "connected" if redis.ping() else "disconnected"
    }
