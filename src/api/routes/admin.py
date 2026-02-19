from fastapi import APIRouter, Depends
from src.api.dependencies import verify_admin_token
from src.config import reload_config
from src.logger import api_log

router = APIRouter()


@router.post("/reload")
async def reload_config_api(admin_token: str = Depends(verify_admin_token)):
    reload_config()
    api_log("RELOAD_CONFIG", "Configuration reloaded")
    return {"message": "Configuration reloaded successfully"}
