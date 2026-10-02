import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import auth, files, scans, alerts, monitoring, behavioral, threat_prediction
from app.services.user_service import seed_admin_if_empty
from app.services.seed_data import seed_scans_and_alerts_if_empty

app = FastAPI(
    title=settings.app_name,
    description="ThreatLens AI - Malware Detection & Threat Monitoring API",
    version="2.0.0"
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.services.db import DatabaseConnectionError, init_db_and_migrate

# Custom HTTPException handler
@app.exception_handler(DatabaseConnectionError)
async def db_connection_exception_handler(request: Request, exc: DatabaseConnectionError):
    return JSONResponse(
        status_code=503,
        content={"success": False, "message": "Database service unavailable. MongoDB Atlas connection error. Stale local fallback is disabled."}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": str(exc.detail)})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"success": False, "message": "Validation Error", "details": exc.errors()})

# Global Exception Handler matching Express
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": str(exc) or "Internal Server Error"}
    )

# Include Routers with standard /api and /api/v1 prefixes for robust client interoperability
for prefix in ["/api", "/api/v1"]:
    app.include_router(auth.router, prefix=f"{prefix}/auth", tags=["auth"])
    app.include_router(files.router, prefix=f"{prefix}/files", tags=["files"])
    app.include_router(scans.router, prefix=prefix, tags=["scans"])
    app.include_router(alerts.router, prefix=prefix, tags=["alerts"])
    app.include_router(monitoring.router, prefix=prefix, tags=["monitoring"])
    app.include_router(behavioral.router, prefix=prefix, tags=["behavioral"])
    app.include_router(threat_prediction.router, prefix=prefix, tags=["threat-prediction"])

@app.on_event("startup")
async def startup_event():
    init_db_and_migrate()
    seed_admin_if_empty()
    seed_scans_and_alerts_if_empty()
