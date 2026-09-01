import hashlib
import os
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import JSONResponse

from app.schemas.file import FileUploadResponse, FilesListResponse, StatsResponse, FileMetadata, SystemStats
from app.api.deps import get_current_user, require_role
from app.services.db import get_db, save_db
from app.services.user_service import get_user_count
from app.core.config import settings

router = APIRouter()

ALLOWED_EXTENSIONS = {'.exe', '.dll', '.pdf', '.doc', '.docx', '.zip', '.rar', '.js', '.ps1', '.bat'}

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    if not file:
        return JSONResponse(status_code=400, content={"success": False, "message": "No file provided"})
        
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return JSONResponse(status_code=415, content={"success": False, "message": "Unsupported file type"})
        
    # Check size (if possible via file.size attribute or streaming)
    # FastAPI's UploadFile reads chunks so we can track size while hashing
    
    file_id = str(uuid.uuid4())
    safe_filename = f"{file_id}{ext}"
    upload_dir = Path(settings.upload_directory)
    
    # Ensure directory exists
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    final_path = upload_dir / safe_filename
    
    # Write chunks and calculate SHA256
    sha256_hash = hashlib.sha256()
    size = 0
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    
    try:
        with open(final_path, "wb") as buffer:
            while chunk := await file.read(8192):
                size += len(chunk)
                if size > max_size_bytes:
                    final_path.unlink(missing_ok=True)
                    return JSONResponse(
                        status_code=413, 
                        content={"success": False, "message": "File exceeds the maximum allowed size"}
                    )
                sha256_hash.update(chunk)
                buffer.write(chunk)
    except Exception as e:
        if final_path.exists():
            final_path.unlink()
        raise HTTPException(status_code=500, detail="Failed to save file")
        
    sha256 = sha256_hash.hexdigest()
    
    new_file_data = {
        "file_id": file_id,
        "original_filename": file.filename,
        "size": size,
        "sha256": sha256,
        "content_type": file.content_type or "application/octet-stream",
        "status": "uploaded",
        "ownerId": current_user["id"],
        "uploadedAt": datetime.utcnow().isoformat() + "Z"
    }
    
    db = get_db()
    db["files"].append(new_file_data)
    save_db(db)
    
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "File uploaded successfully",
            "data": new_file_data
        }
    )

@router.get("/", response_model=FilesListResponse)
def get_files(current_user: dict = Depends(get_current_user)):
    db = get_db()
    user_files = db.get("files", [])
    
    if current_user.get("role") == "USER":
        user_files = [f for f in user_files if f.get("ownerId") == current_user["id"]]
        
    return FilesListResponse(
        success=True,
        files=user_files
    )

@router.get("/stats", response_model=StatsResponse)
def get_system_stats(current_user: dict = Depends(require_role(["ADMIN"]))):
    db = get_db()
    files = db.get("files", [])
    
    stats = SystemStats(
        totalFiles=len(files),
        totalUsers=get_user_count(),
        activeUsers=get_user_count(),
        filesPending=len([f for f in files if f.get("status") == "uploaded"]),
        filesAnalyzed=len([f for f in files if f.get("status") == "analyzed"]),
        threatsDetected=0,
        activeAlerts=0,
        systemHealth="100%"
    )
    
    return StatsResponse(
        success=True,
        stats=stats
    )
