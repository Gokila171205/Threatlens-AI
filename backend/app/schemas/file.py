from pydantic import BaseModel
from typing import Optional, List

class FileMetadata(BaseModel):
    file_id: str
    original_filename: str
    size: int
    sha256: str
    content_type: str
    status: str
    ownerId: str
    uploadedAt: str

class FileUploadResponse(BaseModel):
    success: bool
    message: str
    data: FileMetadata

class FilesListResponse(BaseModel):
    success: bool
    files: List[FileMetadata]

class SystemStats(BaseModel):
    totalFiles: int
    totalUsers: int
    activeUsers: int
    filesPending: int
    filesAnalyzed: int
    threatsDetected: int
    activeAlerts: int
    systemHealth: str

class StatsResponse(BaseModel):
    success: bool
    stats: SystemStats
