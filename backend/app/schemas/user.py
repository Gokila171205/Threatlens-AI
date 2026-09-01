from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    name: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: str
    role: str

class LoginResponse(BaseModel):
    success: bool
    token: str
    user: UserResponse

class RegisterResponse(BaseModel):
    success: bool
    message: str
    user: UserResponse

class MeResponse(BaseModel):
    success: bool
    user: UserResponse
