from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.user import UserCreate, UserLogin, LoginResponse, RegisterResponse, MeResponse, UserResponse
from app.services.user_service import create_user, find_user_by_email, find_user_by_id
from app.core.security import verify_password, create_access_token
from app.api.deps import get_current_user

router = APIRouter()

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate):
    try:
        new_user = create_user(user_in.name, user_in.email, user_in.password, "USER")
        return RegisterResponse(
            success=True,
            message="Registration successful",
            user=UserResponse(
                id=new_user["id"],
                name=new_user["name"],
                email=new_user["email"],
                role=new_user["role"]
            )
        )
    except ValueError as e:
        if str(e) == "Email already registered":
            raise HTTPException(status_code=409, detail={"success": False, "message": str(e)})
        raise HTTPException(status_code=500, detail={"success": False, "message": "Internal server error"})

@router.post("/login", response_model=LoginResponse)
def login(user_in: UserLogin):
    user = find_user_by_email(user_in.email)
    if not user:
        raise HTTPException(status_code=401, detail={"success": False, "message": "Invalid email or password"})
        
    if not verify_password(user_in.password, user["passwordHash"]):
        raise HTTPException(status_code=401, detail={"success": False, "message": "Invalid email or password"})
        
    token = create_access_token({"id": user["id"], "email": user["email"], "role": user["role"], "name": user["name"]})
    
    return LoginResponse(
        success=True,
        token=token,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            role=user["role"]
        )
    )

@router.get("/me", response_model=MeResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    user = find_user_by_id(current_user["id"])
    if not user:
        raise HTTPException(status_code=404, detail={"success": False, "message": "User not found"})
        
    return MeResponse(
        success=True,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            role=user["role"]
        )
    )
