import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# App setup
app = FastAPI(title="SaaS Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth / Security setup
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 14  # 14 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


# -------------------------
# Pydantic models
# -------------------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class MeResponse(BaseModel):
    id: str
    name: str
    email: EmailStr

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)

class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)

class ProjectOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


# -------------------------
# Utility functions
# -------------------------

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # fetch user
    user = db["user"].find_one({"_id": _to_object_id(user_id)}) if db else None
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# Mongo helpers
from bson import ObjectId

def _to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id format")


def _serialize_id(doc: dict) -> dict:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    return doc


# -------------------------
# Health / root
# -------------------------
@app.get("/")
def read_root():
    return {"message": "SaaS Backend Running"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# -------------------------
# Auth endpoints
# -------------------------
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: UserCreate):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": payload.name.strip(),
        "email": payload.email.lower(),
        "password_hash": get_password_hash(payload.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)

    token = create_access_token({"sub": str(result.inserted_id)})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: UserLogin):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)


@app.get("/auth/me", response_model=MeResponse)
def me(current_user=Depends(get_current_user)):
    return MeResponse(id=str(current_user["_id"]), name=current_user.get("name", ""), email=current_user.get("email", ""))


# -------------------------
# Projects CRUD (protected)
# -------------------------
@app.get("/projects", response_model=List[ProjectOut])
def list_projects(current_user=Depends(get_current_user)):
    docs = db["project"].find({"owner_id": str(current_user["_id"])})
    return [ProjectOut(**_serialize_id(d)) for d in docs]


@app.post("/projects", response_model=ProjectOut)
def create_project(payload: ProjectCreate, current_user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    doc = {
        "owner_id": str(current_user["_id"]),
        "name": payload.name.strip(),
        "description": payload.description.strip() if payload.description else None,
        "created_at": now,
        "updated_at": now,
    }
    result = db["project"].insert_one(doc)
    created = db["project"].find_one({"_id": result.inserted_id})
    return ProjectOut(**_serialize_id(created))


@app.put("/projects/{project_id}", response_model=ProjectOut)
def update_project(project_id: str, payload: ProjectUpdate, current_user=Depends(get_current_user)):
    update_fields = {k: v.strip() if isinstance(v, str) else v for k, v in payload.model_dump(exclude_unset=True).items()}
    update_fields["updated_at"] = datetime.now(timezone.utc)

    result = db["project"].find_one_and_update(
        {"_id": _to_object_id(project_id), "owner_id": str(current_user["_id"])},
        {"$set": update_fields},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut(**_serialize_id(result))


@app.delete("/projects/{project_id}")
def delete_project(project_id: str, current_user=Depends(get_current_user)):
    res = db["project"].delete_one({"_id": _to_object_id(project_id), "owner_id": str(current_user["_id"])})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
