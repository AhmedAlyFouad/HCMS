import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Optional, Literal
import pyodbc
from passlib.context import CryptContext
from dotenv import load_dotenv
from jose import JWTError, jwt

# =============================
# CONFIGURATION
# =============================
load_dotenv()

DB_SERVER = os.getenv("DB_SERVER")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="HCMS API")

# =============================
# DATABASE CONNECTION
# =============================
def get_db_connection():
    try:
        return pyodbc.connect(
            f"Driver={{ODBC Driver 18 for SQL Server}};"
            f"Server={DB_SERVER};Database={DB_NAME};"
            f"UID={DB_USER};PWD={DB_PASSWORD};"
            "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
        )
    except pyodbc.Error as ex:
        raise HTTPException(status_code=500, detail=f"Database connection error: {ex}")

# =============================
# PASSWORD UTILITIES
# =============================
MAX_BCRYPT_LENGTH = 72

def hash_password(password: str) -> str:
    truncated = password[:MAX_BCRYPT_LENGTH]
    return pwd_context.hash(truncated)

def verify_password(plain: str, hashed: str) -> bool:
    truncated = plain[:MAX_BCRYPT_LENGTH]
    return pwd_context.verify(truncated, hashed)

# =============================
# JWT AUTH UTILITIES
# =============================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_id(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

# =============================
# Pydantic MODELS
# =============================
class RegisterUserRequest(BaseModel):
    email: str
    password: str
    role: str
    language: Optional[str] = None
    isAnonymous: Optional[bool] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str

class ComplaintCreateRequest(BaseModel):
    hospitalId: int
    category: Literal["complaint", "request", "suggestion"]
    department: Optional[str] = None
    description: Optional[str] = None
    attachmentUrl: Optional[str] = None

class ComplaintResponse(BaseModel):
    id: int
    userId: int
    hospitalId: int
    category: str
    department: Optional[str]
    description: Optional[str]
    status: str
    attachmentUrl: Optional[str]
    createdAt: Optional[datetime]
    resolvedAt: Optional[datetime]

class LoginRequest(BaseModel):
    email: str
    password: str

class CommentCreateRequest(BaseModel):
    complaintId: int
    content: str

class CommentResponse(BaseModel):
    id: int
    complaintId: int
    authorId: int
    content: Optional[str]
    timestamp: Optional[datetime]

# =============================
# USER ENDPOINTS
# =============================
@app.post("/register")
def register_user(data: RegisterUserRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Users WHERE email = ?", (data.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(data.password)
    cursor.execute("""
        INSERT INTO Users (email, password, role, language, isAnonymous)
        VALUES (?, ?, ?, ?, ?)
    """, (data.email, hashed_pw, data.role, data.language, data.isAnonymous))
    conn.commit()
    user_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
    conn.close()

    return {"message": "User registered successfully", "userId": user_id}

@app.post("/login", response_model=LoginResponse)
def login(data: LoginRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Use data.email (from JSON) for the query
    cursor.execute("SELECT id, password FROM Users WHERE email = ?", (data.email,)) 
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id, hashed_pw = row
    
    # 2. Use data.password (from JSON) for verification
    if not verify_password(data.password, hashed_pw): 
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token({"user_id": user_id})
    return {"access_token": access_token, "token_type": "bearer"}
# =============================
# COMPLAINT ENDPOINTS
# =============================
@app.post("/complaints", response_model=ComplaintResponse)
def create_complaint(data: ComplaintCreateRequest, user_id: int = Depends(get_current_user_id)):
    now = datetime.now()
    status = "Open"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Complaints (userId, hospitalId, category, department, description, status, attachmentUrl, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, data.hospitalId, data.category, data.department, data.description, status, data.attachmentUrl, now))
    complaint_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
    conn.commit()
    conn.close()

    return ComplaintResponse(
        id=complaint_id,
        userId=user_id,
        hospitalId=data.hospitalId,
        category=data.category,
        department=data.department,
        description=data.description,
        status=status,
        attachmentUrl=data.attachmentUrl,
        createdAt=now,
        resolvedAt=None
    )

@app.get("/complaints", response_model=List[ComplaintResponse])
def get_user_complaints(user_id: int = Depends(get_current_user_id)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, userId, hospitalId, category, department, description, status, attachmentUrl, createdAt, resolvedAt
        FROM Complaints
        WHERE userId = ?
        ORDER BY createdAt DESC
    """, (user_id,))
    rows = cursor.fetchall()
    columns = [col[0] for col in cursor.description]
    complaints = [ComplaintResponse(**dict(zip(columns, r))) for r in rows]
    conn.close()
    return complaints

@app.get("/complaints/stats")
def get_complaint_stats(user_id: int = Depends(get_current_user_id)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Complaints WHERE userId=?", (user_id,))
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Complaints WHERE userId=? AND status='Open'", (user_id,))
    pending = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Complaints WHERE userId=? AND status='Resolved'", (user_id,))
    solved = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Complaints WHERE userId=? AND status NOT IN ('Open', 'Resolved')", (user_id,))
    unsolved = cursor.fetchone()[0]
    conn.close()

    return {"total": total, "pending": pending, "solved": solved, "unsolved": unsolved}

@app.post("/complaints/{complaint_id}/resolve")
def resolve_complaint(complaint_id: int, user_id: int = Depends(get_current_user_id)):
    now = datetime.now()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Complaints
        SET status='Resolved', resolvedAt=?
        WHERE id=? AND userId=?
    """, (now, complaint_id, user_id))
    conn.commit()
    conn.close()
    return {"message": "Complaint marked as resolved"}

# =============================
# COMMENTS ENDPOINTS
# =============================
@app.post("/comments", response_model=CommentResponse)
def add_comment(data: CommentCreateRequest, user_id: int = Depends(get_current_user_id)):
    now = datetime.now()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Comments (complaintId, authorId, content, timestamp)
        VALUES (?, ?, ?, ?)
    """, (data.complaintId, user_id, data.content, now))
    comment_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
    conn.commit()
    conn.close()

    return CommentResponse(
        id=comment_id,
        complaintId=data.complaintId,
        authorId=user_id,
        content=data.content,
        timestamp=now
    )

@app.get("/complaints/{complaint_id}/comments", response_model=List[CommentResponse])
def get_comments(complaint_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, complaintId, authorId, content, timestamp
        FROM Comments
        WHERE complaintId=?
        ORDER BY timestamp ASC
    """, (complaint_id,))
    rows = cursor.fetchall()
    columns = [col[0] for col in cursor.description]
    comments = [CommentResponse(**dict(zip(columns, r))) for r in rows]
    conn.close()
    return comments