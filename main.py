from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List
from uuid import uuid4
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os, shutil
from pymongo import MongoClient
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
import jwt

# ---------- CONFIG ----------
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
AccessTokenExpiresInMinutes= 60
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

client = MongoClient("mongodb://localhost:27017")
db = client.secure_share
users = db.users
files = db.files

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# pending_users: Dict[str, Dict] = {}
app=FastAPI()

class UserCreate(BaseModel):
    email: str
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str
    
class User(BaseModel):
    email: str
    role: str



def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# def create_access_token(data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=AccessTokenExpiresInMinutes)
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=AccessTokenExpiresInMinutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(email: str):
    return users.find_one({'email': email})

def authenticate_user(username: str, password: str):
    # Dummy authentication function
    user=get_user_by_email(username)
    if not user or not verify_password(password, user['password']):
        return False
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = get_user_by_email(payload.get("sub"))
        if user is None:
            raise HTTPException(status_code=401)
        return user
    except JWTError:
        raise HTTPException(status_code=401)


def send_verification_email(email: str, encrypted_url: str):
    msg=MIMEText(f"Click to verify: http://localhost:8001/verify-email?token={encrypted_url}")
    msg['Subject'] = 'Email Verification'
    msg['From'] = '2003guptakunal@gmail.com'
    msg['To'] = email
    with smtplib.SMTP('localhost', 1025) as server:
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        
@app.post("/signup")
def signup(user: UserCreate, background_tasks: BackgroundTasks):
    if users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    uid=str(uuid4())
    encrypted_url = fernet.encrypt(uid.encode()).decode()
    users.insert_one({"_id": uid, "email": user.email, "password": get_password_hash(user.password), "role": "client", "is_verified": False})
    background_tasks.add_task(send_verification_email, user.email, encrypted_url)
    return {"message": "User created. Verification email sent.", "url": encrypted_url}

@app.get("/verify_email")
def verify_email(token: str):
     try:
         uid=fernet.decrypt(token.encode()).decode()
         users.update_one({"_id": uid}, {"$set": {"is_verified": True}})
         return {"message": "Email verified successfully"}
     except Exception as e:
         print(f"Error during email verification: {e}")
         raise HTTPException(status_code=400, detail="Invalid token")
     
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user=authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect Credentials")
    if not user.get('is_verified', False) and user['role']=="client":
        raise HTTPException(status_code=403, detail="User not verified")
    access_token_time=timedelta(minutes=AccessTokenExpiresInMinutes)    
    access_token= create_access_token(data={"sub": user['email']}, expires_delta=access_token_time)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'ops':
        raise HTTPException(status_code=403, detail="Only Ops can upload")
    if file.filename.split('.')[-1] not in ['docx', 'pptx', 'xlsx']:
        raise HTTPException(status_code=400, detail="Invalid file type")
    file_id = str(uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    files.insert_one({"_id": file_id, "filename": file.filename, "path": file_path, "uploaded_by": current_user['_id'], "timestamp": datetime.utcnow()})
    return {"message": "File uploaded successfully", "file_id": file_id}

@app.get("/files")
def list_files(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'client':
        raise HTTPException(status_code=403, detail="Only clients can view files")
    return list(files.find({}, {"_id": 1, "filename": 1}))

@app.get("/download/{file_id}")
def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'client':
        raise HTTPException(status_code=403, detail="Only clients can download files")
    
    file_doc = files.find_one({"_id": file_id})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Generate encrypted download URL
    download_url = f"http://localhost:8000/download-file/{file_id}"
    encrypted_url = fernet.encrypt(download_url.encode()).decode()
    
    return {"download-link": encrypted_url, "message": "success"}

