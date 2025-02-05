from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import datetime
from typing import Optional

app = FastAPI()

# Secret key for JWT
token_secret = "your_secret_key"

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulated user database
fake_db = {}

# Models
class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

class LoginRequest(BaseModel):
    email: str
    password: str

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt(email: str) -> str:
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {"sub": email, "exp": expiration}
    return jwt.encode(payload, token_secret, algorithm="HS256")

def decode_jwt(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, token_secret, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Endpoints
@app.post("/register")
def register_user(request: RegisterRequest):
    if request.email in fake_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = hash_password(request.password)
    fake_db[request.email] = {"name": request.name, "password": hashed_password}
    return {"message": "User registered successfully"}

@app.post("/login")
def login_user(request: LoginRequest):
    user = fake_db.get(request.email)
    if not user or not verify_password(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_jwt(request.email)
    return {"token": token}

@app.get("/profile")
def get_profile(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.split(" ")[1]
    email = decode_jwt(token)
    user = fake_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"email": email, "name": user["name"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
