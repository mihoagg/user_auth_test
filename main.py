from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime, timezone, timedelta
from pymongo.errors import PyMongoError, DuplicateKeyError
# from bson import ObjectId
# from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import ulid
import logging


app = FastAPI()

logger = logging.getLogger(__name__)

# bcrypt
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# Token extractor
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# JWT config
SECRET_KEY = "secretkeychangeme" # In real apps, SECRET_KEY goes in env vars.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB connection
MONGO_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URL)
db = client["users"]        # change db name
collection = db["users"]  # change collection name

class User(BaseModel):
    email: EmailStr
    password: str
    
    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v
    
class UserOut(BaseModel):
    id: str
    email: str

# class LoginRequest(BaseModel):
#     email: EmailStr
#     password: str

@app.get("/")
async def hello():
    return "hello"

@app.post("/new_user")
async def new_user(item: User):
    user_id = await create_user(item)
    return {
        "message": "User created",
        "ID": user_id
    }
    
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    login_email = form_data.username
    login_pw = form_data.password
    try:   
        account = await collection.find_one({
            "email": login_email
        })
    except:
        raise HTTPException(status_code=500, detail="Database error")
    if account is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not (verify_password(login_pw, account["password_hash"])):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(
        data = {
            "sub": account["id"]
        },
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        #"message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer"
        }
    
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, ALGORITHM)
        id = payload.get("sub")
        if id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return id

@app.get("/protected")
async def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello {current_user}"}

@app.get("/me", response_model=UserOut)
async def get_me(current_user: str = Depends(get_current_user)):
    try:   
        account = await collection.find_one({
            "id": current_user
        })
        if not account:
            raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=500, detail="Database error")
    return account

async def create_user(user: User):
    uid = str(ulid.new())
    user_dict = user.model_dump()
    email = user_dict["email"].strip().lower()
    password = user_dict["password"]
    password_hash = hash_password(password)
    date = datetime.now(timezone.utc)
    new_user = {
        "id": uid,
        "email": email,
        "password_hash": password_hash,
        "created_at": date
    }
    try:
        result = await collection.insert_one(new_user)
        return uid
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    except PyMongoError as e:
        logger.exception("MongoDB write error")
        raise HTTPException(
            status_code=500,
            detail="Database write failed"
        )
        
# iat later       
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# example user document
# {
#   _id: ObjectId("65b1ca4a8a1e3c2d4f9b1111"),
#   id: "usr_01HMY7ZP5M8R2F9YQW8K3J2A6B",
#   email: "user@example.com",
#   password_hash: "$2b$12$Q9w1Z9...",
#   created_at: ISODate("2026-01-15T10:42:00Z")
# }
