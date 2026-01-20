from fastapi import FastAPI, HTTPException, Depends, status, Response, Cookie
from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime, timezone, timedelta
from pymongo.errors import PyMongoError, DuplicateKeyError
from pymongo import ReturnDocument
# from bson import ObjectId
# from fastapi import Query
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import ulid
import logging
import secrets
import hashlib

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
REFRESH_TOKEN_EXPIRE_DAYS = 30

# MongoDB connection
MONGO_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URL)
db = client["users"]       
users_collection = db["users"]  
refresh_token_collection = db["refreshtokens"]

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

class JwtToken(BaseModel):
    access_token: str
    token_type: str

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
    
@app.post("/login", response_model=JwtToken)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    login_email = form_data.username
    login_pw = form_data.password
    try:   
        account = await users_collection.find_one({
            "email": login_email
        })
    except PyMongoError:
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
    refresh_token = await create_refresh_token(account.get("id"))
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,        # True in prod
        samesite="lax",
        path="/refresh",
        max_age=60 * 60 * 24 * REFRESH_TOKEN_EXPIRE_DAYS  # 30 days
    )
    
    return JwtToken(
        access_token=access_token,
        token_type="bearer",
    )
# TODO: return user, not id
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("sub")
        if id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return id

@app.post("/refresh", response_model=JwtToken)
async def refresh_access_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    hashed_token = hashlib.sha256(refresh_token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    token = await refresh_token_collection.find_one_and_update(
    {
        "token_hash": hashed_token,
        "used": False,
        "revoked": False,
        "expires_at": {"$gt": now},
    },
    {
        "$set": {
            "used": True,
            "used_at": now,
        }
    },
    return_document=ReturnDocument.AFTER,
)  
    if not token:
        #second lookup to detect reused tokens
        existing = await refresh_token_collection.find_one({
        "token_hash": hashed_token
    })
        clear_cookies_token(response)
        if existing and existing.get("used"):
            await users_collection.update_one(
                {"id": existing.get("user_id")},
                {"$inc": {"token_version": 1}}
            )
            raise HTTPException(
                status_code=401,
                detail="Unauthorized"
            )
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    account = await users_collection.find_one({"id": token["user_id"]})
    # if invalid token version
    if token.get("version") != account.get("token_version"):   
        clear_cookies_token(response)
        raise HTTPException(
                status_code=401,
                detail="Unauthorized"
            )
    # if token is legit
    else:
        current_user = token.get("user_id")
        new_refresh_token = await create_refresh_token(current_user)
        new_access_token = await create_access_token(
        data = {
            "sub": current_user
        },
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=True,        # True in prod
            samesite="lax",
            path="/refresh",
            max_age=60 * 60 * 24 * REFRESH_TOKEN_EXPIRE_DAYS  # 30 days
        )
        return JwtToken(
            access_token=new_access_token,
            token_type="bearer",
    )

    

@app.get("/protected")
async def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello {current_user}"}

@app.get("/me", response_model=UserOut)
async def get_me(current_user: str = Depends(get_current_user)):
    try:   
        account = await users_collection.find_one({
            "id": current_user
        })
        if not account:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception:
        raise HTTPException(status_code=500, detail="Database error")
    return UserOut(
        id = account.get("id")  ,
        email = account.get("email")  
    )

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
        "created_at": date,
        "token_version": 1
    }
    try:
        result = await users_collection.insert_one(new_user) # why result ??
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

async def create_refresh_token(current_user: str):
    raw_token = secrets.token_urlsafe(32) #TODO: Unique index on token_hash on db
    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
    try:   
        account = await users_collection.find_one({
            "id": current_user
        })
        if not account:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception:
        raise HTTPException(status_code=500, detail="Database error")
    user_id = account.get("id")
    version = account.get("token_version")
    now = datetime.now(timezone.utc)
    new_token = {
        "token_hash": hashed_token,
        "user_id": user_id,
        #"scope": "session"
        "version" : version,
        "created_at": now,
        "expires_at": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "used_at": None,
        "used": False,
        "revoked": False
    }
    try:
        await refresh_token_collection.insert_one(new_token)
    except PyMongoError as e:
        logger.exception("MongoDB write error")
        raise HTTPException(
            status_code=500,
            detail="Database write failed"
        ) from e
    return raw_token
    
#TODO: iat later       
def create_access_token(
    data: dict, 
    expires_delta: timedelta | None = None
):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def clear_cookies_token(response: Response):
    response.delete_cookie(
            key="refresh_token",
            path="/refresh",
            secure=True,
            samesite="lax",
        )

def force_logout_user():
    pass

# example user document
# {
#   _id: ObjectId("65b1ca4a8a1e3c2d4f9b1111"),
#   id: "usr_01HMY7ZP5M8R2F9YQW8K3J2A6B",
#   email: "user@example.com",
#   password_hash: "$2b$12$Q9w1Z9...",
#   created_at: ISODate("2026-01-15T10:42:00Z")
# }
