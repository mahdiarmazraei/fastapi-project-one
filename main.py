from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from database import SessionLocal, engine
import models
from pydantic import BaseModel
from fastapi import Body
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Response, Cookie
from jose import jwt, ExpiredSignatureError

SECRET_KEY = "3faa53f02b282c59494d692e1dbb8f1c7f7a820607a9e6a783c40592b6dd0ce0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

class UserSignin(BaseModel):
    username: str
    password: str
    # example_cookie: str = Cookie(None, description="Example cookie for authentication purposes.")
class UserSignup(UserSignin):
    email: str


class OwnerSignin(BaseModel):
    username : str
    password : str
class OwnerSignup(OwnerSignin):
    shop_name : str
    first_name : str
    last_name : str
    email : str

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class PasswordHasher:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

pwd_context = PasswordHasher()

@app.post("/register/")
def register(response: Response ,user: UserSignup = Body(...),token_cookie: str = Cookie(None),db: Session = Depends(get_db)):
    userexist = db.query(models.User).filter(models.User.username == user.username).first()

    if token_cookie != None:
        try:
            payload = jwt.decode(token_cookie, SECRET_KEY, algorithms=[ALGORITHM])
            exp_timestamp = payload.get("exp")
            expiration_datetime = datetime.utcnow() + timedelta(seconds=exp_timestamp)
            if expiration_datetime > datetime.utcnow():
                return {"message": "you eldearly logn"}
        except:
            if not userexist:
                token_cookie = create_access_token({"username" : user.username})
                response.set_cookie(key="token_cookie", value = token_cookie)
                hashed_password = pwd_context.get_password_hash(user.password)
                db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password,)
                db.add(db_user)
                db.commit()
                db.refresh(db_user)
                return db_user
            else:
                return {" you should login, this username is exist"}
    else:
        if not userexist:
            token_cookie = create_access_token({"username" : user.username})
            response.set_cookie(key="token_cookie", value = token_cookie)
            hashed_password = pwd_context.get_password_hash(user.password)
            db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password,)
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            return db_user
        else:
            token_cookie = create_access_token({"username" : user.username})
            response.set_cookie(key="token_cookie", value = token_cookie)

@app.post("/login/")
def login(response: Response ,users: UserSignin = Body(...),token_cookie: str = Cookie(None), db: Session = Depends(get_db)):
    if token_cookie:
        try:
            payload = jwt.decode(token_cookie, SECRET_KEY, algorithms=["HS256"])
            exp_timestamp = payload.get("exp")
            expiration_datetime = datetime.utcnow() + timedelta(seconds=exp_timestamp)
            if expiration_datetime > datetime.utcnow():
                return {"message": "you eldearly login"}
        except ExpiredSignatureError:
            user = db.query(models.User).filter(models.User.username == users.username).first()
            if not user or not pwd_context.verify_password(users.password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            token_cookie = create_access_token({"username" : users.username})
            response.set_cookie(key="token_cookie", value = token_cookie)
            return {"message": "Login successful"}
    else:
        user = db.query(models.User).filter(models.User.username == users.username).first()
        if not user or not pwd_context.verify_password(users.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_cookie = create_access_token({"username" : users.username})
        response.set_cookie(key="token_cookie", value = token_cookie)
        return {"message": "Login successful"}
@app.post("/signout/")
def signout(response: Response,token_cookie: str = Cookie(None)):
    if  token_cookie is not None:
        # حذف کوکی با استفاده از نام کوکی
        response.delete_cookie("token_cookie")
        return {"message": f"Cookie '{token_cookie}' deleted successfully"}
    else:
        return {"message": "No cookie name provided"}
    





    