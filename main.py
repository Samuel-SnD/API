import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from db import crud, models, schemas
from db.database import SessionLocal, engine
from response import responses
import response.responses
from passlib.context import CryptContext
from jose import JWTError, jwt

import uuid

from dotenv import load_dotenv

from xml.etree import ElementTree as ET

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(correo: str, password: str, db: Session = Depends(get_db)):
    user:models.Usuario = crud.get_user_by_email(db, correo)
    if not user:
        return False
    if not verify_password(password, user.contraseña):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        correo: str = payload.get("sub")
        if correo is None:
            raise credentials_exception
        token_data = schemas.TokenData(correo = correo)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_email(db, token_data.correo)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token", response_model=schemas.Token, responses={**responses.UNAUTORIZED}, tags=["auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect correo or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.correo}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED})
async def get_current_user(current_user:schemas.Usuario = Depends(get_current_user)) :
    return current_user

@app.get("/users/{user_id}", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND})
async def get_user_by_id(user_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    user = crud.get_user(db, user_id)
    if user is None :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")
    return user

@app.get("/users/", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND})
async def get_user_by_email(user_email:str, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    user = crud.get_user_by_email(db, user_email)
    if user is None :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")
    return user

@app.get("/users", response_model = List[schemas.Usuario], responses = {**responses.UNAUTORIZED})
async def get_users(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_users(db, skip, limit)

@app.post("/users/", response_model = schemas.Usuario, responses = {**responses.USER_ALREADY_REGISTERED})
async def create_user(user:schemas.UsuarioCreate, db:Session = Depends(get_db)) :
    db_user = crud.get_user_by_email(db, user.correo)
    if db_user:
        raise HTTPException (status_code = 400, detail = "Usuario ya registrado")
    return crud.create_user(db, user)

