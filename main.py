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

#Usuarios

@app.get("/users/me", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED},  tags=["users"])
async def get_current_user(current_user:schemas.Usuario = Depends(get_current_user)) :
    return current_user

@app.get("/users/{user_id}", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["users"])
async def get_user_by_id(user_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    user = crud.get_user(db, user_id)
    if user is None :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")
    return user

@app.get("/users/", response_model = schemas.Usuario, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["users"])
async def get_user_by_email(user_email:str, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    user = crud.get_user_by_email(db, user_email)
    if user is None :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")
    return user

@app.get("/users", response_model = List[schemas.Usuario], responses = {**responses.UNAUTORIZED}, tags=["users"])
async def get_users(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_users(db, skip, limit)

@app.post("/users", response_model = schemas.Usuario, responses = {**responses.USER_ALREADY_REGISTERED}, tags=["users"])
async def create_user(user:schemas.UsuarioCreate, db:Session = Depends(get_db)) :
    db_user = crud.get_user_by_email(db, user.correo)
    if db_user:
        raise HTTPException (status_code = 400, detail = "Usuario ya registrado")
    return crud.create_user(db, user)

#Administradores

@app.get("/admins/{admin_id}", response_model = schemas.Administrador, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["admins"])
async def get_admin_by_id(admin_id:int, db:Session = Depends(get_db), current_user:schemas.Administrador = Depends(get_current_user)) :
    admin = crud.get_admin(db, admin_id)
    if admin is None :
        raise HTTPException (status_code = 404, detail = "Administrador no encontrado")
    return admin

@app.get("/admins/", response_model = schemas.Administrador, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["admins"])
async def get_admin_by_email(admin_email:str, db:Session = Depends(get_db), current_user:schemas.Administrador = Depends(get_current_user)) :
    admin = crud.get_admin_by_email(db, admin_email)
    if admin is None :
        raise HTTPException (status_code = 404, detail = "Administrador no encontrado")
    return admin

@app.get("/admins", response_model = List[schemas.Administrador], responses = {**responses.UNAUTORIZED}, tags=["admins"])
async def get_admins(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Administrador = Depends(get_current_user)) :
    return crud.get_admins(db, skip, limit)

@app.post("/admins", response_model = schemas.Administrador, responses = {**responses.USER_ALREADY_REGISTERED}, tags=["admins"])
async def create_admin(admin:schemas.AdministradorCreate, db:Session = Depends(get_db)) :
    db_admin = crud.get_admin_by_email(db, admin.correo)
    if db_admin:
        raise HTTPException (status_code = 400, detail = "Administrador ya registrado")
    return crud.create_admin(db, admin)

#Comedores

@app.get("/comedores/{comedor_id}", response_model = schemas.Comedor, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["comedores"])
async def get_comedor_by_id(comedor_id:int, db:Session = Depends(get_db), current_user:schemas.Comedor = Depends(get_current_user)) :
    comedor = crud.get_comedor(db, comedor_id)
    if comedor is None :
        raise HTTPException (status_code = 404, detail = "Comedor no encontrado")
    return schemas.Comedor(
            id = comedor.id,
            ajustes = str(comedor.ajustes)
        )

@app.get("/comedores", response_model = List[schemas.Comedor], responses = {**responses.UNAUTORIZED}, tags=["comedores"])
async def get_comedores(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Comedor = Depends(get_current_user)) :
    comedores = crud.get_comedores(db, skip, limit)
    comedores_return = []
    for comedor in comedores :
        comedores_return.append(schemas.Comedor(
            id = comedor.id,
            ajustes = str(comedor.ajustes)
        ))
    return comedores_return

@app.post("/comedores", response_model = schemas.Comedor, tags=["comedores"])
async def create_comedor(comedor:schemas.ComedorCreate, db:Session = Depends(get_db)) :
    return crud.create_comedor(db, comedor)

@app.get("/menus/{menu_id}", response_model = schemas.Menu, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu(menu_id:int, db:Session = Depends(get_db), current_user:schemas.Comedor = Depends(get_current_user)) :
    menu = crud.get_menu(db, menu_id)
    if menu is None :
        raise HTTPException (status_code = 404, detail = "Menu no encontrado")
    return schemas.Menu(
            id = menu.id,
            nombre = menu.nombre,
            platos = str(menu.platos),
            bebidas = str(menu.bebidas),
            idComedor = menu.idComedor
        )

#Menus

@app.get("/menus/{comedor_id}", response_model = schemas.Menu, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu_by_idComedor(comedor_id:int, db:Session = Depends(get_db), current_user:schemas.Comedor = Depends(get_current_user)) :
    menu = crud.get_menu_by_idComedor(db, comedor_id)
    if menu is None :
        raise HTTPException (status_code = 404, detail = "Menu no encontrado")
    return schemas.Menu(
            id = menu.id,
            nombre = menu.nombre,
            platos = str(menu.platos),
            bebidas = str(menu.bebidas),
            idComedor = menu.idComedor
        )

@app.get("/menus/", response_model = schemas.Menu, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu_by_name(menu_nombre:int, db:Session = Depends(get_db), current_user:schemas.Menu = Depends(get_current_user)) :
    menu = crud.get_menu_by_name(db, menu_nombre)
    if menu is None :
        raise HTTPException (status_code = 404, detail = f"Menu no encontrado: {menu_nombre}")
    return schemas.Menu(
            id = menu.id,
            nombre = menu.nombre,
            platos = str(menu.platos),
            bebidas = str(menu.bebidas),
            idComedor = menu.idComedor
        )

@app.get("/menus", response_model = List[schemas.Menu], responses = {**responses.UNAUTORIZED}, tags=["menus"])
async def get_menus(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Menu = Depends(get_current_user)) :
    menus = crud.get_menus(db, skip, limit)
    menus_return = []
    for menu in menus :
        menus_return.append(schemas.Menu(
            id = menu.id,
            nombre = menu.nombre,
            platos = str(menu.platos),
            bebidas = str(menu.bebidas),
            idComedor = menu.idComedor
        ))
    return menus_return

@app.post("/menus", response_model = schemas.Menu, tags=["menus"])
async def create_menu(menu:schemas.MenuCreate, db:Session = Depends(get_db)) :
    return crud.create_menu(db, menu)

#Mesas

@app.get("/mesas/{mesa_id}", response_model = schemas.Mesa, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def get_mesa_by_id(mesa_id:int, db:Session = Depends(get_db), current_user:schemas.Mesa = Depends(get_current_user)) :
    mesa = crud.get_mesa(db, mesa_id)
    if mesa is None :
        raise HTTPException (status_code = 404, detail = "Mesa no encontrada")
    return mesa

@app.get("/mesas/", response_model = schemas.Mesa, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def get_mesa_by_idComedor(comedor_id:str, db:Session = Depends(get_db), current_user:schemas.Comedor = Depends(get_current_user)) :
    mesa = crud.get_mesa_by_idComedor(db, comedor_id)
    if mesa is None :
        raise HTTPException (status_code = 404, detail = "Mesa no encontrada")
    return mesa

@app.get("/mesas", response_model = List[schemas.Mesa], responses = {**responses.UNAUTORIZED}, tags=["mesas"])
async def get_mesas(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Mesa = Depends(get_current_user)) :
    return crud.get_mesas(db, skip, limit)

@app.post("/mesas", response_model = schemas.Mesa, tags=["mesas"])
async def create_mesa(mesa:schemas.MesaCreate, db:Session = Depends(get_db)) :
    return crud.create_mesa(db, mesa)

#Reservas

@app.get("/reservas/{reserva_id}", response_model = schemas.Reserva, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_id(reserva_id:int, db:Session = Depends(get_db), current_user:schemas.Reserva = Depends(get_current_user)) :
    reserva = crud.get_reserva(db, reserva_id)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas/", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_fecha(reserva_fecha:str, db:Session = Depends(get_db), current_user:schemas.Reserva = Depends(get_current_user)) :
    reserva = crud.get_reserva_by_fecha(db, reserva_fecha)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas/user/{reserva_user}", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_user(reserva_user:int, db:Session = Depends(get_db), current_user:schemas.Reserva = Depends(get_current_user)) :
    reserva = crud.get_reserva_by_user(db, reserva_user)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas/mesa/{reserva_mesa}", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_mesa(reserva_mesa:int, db:Session = Depends(get_db), current_user:schemas.Reserva = Depends(get_current_user)) :
    reserva = crud.get_reserva_by_mesa(db, reserva_mesa)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED}, tags=["reservas"])
async def get_reservas(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Reserva = Depends(get_current_user)) :
    return crud.get_reservas(db, skip, limit)

@app.post("/reservas", response_model = schemas.Reserva, tags=["reservas"])
async def create_reserva(reserva:schemas.ReservaCreate, db:Session = Depends(get_db)) :
    return crud.create_reserva(db, reserva)