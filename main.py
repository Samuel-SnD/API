from curses.ascii import HT
from io import StringIO, BytesIO
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
from fpdf import FPDF
from fastapi.responses import StreamingResponse

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

async def get_current_admin(user : schemas.Usuario = Depends(get_current_user)) :
    if user.is_Admin != 1 :
        raise HTTPException (status_code = 401, detail = "No tienes suficientes permisos")

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

#region Usuarios

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

@app.get("/admins", response_model = List[schemas.Usuario], responses = {**responses.UNAUTORIZED}, tags=["users"])
async def get_admins(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    return crud.get_admins(db, skip, limit)

@app.get("/users", response_model = List[schemas.Usuario], responses = {**responses.UNAUTORIZED}, tags=["users"])
async def get_users(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_users(db, skip, limit)

@app.post("/users", response_model = schemas.Usuario, responses = {**responses.USER_ALREADY_REGISTERED}, tags=["users"])
async def create_user(user:schemas.UsuarioCreate, db:Session = Depends(get_db)) :
    db_user = crud.get_user_by_email(db, user.correo)
    if db_user:
        raise HTTPException (status_code = 400, detail = "Usuario ya registrado")
    return crud.create_user(db, user)

@app.put("/makeadmin/", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["users"])
async def make_admin(email : str, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.make_admin(db, email) :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")

@app.delete("/users/{user_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["users"])
async def delete_user(user : int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.get_user(db, user) :
        raise HTTPException (status_code = 404, detail = "Usuario no encontrado")
    crud.delete_user(db, user)

#endregion

#region Comedores

@app.get("/comedores/{comedor_id}", response_model = schemas.Comedor, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["comedores"])
async def get_comedor_by_id(comedor_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    comedor = crud.get_comedor(db, comedor_id)
    if comedor is None :
        raise HTTPException (status_code = 404, detail = "Comedor no encontrado")
    return schemas.Comedor(
            id = comedor.id,
            ajustes = str(comedor.ajustes)
        )

@app.get("/comedores", response_model = List[schemas.Comedor], responses = {**responses.UNAUTORIZED}, tags=["comedores"])
async def get_comedores(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    comedores = crud.get_comedores(db, skip, limit)
    comedores_return = []
    for comedor in comedores :
        comedores_return.append(schemas.Comedor(
            id = comedor.id,
            ajustes = str(comedor.ajustes)
        ))
    return comedores_return

@app.post("/comedores", response_model = schemas.Comedor, tags=["comedores"])
async def create_comedor(comedor:schemas.ComedorCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    return crud.create_comedor(db, comedor)

@app.put("/comedores/{comedor_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["comedores"])
async def update_comedor(comedor_id : int, cm : schemas.ComedorCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.update_comedor(db, comedor_id, cm) :
        raise HTTPException (status_code = 404, detail = "Comedor no encontrado")

@app.delete("/comedores/{comedor_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["comedores"])
async def delete_comedor(comedor : int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.get_comedor(db, comedor) :
        raise HTTPException (status_code = 404, detail = "Comedor no encontrado")
    crud.delete_comedor(db, comedor)

#endregion

#region Menus

@app.get("/menus/{menu_id}", response_model = schemas.Menu, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu(menu_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
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

@app.get("/menus/{comedor_id}", response_model = List[schemas.Menu], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu_by_idComedor(comedor_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    menu = crud.get_menu_by_idComedor(db, comedor_id)
    if menu is None :
        raise HTTPException (status_code = 404, detail = "Menu no encontrado")
    return menu

@app.get("/menus/", response_model = schemas.Menu, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def get_menu_by_name(menu_nombre:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
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
async def get_menus(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
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
async def create_menu(menu:schemas.MenuCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    return crud.create_menu(db, menu)

@app.put("/menus/{menu_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def update_menu(menu_id : int, m : schemas.MenuCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.update_menu(db, menu_id, m) :
        raise HTTPException (status_code = 404, detail = "Menu no encontrado")

@app.delete("/menus/{menu_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["menus"])
async def delete_menu(menu : int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.get_menu(db, menu) :
        raise HTTPException (status_code = 404, detail = "Menu no encontrado")
    crud.delete_menu(db, menu)

#endregion

#region Mesas

@app.get("/mesas/{mesa_id}", response_model = schemas.Mesa, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def get_mesa_by_id(mesa_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    mesa = crud.get_mesa(db, mesa_id)
    if mesa is None :
        raise HTTPException (status_code = 404, detail = "Mesa no encontrada")
    return mesa

@app.get("/mesas/", response_model = List[schemas.Mesa], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def get_mesa_by_idComedor(comedor_id:str, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_mesa_by_idComedor(db, comedor_id)

@app.get("/mesas", response_model = List[schemas.Mesa], responses = {**responses.UNAUTORIZED}, tags=["mesas"])
async def get_mesas(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_mesas(db, skip, limit)

@app.post("/mesas", response_model = schemas.Mesa, tags=["mesas"])
async def create_mesa(mesa:schemas.MesaCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    return crud.create_mesa(db, mesa)

@app.put("/mesas/{mesa_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def update_mesa(mesa_id : int, me : schemas.MesaCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.update_mesa(db, mesa_id, me) :
        raise HTTPException (status_code = 404, detail = "Mesa no encontrado")

@app.delete("/mesas/{mesa_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["mesas"])
async def delete_mesa(mesa_id : int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_admin)) :
    if not crud.get_mesa(db, mesa_id) :
        raise HTTPException (status_code = 404, detail = "Mesa no encontrada")
    try :
        crud.delete_mesa(db, mesa_id)
    except :
        raise HTTPException (status_code = 409, detail = "Existen reservas en la mesa")

#endregion

#region Reservas

@app.get("/reservas/{reserva_id}", response_model = schemas.Reserva, responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_id(reserva_id:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    reserva = crud.get_reserva(db, reserva_id)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas/{reserva_id}/pdf", responses = {**responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_pdf_reserva(reserva_id:int, db:Session = Depends(get_db)) :
    reserva : models.Reserva = crud.get_reserva(db, reserva_id)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    current_user = crud.get_user(db, reserva.usuario)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size = 15)
    pdf.cell(200, 10, txt = f"Comedor: {crud.get_comedor(db, crud.get_mesa(db, reserva.mesa).id).id}", ln = 1, align = 'C')
    pdf.cell(200, 10, txt = f"Mesa: {reserva.mesa}", ln = 2, align = 'C')
    pdf.cell(200, 10, txt = f"Usuario: {current_user.nombre}", ln = 3, align = 'C')
    pdf.cell(200, 10, txt = f"Fecha: {reserva.fecha}", ln = 4, align = 'C')
    pdf.cell(200, 10, txt = f"Hora: {reserva.hora}", ln = 5, align = 'C')
    bytes_send = BytesIO(bytes(pdf.output(dest = 'S'), encoding='latin1'))
    return StreamingResponse(iter(bytes_send), media_type = "application/pdf")
    
@app.get("/reservas/", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_fecha(reserva_fecha:str, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_reserva_by_fecha(db, reserva_fecha)

@app.get("/reservas/user/{reserva_user}", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_user(reserva_user:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    reserva = crud.get_reserva_by_user(db, reserva_user)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas/mesa/{reserva_mesa}", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def get_reserva_by_mesa(reserva_mesa:int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    reserva = crud.get_reserva_by_mesa(db, reserva_mesa)
    if reserva is None :
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    return reserva

@app.get("/reservas", response_model = List[schemas.Reserva], responses = {**responses.UNAUTORIZED}, tags=["reservas"])
async def get_reservas(skip : int = 0, limit : int = 100 , db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    return crud.get_reservas(db, skip, limit)

@app.post("/reservas", response_model = schemas.Reserva, responses = {**responses.CONFLICT, **responses.UNAUTORIZED}, tags=["reservas"])
async def create_reserva(reserva:schemas.ReservaCreate, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    if crud.get_reserva_dup(db, reserva.mesa, reserva.fecha, reserva.hora) :
        raise HTTPException (status_code = 409, detail = "Ya existe una reserva ese dia y hora")
    return crud.create_reserva(db, reserva, current_user)

@app.delete("/reservas/{reserva_id}", responses = {**responses.UNAUTORIZED, **responses.ENTITY_NOT_FOUND}, tags=["reservas"])
async def delete_reserva(reserva_id : int, db:Session = Depends(get_db), current_user:schemas.Usuario = Depends(get_current_user)) :
    reserva = crud.get_reserva(db, reserva_id)
    if not  reserva:
        raise HTTPException (status_code = 404, detail = "Reserva no encontrada")
    if not (current_user.is_Admin == 1 or current_user.id == reserva.usuario) : 
        raise HTTPException (status_code = 401, detail = "No tienes suficientes permisos")
    crud.delete_reserva(db, reserva_id)

#endregion