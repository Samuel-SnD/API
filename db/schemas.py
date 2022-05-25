from datetime import date
from typing import List, Optional
from pydantic import BaseModel, Json

class ComedorBase (BaseModel):
    ajustes : str

    class Config :
        orm_mode = True

class ComedorCreate (ComedorBase) : 
    pass

class Comedor (ComedorBase) :
    id : int

class MenuBase (BaseModel) :
    nombre : int
    platos : str
    bebidas : str
    idComedor : int

    class Config :
        orm_mode = True

class MenuCreate (MenuBase) :
    pass

class Menu (MenuBase) :
    id : int

class MesaBase (BaseModel) :
    asientos : int
    idComedor : int

    class Config :
        orm_mode = True

class MesaCreate (MesaBase) :
    pass

class Mesa (MesaBase) :
    id : int

class ReservaBase (BaseModel) :
    mesa : int
    fecha : date

    class Config :
        orm_mode = True

class ReservaCreate (ReservaBase) :
    pass

class Reserva (ReservaBase) :
    id : int
    usuario : int

class UsuarioBase (BaseModel) :
    nombre : str
    apellidos : str
    correo : str

    class Config :
        orm_mode = True

class UsuarioCreate (UsuarioBase) :
    contraseña : str

class Usuario (UsuarioBase) :
    id : int
    is_Admin : int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    correo: Optional[str] = None