from typing import List, Optional
from pydantic import BaseModel

class ComedorBase (BaseModel):
    ajustes : str

    class Config :
        orm_mode = True

class ComedorCreate (ComedorBase) : 
    pass

class Comedor (ComedorBase) :
    id : int

class AdministradorBase (BaseModel) :
    nombre : str
    apellidos : str
    correo : str

    class Config :
        orm_mode = True

class AdministradorCreate (AdministradorBase) :
    contraseña : str

class Administrador (AdministradorBase) :
    id : int

class MenuBase (BaseModel) :
    nombre : str
    platos : str
    bebidas : str

    class Config :
        orm_mode = True

class MenuCreate (MenuBase) :
    idComedor : int

class Menu (MenuBase) :
    id : int
    idComedor : int

class MesaBase (BaseModel) :
    asientos : int

    class Config :
        orm_mode = True

class MesaCreate (MesaBase) :
    idComedor : int

class Mesa (MesaBase) :
    id : int
    idComedor : int

class ReservaBase (BaseModel) :
    mesa : int
    usuario : int
    fecha : str

    class Config :
        orm_mode = True

class ReservaCreate (ReservaBase) :
    pass

class Reserva (ReservaBase) :
    id : int

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