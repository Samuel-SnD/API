from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON
from .database import Base

admin_comedor = Table ('Admin_Comedor', Base.metadata,
    Column('idComedor', ForeignKey('Comedor.id'), primary_key=True, nullable = False),
    Column('idAdministrador', ForeignKey('Usuario.id'), primary_key=True, nullable = False)
    )

class Comedor(Base):
    __tablename__ = "Comedor"

    id = Column(Integer, primary_key = True, index = True, autoincrement = True, nullable = False)
    ajustes = Column(JSON, nullable = False)
    administradores = relationship("Usuario", secondary = admin_comedor)

class Menu(Base):
    __tablename__ = "Menu"

    id = Column(Integer, primary_key = True, index = True, autoincrement = True, nullable = False)
    nombre = Column(Integer, index = True, nullable = False)
    platos = Column(JSON, nullable = False)
    bebidas = Column(JSON, nullable = False)
    idComedor = Column(Integer, ForeignKey("Comedor.id"), primary_key = True, nullable = False)

class Usuario(Base):
    __tablename__ = "Usuario"

    id = Column(Integer, primary_key = True, index = True, autoincrement = True, nullable = False)
    nombre = Column(String, nullable = False)
    apellidos = Column(String, nullable = False)
    correo = Column(String, nullable = False)
    contraseña = Column(String, nullable = False)
    is_Admin = Column(Integer, nullable = False)
    comedores = relationship("Comedor", secondary = admin_comedor)

class Mesa(Base):
    __tablename__ = "Mesa"

    id = Column(Integer, primary_key = True, index = True, autoincrement = True, nullable = False)
    asientos = Column(Integer, nullable = False)
    idComedor = Column(Integer, ForeignKey("Comedor.id"), primary_key = True, nullable = False)

class Reserva(Base):
    __tablename__ = "Reserva"

    id = Column(Integer, primary_key = True, index = True, autoincrement = True, nullable = False)
    mesa = Column(Integer, primary_key = True, index = True, nullable = False)
    usuario = Column(Integer, primary_key = True, index = True, nullable = False)
    fecha = Column(DateTime, primary_key = True, index = True, nullable = False)