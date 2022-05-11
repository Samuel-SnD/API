from datetime import datetime
from sqlalchemy.orm import Session
from . import models, schemas

def get_admin (db : Session, admin_id : int) :
    return db.query(models.Administrador).filter(models.Administrador.id == admin_id).first()

def get_admin_by_email (db : Session, email : str) :
    return db.query(models.Administrador).filter(models.Administrador.correo == email).first()

def get_admins (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Administrador).offset(skip).limit(limit).all()

def create_admin(db: Session, admin : schemas.AdministradorCreate):
    db_admin = models.Administrador(correo = admin.correo, nombre = admin.nombre, apellidos = admin.apellidos, contraseña = admin.contraseña)
    db.add(db_admin)
    db.commit()
    db.refresh(db_admin)
    return db_admin

def get_user (db : Session, user_id : int) :
    return db.query(models.Usuario).filter(models.Usuario.id == user_id).first()

def get_user_by_email (db : Session, email : str) :
    return db.query(models.Usuario).filter(models.Usuario.correo == email).first()

def get_users (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Usuario).offset(skip).limit(limit).all()

def create_user(db: Session, user : schemas.UsuarioCreate):
    db_user = models.Usuario(correo = user.correo, nombre = user.nombre, apellidos = user.apellidos, contraseña = user.contraseña)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_comedor (db : Session, comedor_id : int) :
    return db.query(models.Comedor).filter(models.Comedor.id == comedor_id).first()

def get_comedores (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Comedor).offset(skip).limit(limit).all()

def create_comedor(db: Session, comedor : schemas.ComedorCreate):
    db_comedor = models.Comedor(ajustes = comedor.ajustes)
    db.add(db_comedor)
    db.commit()
    db.refresh(db_comedor)
    return db_comedor

def get_menu (db : Session, menu_id : int) :
    return db.query(models.Menu).filter(models.Menu.id == menu_id).first()

def get_menu_by_idComedor (db : Session, id_comedor : int) :
    return db.query(models.Menu).filter(models.Menu.idComedor == id_comedor).first()

def get_menus (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Menu).offset(skip).limit(limit).all()

def create_menu(db: Session, menu : schemas.MenuCreate):
    db_menu = models.Menu(nombre = menu.nombre, platos = menu.platos, bebidas = menu.bebidas, idComedor = menu.idComedor)
    db.add(db_menu)
    db.commit()
    db.refresh(db_menu)
    return db_menu

def get_mesa (db : Session, mesa_id : int) :
    return db.query(models.Mesa).filter(models.Mesa.id == mesa_id).first()

def get_mesa_by_idComedor (db : Session, id_comedor : int) :
    return db.query(models.Mesa).filter(models.Mesa.idComedor == id_comedor).first()

def get_mesas (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Mesa).offset(skip).limit(limit).all()

def create_mesa(db: Session, mesa : schemas.MesaCreate):
    db_mesa = models.Mesa(asientos = mesa.asientos, idComedor = mesa.idComedor)
    db.add(db_mesa)
    db.commit()
    db.refresh(db_mesa)
    return db_mesa

def get_reserva (db : Session, reserva_id : int) :
    return db.query(models.Reserva).filter(models.Reserva.id == reserva_id).first()

def get_reserva_by_fecha (db : Session, reserva_fecha : datetime) :
    return db.query(models.Reserva).filter(models.Reserva.fecha == reserva_fecha).all()

def get_reserva_by_user (db : Session, user : int) :
    return db.query(models.Reserva).filter(models.Reserva.usuario == user).all()

def get_reserva_by_mesa (db : Session, mesa : int) :
    return db.query(models.Reserva).filter(models.Reserva.mesa == mesa).all()

def get_reservas (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Reserva).offset(skip).limit(limit).all()

def create_reserva(db: Session, reserva : schemas.ReservaCreate):
    db_reserva = models.Reserva(mesa = reserva.mesa, usuario = reserva.usuario, fecha = reserva.fecha)
    db.add(db_reserva)
    db.commit()
    db.refresh(db_reserva)
    return db_reserva