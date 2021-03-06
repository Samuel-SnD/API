from datetime import datetime
from sqlalchemy.orm import Session
from . import models, schemas

#Usuarios && Admin

def get_user (db : Session, user_id : int) :
    return db.query(models.Usuario).filter(models.Usuario.id == user_id).first()

def get_user_by_email (db : Session, email : str) :
    return db.query(models.Usuario).filter(models.Usuario.correo == email).first()

def get_users (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Usuario).offset(skip).limit(limit).all()

def get_admins (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Usuario).filter(models.Usuario.is_Admin == 1).all()

def make_admin (db : Session, email : str) :
    user : models.Usuario = db.query(models.Usuario).filter(models.Usuario.correo == email).first()
    if user is None : return False
    user.is_Admin = 1
    db.commit()
    return True

def delete_user (db : Session, user : int) :
    db.delete(get_user(db, user))
    db.commit()

def create_user(db: Session, user : schemas.UsuarioCreate):
    db_user = models.Usuario(correo = user.correo, nombre = user.nombre, apellidos = user.apellidos, contraseña = user.contraseña)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

#Comedores

def get_comedor (db : Session, comedor_id : int) :
    return db.query(models.Comedor).filter(models.Comedor.id == comedor_id).first()

def get_comedores (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Comedor).offset(skip).limit(limit).all()

def delete_comedor (db : Session, comedor : int) :
    db.delete(get_comedor(db, comedor))
    db.commit()

def create_comedor(db: Session, comedor : schemas.ComedorCreate):
    db_comedor = models.Comedor(ajustes = comedor.ajustes)
    db.add(db_comedor)
    db.commit()
    db.refresh(db_comedor)
    return db_comedor

def update_comedor (db : Session, id : int, ajustes : schemas.ComedorCreate) :
    comedor : models.Comedor = db.query(models.Comedor).filter(models.Comedor.id == id).first()
    if comedor is None : return False
    comedor.ajustes = ajustes.ajustes
    db.commit()
    return True

#Menus

def get_menu (db : Session, menu_id : int) :
    return db.query(models.Menu).filter(models.Menu.id == menu_id).first()

def get_menu_by_name (db : Session, menu_name : int) :
    return db.query(models.Menu).filter(models.Menu.nombre == menu_name).first()

def get_menu_by_idComedor (db : Session, id_comedor : int) :
    return db.query(models.Menu).filter(models.Menu.idComedor == id_comedor).all()

def get_menus (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Menu).offset(skip).limit(limit).all()

def delete_menu (db : Session, menu : int) :
    db.delete(get_menu(db, menu))
    db.commit()

def create_menu(db: Session, menu : schemas.MenuCreate):
    db_menu = models.Menu(nombre = menu.nombre, platos = menu.platos, bebidas = menu.bebidas, idComedor = menu.idComedor)
    db.add(db_menu)
    db.commit()
    db.refresh(db_menu)
    return db_menu

def update_menu (db : Session, id : int, menu : schemas.MenuCreate) :
    mn : models.Menu = db.query(models.Menu).filter(models.Menu.id == id).first()
    if mn is None : return False
    mn.nombre = menu.nombre
    mn.bebidas = menu.bebidas
    mn.platos = menu.platos
    db.commit()
    return True

#Mesas

def get_mesa (db : Session, mesa_id : int) :
    return db.query(models.Mesa).filter(models.Mesa.id == mesa_id).first()

def get_mesa_by_idComedor (db : Session, id_comedor : int) :
    return db.query(models.Mesa).filter(models.Mesa.idComedor == id_comedor).all()

def get_mesas (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Mesa).offset(skip).limit(limit).all()

def delete_mesa (db : Session, mesa : int) :
    db.delete(get_mesa(db, mesa))
    db.commit()

def create_mesa(db: Session, mesa : schemas.MesaCreate):
    db_mesa = models.Mesa(asientos = mesa.asientos, idComedor = mesa.idComedor)
    db.add(db_mesa)
    db.commit()
    db.refresh(db_mesa)
    return db_mesa

def update_mesa (db : Session, id : int, mesa : schemas.MesaCreate) :
    ms : models.Mesa = db.query(models.Mesa).filter(models.Mesa.id == id).first()
    if ms is None : return False
    ms.asientos = mesa.asientos
    db.commit()
    return True

#Reservas

def get_reserva (db : Session, reserva_id : int) :
    return db.query(models.Reserva).filter(models.Reserva.id == reserva_id).first()

def get_reserva_by_fecha (db : Session, reserva_fecha : datetime) :
    return db.query(models.Reserva).filter(models.Reserva.fecha == reserva_fecha).all()

def get_reserva_dup (db : Session, reserva_mesa : int, reserva_fecha : datetime, reserva_hora : str) :
    return True if db.query(models.Reserva).filter(models.Reserva.fecha == reserva_fecha, models.Reserva.hora == reserva_hora, models.Reserva.mesa == reserva_mesa).first() else False

def get_reserva_by_user (db : Session, user : int) :
    return db.query(models.Reserva).filter(models.Reserva.usuario == user).all()

def get_reserva_by_mesa (db : Session, mesa : int) :
    return db.query(models.Reserva).filter(models.Reserva.mesa == mesa).all()

def get_reservas (db : Session, skip : int = 0, limit : int = 100) :
    return db.query(models.Reserva).offset(skip).limit(limit).all()

def delete_reserva (db : Session, reserva : int) :
    db.delete(get_reserva(db, reserva))
    db.commit()

def create_reserva(db: Session, reserva : schemas.ReservaCreate, usuario : schemas.Usuario):
    db_reserva = models.Reserva(mesa = reserva.mesa, usuario = usuario.id, fecha = reserva.fecha, hora = reserva.hora)
    db.add(db_reserva)
    db.commit()
    db.refresh(db_reserva)
    return db_reserva