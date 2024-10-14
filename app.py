# Sistema de Control y Rastreo de Garantías con Interfaz de Usuario

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import uuid
import qrcode
import os

# Inicializamos la aplicación Flask
app = Flask(__name__)
app.secret_key = 'mi_llave_secreta'

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///garantias.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializamos SQLAlchemy y otras librerías necesarias
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Roles: admin, usuario_sucursal

# Modelo de Garantía
class Garantia(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    nombre_producto = db.Column(db.String(100), nullable=False)
    proveedor = db.Column(db.String(100), nullable=False)
    cliente = db.Column(db.String(100), nullable=False)
    defecto_reportado = db.Column(db.String(200), nullable=False)
    tamanio_caja = db.Column(db.String(50), nullable=True)
    sucursal_origen = db.Column(db.String(100), nullable=False)
    sucursal_actual = db.Column(db.String(100), nullable=False)
    fecha_envio = db.Column(db.DateTime, default=datetime.utcnow)
    transportista = db.Column(db.String(100), nullable=True)
    observaciones = db.Column(db.String(200), nullable=True)
    estado = db.Column(db.String(50), default="Recibido en sucursal")
    responsable = db.Column(db.String(100), nullable=True)

# Modelo para el Historial de Estados
class HistorialEstado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    garantia_id = db.Column(db.String(36), db.ForeignKey('garantia.id'), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    estado_anterior = db.Column(db.String(50))
    nuevo_estado = db.Column(db.String(50))
    usuario = db.Column(db.String(100), nullable=False)
    comentario = db.Column(db.String(200), nullable=True)
    sucursal = db.Column(db.String(100), nullable=True)

# Cargar usuario para login_manager
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Ruta para la página principal con filtros
@app.route('/')
@login_required
def index():
    sucursal = request.args.get('sucursal')
    proveedor = request.args.get('proveedor')
    dias_transcurridos = request.args.get('dias_transcurridos')
    estado = request.args.get('estado')

    query = Garantia.query

    if sucursal:
        query = query.filter(Garantia.sucursal_actual == sucursal)
    if proveedor:
        query = query.filter(Garantia.proveedor == proveedor)
    if dias_transcurridos:
        try:
            dias_transcurridos = int(dias_transcurridos)
            fecha_limite = datetime.utcnow() - timedelta(days=dias_transcurridos)
            query = query.filter(Garantia.fecha_envio <= fecha_limite)
        except ValueError:
            flash('El valor para días transcurridos debe ser un número entero.', 'warning')
    if estado:
        query = query.filter(Garantia.estado == estado)

    garantias = query.all()

    for garantia in garantias:
        garantia.dias_transcurridos = (datetime.utcnow() - garantia.fecha_envio).days
        garantia.alerta = garantia.dias_transcurridos >= 25

    sucursales = ["Ocosingo", "San Cristóbal", "Yajalón", "Palenque", "Innotec"]
    estados = [
        "Recibido en sucursal",
        "Enviado al proveedor",
        "En tránsito",
        "Recibido por el proveedor",
        "En proceso de reparación",
        "Producto listo para devolución",
        "De vuelta a sucursal",
        "Producto entregado al cliente"
    ]
    return render_template('index.html', garantias=garantias, sucursales=sucursales, estados=estados, datetime=datetime)

# Ruta para iniciar sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Usuario.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            error = "Nombre de usuario o contraseña incorrectos"
    return render_template('login.html', error=error)

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ruta para registrar una nueva garantía (formulario)
@app.route('/nueva', methods=['GET', 'POST'])
@login_required
def nueva_garantia():
    if request.method == 'POST':
        data = request.form
        nueva_garantia = Garantia(
            id=str(uuid.uuid4()),
            nombre_producto=data['nombre_producto'],
            proveedor=data['proveedor'],
            cliente=data['cliente'],
            defecto_reportado=data['defecto_reportado'],
            tamanio_caja=data.get('tamanio_caja', None),
            sucursal_origen=data['sucursal_origen'],
            sucursal_actual=data['sucursal_actual'],
            transportista=data.get('transportista', None),
            observaciones=data.get('observaciones', None),
            responsable=data.get('responsable', None)
        )
        db.session.add(nueva_garantia)
        db.session.commit()

        qr = qrcode.make(f'http://127.0.0.1:5001/garantias/{nueva_garantia.id}')
        qr_path = os.path.join('static', f'{nueva_garantia.id}.png')
        qr.save(qr_path)
        return redirect(url_for('index'))
    sucursales = ["Ocosingo", "San Cristóbal", "Yajalón", "Palenque", "Innotec"]
    usuarios = Usuario.query.filter_by(role='usuario_sucursal').all()
    return render_template('nueva_garantia.html', sucursales=sucursales, usuarios=usuarios)

# Ruta para obtener el estado de una garantía
@app.route('/garantias/<string:id>', methods=['GET'])
@login_required
def obtener_garantia(id):
    garantia = Garantia.query.get(id)
    if not garantia:
        return jsonify({'mensaje': 'Garantía no encontrada'}), 404
    historial = HistorialEstado.query.filter_by(garantia_id=id).all()
    return render_template('detalle_garantia.html', garantia=garantia, historial=historial, datetime=datetime)

# Ruta para actualizar el estado de una garantía (formulario)
@app.route('/garantias/<string:id>/actualizar', methods=['GET', 'POST'])
@login_required
def actualizar_estado_garantia(id):
    garantia = Garantia.query.get(id)
    if not garantia:
        return jsonify({'mensaje': 'Garantía no encontrada'}), 404

    if request.method == 'POST':
        data = request.form
        estado_anterior = garantia.estado
        garantia.estado = data['estado']
        garantia.sucursal_actual = data.get('sucursal_actual', garantia.sucursal_actual)
        garantia.responsable = data.get('responsable', garantia.responsable)
        db.session.commit()

        nuevo_historial = HistorialEstado(
            garantia_id=id,
            estado_anterior=estado_anterior,
            nuevo_estado=garantia.estado,
            usuario=current_user.username,
            comentario=data.get('comentario', None),
            sucursal=garantia.sucursal_actual
        )
        db.session.add(nuevo_historial)
        db.session.commit()

        return redirect(url_for('index'))
    sucursales = ["Ocosingo", "San Cristóbal", "Yajalón", "Palenque", "Innotec"]
    usuarios = Usuario.query.filter_by(role='usuario_sucursal').all()
    estados = [
        "Recibido en sucursal",
        "Enviado al proveedor",
        "En tránsito",
        "Recibido por el proveedor",
        "En proceso de reparación",
        "Producto listo para devolución",
        "De vuelta a sucursal",
        "Producto entregado al cliente"
    ]
    return render_template('actualizar_garantia.html', garantia=garantia, sucursales=sucursales, usuarios=usuarios, estados=estados)

# Ruta para el dashboard de usuarios
@app.route('/dashboard_usuarios', methods=['GET', 'POST'])
@login_required
def dashboard_usuarios():
    if current_user.role != 'admin':
        flash('No tienes permiso para acceder a esta página.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        nuevo_usuario = Usuario(username=username, password=password, role=role)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Usuario creado con éxito', 'success')
        return redirect(url_for('dashboard_usuarios'))

    usuarios = Usuario.query.all()
    return render_template('dashboard_usuarios.html', usuarios=usuarios)

# Ruta para eliminar un usuario
@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    if current_user.role != 'admin':
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return redirect(url_for('index'))

    usuario = Usuario.query.get(id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario eliminado con éxito', 'success')
    else:
        flash('Usuario no encontrado', 'warning')
    return redirect(url_for('dashboard_usuarios'))

# Inicializar la base de datos
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Ejecutar la aplicación Flask
    app.run(debug=True, host='0.0.0.0', port=5001)
