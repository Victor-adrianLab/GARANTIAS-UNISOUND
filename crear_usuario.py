from app import app, db, Usuario, bcrypt

with app.app_context():
    # Crear una contraseña segura para el nuevo usuario
    hashed_password = bcrypt.generate_password_hash("contraseña123").decode('utf-8')

    # Crear un nuevo usuario administrador
    nuevo_usuario = Usuario(username="admin", password=hashed_password, role="admin")

    # Añadir el nuevo usuario a la base de datos
    db.session.add(nuevo_usuario)
    db.session.commit()

    print("Usuario administrador creado con éxito.")
