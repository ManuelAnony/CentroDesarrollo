from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from config import *
import re 

app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key'

# Instancia de conexión a la base de datos
con_bd = Conexion()

# Ruta para el inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        # Validar el formato del correo electrónico utilizando una expresión regular
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Por favor, ingresa una dirección de correo electrónico válida.', 'danger')
            return redirect(url_for('login'))

        usuario = con_bd.usuarios.find_one({"email": email})
        
        if usuario and check_password_hash(usuario["password"], password):
            session['email'] = usuario['email']
            if usuario.get("rol") == "Administrador":
                 flash('Inicio de sesión exitoso como administrador', 'success')
                 return redirect(url_for('index'))
            elif usuario.get("rol") == "Desarrollador":
                flash('Inicio de sesión exitoso como usuario', 'success')
                return redirect(url_for('proyecto'))
            elif usuario.get("rol") == "Empresa":
                flash('Inicio de sesión exitoso como usuario', 'success')
                return redirect(url_for('dashcompany'))
        else:   
            flash('Credenciales inválidas. Por favor, verifica tu email y contraseña.', 'danger')

    return render_template('login.html')

# Función para validar la complejidad de la contraseña
def validar_contraseña(password):
    # Al menos 8 caracteres
    if len(password) < 8:
        return False
    # Al menos un número
    if not re.search(r"\d", password):
        return False
    # Al menos una letra minúscula
    if not re.search(r"[a-z]", password):
        return False
    # Al menos una letra mayúscula
    if not re.search(r"[A-Z]", password):
        return False
    # Al menos un carácter especial
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

@app.route('/registroEmpresa', methods=['GET', 'POST'])
def registroEmpresa():
    if request.method == 'POST':
        nombreEmpresa = request.form.get("nombreEmpresa")
        nit = request.form.get("nit")
        administrador = request.form.get("administrador")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmar_password = request.form.get("confirmar_password")
        admin = "Empresa"

        # Validar formato de correo electrónico
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("El correo electrónico no es válido.")
            return redirect(url_for('registroEmpresa'))

        # Verificar si las contraseñas coinciden
        if password != confirmar_password:
            flash("Las contraseñas no coinciden.")
            return redirect(url_for('registroEmpresa'))

        # Validar complejidad de la contraseña
        if not validar_contraseña(password):
            flash("La contraseña debe contener al menos 8 caracteres, un número, una letra minúscula, una letra mayúscula y un carácter especial.")
            return redirect(url_for('registroEmpresa'))

        existe_usuario = con_bd.usuarios.find_one({"email": email})

        if existe_usuario:
            flash("El usuario ya existe. Por favor, inicia sesión o utiliza otro correo electrónico.")
            return redirect(url_for('registroEmpresa'))
        else:
            hashed_password = generate_password_hash(password)
            nuevo_usuario = {
                "nombreEmpresa": nombreEmpresa,
                "nit": nit,
                "administrador": administrador,
                "email": email,
                "password": hashed_password,
                "rol": admin
            }
            con_bd.usuarios.insert_one(nuevo_usuario)
            return redirect(url_for('dashcompany'))

    return render_template('registro.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form.get("email")        
        password = request.form.get("password")
        admin = "Desarrollador"

        existe_usuario = con_bd.usuarios.find_one({"email": email})
        
        if existe_usuario:
            return "El usuario ya existe. Por favor, inicia sesión o utiliza otro correo electrónico."
        else:
            # Utiliza generate_password_hash para cifrar la contraseña antes de almacenarla
            hashed_password = generate_password_hash(password, method='sha256')
            
            nuevo_usuario = {
                "email": email,
                "password": hashed_password,  # Almacena la contraseña cifrada
                "rol": admin
            }
            con_bd.usuarios.insert_one(nuevo_usuario) 
            return redirect(url_for('index'))  

    return render_template('registroequipo.html')

def obtener_datos_empresa(email):
    try:
        empresa = con_bd.usuarios.find_one({"email": email, "rol": "Empresa"},
                                           {"_id": 0, "nombreEmpresa": 1, "nit": 1, "administrador": 1, "email": 1, "rol": 1})
        return empresa
    except Exception as e:
        print(f"Error al obtener datos de la empresa: {e}")
        return None


@app.route('/dashcompany')
def dashcompany():
    if 'email' not in session or con_bd.usuarios.find_one({"email": session['email'], "rol": "Empresa"}) is None:
        return redirect(url_for('login'))

    email_empresa = session['email']

    # Obtén los datos de la empresa desde la base de datos
    empresa = obtener_datos_empresa(email_empresa)

    if empresa:
        # Puedes acceder directamente a los campos de la empresa
        nombre_empresa = empresa.get("nombreEmpresa", "")
        nit = empresa.get("nit", "")
        administrador = empresa.get("administrador", "")
        email_empresa = empresa.get("email", "")
        rol = empresa.get("rol", "")

        # Obtén las solicitudes más recientes de la base de datos
        solicitudes = obtener_solicitudes(email_empresa)

        return render_template('dashcompany.html', nombre_empresa=nombre_empresa, nit=nit, administrador=administrador, email_empresa=email_empresa, rol=rol, solicitudes=solicitudes)
    else:
        return "Error al obtener los datos de la empresa"


@app.route('/enviar_solicitud', methods=['POST'])
def enviar_solicitud():
    try:
        if 'email' not in session or con_bd.usuarios.find_one({"email": session['email'], "rol": "Empresa"}) is None:
            return redirect(url_for('login'))

        if request.method == 'POST':
           # Obtener los datos del formulario
            nombre_solicitud = request.form.get("nombreSolicitud")
            descripcion_solicitud = request.form.get("descripcionSolicitud")
            fecha_solicitud = request.form.get("fechaSolicitud")

            # Crear un objeto de solicitud para guardar en la base de datos
            nueva_solicitud = {
                "nombre_solicitud": nombre_solicitud,
                "descripcion_solicitud": descripcion_solicitud,
                "fecha": fecha_solicitud,
                "porcentaje_solicitud": 0,
                "email_empresa": session['email']  # Añadir el email de la empresa
            }

            # Guardar la solicitud en la base de datos
            con_bd.solicitudes.insert_one(nueva_solicitud)

            flash('Solicitud enviada con éxito', 'success')

            # Puedes redirigir a donde quieras después de enviar la solicitud
            return redirect(url_for('dashcompany'))

        # Manejar casos en los que la solicitud no es POST
        flash('Error al enviar la solicitud', 'danger')
        return redirect(url_for('dashcompany'))
    except Exception as e:
        # Maneja cualquier error que pueda ocurrir
        print(f"Error al procesar la solicitud: {e}")
        flash('Error al enviar la solicitud', 'danger')
        return redirect(url_for('dashcompany'))

def obtener_solicitudes(email_empresa):
    try:
        # Obtén las solicitudes para la empresa específica desde la base de datos
        solicitudes = con_bd.solicitudes.find({"email_empresa": email_empresa})
        return list(solicitudes)
    except Exception as e:
        print(f"Error al obtener las solicitudes: {e}")
        return []



@app.route('/empresas')
def ver_empresas():
    if 'email' not in session:
        return redirect(url_for('login'))

    email_empresa = session['email']

    # Obtén los datos de la empresa desde la base de datos
    empresa = obtener_datos_empresa(email_empresa)

    if empresa:
        # Puedes acceder directamente a los campos de la empresa
        nombre_empresa = empresa.get("nombreEmpresa", "")
        nit = empresa.get("nit", "")
        administrador = empresa.get("administrador", "")
        email_empresa = empresa.get("email", "")

        return render_template('dashboard.html', nombre_empresa=nombre_empresa, nit=nit, administrador=administrador, email_empresa=email_empresa)
    else:
        return "Error al obtener los datos de la empresa"


def obtener_solicitudes_empresa(email_empresa):
    try:
        # Obtén las solicitudes para la empresa específica desde la base de datos
        solicitudes = con_bd.solicitudes.find({"email_empresa": email_empresa})
        return list(solicitudes)
    except Exception as e:
        print(f"Error al obtener las solicitudes: {e}")
        return []

@app.route('/solicitudes')
def ver_solicitudes():
    if 'email' not in session:
        return redirect(url_for('login'))

    email_empresa = session['email']

    # Obtén las solicitudes de la empresa desde la base de datos
    solicitudes = obtener_solicitudes_empresa(email_empresa)

    return render_template('dashboard.html', solicitudes=solicitudes, nombre_empresa=nombre_empresa, nit=nit, administrador=administrador, email_empresa=email_empresa)





# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    # Eliminar la sesión
    session.pop('email', None)
    flash('Sesión cerrada', 'info')
    return redirect(url_for('login'))

# Ruta para la página de inicio (requiere inicio de sesión)
@app.route('/')
def index():
    
    if 'email' not in session:
        return redirect(url_for('login'))
    
    # Obtener proyectos en curso desde la base de datos
    proyectos = con_bd.proyectos.find()
    return render_template('index.html', proyectos=proyectos)
@app.route('/registrar_proyecto', methods=['POST'])
def registrar_proyecto():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Obtén los datos del formulario
        nombre_proyecto = request.form.get("nombre_proyecto")
        descripcion = request.form.get("descripcion")
        fecha_inicio = request.form.get("fecha_inicio")
        fecha_finalizacion = request.form.get("fecha_finalizacion")
        estado = request.form.get("estado")

        # Implementa la lógica para registrar un nuevo proyecto en la base de datos
        nuevo_proyecto = {
            "nombre": nombre_proyecto,
            "descripcion": descripcion,
            "fecha_inicio": fecha_inicio,
            "fecha_finalizacion": fecha_finalizacion,
            "estado": estado,
            "equipo": []  # Inicialmente sin equipo asignado
        }
        con_bd.proyectos.insert_one(nuevo_proyecto)

        flash('Proyecto registrado con éxito', 'success')
        return redirect(url_for('index'))
@app.route('/crear_actividad', methods=['POST'])
def crear_actividad():
    if request.method == 'POST':
        # Procesa la información del formulario para crear una nueva actividad
        admin_email = request.form.get("admin_email")
        nombre_actividad = request.form.get("nombre_actividad")
        fecha_vencimiento = request.form.get("fecha_vencimiento")
        proyecto_id = ObjectId(request.form.get("proyecto_id"))

        # Aquí debes guardar la información en la base de datos, por ejemplo, en la colección de actividades
        nueva_actividad = {
            "admin_email": admin_email,
            "nombre": nombre_actividad,
            "fecha_vencimiento": fecha_vencimiento,
            "proyecto_id": proyecto_id
        }
        con_bd.actividades.insert_one(nueva_actividad)

        flash('Actividad creada con éxito', 'success')
        return redirect(url_for('proyecto'))
    
@app.route('/editar_estado/<proyecto_id>', methods=['GET', 'POST'])
def editar_estado(proyecto_id):
    if request.method == 'POST':
        nuevo_estado = request.form.get("nuevo_estado")

        # Actualiza el estado del proyecto en la base de datos
        proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
        proyecto["estado"] = nuevo_estado
        con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": proyecto})

        flash('Estado del proyecto actualizado', 'success')
        return redirect(url_for('proyecto'))

    # Obtén el proyecto que se va a editar y pasa su estado actual al formulario
    proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
    estado_actual = proyecto.get("estado")

    return render_template('editar_estado.html', proyecto_id=proyecto_id, estado_actual=estado_actual)

@app.route('/eliminar_proyecto/<proyecto_id>')
def eliminar_proyecto(proyecto_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    
    # Agrega la lógica para eliminar el proyecto en función de su ID
    proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})

    if proyecto:
        con_bd.proyectos.delete_one({"_id": ObjectId(proyecto_id)})
        flash('Proyecto eliminado con éxito', 'success')
    else:
        flash('Proyecto no encontrado', 'danger')
    
    return redirect(url_for('index'))
    
@app.route('/proyecto')
def proyecto():
    if 'email' not in session:
        return redirect(url_for('login'))

    # Consulta para obtener los proyectos asignados al administrador
    proyectos_cursor = con_bd.proyectos.find({"miembros_equipo": session['email']})
    proyectos = list(proyectos_cursor)

    # Consulta para obtener las actividades relacionadas con cada proyecto
    actividades_por_proyecto = {}  # Un diccionario para almacenar actividades por proyecto

    for proyecto in proyectos:
        actividades_cursor = con_bd.actividades.find({"proyecto_id": proyecto['_id']})
        actividades = list(actividades_cursor)
        actividades_por_proyecto[proyecto['_id']] = actividades

    return render_template('proyecto.html', proyectos=proyectos, actividades_por_proyecto=actividades_por_proyecto)


@app.route('/asignar_equipo/<proyecto_id>', methods=['GET', 'POST'])
def asignar_equipo(proyecto_id):
    if request.method == 'POST':
        # Aquí puedes procesar la información del formulario para asignar el equipo al proyecto.
        # Recuerda que necesitarás usar la variable "proyecto_id" para identificar el proyecto.

        # Por ejemplo, puedes acceder a los datos del formulario de esta manera:
        nombre_equipo = request.form.get("nombre_equipo")
        miembros = request.form.getlist("miembros")  # Si tienes una lista de miembros

        # Luego, puedes realizar las operaciones necesarias, como almacenar los datos en la base de datos.

        # Una vez que hayas realizado las operaciones, podrías redirigir a otra página o mostrar un mensaje de éxito.
        flash('Equipo asignado con éxito', 'success')
        return redirect(url_for('proyectos'))

    # Si el método de solicitud es GET, puedes mostrar el formulario para asignar el equipo
    # y permitir al usuario seleccionar miembros y proporcionar detalles.

    # Debes asegurarte de que "proyecto_id" se pase a la plantilla para que lo uses en el formulario si es necesario.
    return render_template('formulario_asignar_equipo.html', proyecto_id=proyecto_id)

@app.route('/notificar_equipo/<proyecto_id>', methods=['GET', 'POST'])
def notificar_equipo(proyecto_id):
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Obtén los datos del formulario
        equipo_id = request.form.get('equipo_id')
        mensaje = request.form.get('mensaje')

        # Realiza la lógica para notificar al equipo, por ejemplo, enviar correos o notificaciones

        flash(f'Notificación enviada al equipo {equipo_id} del proyecto {proyecto_id}', 'success')

    # Puedes obtener más información sobre el proyecto, como el equipo asignado, a través de la base de datos aquí
    # proyecto = con_bd.proyectos.find_one({"_id": proyecto_id})
    # equipo = con_bd.equipos.find({"proyecto_id": proyecto_id})

    return render_template('notificar_equipo.html', proyecto_id=proyecto_id)

if __name__ == '__main__':
    app.run(debug=True)
