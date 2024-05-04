from flask import Flask, render_template, request, redirect, url_for, flash, session, after_this_request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from config import *
import os
import re 
import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def crear_app():       
        app = Flask(__name__, static_folder='static')
        app.secret_key = os.getenv('mykey')
        # Instancia de conexión a la base de datos
        con_bd = Conexion()
        # Esta función generará un código de verificación de 6 dígitos
        def generate_verification_code():
            return ''.join(str(random.randint(0, 9)) for _ in range(6))
        # Esta función enviará el correo electrónico con el código de verificación
        def send_verification_email(to_email, verification_code):
            # Configuración del servidor SMTP
            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "cddta3211@gmail.com"
            sender_password = "ypix xxef wbmi zqxl"  # Asegúrate de que esta sea la clave de la aplicación correcta

            # Crear el mensaje
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = to_email
            msg['Subject'] = "Código de verificación"

            # Cuerpo del mensaje
            body = f"Tu código de verificación es: {verification_code}"
            msg.attach(MIMEText(body, 'plain'))

            # Conexión al servidor SMTP
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)

            # Envío del mensaje
            server.send_message(msg)

            # Cerrar la conexión
            server.quit()
        @app.route('/enviar_codigo_verificacion', methods=['POST'])
        def enviar_codigo_verificacion():
            # Aquí generas el código de verificación
            verification_code = generate_verification_code()
            
            # Aquí obtienes el correo electrónico del usuario desde el formulario
            to_email = request.form.get('email')

            # Guarda el código de verificación en la sesión
            session['verification_code'] = verification_code

            # Aquí envías el correo electrónico con el código de verificación
            send_verification_email(to_email, verification_code)

            # Redirige al usuario a la página de verificación
            return redirect(url_for('verificacionEmpresa'))
        @app.route('/validar_codigo_verificacion', methods=['POST'])
        def validar_codigo_verificacion():
            if request.method == 'POST':
                entered_code = request.form.get('verification_code')
                verification_code = session.get('verification_code')

                if entered_code == verification_code:
                    flash('Registro completado exitosamente', 'success')
                    session.pop('verification_code', None)
                    return redirect(url_for('login'))
                else:
                    flash('Código de verificación incorrecto', 'danger')

            return render_template('verificacion.html')
        @app.route('/eliminar_usuario/<usuario_id>')
        def eliminar_usuario(usuario_id):
            if 'email' not in session:
                return redirect(url_for('login'))
            
            # Agrega la lógica para eliminar el proyecto en función de su ID
            usuario = con_bd.usuarios.find_one({"_id": ObjectId(usuario_id)})

            if usuario:
                con_bd.usuarios.delete_one({"_id": ObjectId(usuario_id)})
                flash('usuario eliminado con éxito', 'success')
            else:
                flash('Usuario no encontrado', 'danger')
            
            return redirect(url_for('index'))
        @app.route('/eliminar_solicitud/<solicitud_id>')
        def eliminar_solicitud(solicitud_id):
            if 'email' not in session:
                return redirect(url_for('login'))
            
            # Agrega la lógica para eliminar el proyecto en función de su ID
            solicitud = con_bd.solicitudes.find_one({"_id": ObjectId(solicitud_id)})

            if solicitud:
                con_bd.solicitudes.delete_one({"_id": ObjectId(solicitud_id)})
                flash('Solicitud eliminado con éxito', 'success')
            else:
                flash('Solicitud no encontrado', 'danger')
            
            return redirect(url_for('index'))
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
        # Ruta para el inicio de sesión
        @app.route('/login', methods=['GET', 'POST'])
        def login():
            # Verificar si el usuario ya ha iniciado sesión
            if 'email' in session:
                # Si el usuario ya ha iniciado sesión, redirigir a su página correspondiente según su rol
                return redirect(get_redirect_url())

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
                    flash('Inicio de sesión exitoso', 'success')
                    return redirect(get_redirect_url())

                flash('Correo electrónico o contraseña incorrectos. Por favor, verifica tus credenciales.', 'danger')

            return render_template('login.html')

        def get_redirect_url():
            """
            Obtiene la URL de redirección adecuada según el rol del usuario.
            """
            if 'next' in request.args:
                return request.args.get('next')
            else:
                if 'email' not in session:
                    return url_for('login')
                usuario = con_bd.usuarios.find_one({"email": session['email']})
                if usuario:
                    if usuario.get("rol") == "Empresa" and usuario.get("verificado"):
                        return url_for('dashcompany')
                    elif usuario.get("rol") == "Desarrollador":
                        return url_for('proyecto')
                    elif usuario.get("rol") == "Administrador":
                        return url_for('index')
            return url_for('login')
        @app.after_request
        def add_header(response):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
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
        # Página de registro de empresa
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

                # Verificar si el correo electrónico ya está en uso
                if con_bd.usuarios.find_one({"email": email}):
                    flash("El correo electrónico ya está en uso.")
                    return redirect(url_for('registroEmpresa'))

                # Generar código de verificación y enviar correo electrónico
                verification_code = generate_verification_code()
                session['verification_code'] = verification_code
                send_verification_email(email, verification_code)

                # Guardar los datos del usuario en la base de datos
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

                flash("Se ha enviado un correo electrónico con el código de verificación. Por favor, ingrésalo para completar el registro.", "success")
                return redirect(url_for('verificacionEmpresa'))

            return render_template('registro.html')
        # Página de verificación de registro de empresa
        @app.route('/verificacionEmpresa', methods=['GET', 'POST'])
        def verificacionEmpresa():
            if request.method == 'POST':
                entered_code = request.form.get('verification_code')
                verification_code = session.get('verification_code')

                if entered_code == verification_code:
                    flash('Registro completado exitosamente', 'success')
                    session.pop('verification_code', None)
                    return redirect(url_for('login'))
                else:
                    flash('Código de verificación incorrecto', 'danger')

            return render_template('verificacion.html')
        @app.route('/registroEquipo', methods=['GET', 'POST'])
        def registroEquipo():
            if request.method == 'POST':
                nombreDesarrollador = request.form.get("nombreDesarrollador")
                email = request.form.get("email")        
                password = request.form.get("password")
                confirmar_password = request.form.get("confirmar_password")
                rol = request.form.get("rol")
                
                # Validar formato de correo electrónico
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    flash("El correo electrónico no es válido.")
                    print("El correo electrónico no es válido.")
                    return redirect(url_for('index'))

                # Verificar si las contraseñas coinciden
                if password != confirmar_password:
                    flash("Las contraseñas no coinciden.")
                    print("Contraseña no coincide")
                    return redirect(url_for('index'))
                
                # Validar complejidad de la contraseña
                if not validar_contraseña(password):
                    flash("La contraseña debe contener al menos 8 caracteres, un número, una letra minúscula, una letra mayúscula y un carácter especial.")
                    print("La contraseña debe contener al menos 8 caracteres, un número, una letra minúscula, una letra mayúscula y un carácter especial.")
                    return redirect(url_for('index'))
                
                existe_usuario = con_bd.usuarios.find_one({"email": email})
                
                if existe_usuario:
                    return "El usuario ya existe. Por favor, inicia sesión o utiliza otro correo electrónico."
                else:
                    # Utiliza generate_password_hash para cifrar la contraseña antes de almacenarla
                    hashed_password = generate_password_hash(password)
                    
                    print(nombreDesarrollador)
                    print(email)
                    print(hashed_password)
                    print(rol)
                    
                    nuevo_usuario = {
                        
                        "nombreDesarrollador": nombreDesarrollador,
                        "email": email,
                        "password": hashed_password,  # Almacena la contraseña cifrada
                        "rol": rol
                    }
                    con_bd.usuarios.insert_one(nuevo_usuario) 
                    return redirect(url_for('index'))  

            return render_template('index.html')
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
                        "estado": "Pendiente",
                        "email": session['email']  # Añadir el email de la empresa
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
        def obtener_solicitudes(email):
            try:
                # Obtén las solicitudes para la empresa específica desde la base de datos
                solicitudes = con_bd.solicitudes.find({"email": email})
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
        def obtener_solicitudes_empresa():
            try:
                solicitudes = con_bd.solicitudes.find()
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
        def obtener_usuarios_empresa():
            try:
                usuarios_empresa = con_bd.usuarios.find({"rol": "Empresa"})
                return list(usuarios_empresa)
            except Exception as e:
                print(f"Error al obtener los usuarios de empresa: {e}")
                return []
        def obtener_usuarios_desarrollador():
            try:
                usuarios_desarrollador= con_bd.usuarios.find({"rol": "Desarrollador"})
                return list(usuarios_desarrollador)
            except Exception as e:
                print(f"Error al obtener los usuarios de empresa: {e}")
                return []
        def obtener_usuarios_admin():
            try:
                usuarios_admin= con_bd.usuarios.find({"rol": "Administrador"})
                return list(usuarios_admin)
            except Exception as e:
                print(f"Error al obtener los usuarios de empresa: {e}")
                return []  
           
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
            
            # Obtener empresas registradas
            #empresas = con_bd.usuarios.find({"rol": "Empresa"}, {"_id": 0, "nombreEmpresa": 1})
            usuarios_empresa = obtener_usuarios_empresa()
            # Obtener solicitudes de la empresa actual
            # solicitudes = obtener_solicitudes_empresa(session['email'])  
            solicitudes = obtener_solicitudes_empresa() 
            
            
            # Obtener desarrolladores registrados
            desarrolladores = obtener_usuarios_desarrollador()

            usuarios_admin = obtener_usuarios_admin()    
            # Obtener proyectos en curso desde la base de datos
            proyectos = con_bd.proyectos.find()
            return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin )
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
        # Ruta para el formulario de asignar equipo
        @app.route('/asignar_equipo/<proyecto_id>', methods=['GET', 'POST'])
        def asignar_equipo(proyecto_id):
            if request.method == 'POST':
                nombre_equipo = request.form.get("nombre_equipo")
                cantidad_miembros = int(request.form.get("cantidad_miembros"))
                miembros = []

                for i in range(cantidad_miembros):
                    miembro = request.form.get(f"miembros_{i}")
                    miembros.append(miembro)

                # Obtén la lista de usuarios con el rol "Desarrollador"
                usuarios_cursor = con_bd.usuarios.find({"rol": "Desarrollador"})
                usuarios = list(usuarios_cursor)

                # Guarda la información en la base de datos (proyecto)
                proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
                proyecto["nombre_equipo"] = nombre_equipo
                proyecto["miembros_equipo"] = miembros
                con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": proyecto})

                flash('Equipo asignado con éxito', 'success')
                return redirect(url_for('index'))

            # Envia la lista de usuarios "Desarrollador" a la plantilla
            usuarios_cursor = con_bd.usuarios.find({"rol": "Desarrollador"})
            usuarios = list(usuarios_cursor)

            return render_template('asignar_equipo.html', proyecto_id=proyecto_id, usuarios=usuarios)
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
        @app.route('/asignar_equipo', methods=['GET'])
        def mostrar_formulario_asignar_equipo():
            # Obtén la lista de usuarios con el rol "Desarrollador" desde tu base de datos
            usuarios_desarrolladores = con_bd.usuarios.find({"rol": "Desarrollador"})

            return render_template('asignar_equipo.html', usuarios=usuarios_desarrolladores)
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
        
        return app

if __name__ == '__main__':
    app = crear_app()
    app.run()
