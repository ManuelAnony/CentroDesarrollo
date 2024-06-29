from flask import Flask, render_template, request, redirect, url_for, flash, session, after_this_request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from config import *
import re 

import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def crear_app():
    
    
        app = Flask(__name__, static_folder='static')
        # Establecer la directiva X-Frame-Options en DENY
        app.config['X_FRAME_OPTIONS'] = 'DENY'
        app.secret_key = 'u26kWaqy5XWNmdPS2%h%Lvf^uuBh47'
        # Instancia de conexión a la base de datos
        con_bd = Conexion()

        # Función para validar la URL y prevenir SSRF
        def validate_url(url):
            parsed_url = urlparse(url)
            if parsed_url.scheme not in ('http', 'https'):
                return False  # Solo se permiten URLs HTTP/HTTPS

                # Validar si el dominio está en la lista de dominios permitidos
            if parsed_url.hostname not in allowed_domains:
                  return False  # Dominio no autorizado

            return True
        allowed_domains = ['centrodesarrollo.onrender.com', '127.0.0.1']

        
        
        # Esta función generará un código de verificación de 6 dígitos
        def generate_verification_code():
            return ''.join(str(random.randint(0, 9)) for _ in range(6))
        
        
        ##Cambio contraseña empresa
        @app.route('/change_password', methods=['GET', 'POST'])
        def change_password():
            if 'email' not in session:
                return redirect(url_for('login'))
            
            email = session['email']
            usuario = con_bd.usuarios.find_one({"email": email})
            
            if request.method == 'POST':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_new_password = request.form.get('confirm_new_password')

                if not current_password or not new_password or not confirm_new_password:
                    flash('Por favor, completa todos los campos.', 'danger')
                    return redirect(url_for('change_password'))

                if not usuario or not check_password_hash(usuario['password'], current_password):
                    flash('La contraseña actual no es correcta.', 'danger')
                    return redirect(url_for('change_password'))

                if new_password != confirm_new_password:
                    flash('Las nuevas contraseñas no coinciden.', 'danger')
                    return redirect(url_for('change_password'))

                if current_password == new_password:
                    flash('La nueva contraseña no puede ser igual a la anterior.', 'danger')
                    return redirect(url_for('change_password'))

                hashed_new_password = generate_password_hash(new_password)
                con_bd.usuarios.update_one({"email": email}, {"$set": {"password": hashed_new_password}})
                flash('La contraseña ha sido actualizada correctamente.', 'success')

                if usuario['rol'] == 'Empresa':
                    return redirect(url_for('dashcompany'))
                elif usuario['rol'] == 'Desarrollador':
                    return redirect(url_for('proyecto'))
                elif usuario['rol'] == 'Administrador':
                    return redirect(url_for('index'))

            return render_template('change_password.html', usuario=usuario)


        ##Cambio Contraseña
        
        ##Inicio Restablecer contraseña
        # Función para enviar correo de restablecimiento de contraseña
        def send_reset_email(to_email, reset_link):
            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "cddta3211@gmail.com"
            sender_password = "ypix xxef wbmi zqxl"

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = to_email
            msg['Subject'] = "Restablecer Contraseña"

            body = f"Usa el siguiente enlace para restablecer tu contraseña: {reset_link}"
            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()

        @app.route('/restablecer_contraseña', methods=['GET', 'POST'])
        def restablecer_contraseña():
            if request.method == 'POST':
                email = request.form.get('email')
                usuario = con_bd.usuarios.find_one({"email": email})
                
                if usuario:
                    token = generate_verification_code()
                    reset_link = url_for('resetear_con_token', token=token, _external=True)
                    con_bd.tokens.insert_one({"email": email, "token": token})
                    send_reset_email(email, reset_link)
                    flash('Se ha enviado un enlace de restablecimiento a tu correo electrónico.', 'info')
                else:
                    flash('No se encontró una cuenta con ese correo electrónico.', 'danger')
            
            return render_template('restablecer_contraseña.html')

        @app.route('/resetear_con_token/<token>', methods=['GET', 'POST'])
        def resetear_con_token(token):
            token_doc = con_bd.tokens.find_one({"token": token})
            
            if not token_doc:
                flash('Token inválido o caducado.', 'danger')
                return redirect(url_for('login'))
            
            if request.method == 'POST':
                new_password = request.form.get('password')
                confirm_password = request.form.get('confirmar_password')
                
                if new_password != confirm_password:
                    flash('Las contraseñas no coinciden.', 'danger')
                    return redirect(url_for('resetear_con_token', token=token))
                
                hashed_password = generate_password_hash(new_password)
                con_bd.usuarios.update_one({"email": token_doc['email']}, {"$set": {"password": hashed_password}})
                con_bd.tokens.delete_one({"token": token})
                flash('Tu contraseña ha sido restablecida exitosamente.', 'success')
                return redirect(url_for('login'))
            
            return render_template('resetear_con_token.html', token=token)
        ##Fin Restablecer contraseña
        
        

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
                usuario = con_bd.usuarios.find_one({"email": session['email']})
                if usuario:
                    if usuario.get("rol") == "Administrador":
                        return redirect(url_for('index'))
                    elif usuario.get("rol") == "Desarrollador":
                        return redirect(url_for('proyecto'))
                    elif usuario.get("rol") == "Empresa":
                        return redirect(url_for('dashcompany'))

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
                    elif usuario.get("rol") == "Empresa" and usuario.get("verificado"):
                         # Verifica si la cuenta está verificada   
                        flash('Inicio de sesión exitoso como empresa', 'success')
                        return redirect(url_for('dashcompany'))
                    else:
                        flash('Error vuelve a intentarlo.', 'danger')
                else:   
                    flash('Credenciales inválidas. Por favor, verifica tu email y contraseña.', 'danger')

            return render_template('login.html')

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
        @app.route('/index')
        @app.route('/home')
        def index():
            
            if 'email' not in session:
                return redirect(url_for('login'))
            
            # Obtener empresas registradas
            #empresas = con_bd.usuarios.find({"rol": "Empresa"}, {"_id": 0, "nombreEmpresa": 1})
            #usuarios_empresa = obtener_usuarios_empresa()
            # Obtener solicitudes de la empresa actual
            # solicitudes = obtener_solicitudes_empresa(session['email'])  
            #solicitudes = obtener_solicitudes_empresa()       
            # Obtener desarrolladores registrados
            #desarrolladores = obtener_usuarios_desarrollador()
            #usuarios_admin = obtener_usuarios_admin()    
            # Obtener proyectos en curso desde la base de datos
            #proyectos = con_bd.proyectos.find()
            proyectos = list(con_bd.proyectos.find())
            usuarios_empresa = list(con_bd.usuarios.find({"rol": "Empresa"}))
            solicitudes = list(con_bd.solicitudes.find())
            desarrolladores = list(con_bd.usuarios.find({"rol": "Desarrollador"}))
            usuarios_admin = list(con_bd.usuarios.find({"rol": "Administrador"}))
            
            #return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin )
            return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)
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
                con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": {"estado": nuevo_estado}})

                flash('Estado del proyecto actualizado', 'success')
                return redirect(url_for('proyecto'))

            # Obtén el proyecto que se va a editar y pasa su estado actual al formulario
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
            
            if not proyecto:
                flash('Proyecto no encontrado.', 'danger')
                return redirect(url_for('proyecto'))
            
            return render_template('editar_estado.html', proyecto=proyecto)


        ##Panel Desarrollador mods
        @app.route('/actualizar_actividad', methods=['POST'])
        def actualizar_actividad():
            data = request.get_json()
            actividad_id = data.get('actividad_id')
            nuevo_estado = data.get('nuevo_estado')
            observaciones = data.get('observaciones')

            if not actividad_id or not nuevo_estado:
                return jsonify({'error': 'Datos incompletos'}), 400

            con_bd.actividades.update_one(
                {"_id": ObjectId(actividad_id)},
                {"$set": {"estado": nuevo_estado, "observaciones": observaciones}}
            )

            return jsonify({'success': 'Actividad actualizada'})


            return jsonify({'success': 'Estado actualizado'})

        @app.route('/proyecto/<proyecto_id>', methods=['GET'])
        def ver_proyecto(proyecto_id):
            if 'email' not in session:
                return redirect(url_for('login'))
            
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
            actividades = list(con_bd.actividades.find({"proyecto_id": ObjectId(proyecto_id)}))

            if not proyecto:
                flash('Proyecto no encontrado.', 'danger')
                return redirect(url_for('proyecto'))
            
            return render_template('proyecto_detalle.html', proyecto=proyecto, actividades=actividades)


        ##Panel Desarrollador mods
            
        @app.route('/proyecto')
        def proyecto():
            if 'email' not in session:
                return redirect(url_for('login'))
            
            email_usuario = session['email']
            usuario = con_bd.usuarios.find_one({"email": email_usuario})

            # Consulta para obtener los proyectos asignados al desarrollador
            proyectos_cursor = con_bd.proyectos.find({"miembros_equipo": email_usuario})
            proyectos = list(proyectos_cursor)

            # Consulta para obtener las actividades relacionadas con cada proyecto
            actividades_por_proyecto = {}  # Un diccionario para almacenar actividades por proyecto

            for proyecto in proyectos:
                actividades_cursor = con_bd.actividades.find({"proyecto_id": proyecto['_id']})
                actividades = list(actividades_cursor)
                actividades_por_proyecto[proyecto['_id']] = actividades

            return render_template('proyecto.html', usuario=usuario, proyectos=proyectos, actividades_por_proyecto=actividades_por_proyecto)





        # Ruta para el formulario de asignar equipo
        @app.route('/asignar_equipo/<proyecto_id>', methods=['GET', 'POST'])
        def asignar_equipo(proyecto_id):
            equipo = con_bd.equipos.find_one({"proyecto_id": proyecto_id})

            if equipo:
                flash('Ya existe un equipo asignado a este proyecto. Redirigiendo a la página de edición.', 'info')
                return redirect(url_for('editar_equipo', equipo_id=equipo['_id']))

            if request.method == 'POST':
                nombre_equipo = request.form.get("nombre_equipo")
                cantidad_miembros = int(request.form.get("cantidad_miembros"))
                miembros = []

                for i in range(cantidad_miembros):
                    miembro = request.form.get(f"miembros_{i}")
                    miembros.append(miembro)

                # Guarda la información en la base de datos (proyecto)
                proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
                if proyecto:
                    equipo = {
                        "nombre": nombre_equipo,
                        "miembros": miembros,
                        "proyecto_id": proyecto_id,
                        "proyecto_nombre": proyecto["nombre"]
                    }
                    con_bd.equipos.insert_one(equipo)
                    proyecto["miembros_equipo"] = miembros
                    con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": proyecto})

                    # Enviar notificación por correo a los miembros del equipo
                    subject = f"Asignación al Proyecto: {proyecto['nombre']}"
                    body = f"Has sido asignado al equipo '{nombre_equipo}' para el proyecto '{proyecto['nombre']}'."
                    for miembro in miembros:
                        enviar_notificacion(miembro, subject, body)

                    flash('Equipo asignado y notificación enviada con éxito', 'success')
                else:
                    flash('Proyecto no encontrado.', 'danger')

                return redirect(url_for('index'))

            # Envia la lista de usuarios "Desarrollador" a la plantilla
            usuarios_cursor = con_bd.usuarios.find({"rol": "Desarrollador"})
            usuarios = list(usuarios_cursor)
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})

            return render_template('asignar_equipo.html', proyecto=proyecto, usuarios=usuarios, equipos=list(con_bd.equipos.find({"proyecto_id": proyecto_id})))

        def enviar_notificacion(email, subject, body):
            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            sender_email = "cddta3211@gmail.com"
            sender_password = "ypix xxef wbmi zqxl"
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = email
            msg['Subject'] = subject
            # body = f"Has sido asignado al equipo {equipo} para el proyecto: {proyecto} ."
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()



        @app.route('/notificar_equipo/<proyecto_id>', methods=['GET', 'POST'])
        def notificar_equipo(proyecto_id):
            if 'email' not in session:
                return redirect(url_for('login'))

            if request.method == 'POST':
                equipo_id = request.form.get('equipo_id')
                mensaje = request.form.get('mensaje')
                flash(f'Notificación enviada al equipo {equipo_id} del proyecto {proyecto_id}', 'success')

            return render_template('notificar_equipo.html', proyecto_id=proyecto_id)

        @app.route('/ver_equipos', methods=['GET'])
        def ver_equipos():
            page = int(request.args.get('page', 1))
            per_page = 6
            skip = (page - 1) * per_page

            total_equipos = con_bd.equipos.count_documents({})
            equipos = list(con_bd.equipos.find().skip(skip).limit(per_page))

            next_page = page + 1 if (skip + per_page) < total_equipos else None
            prev_page = page - 1 if page > 1 else None

            return render_template('ver_equipos.html', equipos=equipos, next_page=next_page, prev_page=prev_page)


        
        
        @app.route('/editar_equipo/<equipo_id>', methods=['GET', 'POST'])
        def editar_equipo(equipo_id):
            equipo = con_bd.equipos.find_one({"_id": ObjectId(equipo_id)})
            if not equipo:
                flash('Equipo no encontrado', 'danger')
                return redirect(url_for('ver_equipos'))

            proyecto_id = equipo.get("proyecto_id")
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)}) if proyecto_id else None

            if request.method == 'POST':
                nombre_equipo = request.form.get("nombre_equipo")
                cantidad_miembros = int(request.form.get("cantidad_miembros"))
                miembros = []

                for i in range(cantidad_miembros):
                    miembro = request.form.get(f"miembros_{i}")
                    miembros.append(miembro)

                con_bd.equipos.update_one({"_id": ObjectId(equipo_id)}, {"$set": {"nombre": nombre_equipo, "miembros": miembros}})

                flash('Equipo editado con éxito', 'success')
                return redirect(url_for('ver_equipos'))

            usuarios_cursor = con_bd.usuarios.find({"rol": "Desarrollador"})
            usuarios = list(usuarios_cursor)
            return render_template('editar_equipo.html', equipo=equipo, proyecto=proyecto, usuarios=usuarios)



        @app.route('/eliminar_equipo/<equipo_id>')
        def eliminar_equipo(equipo_id):
            con_bd.equipos.delete_one({"_id": ObjectId(equipo_id)})
            flash('Equipo eliminado con éxito', 'success')
            return redirect(url_for('ver_equipos'))
        
        

        return app

if __name__ == '__main__':
    app = crear_app()
    app.run()