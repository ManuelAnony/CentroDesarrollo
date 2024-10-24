from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from config import *
import re
import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_mail import Mail, Message  # Importa Mail y Message desde Flask-Mail

def crear_app():
    app = Flask(__name__, static_folder='static')
    # Establecer la directiva X-Frame-Options en DENY
    app.config['X_FRAME_OPTIONS'] = 'DENY'
    app.secret_key = 'u26kWaqy5XWNmdPS2%h%Lvf^uuBh47'

    mail = Mail(app)  # Inicializa Flask-Mail
    
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

    # Generar código de verificación de 6 dígitos
    def generate_verification_code():
        return ''.join(str(random.randint(0, 9)) for _ in range(6))

    ## Cambio de contraseña de empresa
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

    ## Restablecimiento de contraseña
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

    # Función para enviar enlace de establecimiento de contraseña para nuevos usuarios
    def send_establish_password_email(to_email, establish_link):
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "cddta3211@gmail.com"
        sender_password = "ypix xxef wbmi zqxl"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = "Establecer Contraseña"

        body = f"Hola,\n\nHas sido registrado en nuestra plataforma. Usa el siguiente enlace para establecer tu contraseña: {establish_link}\n\nGracias."
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

    ## Verificación de email
    def send_verification_email(to_email, verification_code):
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "cddta3211@gmail.com"
        sender_password = "ypix xxef wbmi zqxl"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = "Código de verificación"

        body = f"Tu código de verificación es: {verification_code}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()

    @app.route('/enviar_codigo_verificacion', methods=['POST'])
    def enviar_codigo_verificacion():
        verification_code = generate_verification_code()
        to_email = request.form.get('email')
        session['verification_code'] = verification_code
        send_verification_email(to_email, verification_code)
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

    ## Eliminar usuario, solicitud o proyecto
    @app.route('/eliminar_usuario/<usuario_id>')
    def eliminar_usuario(usuario_id):
        if 'email' not in session:
            return redirect(url_for('login'))
        
        usuario = con_bd.usuarios.find_one({"_id": ObjectId(usuario_id)})
        if usuario:
            con_bd.usuarios.delete_one({"_id": ObjectId(usuario_id)})
            flash('Usuario eliminado con éxito', 'success')
        else:
            flash('Usuario no encontrado', 'danger')
        
        return redirect(url_for('index'))

    @app.route('/eliminar_solicitud/<solicitud_id>')
    def eliminar_solicitud(solicitud_id):
        if 'email' not in session:
            return redirect(url_for('login'))
        
        solicitud = con_bd.solicitudes.find_one({"_id": ObjectId(solicitud_id)})
        if solicitud:
            con_bd.solicitudes.delete_one({"_id": ObjectId(solicitud_id)})
            flash('Solicitud eliminada con éxito', 'success')
        else:
            flash('Solicitud no encontrada', 'danger')
        
        return redirect(url_for('index'))

    @app.route('/eliminar_solicitud_empresa/<solicitud_id>', methods=['POST'])
    def eliminar_solicitud_empresa(solicitud_id):
        if 'email' not in session:
            return redirect(url_for('login'))
        
        solicitud = con_bd.solicitudes.find_one({"_id": ObjectId(solicitud_id)})
        if solicitud:
            con_bd.solicitudes.delete_one({"_id": ObjectId(solicitud_id)})
            flash('Solicitud eliminada con éxito', 'success')
        else:
            flash('Solicitud no encontrada', 'danger')
        
        return redirect(url_for('dashcompany'))

    
    @app.route('/eliminar_proyecto/<proyecto_id>')
    def eliminar_proyecto(proyecto_id):
        if 'email' not in session:
            return redirect(url_for('login'))
        
        proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
        if proyecto:
            con_bd.proyectos.delete_one({"_id": ObjectId(proyecto_id)})
            flash('Proyecto eliminado con éxito', 'success')
        else:
            flash('Proyecto no encontrado', 'danger')
        
        return redirect(url_for('index'))

    ## Login de usuarios
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if 'email' in session:
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

            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash('Por favor, ingresa una dirección de correo electrónico válida.', 'danger')
                return redirect(url_for('login'))

            usuario = con_bd.usuarios.find_one({"email": email})
            
            if usuario and check_password_hash(usuario["password"], password):
                session['email'] = usuario['email']
                if usuario.get("rol") == "Administrador":
                    return redirect(url_for('index'))
                elif usuario.get("rol") == "Desarrollador":
                    return redirect(url_for('proyecto'))
                elif usuario.get("rol") == "Empresa" and usuario.get("verificado"):
                    return redirect(url_for('dashcompany'))
                else:
                    flash('Error vuelve a intentarlo.', 'danger')
            else:
                flash('Credenciales inválidas. Por favor, verifica tu email y contraseña.', 'danger')

        return render_template('login.html')

    ## Seguridad de caché y cabeceras
    @app.after_request
    def add_header(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    ## Validación de contraseñas seguras
    def validar_contraseña(password):
        if len(password) < 8:
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    ## Registro de empresas
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

            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash("El correo electrónico no es válido.")
                return redirect(url_for('registroEmpresa'))

            if password != confirmar_password:
                flash("Las contraseñas no coinciden.")
                return redirect(url_for('registroEmpresa'))

            if not validar_contraseña(password):
                flash("La contraseña debe contener al menos 8 caracteres, un número, una letra minúscula, una letra mayúscula y un carácter especial.")
                return redirect(url_for('registroEmpresa'))

            if con_bd.usuarios.find_one({"email": email}):
                flash("El correo electrónico ya está en uso.")
                return redirect(url_for('registroEmpresa'))

            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            send_verification_email(email, verification_code)

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

    ## Página de verificación de registro de empresa
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
        # Obtener los datos necesarios para la página desde la base de datos
        desarrolladores = list(con_bd.usuarios.find({"rol": "Desarrollador"}))
        proyectos = list(con_bd.proyectos.find())
        solicitudes = list(con_bd.solicitudes.find())
        usuarios_empresa = list(con_bd.usuarios.find({"rol": "Empresa"}))
        usuarios_admin = list(con_bd.usuarios.find({"rol": "Administrador"}))

        if request.method == 'POST':
            nombreDesarrollador = request.form.get("nombreDesarrollador")
            email = request.form.get("email")        
            rol = request.form.get("rol")
            
            # Validar el formato del correo electrónico
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash("El correo electrónico no es válido.")
                return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)

            # Validar que el correo sea institucional
            if not email.endswith('@ucundinamarca.edu.co'):
                flash("El correo electrónico debe ser institucional y terminar en @ucundinamarca.edu.co.", 'danger')
                return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)

            # Verificar si el usuario ya existe
            existe_usuario = con_bd.usuarios.find_one({"email": email})
            
            if existe_usuario:
                flash('El usuario ya existe. Por favor, utiliza otro correo electrónico.', 'danger')
                return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)

            # Generar token para que el usuario establezca la contraseña
            token = generate_verification_code()
            establish_link = url_for('establecer_contraseña_token', token=token, _external=True)

            # Guardar el token en la base de datos
            con_bd.tokens.insert_one({"email": email, "token": token})

            # Enviar el correo al desarrollador o administrador para que establezca la contraseña
            send_establish_password_email(email, establish_link)

            # Crear el usuario en la base de datos sin contraseña por ahora
            nuevo_usuario = {
                "nombreDesarrollador": nombreDesarrollador,
                "email": email,
                "rol": rol
            }
            con_bd.usuarios.insert_one(nuevo_usuario) 
            
            flash('Se ha enviado un enlace de establecimiento de contraseña al desarrollador/administrador.', 'success')
            return redirect(url_for('index'))

        # Si es un GET, renderizamos la plantilla normalmente
        return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)

    
    # Ruta para establecer la contraseña usando el token
    @app.route('/establecer_contraseña/<token>', methods=['GET', 'POST'])
    def establecer_contraseña_token(token):
        token_doc = con_bd.tokens.find_one({"token": token})
        
        if not token_doc:
            flash('Token inválido o caducado.', 'danger')
            return redirect(url_for('login'))

        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if new_password != confirm_password:
                flash('Las contraseñas no coinciden.', 'danger')
                return redirect(url_for('establecer_contraseña_token', token=token))
            
            hashed_password = generate_password_hash(new_password)
            con_bd.usuarios.update_one({"email": token_doc['email']}, {"$set": {"password": hashed_password}})
            con_bd.tokens.delete_one({"token": token})
            flash('Tu contraseña ha sido restablecida exitosamente.', 'success')

            # Redirigir al login después de cambiar la contraseña
            return redirect(url_for('login'))

        return render_template('establecer_contraseña.html', token=token)


    ## Funciones de obtener datos y enviar solicitudes
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

        empresa = obtener_datos_empresa(email_empresa)

        if empresa:
            nombre_empresa = empresa.get("nombreEmpresa", "")
            nit = empresa.get("nit", "")
            administrador = empresa.get("administrador", "")
            email_empresa = empresa.get("email", "")
            rol = empresa.get("rol", "")

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
                nombre_solicitud = request.form.get("nombreSolicitud")
                descripcion_solicitud = request.form.get("descripcionSolicitud")
                fecha_solicitud = request.form.get("fechaSolicitud")

                nueva_solicitud = {
                    "nombre_solicitud": nombre_solicitud,
                    "descripcion_solicitud": descripcion_solicitud,
                    "fecha": fecha_solicitud,
                    "estado": "Pendiente",
                    "email": session['email']  # Añadir el email de la empresa
                }

                con_bd.solicitudes.insert_one(nueva_solicitud)

                flash('Solicitud enviada con éxito', 'success')

                return redirect(url_for('dashcompany'))

            flash('Error al enviar la solicitud', 'danger')
            return redirect(url_for('dashcompany'))
        except Exception as e:
            print(f"Error al procesar la solicitud: {e}")
            flash('Error al enviar la solicitud', 'danger')
            return redirect(url_for('dashcompany'))

    @app.route('/actualizar_solicitud/<solicitud_id>', methods=['POST'])
    def actualizar_solicitud(solicitud_id):
        if 'email' not in session:
            return redirect(url_for('login'))

        solicitud = con_bd.solicitudes.find_one({"_id": ObjectId(solicitud_id)})
        if not solicitud:
            flash('Solicitud no encontrada.', 'danger')
            return redirect(url_for('dashcompany'))

        nuevo_estado = request.form.get("estado")
        comentario = request.form.get("comentario")
        fecha_actualizacion = request.form.get("fecha_actualizacion")

        if not nuevo_estado or not comentario:
            flash('Por favor, ingresa un estado y un comentario.', 'danger')
            return redirect(url_for('dashcompany'))

        # Agregar la actualización a la lista de actualizaciones
        nueva_actualizacion = {
            "estado": nuevo_estado,
            "comentario": comentario,
            "fecha": fecha_actualizacion
        }

        con_bd.solicitudes.update_one(
            {"_id": ObjectId(solicitud_id)},
            {"$push": {"actualizaciones": nueva_actualizacion}, "$set": {"estado": nuevo_estado}}
        )

        # Enviar notificación por correo
        enviar_correo_actualizacion(
            solicitud['email'],
            solicitud['nombre_solicitud'],
            nuevo_estado,
            comentario,
            fecha_actualizacion
        )

        flash('Solicitud actualizada correctamente y notificación enviada.', 'success')
        return redirect(url_for('dashcompany'))



    def enviar_correo_actualizacion(email, nombre_solicitud, estado, comentario, fecha):
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "cddta3211@gmail.com"
        sender_password = "ypix xxef wbmi zqxl"  # Asegúrate de que esta es la contraseña correcta

        # Contenido del correo
        subject = f"Actualización de solicitud: {nombre_solicitud}"
        body = (
            f"Estimado usuario,\n\n"
            f"Se ha realizado una nueva actualización en la solicitud '{nombre_solicitud}'.\n"
            f"Estado: {estado}\n"
            f"Comentario: {comentario}\n"
            f"Fecha de actualización: {fecha}\n\n"
            f"Gracias por utilizar nuestra plataforma.\n\n"
            f"Saludos,\nEquipo CDDT"
        )

        # Configuración del mensaje
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            # Envío del correo
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            print(f"Correo enviado exitosamente a {email}")
        except Exception as e:
            print(f"Error al enviar el correo a {email}: {e}")

    def obtener_solicitudes(email):
        try:
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

        empresa = obtener_datos_empresa(email_empresa)

        if empresa:
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
        solicitudes = obtener_solicitudes_empresa(email_empresa)

        return render_template('dashboard.html', solicitudes=solicitudes)

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
        # Limpiar completamente todos los datos de la sesión.
        session.clear()  # Elimina toda la sesión.
        flash('Sesión cerrada correctamente', 'info')
        return redirect(url_for('login'))
    @app.before_request
    def verificar_sesion():
        rutas_protegidas = ['proyecto', 'ver_equipos', 'dashcompany','editar_equipo']
        if 'email' not in session and request.endpoint in rutas_protegidas:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        
    @app.route('/')
    @app.route('/index')
    @app.route('/home')
    def index():
        if 'email' not in session:
            return redirect(url_for('login'))

        proyectos = list(con_bd.proyectos.find())
        usuarios_empresa = list(con_bd.usuarios.find({"rol": "Empresa"}))
        solicitudes = list(con_bd.solicitudes.find())
        desarrolladores = list(con_bd.usuarios.find({"rol": "Desarrollador"}))
        usuarios_admin = list(con_bd.usuarios.find({"rol": "Administrador"}))

        return render_template('index.html', proyectos=proyectos, usuarios_empresa=usuarios_empresa, solicitudes=solicitudes, desarrolladores=desarrolladores, usuarios_admin=usuarios_admin)

    @app.route('/registrar_proyecto', methods=['POST'])
    def registrar_proyecto():
        if 'email' not in session:
            return redirect(url_for('login'))

        if request.method == 'POST':
            nombre_proyecto = request.form.get("nombre_proyecto")
            descripcion = request.form.get("descripcion")
            fecha_inicio = request.form.get("fecha_inicio")
            fecha_finalizacion = request.form.get("fecha_finalizacion")
            estado = request.form.get("estado")

            nuevo_proyecto = {
                "nombre": nombre_proyecto,
                "descripcion": descripcion,
                "fecha_inicio": fecha_inicio,
                "fecha_finalizacion": fecha_finalizacion,
                "estado": estado,
                "equipo": []
            }
            con_bd.proyectos.insert_one(nuevo_proyecto)

            flash('Proyecto registrado con éxito', 'success')
            return redirect(url_for('index'))

    @app.route('/crear_actividad', methods=['POST'])
    def crear_actividad():
        if request.method == 'POST':
            admin_email = request.form.get("admin_email")
            nombre_actividad = request.form.get("nombre_actividad")
            fecha_vencimiento = request.form.get("fecha_vencimiento")
            proyecto_id = ObjectId(request.form.get("proyecto_id"))

            nueva_actividad = {
                "admin_email": admin_email,
                "nombre": nombre_actividad,
                "fecha_vencimiento": fecha_vencimiento,
                "proyecto_id": proyecto_id
            }
            con_bd.actividades.insert_one(nueva_actividad)
            

            flash('Actividad creada con éxito', 'success')
            return redirect(url_for('proyecto'))

    @app.route('/crear_actividad_1/<proyecto_id>', methods=['POST'])
    def crear_actividad_1(proyecto_id):
        if request.method == 'POST':
            admin_email = request.form.get("admin_email")
            nombre_actividad = request.form.get("nombre_actividad")
            fecha_vencimiento = request.form.get("fecha_vencimiento")

            nueva_actividad = {
                "admin_email": admin_email,
                "nombre": nombre_actividad,
                "fecha_vencimiento": fecha_vencimiento,
                "proyecto_id": ObjectId(proyecto_id)
            }
            con_bd.actividades.insert_one(nueva_actividad)

            # Notificar a los miembros del equipo por correo
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
            if proyecto:
                miembros_equipo = proyecto.get('miembros_equipo', [])
                subject = f"Se ha creado una nueva actividad en el proyecto {proyecto['nombre']}"
                body = f"Se ha añadido una nueva actividad: {nombre_actividad} con fecha de vencimiento {fecha_vencimiento}."

                for miembro in miembros_equipo:
                    usuario = con_bd.usuarios.find_one({"email": miembro})
                    if usuario:
                        enviar_notificacion(
                            miembro,
                            subject,
                            f"Hola {usuario.get('nombre_desarrollador', 'Usuario')}, {body}"
                        )

            flash('Actividad creada con éxito', 'success')
            return redirect(url_for('ver_proyecto', proyecto_id=proyecto_id))


    @app.route('/editar_estado/<proyecto_id>', methods=['GET', 'POST'])
    def editar_estado(proyecto_id):
        if request.method == 'POST':
            nuevo_estado = request.form.get("nuevo_estado")

            con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": {"estado": nuevo_estado}})
            flash('Estado del proyecto actualizado', 'success')
            return redirect(url_for('proyecto'))

        proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})

        if not proyecto:
            flash('Proyecto no encontrado.', 'danger')
            return redirect(url_for('proyecto'))

        return render_template('editar_estado.html', proyecto=proyecto)

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

    @app.route('/proyecto')
    def proyecto():
        if 'email' not in session:
            return redirect(url_for('login'))
        
        email_usuario = session['email']
        usuario = con_bd.usuarios.find_one({"email": email_usuario})

        proyectos_cursor = con_bd.proyectos.find({"miembros_equipo": email_usuario})
        proyectos = list(proyectos_cursor)

        actividades_por_proyecto = {}

        for proyecto in proyectos:
            actividades_cursor = con_bd.actividades.find({"proyecto_id": proyecto['_id']})
            actividades = list(actividades_cursor)
            actividades_por_proyecto[proyecto['_id']] = actividades

        return render_template('proyecto.html', usuario=usuario, proyectos=proyectos, actividades_por_proyecto=actividades_por_proyecto)

    @app.route('/asignar_equipo/<proyecto_id>', methods=['GET', 'POST'])
    def asignar_equipo(proyecto_id):
        # Comprobar si ya existe un equipo asignado a este proyecto
        equipo = con_bd.equipos.find_one({"proyecto_id": proyecto_id})

        if equipo:
            flash('Ya existe un equipo asignado a este proyecto. Redirigiendo a la página de edición.', 'info')
            return redirect(url_for('editar_equipo', equipo_id=equipo['_id']))

        # Si se envía el formulario, procesamos la asignación del equipo
        if request.method == 'POST':
            nombre_equipo = request.form.get("nombre_equipo")
            cantidad_miembros = int(request.form.get("cantidad_miembros"))
            miembros = []

            # Extraer los miembros del formulario
            for i in range(cantidad_miembros):
                miembro = request.form.get(f"miembros_{i}")
                miembros.append(miembro)

            # Obtener el proyecto correspondiente
            proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})
            if proyecto:
                # Crear el equipo y asignarlo al proyecto
                equipo = {
                    "nombre": nombre_equipo,
                    "miembros": miembros,
                    "proyecto_id": proyecto_id,
                    "proyecto_nombre": proyecto["nombre"]
                }
                con_bd.equipos.insert_one(equipo)

                # Actualizar la lista de miembros del proyecto
                con_bd.proyectos.update_one({"_id": ObjectId(proyecto_id)}, {"$set": {"miembros_equipo": miembros}})

                # Enviar notificación a los miembros asignados
                subject = f"Asignación al Proyecto: {proyecto['nombre']}"
                body = f"Has sido asignado al equipo '{nombre_equipo}' para el proyecto '{proyecto['nombre']}'."

                for miembro in miembros:
                    usuario = con_bd.usuarios.find_one({"email": miembro})
                    if usuario:
                        enviar_notificacion(
                            miembro,
                            subject,
                            f"Hola {usuario.get('nombre_desarrollador', 'Usuario')}, has sido asignado al equipo '{nombre_equipo}' en el proyecto '{proyecto['nombre']}'."
                        )

                flash('Equipo asignado y notificación enviada con éxito', 'success')
            else:
                flash('Proyecto no encontrado.', 'danger')

            return redirect(url_for('index'))

        # Si es una solicitud GET, renderizar el formulario de asignación de equipo
        usuarios_cursor = con_bd.usuarios.find({"rol": "Desarrollador"})
        usuarios = list(usuarios_cursor)
        proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)})

        return render_template('asignar_equipo.html', proyecto=proyecto, usuarios=usuarios)

    def enviar_notificacion(email, subject, body):
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "cddta3211@gmail.com"
        sender_password = "ypix xxef wbmi zqxl"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            print(f"Correo enviado exitosamente a {email}")
        except Exception as e:
            print(f"Error al enviar el correo a {email}: {e}")


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
        # Cargar equipo desde la base de datos
        equipo = con_bd.equipos.find_one({"_id": ObjectId(equipo_id)})
        if not equipo:
            flash('Equipo no encontrado', 'danger')
            return redirect(url_for('ver_equipos'))

        proyecto_id = equipo.get("proyecto_id")
        proyecto = con_bd.proyectos.find_one({"_id": ObjectId(proyecto_id)}) if proyecto_id else None

        # Imprimir equipo y proyecto para depuración
        print("Equipo cargado desde la base de datos:", equipo)
        print("Proyecto asociado:", proyecto)

        miembros_anteriores = set(equipo.get("miembros", []))

        if request.method == 'POST':
            # Obtener datos del formulario
            nombre_equipo = request.form.get("nombre_equipo")
            cantidad_miembros = int(request.form.get("cantidad_miembros", 0))
            miembros = [request.form.get(f"miembros_{i}") for i in range(cantidad_miembros)]

            # Identificar miembros nuevos y eliminados
            miembros_actuales = set(miembros)
            nuevos_miembros = miembros_actuales - miembros_anteriores
            miembros_eliminados = miembros_anteriores - miembros_actuales

            # Actualizar equipo en la base de datos
            con_bd.equipos.update_one(
                {"_id": ObjectId(equipo_id)},
                {"$set": {"nombre": nombre_equipo, "miembros": list(miembros_actuales)}}
            )

            # Solo enviar correos si se encontró un proyecto asociado
            if proyecto:
                for miembro in nuevos_miembros:
                    usuario = con_bd.usuarios.find_one({"email": miembro})
                    if usuario:
                        enviar_correo(
                            usuario['email'],
                            f'Asignación al proyecto: {proyecto.get("nombre", "Proyecto sin nombre")}',
                            f'Hola {usuario.get("nombreDesarrollador", "Usuario")}, '
                            f'has sido asignado al equipo "{nombre_equipo}" '
                            f'en el proyecto "{proyecto.get("nombre", "sin nombre")}".'
                        )

                for miembro in miembros_eliminados:
                    usuario = con_bd.usuarios.find_one({"email": miembro})
                    if usuario:
                        enviar_correo(
                            usuario['email'],
                            f'Removido del proyecto: {proyecto.get("nombre", "Proyecto sin nombre")}',
                            f'Hola {usuario.get("nombreDesarrollador", "Usuario")}, '
                            f'has sido removido del equipo "{nombre_equipo}" '
                            f'en el proyecto "{proyecto.get("nombre", "sin nombre")}".'
                        )
            else:
                print("No se encontró un proyecto asociado. No se enviaron correos.")

            flash('Equipo editado con éxito', 'success')
            return redirect(url_for('ver_equipos'))

        # Convertir ObjectId a str en usuarios para evitar problemas de serialización
        usuarios = list(con_bd.usuarios.find({"rol": "Desarrollador"}))
        for usuario in usuarios:
            usuario['_id'] = str(usuario['_id'])

        equipo['_id'] = str(equipo['_id'])

        return render_template(
            'editar_equipo.html',
            equipo=equipo,
            proyecto=proyecto,
            usuarios=usuarios
        )

    def enviar_correo(email, subject, body):
            smtp_server = "smtp.gmail.com"
            smtp_port = 587  # Asegúrate de que este es el puerto correcto
            sender_email = "cddta3211@gmail.com"
            sender_password = "ypix xxef wbmi zqxl"  # Verifica que esta sea la contraseña correcta

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            try:
                print("Estableciendo conexión con el servidor SMTP...")
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                print("Iniciando sesión en el servidor SMTP...")
                server.login(sender_email, sender_password)
                print("Enviando mensaje...")
                server.send_message(msg)
                server.quit()
                print(f"Correo enviado exitosamente a {email}")
            except smtplib.SMTPAuthenticationError:
                print("Error de autenticación: verifica tu correo y contraseña.")
            except smtplib.SMTPConnectError:
                print("No se pudo conectar al servidor SMTP. Verifica la conexión de red.")
            except smtplib.SMTPException as e:
                print(f"Ocurrió un error durante el envío del correo: {e}")

    @app.route('/eliminar_equipo/<equipo_id>')
    def eliminar_equipo(equipo_id):
        con_bd.equipos.delete_one({"_id": ObjectId(equipo_id)})
        flash('Equipo eliminado con éxito', 'success')
        return redirect(url_for('ver_equipos'))

    return app

if __name__ == '__main__':
    app = crear_app()
    app.run()
