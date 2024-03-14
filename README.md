# CentroDesarrollo

![Imagen de proyecto](images/logo.jfif)
## Requisitos previos

- Python 3.x instalado en tu sistema.
- Git instalado en tu sistema (opcional).

## Configuración del Entorno Virtual

1. Abre una terminal y navega hasta el directorio raíz de tu proyecto.

2. Crea un nuevo entorno virtual ejecutando el siguiente comando:
    
    
    python3 -m venv venv


3. Activa el entorno virtual. En sistemas Unix/Linux/macOS:
    
    
    source venv/bin/activate

En Windows:
    
    .\venv\Scripts\activate
    
si no ejecuta dar permisos con el siguiente comando:

    Set-ExecutionPolicy RemoteSigned -Scope Process


4. ¡Ahora estás dentro de tu entorno virtual y listo para instalar las dependencias del proyecto!

## Instalación de Dependencias

Para instalar las dependencias del proyecto, utiliza el archivo `requirements.txt` proporcionado. Ejecuta el siguiente comando:

    
    pip install -r requirements.txt


## Ejecución del Proyecto

Una vez que todas las dependencias estén instaladas, puedes ejecutar el proyecto Flask. Asegúrate de que estás dentro del entorno virtual. Ejecuta el siguiente comando:
    
    
    py .\src\app.py o flask run

Esto iniciará el servidor de desarrollo de Flask. Puedes acceder a la aplicación abriendo un navegador web y navegando a `http://localhost:5000`.


