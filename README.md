# CentroDesarrollo

<p align="center">
  <img src="images/logo.jfif" alt="Logo del Proyecto" width="200">
</p>
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

# Ejecucion en Docker

Para ejecutar este proyecto en un contenedor Docker, sigue estos pasos:

1. Asegúrate de tener Docker instalado en tu máquina. Si no lo tienes instalado, puedes descargarlo desde [Docker Hub](https://docs.docker.com/get-docker/).

2. Clona este repositorio en tu máquina local:

    ```bash
    git clone https://github.com/tu-usuario/tu-proyecto.git
    ```

3. Navega al directorio raíz de tu proyecto:

    ```bash
    cd tu-proyecto
    ```
Construye la imagen Docker ejecutando el siguiente comando:

    ```bash
    docker build -t centro_desarrollo .
    ```
5. Una vez que la imagen se haya construido correctamente, ejecuta el contenedor con el siguiente comando:

    ```bash
    docker run -p 5000:5000 centro_desarrollo
    ```
7. Accede a tu aplicación Flask desde tu navegador web en la siguiente dirección:

    ```
    http://localhost:5000
    ```
¡Eso es todo! Ahora tu aplicación Flask debería estar en funcionamiento dentro de un contenedor Docker.