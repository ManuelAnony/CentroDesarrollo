# Use the official Python image from the Docker Hub
FROM python:3.12

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos y luego instala las dependencias
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Copia todos los archivos al directorio de trabajo del contenedor
COPY . .

# Expone el puerto 5000 para que Flask pueda ser accedido
EXPOSE 5000

# Define el comando a ejecutar cuando el contenedor se inicie
CMD ["python", "app.py"]
