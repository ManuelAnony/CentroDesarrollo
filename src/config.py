from pymongo import MongoClient
import certifi
mongo = 'mongodb+srv://Varsity2303:1FUFNbhftG9k6oT4@cluster0.umu6mts.mongodb.net/?retryWrites=true&w=majority'
certificado = certifi.where()

def Conexion():
    try: 
        client = MongoClient(mongo, tlsCAFile=certificado)
        bd = client["gestionproyectos"]
        print('Conectado')
    except ConnectionError:
        print('Error de Conexión')
    return bd      