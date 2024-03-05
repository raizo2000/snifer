import json
import bcrypt
import os
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QDialog

class Autenticador:
    @staticmethod
    def cargar_usuarios_desde_json(ruta_json):
        try:
            with open(ruta_json, 'r') as file:
                data = file.read()
                if not data:
                    return {'usuarios': []}
                datos = json.loads(data)
                if 'usuarios' not in datos:
                    datos['usuarios'] = []
            return datos
        except FileNotFoundError:
            return {'usuarios': []}

    @staticmethod
    def guardar_usuario_en_json(usuario, contrasena, ruta_json='usuarios.json'):
        datos = Autenticador.cargar_usuarios_desde_json(ruta_json)

        # Encriptar la contraseña antes de guardarla
        contrasena_encriptada = Autenticador.encriptar_contrasena(contrasena)

        nuevo_usuario = {'usuario': usuario, 'contrasena': contrasena_encriptada}
        datos['usuarios'].append(nuevo_usuario)

        with open(ruta_json, 'w') as file:
            json.dump(datos, file)

    @staticmethod
    def encriptar_contrasena(contrasena):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(contrasena.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    @staticmethod
    def verificar_credenciales(usuario, contrasena, ruta_json='usuarios.json'):
        datos = Autenticador.cargar_usuarios_desde_json(ruta_json)
        usuarios = datos['usuarios']

        for user in usuarios:
            if user['usuario'] == usuario and bcrypt.checkpw(contrasena.encode('utf-8'), user['contrasena'].encode('utf-8')):
                return True
        return False

class CrearUsuarioWindow(QDialog):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Crear Usuario')
        self.setGeometry(300, 300, 400, 200)

        self.label_usuario = QLabel('Nuevo Usuario:', self)
        self.usuario_entry = QLineEdit(self)
        self.label_contrasena = QLabel('Nueva Contraseña:', self)
        self.contrasena_entry = QLineEdit(self)
        self.boton_crear_usuario = QPushButton('Crear Usuario', self)

        layout = QVBoxLayout()
        layout.addWidget(self.label_usuario)
        layout.addWidget(self.usuario_entry)
        layout.addWidget(self.label_contrasena)
        layout.addWidget(self.contrasena_entry)
        layout.addWidget(self.boton_crear_usuario)

        self.boton_crear_usuario.clicked.connect(self.crear_usuario)

        self.setLayout(layout)

    def crear_usuario(self):
        nuevo_usuario = self.usuario_entry.text()
        nueva_contrasena = self.contrasena_entry.text()

        if nuevo_usuario and nueva_contrasena:
            # Guardar el nuevo usuario en el archivo JSON
            Autenticador.guardar_usuario_en_json(nuevo_usuario, nueva_contrasena)
            QMessageBox.information(self, 'Éxito', 'Usuario creado con éxito.')
            self.accept()  # Cerrar el diálogo después de crear el usuario
        else:
            QMessageBox.warning(self, 'Error', 'Por favor, ingresa un usuario y una contraseña válidos.')

class LoginForm(QWidget):
    inicio_sesion_correcto = pyqtSignal()

    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Inicio de Sesión')
        self.setGeometry(200, 200, 400, 200)

        self.label_usuario = QLabel('Usuario:', self)
        self.usuario_entry = QLineEdit(self)
        self.label_contrasena = QLabel('Contraseña:', self)
        self.contrasena_entry = QLineEdit(self)
        self.contrasena_entry.setEchoMode(QLineEdit.Password)
        self.boton_iniciar_sesion = QPushButton('Iniciar Sesión', self)
        self.boton_crear_usuario = QPushButton('Crear Usuario', self)

        layout = QVBoxLayout()
        layout.addWidget(self.label_usuario)
        layout.addWidget(self.usuario_entry)
        layout.addWidget(self.label_contrasena)
        layout.addWidget(self.contrasena_entry)
        layout.addWidget(self.boton_iniciar_sesion)
        layout.addWidget(self.boton_crear_usuario)

        self.boton_iniciar_sesion.clicked.connect(self.verificar_credenciales)
        self.boton_crear_usuario.clicked.connect(self.mostrar_ventana_crear_usuario)

        self.setLayout(layout)

    def verificar_credenciales(self):
        usuario = self.usuario_entry.text()
        contrasena = self.contrasena_entry.text()

        if Autenticador.verificar_credenciales(usuario, contrasena):
            self.inicio_sesion_correcto.emit()
            self.close()
        else:
            self.mostrar_mensaje("Credenciales incorrectas")

    def mostrar_ventana_crear_usuario(self):
        ventana_crear_usuario = CrearUsuarioWindow()
        if ventana_crear_usuario.exec_() == QDialog.Accepted:
            # El diálogo se cerró correctamente, puedes realizar acciones adicionales aquí si es necesario
            print("Diálogo cerrado correctamente")

    def mostrar_mensaje(self, mensaje):
        msg_box = QMessageBox()
        msg_box.setText(mensaje)
        msg_box.exec_()

if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication

    # Verifica si el archivo usuarios.json existe y créalo si no existe
    ruta_json = 'usuarios.json'
    if not os.path.exists(ruta_json):
        with open(ruta_json, 'w') as file:
            file.write('{"usuarios": []}')

    app = QApplication(sys.argv)

    login_window = LoginForm()
    login_window.show()

    sys.exit(app.exec_())