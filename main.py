import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon
from login import LoginForm
from qdarkstyle import load_stylesheet_pyqt5
from snifer import EscanerDispositivos

if __name__ == "__main__":
    app = QApplication(sys.argv)

    app.setStyleSheet(load_stylesheet_pyqt5())

    # Crear la ruta del icono usando la carpeta "icon"
    icon_path = "icon/red.png"  # Ajusta el nombre de tu icono y su extensión

    # Crear el icono
    app_icon = QIcon(icon_path)

    # Configurar el icono para la aplicación
    app.setWindowIcon(app_icon)

    login_window = LoginForm()
    snifer_window = EscanerDispositivos()

    # Conectar la señal de inicio de sesión al método que abre la ventana de escaneo
    login_window.inicio_sesion_correcto.connect(snifer_window.show)

    login_window.show()

    sys.exit(app.exec_())
    