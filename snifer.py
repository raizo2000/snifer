import sys
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QMainWindow, QDesktopWidget
from scapy.all import ARP, Ether, get_if_hwaddr, srp
import socket
import manuf
import requests

class EscanerDispositivos(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Escanear Dispositivos en la Red')
        self.setGeometry(100, 100, 1200, 800)

        self.label_ip = QLabel('Dirección IP de la Red:', self)
        self.ip_entry = QLineEdit(self)
        self.boton_escanear = QPushButton('Escanear Dispositivos', self)
        self.result_table = QTableWidget(self)
        self.result_table.setColumnCount(5)
        self.result_table.setHorizontalHeaderLabels(["IP", "MAC", "Nombre", "Tipo", "Usuario-Agent"])
        self.result_table.horizontalHeader().setStretchLastSection(True)

        layout = QVBoxLayout()
        layout.addWidget(self.label_ip)
        layout.addWidget(self.ip_entry)
        layout.addWidget(self.boton_escanear)
        layout.addWidget(self.result_table)

        self.boton_escanear.clicked.connect(self.iniciar_escaneo)

        self.setLayout(layout)

    def llenar_tabla(self, dispositivos):
        self.result_table.setRowCount(len(dispositivos))
        for idx, dispositivo in enumerate(dispositivos):
            self.result_table.setItem(idx, 0, QTableWidgetItem(dispositivo['ip']))
            self.result_table.setItem(idx, 1, QTableWidgetItem(dispositivo['mac']))
            self.result_table.setItem(idx, 2, QTableWidgetItem(dispositivo['nombre']))
            self.result_table.setItem(idx, 3, QTableWidgetItem(dispositivo['tipo']))
            self.result_table.setItem(idx, 4, QTableWidgetItem(dispositivo['usuario_agente']))

    def obtener_nombre_dispositivo(self, ip):
        try:
            nombre = socket.gethostbyaddr(ip)[0]
            return nombre
        except socket.herror:
            return "Nombre no disponible"

    def obtener_mac_propia(self):
        try:
            return get_if_hwaddr('eth0')  # Reemplaza 'eth0' con el nombre de tu interfaz de red
        except:
            return None

    def obtener_tipo_dispositivo(self, mac):
        parsed_mac = manuf.MacParser()
        vendor = parsed_mac.get_manuf(mac)
        return vendor if vendor else "Desconocido"

    def obtener_info_usuario_agente(self, ip):
        try:
            url = f'http://{ip}'
            response = requests.get(url)
            user_agent = response.headers.get('User-Agent', 'No disponible')
            return user_agent
        except Exception as e:
            return f"Error al obtener información del usuario-agente: {str(e)}"

    def escanear_dispositivos(self, ip):
        try:
            paquete_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            resultado = srp(paquete_arp, timeout=3, verbose=0)[0]

            dispositivos = []
            mac_propia = self.obtener_mac_propia()

            for sent, received in resultado:
                nombre_dispositivo = self.obtener_nombre_dispositivo(received.psrc)
                tipo_dispositivo = self.obtener_tipo_dispositivo(received.hwsrc)
                info_usuario_agente = self.obtener_info_usuario_agente(received.psrc)

                es_propio = " (Este dispositivo)" if received.hwsrc == mac_propia else ""
                dispositivos.append({'ip': received.psrc, 'mac': received.hwsrc, 'nombre': nombre_dispositivo,
                                     'tipo': tipo_dispositivo, 'usuario_agente': info_usuario_agente})

            return dispositivos

        except Exception as e:
            self.result_table.setRowCount(0)
            self.result_table.clearContents()
            self.result_table.setHorizontalHeaderLabels(["IP", "MAC", "Nombre", "Tipo", "Usuario-Agent"])
            self.result_table.setRowCount(1)
            self.result_table.setItem(0, 0, QTableWidgetItem(f"Error al escanear dispositivos: {str(e)}"))
            return []

    def iniciar_escaneo(self):
        self.result_table.clearContents()
        self.result_table.setRowCount(0)
        ip_red = self.ip_entry.text()
        dispositivos = self.escanear_dispositivos(ip_red)
        self.llenar_tabla(dispositivos)


if __name__ == '__main__':
    app = QMainWindow(sys.argv)
    ventana = EscanerDispositivos()
    ventana.show()
    sys.exit(app.exec_())
    