from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QComboBox,
    QVBoxLayout,
    QLabel
)

from Dummy import create_dummy_data
from FILENAMES import *
from GUI import MainWindow
from communication import CommunicationHandler
from logger import Logger


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class ConfigWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.log = Logger(LOGPATH, "Config Window")
        self.setFixedSize(500, 300)
        self.setWindowTitle("RDM Management Configuration")
        logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(logo_pixmap)
        self.setWindowIcon(logo_icon)

        self.com_handler_setup = CommunicationHandler(JSONPATH, LOGPATH)

        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)

        iface_info_label = QLabel("Select an interface to connect to dmXLAN")

        iface_combo_box = QComboBox()
        iface_combo_box.addItems(list(self.com_handler_setup.available_interfaces.keys()))
        iface_combo_box.currentTextChanged.connect(self._init_mac_combo_box)

        self.mac_info_label = QLabel("No compatible Mac addresses found")
        self.mac_info_label.setVisible(False)

        self.mac_combo_box = QComboBox()  # TODO change to checkboxlist with layout
        self.mac_combo_box.setVisible(False)

        # LAYOUT
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()

        layout.addWidget(logo_label)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(iface_info_label)
        iface_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(iface_combo_box)

        layout.addWidget(self.mac_info_label)
        self.mac_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.mac_combo_box)

        main_widget.setLayout(layout)

    def _init_mac_combo_box(self, iface):
        self.com_handler_setup.selected_interface = iface
        devices = self.com_handler_setup.find_devices_by_manufacturer()  # TODO notify user to wait
        self.mac_info_label.setVisible(True)
        if devices:
            self.mac_info_label.setText("Select a device from the list")
            for dev in devices:
                self.mac_combo_box.addItem(f"{dev["manufacturer"]}: {dev['ip address']}")
            self.mac_combo_box.currentTextChanged.connect(self._start_mainwindow)
            self.mac_combo_box.setVisible(True)

    def _start_mainwindow(self, device):
        self.com_handler_setup.selected_devices = [device]
        data = create_dummy_data()
        self.main_screen = MainWindow(data, self.com_handler_setup)
        self.main_screen.show()  # TODO make sure new window shows

    # TODO add popup while waiting for ip scan, and display available ip's (in scrollable area?)
