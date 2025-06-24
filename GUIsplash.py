from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QComboBox,
    QVBoxLayout,
    QLabel
)

from communication import CommunicationHandler
from logger import Logger

JSONPath1 = "C:/Users/Wesley/PycharmProjects/RDM Management/Ayrton domino packages.json"
LogPath = "C:/Users/Wesley/PycharmProjects/RDM Management/log"


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class ConfigWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.log = Logger("C:/Users/Wesley/PycharmProjects/RDM Management/log", "Config Window")
        self.setFixedSize(500, 300)
        self.setWindowTitle("RDM Management Configuration")
        logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(logo_pixmap)
        self.setWindowIcon(logo_icon)

        self.com_handler_setup = CommunicationHandler(JSONPath1, LogPath)

        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)

        iface_info_label = QLabel("Select an interface to connect to dmXLAN")

        iface_combo_box = QComboBox()
        iface_combo_box.addItems(list(self.com_handler_setup.available_interfaces.keys()))
        iface_combo_box.currentTextChanged.connect(self._init_mac_combo_box)

        self.mac_info_label = QLabel("No compatible Mac addresses found")
        self.mac_info_label.setVisible(False)

        self.mac_combo_box = QComboBox()
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
        self.com_handler_setup.interface = iface
        filtered_mac_list = self.com_handler_setup.find_devices_by_manufacturer(iface, "lukas")
        print(f"devices that match filter: {filtered_mac_list}")
        if len(filtered_mac_list) > 0:
            self.mac_info_label.setText("Select a mac from the list")
            self.mac_combo_box.addItems(filtered_mac_list)
            self.mac_info_label.setVisible(True)
            self.mac_combo_box.setVisible(True)
