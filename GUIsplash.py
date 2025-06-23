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

        com_handler_setup = CommunicationHandler(JSONPath1, LogPath)

        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)

        info_label = QLabel("Select an interface to connect to dmXLAN")

        combo_box = QComboBox()
        combo_box.addItems(com_handler_setup.available_network_interfaces)

        # LAYOUT
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()

        layout.addWidget(logo_label)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(info_label)
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(combo_box)

        main_widget.setLayout(layout)
