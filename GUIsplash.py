from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QWidget,
    QPushButton,
    QComboBox,
    QVBoxLayout,
    QHBoxLayout,
    QTableView,
    QListWidget,
    QLabel,
    QFrame,
    QGridLayout,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QStyle
)

from data import RDM_logs
from logger import Logger, INFO, WARN, ERR


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class ConfigWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.log = Logger("C:/Users/Wesley/PycharmProjects/RDM Management/log", "Config Window")
        self.setGeometry(400, 400, 500, 300)
        self.setWindowTitle("RDM Management Configuration")
        logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(logo_pixmap)
        self.setWindowIcon(logo_icon)

        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)

        info_label = QLabel("Select an interface to connect to dmXLAN")

        combo_box = QComboBox()

        # LAYOUT
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()

        layout.addWidget(logo_label)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(info_label)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout

        main_widget.setLayout(layout)