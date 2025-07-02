import pyqtgraph as pg
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QWidget,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QLabel,
    QGridLayout,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QStyle, QApplication
)

from FILENAMES import *
from GUIdiscoverytab import DiscoveryTab
from GUIfixturetab import FixtureTab
from communication import CommunicationHandler
from data import param_to_string, datetime_to_unix, RDM_logs
from logger import Logger, INFO, WARN, ERR


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class MainWindow(QMainWindow):
    def __init__(self, data_handler: RDM_logs, com_handler: CommunicationHandler):  # Accepteer de RDM_logs instantie en com_handler als argumenten
        super().__init__()
        self.log = Logger(LOGPATH, "GUI Window")
        self.screensize = QApplication.primaryScreen().availableSize()
        self.setGeometry(100, 100, self.screensize.width() - 200, self.screensize.height() - 200)  # Groter startvenster
        self.setWindowTitle("RDM Management")
        logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(logo_pixmap)
        self.setWindowIcon(logo_icon)

        self.data_handler = data_handler  # Gebruik de meegegeven RDM_logs instantie
        self.com_handler = com_handler
        print("selected device(s): ", self.com_handler.selected_devices)

        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        discovery_tab = DiscoveryTab(data_handler)
        self.tab_widget.addTab(discovery_tab, "Discovery")
        self.fixture_tab = FixtureTab(data_handler)
        self.tab_widget.addTab(self.fixture_tab, "Status")

class PopupDialog(QDialog):
    def __init__(self, text, parent=None):
        super().__init__(parent=parent)

        # self.log.write(text)
        self.setWindowTitle("Something went wrong")

        # top
        icon_pixmap = self.style().standardPixmap(QStyle.StandardPixmap.SP_MessageBoxWarning)
        icon_label = QLabel()
        icon_label.setPixmap(icon_pixmap)

        icon = QIcon(icon_pixmap)
        self.setWindowIcon(icon)

        message = QLabel(str(text))

        # bottom
        buttons = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        self.buttonBox = QDialogButtonBox(buttons)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        # --- LAYOUT ---
        layout = QVBoxLayout(self)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        layout.addWidget(message)
        layout.addWidget(self.buttonBox)

        self.exec()
