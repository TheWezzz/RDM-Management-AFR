from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QComboBox,
    QVBoxLayout,
    QLabel,
    QScrollArea,
    QCheckBox,
    QPushButton
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
        self.logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(self.logo_pixmap)
        self.setWindowIcon(logo_icon)

        self.com_handler_setup = CommunicationHandler(JSONPATH, LOGPATH)

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        self._setup_ui()

    def _setup_ui(self):
        # create top widgets
        logo_label = QLabel()
        logo_label.setPixmap(self.logo_pixmap)

        iface_info_label = QLabel("Select an interface to connect to dmXLAN")

        iface_combo_box = QComboBox()
        iface_combo_box.addItems(list(self.com_handler_setup.available_interfaces.keys()))
        iface_combo_box.textActivated.connect(self._init_mac_selection_list)

        # create lower widgets (invisible till iface_combo_box is activated)
        self.mac_info_label = QLabel("No compatible Mac addresses found")
        self.mac_info_label.setVisible(False)

        self.mac_selection_list = QScrollArea()  # widget for scroll area
        self.mac_selection_list.setVisible(False) # hide at creation untill interface is selected

        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self._init_mac_selection_list)
        self.scan_button.setVisible(False)

        # LAYOUT
        main_layout = QVBoxLayout(self.main_widget)

        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(logo_label)

        iface_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(iface_info_label)

        main_layout.addWidget(iface_combo_box)

        self.mac_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.mac_info_label)

        self.scroll_area = QWidget()
        self.mac_selection_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.mac_selection_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.mac_selection_list.setWidgetResizable(True)
        main_layout.addWidget(self.mac_selection_list)

        main_layout.addWidget(self.scan_button)

    def _init_mac_selection_list(self, iface=None):
        """
        - save selected interface and search for devices on that interface
        - show mac info label
        - create a new scroll layout, to update the mac_selection_list, and link layout to scroll area widget
        - fill the scroll layout with checkboxes containing the device description, and link widget to QScrollArea
        - show mac selection list
        - show scan button

        @:param iface: the selected interface from interface combobox
        @:return None
        """
        self.com_handler_setup.selected_interface = iface if iface else self.com_handler_setup.selected_interface
        devices = self.com_handler_setup.find_devices_by_manufacturer()  # TODO notify user to wait
        self.mac_info_label.setVisible(True)

        self.scroll_layout = QVBoxLayout()
        self.scroll_area.setLayout(self.scroll_layout)
        if devices:
            self.mac_info_label.setText("Select a device from the list")
            for dev in devices:
                self.scroll_layout.addWidget(QCheckBox(f"{dev["manufacturer"]}: {dev['ip address']}"))
            self.mac_selection_list.setWidget(self.scroll_area)
            self.mac_selection_list.setVisible(True)

        self.scan_button.setVisible(True)

    def _start_mainwindow(self, device):
        self.com_handler_setup.selected_devices = [device]
        data = create_dummy_data()
        self.main_screen = MainWindow(data, self.com_handler_setup)
        self.main_screen.show()  # TODO make sure new window shows

    # TODO add popup while waiting for ip scan, and display available ip's (in scrollable area?)
