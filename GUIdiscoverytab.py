from PyQt6.QtGui import QStandardItemModel
from PyQt6.QtWidgets import QWidget, QPushButton, QComboBox, QVBoxLayout, QHBoxLayout, QTableView

from FILENAMES import *
from logger import Logger


class DiscoveryTab(QWidget):
    def __init__(self, data_handler, parent=None):
        super().__init__(parent)
        self.data_handler = data_handler
        self.log = Logger(LOGPATH, "GUI Window - Discovery tab")
        self._setup_ui()

    def _setup_ui(self):
        # Create widgets left
        discovery_button = QPushButton("Discovery")
        discovery_button.clicked.connect(self._scan_network)

        protocol_combo = QComboBox()
        protocol_combo.addItems(["Network Search"])
        # protocol_combo.currentTextChanged.connect(self._een_andere_methode)

        # Create widgets right
        self.discovery_table_view = QTableView()
        self.discovery_model = QStandardItemModel(0, 5)
        self.discovery_model.setHorizontalHeaderLabels(
            ["Naam", "IP-adres", "Firmware", "RDM UID", "Online"]
        )
        self.discovery_table_view.setModel(self.discovery_model)

        # --- LAYOUT ---
        # Main layout for this tab
        main_layout = QHBoxLayout(self)  # Set the layout directly on the widget

        # Left side: Button and Combobox
        left_layout = QVBoxLayout()
        left_layout.addWidget(discovery_button)
        left_layout.addWidget(protocol_combo)
        left_layout.addStretch()  # Pushes widgets to the top

        # Right side: Table view
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.discovery_table_view)

        main_layout.addLayout(left_layout, 1)  # Add left layout with a stretch factor of 1
        main_layout.addLayout(right_layout, 4)  # Add right layout with a stretch factor of 4 (takes more space)

    def _scan_network(self):
        pass
