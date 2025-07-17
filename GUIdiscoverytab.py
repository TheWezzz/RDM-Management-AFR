import datetime
from PyQt6.QtGui import QStandardItemModel, QStandardItem
from PyQt6.QtWidgets import QWidget, QPushButton, QComboBox, QVBoxLayout, QHBoxLayout, QTableView, QLabel

from FILENAMES import *
from data import str_to_html
from jsonToLogHelperFunctions import *
from logger import Logger


class DiscoveryTab(QWidget):
    def __init__(self, com_handler, parent=None):
        super().__init__(parent)
        self.com_handler = com_handler
        self.log = Logger(LOGPATH, "GUI Window - Discovery tab")
        self._setup_ui()

    def _setup_ui(self):
        # Create widgets left
        discovery_button = QPushButton("Discovery")
        discovery_button.clicked.connect(self._scan_network)

        protocol_combo = QComboBox()
        protocol_combo.addItems(["Network Search"])
        # protocol_combo.currentTextChanged.connect(self._een_andere_methode)

        info_label = QLabel(str_to_html(self.com_handler.get_info()))
        # Create widgets right
        self.discovery_table_view = QTableView()
        self.discovery_model = QStandardItemModel(0, 5)
        self.discovery_model.setHorizontalHeaderLabels(["Tijd", "IP-adres", "Naam", "Firmware", "RDM UID"])
        self.discovery_table_view.setModel(self.discovery_model)

        # --- LAYOUT ---
        # Main layout for this tab
        main_layout = QHBoxLayout(self)

        # Left side: Button and Combobox
        left_layout = QVBoxLayout()
        left_layout.addWidget(discovery_button)
        left_layout.addWidget(protocol_combo)
        left_layout.addWidget(info_label)
        left_layout.addStretch()  # Pushes widgets to the top

        # Right side: Table view
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.discovery_table_view)

        main_layout.addLayout(left_layout, 1)  # Add left layout with a stretch factor of 1
        main_layout.addLayout(right_layout, 4)  # Add right layout with a stretch factor of 4 (takes more space)

    def _scan_network(self):
        self.com_handler.sniff_json_data("selected")
        selection_result = search_payload(self.com_handler, [fixture_name])
        for res in selection_result:
            self._add_row_to_model(res)

    def _add_row_to_model(self, param_dict):
        time = str(datetime.datetime.fromtimestamp(param_dict.pop("time")))
        ip = str(param_dict.pop("source_ip_address"))

        itemlist = [QStandardItem(time), QStandardItem(ip)]
        for key in param_dict.keys():
            if key not in ["time", "source_ip_address"]:
                itemlist.append(QStandardItem(str(param_dict.get(key, ""))))
        self.discovery_model.appendRow(itemlist)