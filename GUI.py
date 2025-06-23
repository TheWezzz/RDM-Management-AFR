import pyqtgraph as pg
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItemModel, QIcon, QPixmap
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
    QGridLayout,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QStyle
)

from data import param_to_string, datetime_to_unix, RDM_logs
from logger import Logger, INFO, WARN, ERR


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class MainWindow(QMainWindow):
    def __init__(self, data_handler: RDM_logs):  # Accepteer de RDM_logs instantie als argument
        super().__init__()
        self.log = Logger("C:/Users/Wesley/PycharmProjects/RDM Management/log", "GUI Window")
        self.setGeometry(100, 100, 1000, 600)  # Groter startvenster
        self.setWindowTitle("RDM Management")
        logo_pixmap = QPixmap("RDMlogo.jpg")
        logo_icon = QIcon(logo_pixmap)
        self.setWindowIcon(logo_icon)

        self.data_handler = data_handler  # Gebruik de meegegeven RDM_logs instantie
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self._create_discovery_tab()
        self._create_status_tab()
        self._create_history_tab()

    def _create_discovery_tab(self):
        discovery_button = QPushButton("Discovery")
        # discovery_button.clicked.connect(self._een_methode)

        protocol_combo = QComboBox()
        protocol_combo.addItems(["sACN", "RDM", "NFC"])
        # protocol_combo.currentTextChanged.connect(self._een_andere_methode)

        self.discovery_table_view = QTableView()
        self.discovery_model = QStandardItemModel(0, 5)  # Initieel 0 rijen, 5 kolommen (aanpasbaar)
        self.discovery_model.setHorizontalHeaderLabels(
            ["Naam", "IP-adres", "Firmware", "RDM UID", "Online"])  # Voorbeeld headers
        self.discovery_table_view.setModel(self.discovery_model)

        # LAYOUT
        self.discovery_tab = QWidget()
        self.tab_widget.addTab(self.discovery_tab, "Discovery")
        main_layout = QHBoxLayout(self.discovery_tab)

        # Linkerkant: Knop en Combobox
        left_layout = QVBoxLayout()
        left_layout.addWidget(discovery_button)
        left_layout.addWidget(protocol_combo)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)  # Links uitlijnen
        main_layout.addLayout(left_layout)

        # Rechterkant: Tabelview
        main_layout.addWidget(self.discovery_table_view)

        self.discovery_tab.setLayout(main_layout)

    def _create_status_tab(self):
        # TODO: convert to QTableView (Qtreeview's required methods do not match easily with the original data.
        #  RDM UID hopefully does not need to be split up anymore
        #  MVC consists of 3 major components that give a great advantage.
        #   Model holds the data structure which the app is working with.
        #   View is any representation of information as shown to the user, whether graphical or tables.
        #   Multiple views of the same data model are allowed.
        #  Controller accepts input from the user, transforming it into commands to for the model or view.
        fixture_selector = QListWidget()
        rdm_uids = self.data_handler.get_all_rdm_uids()

        try:  # TODO fix and check error printing in GUI in rest of the file
            names = self.data_handler.get_names(rdm_uids)
        except ExceptionGroup as eGroup:
            msg = f"could not retrieve data from RDM logs. {eGroup.message} caused by: "
            popup_msg = msg
            for e in eGroup.exceptions:
                log_msg = msg + e.__repr__()
                popup_msg += f"<br>{e.__repr__()}"
                self.log.write(log_msg, ERR)
            PopupDialog(popup_msg)
            exit(1)

        try:
            serials = self.data_handler.get_fws(rdm_uids)
        except ExceptionGroup as eGroupList:
            msg = f"could not retrieve data from RDM logs. {eGroupList.message}"
            popup_msg = msg
            for eGroup in eGroupList.exceptions:
                log_msg = f"{eGroup.message} caused by: ["
                popup_msg += f"<br>{eGroup.message} caused by:"
                for e in eGroup.exceptions:
                    log_msg += f"{e.__repr__()}, "
                    popup_msg += f"<br>{e.__repr__()}"
                log_msg += "]"
                self.log.write(log_msg, ERR)
            PopupDialog(popup_msg)
            exit(1)

        for i in range(len(rdm_uids)):
            list_item = QListWidgetItem(f"{names[i]} -- Serial: {serials[i]}, RDM UID: {rdm_uids[i]}")  # fixme
            fixture_selector.addItem(list_item)
        fixture_selector.currentItemChanged.connect(self._save_current_selection)
        fixture_selector.currentItemChanged.connect(self._update_status_display)

        self.status_elements_label = QLabel("Selecteer een apparaat aan de linkerkant <br> om de status te bekijken.")
        font = self.status_elements_label.font()
        font.setPointSize(20)
        self.status_elements_label.setFont(font)

        # check_status_button kan lokaal zijn, de connectie wordt hier gemaakt.
        check_status_button = QPushButton("Log current status")
        check_status_button.clicked.connect(self._log_current_status_check)

        # LAYOUT
        self.status_tab = QWidget()
        self.tab_widget.addTab(self.status_tab, "Status")
        main_layout = QHBoxLayout(self.status_tab)

        # Linkerkant: Fixture Selector (ListWidget)
        main_layout.addWidget(fixture_selector)

        # Rechterkant: Status Elementen
        status_layout = QVBoxLayout()
        self.status_elements_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        status_layout.addWidget(self.status_elements_label)
        status_layout.addWidget(check_status_button)
        main_layout.addLayout(status_layout)

        self.status_tab.setLayout(main_layout)

    def _save_current_selection(self, current, previous):
        if current and current != previous:
            self.data_handler.selected_uid = current.text().split("RDM UID: ")[1]
            self.data_handler.selected_name = current.text().split("--")[0]
            self.history_msg_label.setText(f"Geselecteerd apparaat: {self.data_handler.selected_name}")
        else:
            self.data_handler.selected_uid = None
            self.data_handler.selected_name = None
            self.history_msg_label.setText("Selecteer een apparaat")


    def _update_status_display(self):
        uid = self.data_handler.selected_uid
        timestamp, parameters, err = self.data_handler.get_latest_record(uid)
        if timestamp:
            self.status_elements_label.setText(f"<h3>Status van: {uid} </h3><r>"
                                               f"<h4>Laatst gezien op {timestamp}: </h4><r>"
                                               f"{param_to_string(parameters, "<i>", "- ", "<br>")}")
        else:
            self.status_elements_label.setText(err)

    def _log_current_status_check(self):
        pass

    def _create_history_tab(self):
        reload_button = QPushButton("Reload history data")
        reload_button.clicked.connect(self._reload_history_data)

        # selected_item_name = "Geen apparaat geselecteerd"
        # if self.data_handler.selected_uid is not None:
        #     name_tuple = self.data_handler.get_name(self.data_handler.selected_uid)
        #     if name_tuple and name_tuple[0]:
        #         selected_item_name = name_tuple[0]

        self.history_msg_label = QLabel("Selecteer een apparaat")

        # PLOT STYLE
        self.usage_plot = pg.PlotWidget()
        bottom_axis_usage = pg.AxisItem("bottom", pen="g", maxTickLength=10)
        left_axis_usage = pg.AxisItem("left", pen="g")
        self.usage_plot.setAxisItems({"bottom": bottom_axis_usage, "left": left_axis_usage})
        self.usage_plot.setLabel('bottom', 'Maand (1-12)')
        self.usage_plot.setLabel('left', 'Aantal Log-entries')
        self.usage_plot.showGrid(x=False, y=True)

        self.lamp_hour_plot = pg.PlotWidget()
        bottom_axis_hour = pg.DateAxisItem("bottom", pen="b")
        left_axis_hour = pg.AxisItem("left", pen="b")
        self.lamp_hour_plot.setAxisItems({"bottom": bottom_axis_hour, "left": left_axis_hour})
        self.lamp_hour_plot.setLabel('bottom', 'Tijd')
        self.lamp_hour_plot.setLabel('left', 'Aantal Lampuren')
        self.lamp_hour_plot.showGrid(x=True, y=True)

        # LAYOUT
        self.history_tab = QWidget()
        self.tab_widget.addTab(self.history_tab, "History")
        main_layout = QVBoxLayout(self.history_tab)

        # Top
        main_layout.addWidget(reload_button, alignment=Qt.AlignmentFlag.AlignCenter)
        self.history_msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.history_msg_label)

        # Bottom
        graph_layout = QGridLayout(self.history_tab)
        graph_layout.addWidget(self.usage_plot, 0, 0)
        graph_layout.addWidget(self.lamp_hour_plot, 0, 1)
        main_layout.addLayout(graph_layout)

        self.history_tab.setLayout(main_layout)

    def _reload_history_data(self):
        uid = self.data_handler.selected_uid
        self.log.write(f"Reloading history data for {uid}", INFO)

        # gather data
        time_history = []
        monthly_usage_history = [0] * 12  # Correcte initialisatie voor 12 maanden
        lamp_history = []
        try:
            device_records, uid_err = self.data_handler.get_device_records(uid)
        except ValueError as e:
            PopupDialog(e)
            exit(1)
        else:
            if uid_err[:4] == "WARN":
                PopupDialog(
                    uid_err)  # TODO: During this dialog the message label shows the selected uid. This should stay when dialog is closed
            self.log.write(uid_err, WARN)
        message = ""
        if device_records:
            for timestamp in device_records:
                unix_time, time_err = datetime_to_unix(timestamp)
                if unix_time == 0: # TODO convert to normal raise exception
                    message += f"ERROR:    UID: {uid} AT TIMESTAMP: {timestamp}: {time_err}\n"
                    continue

                monthly_usage_history[timestamp.month - 1] += 1

                if 'lamp_hours' in device_records[timestamp]:
                    time_history.append(unix_time)
                    lamp_history.append(device_records[timestamp]['lamp_hours'])

            # plot usage
            usage_bars = pg.BarGraphItem(x=range(1, 13), height=list(monthly_usage_history), width=0.6, brush='g')

            self.usage_plot.clear()
            self.usage_plot.addItem(usage_bars)

            # plot lamp hours
            self.lamp_hour_plot.clear()
            if time_history and lamp_history:
                self.lamp_hour_plot.setLabel('bottom', 'Tijd')  # Label voor de x-as
                self.lamp_hour_plot.setLabel('left', 'Aantal Lampuren')  # Label voor de y-as
                self.lamp_hour_plot.plot(time_history, lamp_history, pen='b')  # Teken de data: x, y, kleur blauw
            else:
                self.lamp_hour_plot.addItem(pg.TextItem("No lamp hour data found"))

        else:
            message += f"ERROR:    UID: {uid}: NO HISTORY FOUND\n"

        self.history_msg_label.setText(str_to_html(f"{uid_err}\n{message}"))


class PopupDialog(QDialog):
    def __init__(self, text, parent=None):
        super().__init__(parent=parent)
        
        # self.log.write(text)
        self.setWindowTitle("Something went wrong")

        icon_pixmap = self.style().standardPixmap(QStyle.StandardPixmap.SP_MessageBoxWarning)
        icon_label = QLabel()
        icon_label.setPixmap(icon_pixmap)

        icon = QIcon(icon_pixmap)
        self.setWindowIcon(icon)

        message = QLabel(str(text))

        buttons = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        self.buttonBox = QDialogButtonBox(buttons)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        layout = QVBoxLayout()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        layout.addWidget(message)
        layout.addWidget(self.buttonBox)
        self.setLayout(layout)

        self.exec()
