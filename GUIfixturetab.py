import pyqtgraph as pg
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QWidget, QPushButton, QListWidget, QLabel, QVBoxLayout,
                             QHBoxLayout, QGridLayout, QListWidgetItem, QTabWidget)

from FILENAMES import *
from data import param_to_string, datetime_to_unix
from logger import Logger, INFO, WARN, ERR


def str_to_html(s: str) -> str:
    return s.replace("\n", "<br>")


class FixtureTab(QWidget):
    def __init__(self, data_handler, parent=None):
        super().__init__(parent)
        self.data_handler = data_handler
        self.log = Logger(LOGPATH, "GUI Window - Fixture tab")  # Path is specific

        # These need to be instance variables to be accessed by other methods
        self.status_elements_label = None
        self.history_msg_label = None
        self.usage_plot = None
        self.lamp_hour_plot = None
        self.firmware_plot = None

        self._setup_ui()

    def _setup_ui(self):
        # Create widgets left
        # TODO: convert to QTableView (Qtreeview's required methods do not match easily with the original data.
        #  RDM UID hopefully does not need to be split up anymore
        #  MVC consists of 3 major components that give a great advantage.
        #   Model holds the data structure which the app is working with.
        #   View is any representation of information as shown to the user, whether graphical or tables.
        #   Multiple views of the same data model are allowed.
        #  Controller accepts input from the user, transforming it into commands to for the model or view.
        fixture_selector = QListWidget()
        rdm_uids = self.data_handler.get_all_rdm_uids()

        names, versions = self._gather_data(rdm_uids)

        # fill listwidget
        for i in range(len(rdm_uids)):
            list_item = QListWidgetItem(f"{names[i]} -- RDM UID: {rdm_uids[i]}, Version: {versions[i]}")  # fixme
            fixture_selector.addItem(list_item)

        fixture_selector.currentItemChanged.connect(self._save_current_selection)
        fixture_selector.currentItemChanged.connect(self._update_status_display)

        # create widgets right - Tab 1
        self.status_elements_label = QLabel("Selecteer een apparaat aan de linkerkant <br> om de status te bekijken.")
        font = self.status_elements_label.font()
        font.setPointSize(16)
        self.status_elements_label.setFont(font)

        check_status_button = QPushButton("Log current status")
        check_status_button.clicked.connect(self._log_current_status_check)

        # create widgets right - Tab 2
        reload_button = QPushButton("Reload history data")
        reload_button.clicked.connect(self._reload_history_data)

        self.history_msg_label = QLabel("Selecteer een apparaat")

        self._create_history_plots()

        # --- LAYOUT ---
        # Main layout for this tab
        main_layout = QHBoxLayout(self)
        # __
        # | left side: Fixture Selector (ListWidget)
        main_layout.addWidget(fixture_selector)
        # |
        # | right side
        fixture_tab_widget = QTabWidget()
        # | __
        # | | LAYOUT - Tab 1:
        self.status_subtab = QWidget()
        fixture_tab_widget.addTab(self.status_subtab, "Fixture")
        status_layout = QVBoxLayout(self.status_subtab)
        # | |
        # | | Last status
        self.status_elements_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        status_layout.addWidget(self.status_elements_label)
        status_layout.addWidget(check_status_button)
        # | L
        # | __
        # | | LAYOUT - Tab 2:
        self.history_subtab = QWidget()
        fixture_tab_widget.addTab(self.history_subtab, "History")
        history_layout = QVBoxLayout(self.history_subtab)
        # | |
        # | | History
        history_layout.addWidget(reload_button,
                                 alignment=Qt.AlignmentFlag.AlignCenter)  # TODO convert all alignment lines to this
        self.history_msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        history_layout.addWidget(self.history_msg_label)
        # | |
        graph_layout = QGridLayout(self.history_subtab)
        graph_layout.addWidget(self.usage_plot, 0, 0)
        graph_layout.addWidget(self.lamp_hour_plot, 0, 1)
        graph_layout.addWidget(self.firmware_plot, 1, 0)
        history_layout.addLayout(graph_layout)
        # | L
        main_layout.addWidget(fixture_tab_widget)
        # L

    def _gather_data(self, rdm_uids: list = None) -> tuple:
        try:
            names = self.data_handler.get_names(rdm_uids)
        except ExceptionGroup as eGroup:
            # group of value errors with either no names found or fewer names than records, or uid error
            # eGroup.message contains "found records with invalid names"
            # then all exceptions from the eGroup are added to both log message and popup message
            msg = f"could not retrieve data from RDM logs. {eGroup.message} caused by: "
            popup_msg = msg
            for e in eGroup.exceptions:
                log_msg = msg + e.__repr__()
                popup_msg += f"<br>{e.__repr__()}"
                self.log.write(log_msg, ERR)
            # PopupDialog(popup_msg)
            exit(1)

        try:
            versions = self.data_handler.get_fws(rdm_uids)
        except ExceptionGroup as eGroupList:
            # group of Exceptiongroups containing exceptions for firmware versions per individual UID
            # eGroupList.message contains "found records with invalid firmware history"
            # eGroup is a group of value errors with either no firmware versions found
            # or fewer firmware versions than records, or uid error
            # eGroup.message contains "retrieved {rec_count} records from uid {uid}: {get_rec_text}. {none found or invalid}."
            # then all exceptions from the eGroup are added to both log message and popup message
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
            # PopupDialog(popup_msg)
            exit(1)

        return names, versions

    def _create_history_plots(self):
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

        self.firmware_plot = pg.PlotWidget()
        bottom_axis_usage = pg.AxisItem("bottom", pen="y", maxTickLength=10)
        left_axis_usage = pg.AxisItem("left", pen="y")
        self.firmware_plot.setAxisItems({"bottom": bottom_axis_usage, "left": left_axis_usage})
        self.firmware_plot.setLabel('bottom', 'Tijd')
        self.firmware_plot.setLabel('left', 'Firmware versie')
        self.firmware_plot.showGrid(x=False, y=True)

    def _save_current_selection(self, current, previous):
        if current and current != previous:
            self.data_handler.selected_uid = current.text().split(", Version")[0].split("RDM UID: ")[1]
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

    def _reload_history_data(self):
        uid = self.data_handler.selected_uid
        self.log.write(f"Reloading history data for {uid}", INFO)

        # gather data
        time_history = []
        monthly_usage_history = [0] * 12  # initialisatie voor 12 maanden
        lamp_history = []
        try:
            device_records, uid_err = self.data_handler.get_device_records(uid)
        except ValueError as e:
            # PopupDialog(e)
            exit(1)
        else:
            # if uid_err[:4] == "WARN":
            #     PopupDialog(
            #         uid_err)  # TODO: During this dialog the message label shows the selected uid. This should stay when dialog is closed
            self.log.write(uid_err, INFO)
        message = ""
        if device_records:
            for timestamp in device_records:
                unix_time, time_err = datetime_to_unix(timestamp)
                if unix_time == 0:  # TODO convert to normal raise exception
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
                self.lamp_hour_plot.plot(time_history, lamp_history, pen='b')  # Teken de data: x, y, kleur blauw
            else:
                self.lamp_hour_plot.addItem(pg.TextItem("No lamp hour data found"))

        else:
            message += f"ERROR:    UID: {uid}: NO HISTORY FOUND\n"

        self.history_msg_label.setText(str_to_html(f"{uid_err}\n{message}"))
