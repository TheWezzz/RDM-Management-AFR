import sys

from PyQt6.QtWidgets import QApplication
from GUI import MainWindow
from GUIsplash import ConfigWindow

from FILENAMES import *
from Dummy import create_dummy_data
from communication import CommunicationHandler, HexSelection
from logger import ERR


if __name__ == "__main__":

    # JSON EXTRACTION
    start_selection = HexSelection("Start of payload", "0x0a", 3, "dec")
    try1 = HexSelection("matching couples", "0x09", 1, "dec")
    value_selection = HexSelection("Value", "0x21", 14, "ascii")

    # try:
    #     res = handler1.search_payload([start_selection, try1, value_selection], prettyprint=False)
    #     # res = handler2.search_payload([field_selection, value_selection])
    # except LookupError as e:
    #     msg = f"something went wrong during extraction of selections from json file"
    #     handler1.log.write(f"{msg}, caused by {e.__repr__()}", ERR)
    #     exit(1)
    # except SyntaxError as e:
    #     res = []
    #     print(f"formatting result failed: {e}")
    #     exit(1)


    # DUMMY DATA TEST
    app = QApplication(sys.argv)
    data = create_dummy_data()
    window = ConfigWindow()
    window.show()
    app.exec()

    # SCAPY SNIFFER TEST
    # handler1.sniff_data()