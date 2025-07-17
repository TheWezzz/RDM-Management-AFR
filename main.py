import sys

from PyQt6.QtWidgets import QApplication
from GUIsplash import ConfigWindow

if __name__ == "__main__":


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
    window = ConfigWindow()
    window.show()
    app.exec()

    # SCAPY SNIFFER TEST
    # handler1.sniff_data()