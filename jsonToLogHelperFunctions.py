from communication import CommunicationHandler
from logger import Logger, INFO, WARN, ERR, CRIT
from FILENAMES import *

def hex_to_str(h: str) -> str:
    """
    Convert hex message to normal message.
    Unknown bytes are replaced by '�'.
    """
    try:
        s_bytes = bytes.fromhex(h)
        return s_bytes.decode('ascii', 'replace')
    except ValueError:
        return '<?>_HEX_ERR'

class HexSelection:
    def __init__(self, name, hex_index, length, formatting) -> None:
        self.name = name
        self.hex_index = hex_index
        self.length = length
        self.formatting = formatting

fixture_name = HexSelection("Value", "0x21", 14, "ascii")

def search_payload(com_handler: CommunicationHandler, selections: list[HexSelection], prettyprint=False) -> list[dict]:
        """
        Searches in specific bytes of the json tree stored in the class. To specify a selection, a HexSelection must be
        passed containing the name of the value that is being searched for, the address index, the length which has
        to be explored after the index, and the preferred formatting.
        :param prettyprint: prints a tree with the found characters
        :param selections: a list of HexSelection objects, the result will be printed in the order these are provided
        :return: a list of lists, containing the relative time and source ip for each packet in the json tree, followed
        by the printable characters/numbers that are found in the given selections
        """
        log = Logger(LOGPATH, "Search payload function")
        log.write("search started, collecting data...", INFO)
        times = com_handler.extract_time()
        source_ips = com_handler.extract_source_ips()
        hex_payloads = com_handler.extract_udp_payloads()[0]

        selection_result = []
        for i in range(len(hex_payloads)):
            # Print een deel van de hex-message ter identificatie
            print(
                f"\nSearching in hex-message: {hex_payloads[i][:50]}...\n"
                f"(relative time: {times[i]}, total length: {len(hex_payloads[i])} characters / {len(hex_payloads[i]) // 2} bytes)\n"
                f"source: {source_ips[i]}") if prettyprint else print(f"searching packet {i}")

            values_dict = {"time": times[i], "source_ip_address": source_ips[i]}
            for sel in selections:
                if prettyprint:
                    print(f"  |\n  Zoeken naar {sel.name}")
                if isinstance(sel.hex_index, str):
                    try:
                        pointer_decimal = int(sel.hex_index, 16)
                    except ValueError:
                        log.write(f"invalid hex index: '{sel.hex_index}' (name: '{sel.name}'). skipped.", WARN)
                        continue
                else:
                    log.write(
                        f"{sel.name} has invalid index type: {type(sel.hex_index)} ('{sel.hex_index}'). skipped.",
                        WARN)
                    continue

                # Bereken de karakterposities in de hex message voor het geselecteerde byte
                # Elk byte wordt gerepresenteerd door 2 hex karakters.
                start_char_pos = pointer_decimal * 2
                end_char_pos = start_char_pos + 2

                value = ""
                for j in range(sel.length):
                    # Controleer of de berekende posities binnen de grenzen van de hex message vallen
                    if 0 <= start_char_pos < len(hex_payloads[i]) and end_char_pos <= len(hex_payloads[i]):
                        # Selecteer het paar hex-karakters (één byte)
                        byte_pair = hex_payloads[i][start_char_pos:end_char_pos]

                        if byte_pair != "00":
                            if sel.formatting == "ascii":
                                ascii_representation = hex_to_str(byte_pair)
                                value += ascii_representation
                                if prettyprint:
                                    print(f"  |  | Byte op index {start_char_pos}: "
                                          f"Hex-paar='{byte_pair}', ASCII='{ascii_representation}'")
                            elif sel.formatting == "dec":
                                dec_representation = str(int(byte_pair, 16))
                                value += dec_representation
                                value += " "
                            elif sel.formatting == "hex":
                                value += byte_pair
                            else:
                                raise SyntaxError(f"geen geldige format voor selectie {sel.name}: {sel.formatting}")

                    start_char_pos += 2
                    end_char_pos += 2
                if prettyprint:
                    print("  |  | Found characters: ", end="")
                    print(value)
                    print("  |  L", "_" * 50)  # Scheidingsteken na verwerking van elke pointer in de lijst
                values_dict.update({sel.name: value})
            if prettyprint:
                print("  L", "_" * 60)  # Scheidingsteken na verwerking van elke selection in de lijst

            selection_result.append(values_dict)
        return selection_result