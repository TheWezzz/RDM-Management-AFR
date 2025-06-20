import json

from scapy.all import sniff

from logger import Logger, LogError, WARN, ERR, CRIT

# VARIABELEN DIE JE KUNT AANPASSEN
NETWERK_INTERFACE = "Ethernet"


def str_to_hex(s: str) -> str:
    """
    Convert message hex byte representation.
    """
    s_bytes = s.encode('ascii', 'replace')
    return s_bytes.hex()


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


class JsonKeyError(LookupError):
    def __init__(self, missing_key: str, skipped_count: int):
        message = f"could not find {missing_key}, skipped {skipped_count} packets"
        super().__init__(message)


class InvalidJsonFormatError(LookupError):
    def __init__(self, msg: str, file: str, position):
        message = f"{msg}: formatting line {position} failed. Check if file (at {file}) is in valid JSON format."
        super().__init__(message)


class HexSelection:
    def __init__(self, name, hex_index, length, formatting) -> None:
        self.name = name
        self.hex_index = hex_index
        self.length = length
        self.formatting = formatting


class CommunicationHandler:
    def __init__(self, json_path, log_path):
        self.path = json_path
        try:
            self.log = Logger(log_path, "CommunicationHandler")
        except LogError as e:
            print(e.__repr__())
            exit(1)
        try:
            self.json_tree = self.load_json()
        except (FileNotFoundError, InvalidJsonFormatError) as e:
            self.log.write(f"Could not initialize handler: {e.__repr__()}", CRIT)
            exit(1)
        self.last_payload_search = [()]
        # self.log.set_printing(True)

    def packet_callback(self, packet):
        """
        Deze functie wordt aangeroepen voor elk gesniffed pakket dat voldoet aan het filter.
        """
        # Controleer of het pakket een IP-laag en een UDP-laag heeft
        if IP in packet and UDP in packet:
            ip_layer = packet[IP]
            udp_layer = packet[UDP]

            # Haal de payload op (de data binnen het UDP pakket)
            payload = udp_layer.payload

            # Converteer payload naar hex message, vergelijkbaar me t Wireshark
            payload_hex = bytes(payload).hex()

            print(f"--- Nieuw UDP Pakket Ontvangen ---")
            print(f"Bron IP:       {ip_layer.src}")
            print(f"Doel IP:       {ip_layer.dst}")
            print(f"Bron Poort:    {udp_layer.sport}")
            print(f"Doel Poort:    {udp_layer.dport}")
            print(f"Payload Lengte:{len(payload)} bytes")
            print(f"Payload (hex): {payload_hex}")

            # Hier kun je logica toevoegen om de payload_hex te analyseren
            # Bijvoorbeeld, zoek naar specifieke RDM start codes of patronen
            # if "5253" in payload_hex: # 'RS'
            #     print("Mogelijk RDM discovery data gevonden!")

    def start_sniffer(self):
        """
        Start de Scapy sniffer.
        """
        # Bouw het BPF filter
        # Basisfilter is "udp"
        # Je kunt dit uitbreiden, bijv. "udp and port 6454"
        # of "udp and host 192.168.1.100"
        bpf_filter = "udp"

        if DOEL_POORT:
            bpf_filter += f" and port {DOEL_POORT}"
        if BRON_IP:
            bpf_filter += f" and src host {BRON_IP}"
        if DOEL_IP:
            bpf_filter += f" and dst host {DOEL_IP}"

        print(
            f"[*] Starten met sniffen op interface: {NETWERK_INTERFACE if NETWERK_INTERFACE else 'automatisch gekozen'}...")
        print(f"[*] Filter: {bpf_filter}")
        print(f"[*] Druk op CTRL+C om te stoppen.")

        try:
            # De sniff functie.
            # `iface` specificeert de netwerkinterface. Als None, probeert Scapy de default te gebruiken.
            # `prn` is de functie die voor elk pakket wordt aangeroepen.
            # `filter` is het BPF filter.
            # `store=0` zorgt ervoor dat pakketten niet in het geheugen worden opgeslagen.
            sniff(iface=NETWERK_INTERFACE, prn=self.packet_callback, filter=bpf_filter, store=0)
        except PermissionError:
            print("[!] Fout: Geen permissie om te sniffen. Probeer het script als administrator/root uit te voeren.")
        except OSError as e:
            if "No such device" in str(e) or "Interface not found" in str(e):
                print(f"[!] Fout: Netwerkinterface '{NETWERK_INTERFACE}' niet gevonden.")
                print(f"    Controleer de naam van de interface en pas NETWERK_INTERFACE aan in het script.")
                print(f"    Beschikbare interfaces (vereist root/admin rechten om te zien):")
                try:
                    from scapy.arch import get_if_list
                    print(f"    {get_if_list()}")
                except Exception as e_if:
                    print(f"    Kon interfaces niet laden: {e_if}")
            else:
                print(f"[!] Een OSError is opgetreden: {e}")
                print(f"    Mogelijk moet Npcap (Windows) of libpcap (Linux/macOS) geïnstalleerd of bijgewerkt worden.")
        except Exception as e:
            print(f"[!] Een onverwachte fout is opgetreden: {e}")

    def load_json(self) -> dict:
        try:
            with open(self.path, 'r') as f:
                packet_data = json.load(f)
        except FileNotFoundError as e:
            msg = f"File not found at '{self.path}', please check spelling. caused by {e.__repr__()}"
            raise FileNotFoundError(msg) from e
        except json.JSONDecodeError as e:
            msg = f"could not decode current Json format. caused by: {e.__repr__()}"
            raise InvalidJsonFormatError(msg, self.path, e.lineno) from e
        else:
            return packet_data

    def extract_udp_payloads(self):
        udp_payloads = []
        udp_ports = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            if ("_source" in packet and
                    "layers" in packet["_source"] and
                    "udp" in packet["_source"]["layers"] and
                    "udp.payload" in packet["_source"]["layers"]["udp"] and
                    "udp.dstport" in packet["_source"]["layers"]["udp"]):
                port = packet["_source"]["layers"]["udp"]["udp.port"]
                udp_ports.append(port)
                payload = packet["_source"]["layers"]["udp"]['udp.payload'].replace(":", "")
                udp_payloads.append(payload)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            raise JsonKeyError("UDP payload (source->layers->udp->udp.payload)",
                               skipped_packets_count)

        print(f"UDP extraction finished.")
        return udp_payloads, udp_ports

    def extract_source_ips(self):
        IPs = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            if ("_source" in packet and
                    "layers" in packet["_source"] and
                    "eth" in packet["_source"]["layers"] and
                    "eth.addr_resolved" in packet["_source"]["layers"]["eth"]["eth.dst_tree"]):
                ip = packet["_source"]["layers"]["eth"]["eth.src_tree"]['eth.addr_resolved']
                IPs.append(ip)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            raise JsonKeyError("source ip adresses(source->layers->eth->eth.src_tree->eth.addr_resolved)",
                               skipped_packets_count)

        print(f"IP extraction finished.")
        return IPs

    def extract_time(self):
        times = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            if ("_source" in packet and
                    "layers" in packet["_source"] and
                    "udp" in packet["_source"]["layers"] and
                    "udp.time_relative" in packet["_source"]["layers"]["udp"]["Timestamps"]):
                time = packet["_source"]["layers"]["udp"]["Timestamps"]["udp.time_relative"]
                times.append(time)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            raise JsonKeyError("time(source->layers->udp->timestamps->udp.time_relative)",
                               skipped_packets_count)

        print(f"Time extraction finished.")
        return times

    def search_payload(self, selections: list[HexSelection], prettyprint=False) -> list[list]:
        """
        Searches in specific bytes of the json tree stored in the class. To specify a selection, a HexSelection must be
        passed containing the name of the value that is being searched for, the address index, the length which has
        to be explored after the index, and the preferred formatting.
        :param selections: a list of HexSelection objects, the result will be printed in the order these are provided
        :return: a list of lists, containing the relative time and source ip for each packet in the json tree, followed
        by the printable characters/numbers that are found in the given selections
        """

        times = self.extract_time()
        source_ips = self.extract_source_ips()
        hex_payloads = self.extract_udp_payloads()[0]

        selection_result = []
        for i in range(len(hex_payloads)):
            # Print een deel van de hex-message ter identificatie
            print(
                f"\nSearching in hex-message: {hex_payloads[i][:50]}...\n"
                f"(relative time: {times[i]}, total length: {len(hex_payloads[i])} characters / {len(hex_payloads[i]) // 2} bytes)\n"
                f"source: {source_ips[i]}") if prettyprint else print(f"searching packet {i}")

            valuelist = [times[i], source_ips[i]]
            for sel in selections:
                if prettyprint:
                    print(f"  |\n  Zoeken naar {sel.name}")
                if isinstance(sel.hex_index, str):
                    try:
                        pointer_decimal = int(sel.hex_index, 16)
                    except ValueError:
                        self.log.write(f"invalid hex index: '{sel.hex_index}' (name: '{sel.name}'). skipped.", WARN)
                        continue
                else:
                    self.log.write(
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
                valuelist.append(value)
            if prettyprint:
                print("  L", "_" * 60)  # Scheidingsteken na verwerking van elke pointer in de lijst

            selection_result.append(valuelist)
        self.last_payload_search = selection_result
        return selection_result
