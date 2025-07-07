import json

from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import (
    conf,
    sniff,
    UDP,
    IP,
    ICMP,
    Ether,
    get_if_list)
from scapy.layers.l2 import getmacbyip

from logger import Logger, LogError, INFO, WARN, CRIT


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


def sniff_iface(interface, bpf_filter, function, timeout=None):
    try:
        # De sniff_iface functie.
        # `iface` specificeert de netwerkinterface.
        # `prn` is de functie die voor elk pakket wordt aangeroepen.
        # `filter` is het BPF filter.
        # `store=0` zorgt ervoor dat pakketten niet in het geheugen worden opgeslagen.
        sniff(iface=interface, prn=function, filter=bpf_filter, store=1, timeout=timeout)
    except PermissionError:
        print("[!] Fout: Geen permissie om te sniffen. Probeer het script als administrator/root uit te voeren.")
    except OSError as e:
        if "No such device" in str(e) or "Interface not found" in str(e):
            print(f"[!] Fout: Netwerkinterface '{interface}' niet gevonden.")
            print(f"    Controleer de naam van de interface en pas NETWERK_INTERFACE aan in het script.")
            print(f"    Beschikbare interfaces (vereist root/admin rechten om te zien):")
            try:
                print(f"    {get_if_list()}")
            except Exception as e_if:
                print(f"    Kon interfaces niet laden: {e_if}")
        else:
            print(f"[!] Een OSError is opgetreden: {e}")
            print(f"    Mogelijk moet Npcap (Windows) of libpcap (Linux/macOS) geïnstalleerd of bijgewerkt worden.")
    except Exception as e:
        print(f"[!] Een onverwachte fout is opgetreden: {e}")


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
            # self.log.set_printing(True)
        except LogError as e:
            print(e.__repr__())
            exit(1)

        try:
            self.json_tree = self.load_json()
        except (FileNotFoundError, InvalidJsonFormatError) as e:
            self.log.write(f"Could not initialize handler: {e.__repr__()}", CRIT)
            exit(1)

        self.maclookup = MacLookup()
        # self.maclookup.update_vendors()

        self.selected_devices = []
        self.available_ips = []
        self.selected_interface = None
        self.available_interfaces = {}
        for iface in conf.ifaces.values():
            self.available_interfaces[iface.description] = iface

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

    def sniff_artnet(self, interface):
        self.log.write(f"Sniffing for ARTNET on interface '{interface.description}'")
        sniff_iface(interface, "udp port 6454", self.add_ip_from_packet, 5)
        return self.available_ips

    def add_ip_from_packet(self, packet):
        if IP in packet:
            if packet[IP].src not in self.available_ips:
                self.available_ips.append(packet[IP].src)

    def sniff_data(self, src_ip, dest_ip, interface):
        bpf_filter = "udp"

        if src_ip:
            bpf_filter += f" and src host {src_ip}"
        if dest_ip:
            bpf_filter += f" or dst host {dest_ip}"

        sniff_iface(interface, bpf_filter, self.packet_callback)

    def packet_callback(self, packet):
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

    def find_devices_by_manufacturer(self, manuf_filter: str = None):
        """
        Scans the network of the selected interface, looks up the manufacturer of each device
        and returns a formatted list.

        @:param:
            manuf_filter (str, optional): A keyword to filter on the manufacturer name. If None, all devices will be returned.
        """
        # Look up the correct Scapy interface object
        target_iface = self.available_interfaces.get(self.selected_interface)
        if not target_iface or not target_iface.ip:
            self.log.write(f"Could not find interface '{self.selected_interface}' or it has no IP.", WARN)
            return []

        replying_ips = self.sniff_artnet(target_iface)
        replying_devices = []
        for i in range(len(replying_ips)):
            ip = replying_ips[i]
            mac = getmacbyip(ip)
            try:
                manuf = self.maclookup.lookup(mac)
            except VendorNotFoundError:
                manuf = "Unknown"
            replying_devices.append(dict({"ip address": ip, "mac address": mac, "manufacturer": manuf}))

        # print results
        print(f"found {len(replying_devices)} device{'s' if len(replying_devices) > 1 else ''}"
              f" on interface '{self.selected_interface}':")
        for device in replying_devices:
            print(f"-- ip address '{device["ip address"]}' with mac '{device["mac address"]}', "
                  f"manufacturer '{device['manufacturer']}' ")

            # Apply the filter (if specified)
            if manuf_filter:
                if manuf_filter.lower() not in device["manufacturer"].lower():
                    continue
            self.selected_devices.append(device)

        self.log.write(f"Scan completed. {len(replying_devices)} devices found matching the filter.", INFO)
        return self.selected_devices

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
                print("  L", "_" * 60)  # Scheidingsteken na verwerking van elke selection in de lijst

            selection_result.append(valuelist)
        return selection_result
