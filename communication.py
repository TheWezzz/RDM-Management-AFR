import json

from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import (
    conf,
    sniff,
    UDP,
    IP,
    ICMP,
    Ether)
from scapy.layers.l2 import getmacbyip

from logger import Logger, LogError, INFO, WARN, ERR, CRIT


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

        self.available_devices = []  # list that holds the replying devices on a network interface, optionally filtered
        self.selected_devices = []

        self.available_ips = []  # list that holds the replying ip's on a network interface

        self.selected_interface = None
        self.available_interfaces = {}
        for iface in conf.ifaces.values():
            self.available_interfaces[iface.description] = iface

    # ==========| JSON formatting and read/write |==========
    def load_json(self) -> dict:
        try:
            with open(self.path, 'r') as f:
                packet_data = json.load(f)
        except FileNotFoundError as e:
            msg = f"File not found at '{self.path}', please check spelling. caused by {e.__repr__()}"
            raise FileNotFoundError(msg) from e
        except json.JSONDecodeError as e:
            if e.lineno == 1:
                # file is probably empty, returning empty list
                return {}
            msg = f"could not decode current Json format. caused by: {e.__repr__()}"
            raise InvalidJsonFormatError(msg, self.path, e.lineno) from e
        else:
            return packet_data

    def json_write_packet(self, packet):
        """
        Loads the existing JSON file,
        appends the new packet, and writes the entire list back to the file.
        This ensures the JSON file remains a valid list of packet objects.

        :param packet: The Scapy packet to be added to the JSON file.
        """
        # Read the existing data, append the new packet, and write back.
        try:
            # Load all current packets from the file. load_json handles empty/new files.
            all_packets = self.load_json()
            if not isinstance(all_packets, list):
                self.log.write(f"JSON file '{self.path}' is not a list. Starting a new list.", WARN)
                all_packets = []
        except FileNotFoundError:
            # If the file doesn't exist we start with an empty list.
            self.log.write(f"File not found, creating a new packet list.", WARN)
            all_packets = []
        except InvalidJsonFormatError:
            self.log.write(f"JSON file is not a valid JSON format. Starting a new list", WARN)
            all_packets = []
        # Append the new packet dictionary
        all_packets.append(self.packet_to_json(packet))
        # Write the updated list back to the file
        try:
            with open(self.path, 'w') as f:
                # Overwrite the file with the updated list of packets.
                # indent=4 makes the file human-readable.
                json.dump(all_packets, f, ensure_ascii=False, indent=4)
            self.log.write(f"Packet '{packet.summary()}' appended to JSON file", INFO)
        except IOError as e:
            self.log.write(f"Failed to write to JSON file: {e}", CRIT)

    def packet_to_json(self, packet) -> dict:
        """
        Formats a Scapy packet into a structured dictionary for JSON serialization.

        :param packet: The Scapy packet.
        :return: A dictionary with key information from the packet.
        """
        packet_dict = {
            "timestamp": packet.time,  # Unix timestamp of packet arrival
            "summary": packet.summary(),
            "layers": {}
        }

        # Ethernet Layer
        if Ether in packet:
            packet_dict["layers"]["eth"] = {
                "src": packet[Ether].src,
                "dst": packet[Ether].dst
            }

        # IP Layer
        if IP in packet:
            packet_dict["layers"]["ip"] = {
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "len": packet[IP].len,
                "proto": packet[IP].proto
            }

        # UDP Layer
        if UDP in packet:
            # Get the raw payload and convert it to a hex string
            payload_hex = bytes(packet[UDP].payload).hex()

            packet_dict["layers"]["udp"] = {
                "sport": packet[UDP].sport,
                "dport": packet[UDP].dport,
                "len": packet[UDP].len,
                "payload": payload_hex  # Store payload as a clean hex string
            }

        # ICMP Layer
        if ICMP in packet:
            packet_dict["layers"]["icmp"] = {
                "type": packet[ICMP].type,
                "code": packet[ICMP].code
            }
        print(packet_dict)
        return packet_dict

    # ==========| Ethernet sniffing, searching packets |==========
    def sniff_iface(self, interface, bpf_filter, function, timeout=None):
        try:
            # De sniff_iface functie.
            # `iface` specificeert de netwerkinterface.
            # `prn` is de functie die voor elk pakket wordt aangeroepen.
            # `filter` is het BPF filter.
            # `store=0` zorgt ervoor dat pakketten niet in het geheugen worden opgeslagen.
            self.log.write(
                f"Sniffing on interface '{interface}' with bpf filter '{bpf_filter}' "
                f"{f"for {timeout} seconds" if timeout else f"until input"}", INFO)
            sniff(iface=interface, prn=function, filter=bpf_filter, store=1, timeout=timeout)
        except PermissionError:
            self.log.write(f"Permission denied for interface {interface}, try to run as administrator", CRIT)
        except OSError as e:
            if "No such device" in str(e) or "Interface not found" in str(e):
                self.log.write(f"Network interface '{interface}' not found, check name")
            else:
                self.log.write(f"OS error occured, Npcap or libpcap possibly needs to be installed or updated: {e}")
        except Exception as e:
            self.log.write(f"An unexpected error occured: {e}")

    def sniff_artnet(self, interface):
        self.log.write(f"Sniffing for ARTNET on interface '{interface.description}'", INFO)
        self.sniff_iface(interface, "udp port 6454", self.add_ip_from_packet, 3)
        return self.available_ips

    def add_ip_from_packet(self, packet):
        if IP in packet:
            if packet[IP].src not in self.available_ips:
                self.available_ips.append(packet[IP].src)

    def sniff_data(self, src_ip: list = None):
        bpf_filter = "udp"
        if src_ip:
            bpf_filter += f" and src host {src_ip}"

        self.sniff_iface(self.selected_interface, bpf_filter, self.packet_callback, 3)

    def packet_callback(self, packet):
        # Controleer of het pakket een IP-laag en een UDP-laag heeft
        if IP in packet and UDP in packet:
            ip_layer = packet[IP]
            udp_layer = packet[UDP]

            # Haal de payload op (de data binnen het UDP pakket)
            payload = udp_layer.payload

            # Converteer payload naar hex message, vergelijkbaar me t Wireshark
            payload_hex = bytes(payload).hex()

            # Write the received packet to the JSON file
            self.json_write_packet(packet)

        else:
            self.log.write("unexpected ip packet passed filter. Check settings and filter", ERR)

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

            if manuf_filter:
                # skip when filter text is not found in device manufacturer
                if (manuf_filter.lower() not in device["manufacturer"].lower() or
                        # skip when device manufacturer is already added to selected devices
                        device["manufacturer"] in self.selected_devices):
                    continue
            self.available_devices.append(device)

        self.log.write(f"Scan completed. {len(replying_devices)} devices found matching the filter.", INFO)
        return self.available_devices

    def extract_udp_payloads(self):
        udp_payloads = []
        udp_ports = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            # Check if the required keys exist in our new format
            if ("layers" in packet and
                "udp" in packet["layers"] and
                "payload" in packet["layers"]["udp"]):

                # Extract port and payload from the new structure
                port = packet["layers"]["udp"].get("dport", "N/A")  # .get is safer
                udp_ports.append(port)
                payload = packet["layers"]["udp"]["payload"]  # No need for .replace(":", "") anymore
                udp_payloads.append(payload)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            # Updated error message for clarity
            self.log.write(f"Skipped {skipped_packets_count} packets that did not contain a UDP payload.", WARN)
            raise JsonKeyError("UDP payload (source->layers->udp->udp.payload)", # TODO update paths in jsonkeyerrors
                               skipped_packets_count)

        return udp_payloads, udp_ports

    def extract_source_ips(self):
        IPs = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            # Check for the IP layer and the source IP key
            if ("layers" in packet and
                    "ip" in packet["layers"] and
                    "src" in packet["layers"]["ip"]):
                ip = packet["layers"]["ip"]["src"]
                IPs.append(ip)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            self.log.write(f"Skipped {skipped_packets_count} packets that did not contain a source IP address.", WARN)
            raise JsonKeyError("source ip adresses(source->layers->eth->eth.src_tree->eth.addr_resolved)",
                               skipped_packets_count)

        return IPs

    def extract_time(self):
        times = []
        skipped_packets_count = 0
        for packet in self.json_tree:
            # Check for the top-level timestamp key
            if "timestamp" in packet:
                time = packet["timestamp"]
                times.append(time)
            else:
                skipped_packets_count += 1
                continue
        if skipped_packets_count > 0:
            self.log.write(f"Skipped {skipped_packets_count} packets that did not have a timestamp.", WARN)
            raise JsonKeyError("time(source->layers->udp->timestamps->udp.time_relative)",
                               skipped_packets_count)

        return times

    def search_payload(self, selections: list[HexSelection], prettyprint=False) -> list[list]:
        """
        Searches in specific bytes of the json tree stored in the class. To specify a selection, a HexSelection must be
        passed containing the name of the value that is being searched for, the address index, the length which has
        to be explored after the index, and the preferred formatting.
        :param prettyprint: prints a tree with the found characters
        :param selections: a list of HexSelection objects, the result will be printed in the order these are provided
        :return: a list of lists, containing the relative time and source ip for each packet in the json tree, followed
        by the printable characters/numbers that are found in the given selections
        """

        self.log.write("search started, collecting data...", INFO)
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
