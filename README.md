import socket
import struct
import threading

class SuperSniffle:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.running = False

    def start_sniffing(self):
        self.running = True
        sniffing_thread = threading.Thread(target=self.sniff)
        sniffing_thread.start()

    def stop_sniffing(self):
        self.running = False

    def sniff(self):
        while self.running:
            raw_data, _ = self.sock.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(raw_data)
            
            # Add your processing logic here
            print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, EtherType: {eth_proto}")
            print(f"Data: {data}\n")

    def parse_ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return self.format_mac_address(dest_mac), self.format_mac_address(src_mac), socket.htons(proto), data[14:]

    def format_mac_address(self, mac_address):
        formatted_mac = ':'.join(map('{:02x}'.format, mac_address))
        return formatted_mac

if __name__ == "__main__":
    super_sniffle = SuperSniffle()
    super_sniffle.start_sniffing()

    try:
        input("Press Enter to stop sniffing...")
    except KeyboardInterrupt:
        pass
    finally:
        super_sniffle.stop_sniffing()
