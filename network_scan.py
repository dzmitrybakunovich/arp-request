import re
import signal
import socket
import sys
from binascii import hexlify
from ipaddress import ip_address
from struct import pack, unpack

import ifaddr
import netifaces

import arp_gui


class NetworkInterface(object):
    @staticmethod
    def find_interface(style):
        # If update network interface
        if style == 'UPDATE':
            for i in range(1, ui.interface_box.count()):
                ui.interface_box.removeItem(i)

        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            if 2 in netifaces.ifaddresses(adapter.name) and adapter.ips[0].nice_name != 'lo':
                ui.interface_box.addItem(adapter.ips[0].nice_name)
        ui.print_message(
            'NETWORK',
            'NETWORKS FOUND',
        )
        return ui.interface_box.setCurrentIndex(0)

    @staticmethod
    def setting_mask():
        adapter_name = ui.interface_box.currentText()

        # If return to the initial value
        if adapter_name == 'CHOOSE A NETWORK...':
            return ui.mask_line.setText(''), ui.ip_line.setText('')

        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            if adapter.ips[0].nice_name == adapter_name:
                adapter_mask = netifaces.ifaddresses(adapter.name)[2][0]['netmask']
                adapter_ip = adapter.ips[0].ip
                return ui.mask_line.setText(adapter_mask), ui.ip_line.setText(adapter_ip)


class ArpRequest(object):
    ip_mac = {}

    def __init__(self):
        # Connection socket RAW
        self.socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.SOCK_RAW,
        )

        # Bind interface
        if ui.interface_box.currentText() == 'CHOOSE A NETWORK...':
            arp_gui.Ui_MainWindow.print_message(
                'ERROR',
                'YOU DO NOT SELECT A NETWORK!',
            )

        else:
            self.socket.bind(
                (
                    ui.interface_box.currentText(),
                    socket.SOCK_RAW,
                )
            )

        self.my_ip = ui.ip_line.text()

    def request(self):
        if ui.interface_box.currentText() == 'CHOOSE A NETWORK...':
            return None

        else:
            ui.table.setRowCount(0)

            working_ip = self.find_working_ip()
            for ip in working_ip:
                for _ in range(10):
                    self.send_request(ip)

                self.timeout(
                    self.wait_response,
                    2,
                    ip,
                )

            for ip, mac in self.ip_mac.items():
                ui.add_table_item(
                    ip,
                    mac,
                    socket.gethostbyaddr(ip)[0],
                )

            ui.print_message(
                'NETWORK',
                'NETWORKS SCANNED',
            )

    def send_request(self, ip_destination):

        # Frame for ARP request
        frame = [
            # Ethernet header
            pack('!6B', *(0xFF,) * 6),
            self.socket.getsockname()[4],
            pack('!H', 0x0806),

            # Arp header
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            pack('!H', 0x0001),
            self.socket.getsockname()[4],
            pack('!4B',
                 *[int(x) for x in self.my_ip.split('.')]),
            pack('!6B', *(0,) * 6),
            pack('!4B',
                 *[int(x) for x in ip_destination.split('.')])
        ]

        packet = b''.join(frame)
        self.socket.send(packet)

    def wait_response(self, ip_destination):
        while True:
            packet = self.socket.recvfrom(2048)
            frame = self.socket.recv(1024)

            op = int.from_bytes(unpack('!s', frame[21:22])[0], 'big')
            if op != 2:
                continue

            ethernet_header = packet[0][0:14]
            ethernet_detailed = unpack("!6s6s2s", ethernet_header)

            arp_header = packet[0][14:42]
            arp_detailed = unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            # only listen to ARP packets
            ethertype = ethernet_detailed[2]
            if ethertype == b'\x08\x06':
                sourcemac = hexlify(arp_detailed[5]).decode('utf-8').upper()
                destmac = hexlify(arp_detailed[7]).decode('utf-8').upper()
                sourceip = ip_address(arp_detailed[6])
                destip = ip_address(arp_detailed[8])

                if sourcemac != "000000000000" and sourcemac != "FFFFFFFFFFFF":
                    if sourceip not in self.ip_mac:
                        sourcemac = re.findall(r'..', sourcemac)
                        sourcemac = ':'.join(sourcemac)
                        self.ip_mac[str(sourceip)] = sourcemac.lower()

                if destmac != "000000000000" and destmac != "FFFFFFFFFFFF":
                    if destip not in self.ip_mac:
                        destmac = re.findall(r'..', destmac)
                        destmac = ':'.join(destmac)
                        self.ip_mac[str(destip)] = destmac.lower()

            hw_size = int.from_bytes(unpack('!s', frame[18:19])[0], 'big')
            pt_size = int.from_bytes(unpack('!s', frame[19:20])[0], 'big')
            total_addresses_byte = hw_size * 2 + pt_size * 2
            arp_address = frame[22:22 + total_addresses_byte]
            src_hw, src_pt, dst_hw, dst_pt = unpack('%ss%ss%ss%ss'
                                                    % (hw_size, pt_size, hw_size, pt_size),
                                                    arp_address
                                                    )
            if src_pt == pack('!4B',
                              *[int(x) for x in ip_destination.split('.')]):
                return True

    @staticmethod
    def timeout(function, wait, ip_destination):
        def raise_timeout(num, frame):
            raise TimeRunError

        signal.signal(signal.SIGALRM, raise_timeout)
        signal.alarm(wait)
        try:
            return_value = function(ip_destination)
        except TimeRunError:
            return None
        else:
            signal.alarm(0)
            return return_value

    @staticmethod
    def find_working_ip():
        mask = list(map(int, ui.mask_line.text().split('.')))
        ip = list(map(int, ui.ip_line.text().split('.')))
        suitable_ip = list()

        # Find all ip
        for i in range(4):
            while mask[i] < 255:
                review_ip = ip[:i] + mask[i:]
                suitable_ip.append('.'.join(map(str, review_ip)))
                mask[i] += 1
                if (i + 1 != 4) and mask[i] == 255 and mask[i + 1] < 255:
                    mask[i + 1] += 1

        nice_ip = list()
        # Find work ip
        for _ in suitable_ip:
            if _ != socket.gethostbyaddr(_)[0] and _ != ui.ip_line.text():
                nice_ip += [_]
        return nice_ip


class TimeRunError(Exception):
    pass


if __name__ == "__main__":
    # Initial GUI
    app = arp_gui.QtWidgets.QApplication(sys.argv)
    MainWindow = arp_gui.QtWidgets.QMainWindow()
    ui = arp_gui.Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()

    ui.find_network_btn.clicked.connect(lambda: NetworkInterface.find_interface(style='UPDATE'))
    ui.scan_btn.clicked.connect(lambda: ArpRequest().request())
    ui.interface_box.currentTextChanged.connect(lambda: NetworkInterface.setting_mask())

    sys.exit(app.exec_())
