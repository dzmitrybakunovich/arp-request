import socket
import sys

import ifaddr
import netifaces
import scapy.all as scapy

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
        return ui.interface_box.setCurrentIndex(1)

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

    @staticmethod
    def get_ip_and_mac(ip):
        response_dict = dict()

        arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
        arp_response = scapy.srp(arp_request, timeout=2, verbose=False)[0]
        if not arp_response:
            return None
        for item in arp_response:
            response_dict[item[1].psrc] = item[1].hwsrc
            if item[1].pdst not in response_dict:
                response_dict[item[1].pdst] = item[1].dst
        return response_dict

    def request_response_arp(self):
        if ui.interface_box.currentText() == 'CHOOSE A NETWORK...':
            return None
        else:
            ui.table.setRowCount(0)

            suitable_ip = self.find_working_ip()
            arp = self.get_ip_and_mac(suitable_ip)

            for ip, mac in arp.items():
                ui.add_table_item(
                    ip,
                    mac,
                    socket.gethostbyaddr(ip)[0],
                )
            return arp

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

        return suitable_ip


if __name__ == "__main__":
    # Initial GUI
    app = arp_gui.QtWidgets.QApplication(sys.argv)
    MainWindow = arp_gui.QtWidgets.QMainWindow()
    ui = arp_gui.Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()

    ui.find_network_btn.clicked.connect(lambda: NetworkInterface.find_interface(style='UPDATE'))
    ui.scan_btn.clicked.connect(lambda: ArpRequest().request_response_arp())
    ui.interface_box.currentTextChanged.connect(lambda: NetworkInterface.setting_mask())

    sys.exit(app.exec_())
