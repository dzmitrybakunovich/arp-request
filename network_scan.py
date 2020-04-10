import sys

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


if __name__ == "__main__":
    # Initial GUI
    app = arp_gui.QtWidgets.QApplication(sys.argv)
    MainWindow = arp_gui.QtWidgets.QMainWindow()
    ui = arp_gui.Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
