import json

from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.spinner import Spinner

from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.checkbox import CheckBox

# ###

import socket
import paramiko as pr
import os
import requests
import re
import time

# Below.: these dependencies are for successful build on Android platform; unused but required!
import cryptography
import bcrypt
import nacl.utils
import nacl.public
import nacl.secret
import nacl.signing

# ###
# BACKEND
# ###

from kivy.utils import platform

if platform == "android":
    from android.permissions import request_permissions, Permission

    request_permissions(
        [Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE, Permission.ACCESS_NETWORK_STATE,
         Permission.ACCESS_WIFI_STATE, Permission.INTERNET])

# Below.: is the BROADCAST address for your network; change accordingly
udp_ip = '255.255.255.255'
udp_port = 9

# Below.: Definition of constants
database_file = 'db.tx'
credentials_file = 'db_creds.tx'
irmc_db = 'irmc_db.tx'


# Below.: Simple conversion of MAC for further use within app; trimming of ':'
def prepare_mac(raw_mac):
    try:
        mac = raw_mac.replace(":", "")
        mac = mac.lower()
        mac = bytearray.fromhex(mac)
        return mac
    except:
        GUI.generic_info_popup("Invalid MAC address!")


# Below.: by passing IP address, the function returns the MAC address of the device
def translate_ip_to_mac(ip):
    return ip_mac_database.get(ip)


# Below.: reach for the database file and load it as a dictionary; create a new one if not found
def database_loader():
    try:
        file = open(database_file, 'r')
    except:
        file = open(database_file, 'x')
        file.write('\n')
        file.close()
        file = open(database_file, 'r')

    try:
        file_credentials = open(credentials_file, 'r')
    except:
        file_credentials = open(credentials_file, 'x')
        file_credentials.write('\n')
        file_credentials.close()
        file_credentials = open(credentials_file, 'r')

    data = file.readlines()[
        -1]  # reads the last line of the file; this entry holds the latest additions to the database
    try:
        data_credentials = file_credentials.readlines()[-1]
    except:
        GUI.generic_info_popup("No SSH credentials found!")
        data_credentials = '\n'
        file_credentials.close()
        file.close()

    global ssh_credentials
    global ip_mac_database
    global irmc_ips

    if data == '\n':  # if the file is empty, create a new entry to it
        ip_mac_database = {}
        ip_mac_database['0.0.0.0'] = '00:00:00:00:00:00'  # Placeholder for IP - MAC mapping
    else:
        ip_mac_database = eval(data)  # if the file is not empty, load it as a dictionary
        try:
            del ip_mac_database['']
        except:
            file.close()
    file.close()

    if data_credentials == '\n':  # if the file is empty, create a new entry to it
        ssh_credentials = {}
    else:
        ssh_credentials = eval(data_credentials)  # if the file is not empty, load it as a dictionary
    file_credentials.close()

    try:
        irmc_data = open(irmc_db, 'r')
    except:
        irmc_data = open(irmc_db, 'x')
        irmc_data.write('\n')
        irmc_data.close()
        irmc_data = open(irmc_db, 'r')
    irmc_data_entries = irmc_data.readlines()[-1]

    if irmc_data_entries == '\n':
        irmc_ips = {}
    else:
        irmc_ips = eval(irmc_data_entries)
    irmc_data.close()


# Below.: STRINGIFY the dictionaries and write them to the database files
def dump_database_to_file():
    file = open(database_file, 'a')
    if "0.0.0.0" in ip_mac_database.keys():
        print(ip_mac_database["0.0.0.0"])
        del ip_mac_database["0.0.0.0"]
    pretreated_data = str(ip_mac_database)
    file.write('\n')
    file.write(pretreated_data)
    file.close()

    file_credentials = open(credentials_file, 'a')
    pretreated_data_credentials = str(ssh_credentials)
    file_credentials.write('\n')
    file_credentials.write(pretreated_data_credentials)
    file_credentials.close()

    file_irmc_data = open(irmc_db, 'a')
    pretreated_data_irmc = str(irmc_ips)
    file_irmc_data.write('\n')
    file_irmc_data.write(pretreated_data_irmc)
    file_irmc_data.close()


# Below.: ssh_handler CLASS holds functions crucial for the SSH connection
class ssh_handler:

    def test_function(host_to_connect):
        ssh_client = pr.SSHClient()
        ssh_client.set_missing_host_key_policy(pr.AutoAddPolicy())
        ssh_credentials_list = list(ssh_credentials.items())
        usr, passwd = ssh_credentials_list[-1][0], ssh_credentials_list[-1][1]
        ssh_client.connect(host_to_connect, username=usr, password=passwd)
        stdin, stdout, stderr = ssh_client.exec_command('uname -a')

    def shutdown_proxmox_via_ssh(selected_ip):
        if selected_ip == "0.0.0.0":
            GUI.info_popup_wrong_ip()
            return
        if udp_socket.ping_selected_ip(str(selected_ip)) == True:
            pass
        else:
            GUI.generic_info_popup("No ECHO REPLY from selected IP")
            return
        ssh_client = pr.SSHClient()
        ssh_client.set_missing_host_key_policy(pr.AutoAddPolicy())
        ssh_credentials_list = list(ssh_credentials.items())
        try:
            usr, passwd = ssh_credentials_list[-1][0], ssh_credentials_list[-1][1]
        except:
            GUI.generic_info_popup("No SSH credentials found!")
            return
        ssh_client.connect(selected_ip, username=usr, password=passwd)
        stdin, stdout, stderr = ssh_client.exec_command(
            'net_dev=$(ip a | grep -Eo "en[a-z0-9]+" | grep -Eo "^enp[0-9][a-z]0\b");'  # get the network device name
            ' ethtool -s $net_dev wol g;'  # set the WOL mode to magic packet
            'qm list | grep "running" | awk `{print $1}` | xargs -n1 shutdown ;'  # shutdown all running VMs 
            'shutdown -h now')  # shutdown the host

    # Below.: terminate established SSH connection
    @staticmethod
    def close_ssh_connection(*cls):
        ssh_client = pr.SSHClient()
        ssh_client.close()


# Below.: udp_socket CLASS holds functions crucial for opening and closing UDP socket PLUS generating the UDP WOL packet
class udp_socket:

    def send_magic_packet(selected_mac):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(b"\xff" * 6 + prepare_mac(selected_mac) * 16,
                        (udp_ip, udp_port))  # payload for the UDP WOL packet
            sock.close()
        except:
            GUI.generic_info_popup("Could not send WOL packet\nCheck if the selected MAC is correct")

    def ping_selected_ip(selected_ip):
        if str(selected_ip) == "Pick item":
            return False
        ping_result = os.system("ping -c1 -W1 " + str(selected_ip))  # ping the selected IP
        if ping_result == 0:
            return True
        else:
            return False


# Below.: class for auto-discovery of Promox hypervisors within selected network
class discovery:
    global proxmox_ips
    proxmox_ips = []

    global proxmox_ips_mac
    proxmox_ips_mac = {}

    def convert_CIDR(subnet_and_port):

        subnetwork_port = list(subnet_and_port.values())[0]

        ip_start = list(subnet_and_port.keys())[0][0]
        ip_range = list(subnet_and_port.keys())[0][1]
        ip_end = ip_start.split('.')
        if len(ip_end) != 4:
            GUI.generic_info_popup("Wrong IP format")
            return
        ip_end[3] = str(int(ip_end[3]) + int(ip_range))
        if int(ip_end[3]) > 255:
            ip_end[3] = str(int(ip_end[3]) - 255)
            ip_end[2] = str(int(ip_end[2]) + 1)
        ip_end = '.'.join(ip_end)

        return discovery.scan_network(start_ip=ip_start, end_ip=ip_end, subnetwork_port=subnetwork_port)

    def scan_network(*self, start_ip, end_ip, subnetwork_port):
        ip_masked_address = start_ip.split('.')
        ip_masked_address = ip_masked_address[0] + '.' + ip_masked_address[1] + '.' + ip_masked_address[2] + '.'
        #
        # WHAT IF THIRD OCTET HAS INCREASED?
        #
        port = str(subnetwork_port)
        ip_range = [ip_masked_address + str(i) for i in range(2, 6)]
        for ip in ip_range:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, int(port)))
            except:
                GUI.generic_info_popup("Could not connect\nto the selected IPs")
                return
            if result == 0:
                proxmox_ips.append(ip)
            else:
                continue
            sock.close()
        return discovery.verify_if_proxmox(proxmox_ips)

    def verify_if_proxmox(proxmox_ips):
        port = "8006"
        for ip in proxmox_ips:
            https_response = requests.get("https://" + str(ip) + ":" + str(port), verify=False)
            tx = https_response.text
            response = re.split("<title>", tx)
            response = re.split("</title>", response[1])
            response = response[0]
            if "Proxmox" in response:
                continue
            else:
                proxmox_ips.remove(ip)
                continue
        return discovery.retrive_proxmox_mac(proxmox_ips)

    def retrive_proxmox_mac(proxmox_ips):
        for ip in proxmox_ips:
            ssh_client = pr.SSHClient()
            ssh_client.set_missing_host_key_policy(pr.AutoAddPolicy())
            ssh_credentials_list = list(ssh_credentials.items())
            try:
                usr, passwd = ssh_credentials_list[-1][0], ssh_credentials_list[-1][1]
            except:
                GUI.generic_info_popup("No SSH credentials found!")
                return
            ssh_client.connect(ip, username=usr, password=passwd)
            ip = str(ip)
            stdin, stdout, stderr = ssh_client.exec_command(f'webui_ip={ip};'
                                                            'ip a | grep -B1 "$webui_ip" | grep -Eo "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})" | grep -Ev "(ff:){5}ff"')
            proxmox_mac = stdout.read().decode('ascii').strip("\n")
            proxmox_ips_mac[ip] = proxmox_mac
        return discovery.append_ips_mac_to_list()

    @staticmethod
    def append_ips_mac_to_list():
        amount_found = 0
        for ip, mac in proxmox_ips_mac.items():
            ip_mac_database[ip] = mac
            amount_found += 1
        return dump_database_to_file(), GUI.generic_info_popup(f'Discovered {amount_found} Proxmoxes')


# Below.: class for handling management via Redfish to Fujitsu iRMC BMC
class redfish_handler:
    global data_type
    data_type = 'Content-type: application/json'

    global get_path
    get_path = 'redfish/v1/Systems/0'

    global power_path
    power_path = get_path + '/Actions/Oem/FTSComputerSystem.Reset'

    global poweroff_data
    poweroff_data = '{"FTSResetType":"PowerOff"}'

    def get_power_state(irmc_ip, user, passwd):
        cmd = os.popen(
            f"curl -s -k -u {user}:{passwd} -H '{data_type}' -X GET https://{irmc_ip}/{get_path}/ | grep -E 'PowerState.*'").read()
        cmd = cmd.strip(',\n')
        if "Off" in cmd:
            print(f"SERVER .: {irmc_ip} :. IF OFF")
            GUI.generic_info_popup(f'SERVER.: {irmc_ip} :. is OFF')
        elif "On" in cmd:
            print(f"SERVER .: {irmc_ip} :. IS ON")
            GUI.generic_info_popup(f'SERVER.: {irmc_ip} :. is already ON')

    def poweron(irmc_ip, user, passwd):
        head = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        payload = {'FTSResetType': 'PowerOn'}
        url = f'https://{irmc_ip}/{power_path}'

        try:
            msg = requests.post(url, headers=head, auth=(user, passwd), data=json.dumps(payload), verify=False)
            print(f'CODE.: {msg.status_code} :.')

            if msg.status_code == 204:
                GUI.generic_info_popup(f"Redfish API wakeup SUCCESS!")
            elif msg.status_code == 202 or msg.status_code == 200:
                GUI.generic_info_popup(f"Redfish API wakeup SUCCESS!")
            elif msg.status_code == 400:
                GUI.generic_info_popup(f"SERVER .: {irmc_ip} :. is already RUNNING")
            else:
                GUI.generic_info_popup(f'ERROR => CODE.: {msg.status_code} :.')
        except:
            return GUI.generic_info_popup(f"Redfish API wakeup failed, response .: {msg.status_code} :.")

    def poweroff(irmc_ip, user, passwd):
        print(f"To be implemented soon")


# ###
# FRONTEND
# ###

# Below.: simple colors for app
red = [1, 0, 0, 1]
green = [0, 1, 0, 1]
blue = [0, 0, 1, 1]
purple = [1, 0, 1, 1]
gray = [0.5, 0.5, 0.5, 1]
yellow = [1, 1, 0, 1]


# Below.: main functions for frontend
class GUI(App):
    check_ref = {}

    # Below.: event saving data to the database upon clicking the 'Save DB' button
    def dump_data(self, event):
        return dump_database_to_file()

    def database_manager(self, *event):
        container = FloatLayout()
        vertical_position = 0.8  # starting vertical position of the widgets

        self.header_ip = Label(text="<IP value>", font_size=35,
                               pos_hint={'center_x': 0.15, 'center_y': vertical_position + 0.1}, color=green)
        container.add_widget(self.header_ip)

        self.header_mac = Label(text="<MAC value>", font_size=35,
                                pos_hint={'center_x': 0.5, 'center_y': vertical_position + 0.1}, color=green)
        container.add_widget(self.header_mac)

        self.header_about_to_remove = Label(text="Remove entry?", font_size=35,
                                            pos_hint={'center_x': 0.85, 'center_y': vertical_position + 0.1}, color=red)
        container.add_widget(self.header_about_to_remove)

        for each_key in ip_mac_database.keys():  # Iterating through each entry in the database
            self.ip_entry = Label(text=each_key, pos_hint={'center_x': 0.15, 'center_y': vertical_position},
                                  font_size=30)
            container.add_widget(self.ip_entry)

            self.mac_entry = Label(text=ip_mac_database[each_key],
                                   pos_hint={'center_x': 0.5, 'center_y': vertical_position}, font_size=30)
            container.add_widget(self.mac_entry)

            self.about_to_remove_checkbox = CheckBox(pos_hint={'center_x': 0.85, 'center_y': vertical_position},
                                                     size_hint=(0.1, 0.1))
            container.add_widget(self.about_to_remove_checkbox)

            self.check_ref[
                str(vertical_position)] = self.about_to_remove_checkbox, self.ip_entry, self.mac_entry  # A handy dictonary for referencing the checkboxes and labels (IPs and MACs)

            vertical_position -= 0.125  # This determines the spacing between the labels

        self.add_ip = TextInput(hint_text="<IP addr>", multiline=False, size_hint=(0.3, 0.05),
                                pos_hint={'center_x': 0.15, 'center_y': vertical_position}, halign='center')
        container.add_widget(self.add_ip)

        self.add_mac = TextInput(hint_text="<MAC addr>", multiline=False, size_hint=(0.3, 0.05),
                                 pos_hint={'center_x': 0.5, 'center_y': vertical_position}, halign='center')
        container.add_widget(self.add_mac)

        self.add_irmc_ip = TextInput(hint_text="<iRMC IP addr>", multiline=False, size_hint=(0.3, 0.05),
                                     pos_hint={'center_x': 0.85, 'center_y': vertical_position}, halign='center')
        container.add_widget(self.add_irmc_ip)

        self.save = Button(text="Save changes", font_size=35,
                           pos_hint={'center_x': 0.5, 'center_y': vertical_position - 0.15}, size_hint=(0.35, 0.125),
                           background_color=green)
        self.save.bind(on_release=self.getcheckboxes_active)
        container.add_widget(self.save)

        popup = Popup(title='Manage database', content=container, size_hint=(0.8, 0.8))
        popup.open()

    def getcheckboxes_active(self, *arg):  # This function is called when the 'Save changes' button is clicked
        for idx, wgt in self.check_ref.items():
            if wgt[0].active:
                ip_to_remove = wgt[1].text
                ip_mac_database.pop(ip_to_remove)
                try:
                    print(f"DICT before .: {irmc_ips}")
                    print(f"TO REMOVE .: {irmc_ips[ip_to_remove]} by a key val .: {ip_to_remove}")
                    to_be_removed = irmc_ips[ip_to_remove]
                    irmc_ips.pop(ip_to_remove)
                    GUI.generic_info_popup(f"Associated iRMC IP .: {to_be_removed} :. removed")
                    # print(f"DICT after .: {irmc_ips}")
                except:
                    GUI.generic_info_popup(
                        f"There was no associated iRMC IP to be removed,\nremoving only Proxmox IP .: {ip_to_remove} :.")
        if self.add_ip.text != "" and self.add_mac.text != "":  # Do not add an entry if the IP and/or MAC are not changed
            ip_mac_database[self.add_ip.text] = self.add_mac.text
            GUI.generic_info_popup(f"Adding IP+MAC pair")
        if self.add_irmc_ip.text != "" and self.add_ip.text in ip_mac_database.keys():
            irmc_ips[self.add_ip.text] = self.add_irmc_ip.text
            GUI.generic_info_popup(f"Adding iRMC address")

    def add_new_credentials(self, event):
        container = FloatLayout()
        self.username = TextInput(hint_text='<Username>', multiline=False, size_hint=(.75, 0.125),
                                  pos_hint={'center_x': .5, 'center_y': .85},
                                  halign='center', font_size=30)
        container.add_widget(Label(text='Enter <Username>.:', font_size='25sp', size_hint=(1, 0.2),
                                   pos_hint={'center_x': .5, 'center_y': .95}))
        container.add_widget(self.username)

        self.password = TextInput(hint_text='<Password>', multiline=False, size_hint=(.75, 0.125),
                                  pos_hint={'center_x': .5, 'center_y': .55},
                                  halign='center', font_size=30, password=True)
        container.add_widget(Label(text='Enter <Password>.:', font_size='25sp', size_hint=(1, 0.2),
                                   pos_hint={'center_x': .5, 'center_y': .65}))
        container.add_widget(self.password)

        popup = Popup(title='Add new <Username> : <Password>',
                      content=container,
                      size_hint=(0.8, 0.8))

        execute = Button(text='Save', background_color=green, size_hint=(0.8, 0.15),
                         pos_hint={'center_x': .5, 'center_y': .15}, halign='center')
        execute.bind(on_press=self.append_to_credentials_on_tap, on_release=popup.dismiss)
        container.add_widget(execute)

        popup.open()

    def input_subnet_and_port(self, event):
        container = FloatLayout()

        self.ip_start = TextInput(hint_text='<IP start>', multiline=False, size_hint=(.75, 0.125),
                                  pos_hint={'center_x': .5, 'center_y': .85},
                                  halign='center', font_size=30)
        container.add_widget(Label(text='Enter <IP start>.:', font_size='25sp', size_hint=(1, 0.2),
                                   pos_hint={'center_x': .5, 'center_y': .95}))
        container.add_widget(self.ip_start)

        self.ip_end = TextInput(hint_text='<IPs to scan?>', multiline=False, size_hint=(.75, 0.125),
                                pos_hint={'center_x': .5, 'center_y': .65},
                                halign='center', font_size=30)
        container.add_widget(Label(text='How many IPs.:', font_size='25sp', size_hint=(1, 0.2),
                                   pos_hint={'center_x': .5, 'center_y': .75}))
        container.add_widget(self.ip_end)

        self.port = TextInput(hint_text='<Port>', multiline=False, size_hint=(.75, 0.125),
                              pos_hint={'center_x': .5, 'center_y': .45},
                              halign='center', font_size=30)
        container.add_widget(Label(text='Enter <Port>.:', font_size='25sp', size_hint=(1, 0.2),
                                   pos_hint={'center_x': .5, 'center_y': .55}))
        container.add_widget(self.port)

        popup = Popup(title='Add new <Subnet> : <Port>',
                      content=container,
                      size_hint=(0.8, 0.8))

        execute = Button(text='Save', background_color=green, size_hint=(0.8, 0.15),
                         pos_hint={'center_x': .5, 'center_y': .15}, halign='center')
        execute.bind(on_press=self.append_to_subnet_and_port_on_tap, on_release=popup.dismiss)
        container.add_widget(execute)

        popup.open()

    def append_to_subnet_and_port_on_tap(self, *arg):
        subnet_and_port_database = {}
        ip_range = (self.ip_start.text, self.ip_end.text)
        if int(self.ip_end.text) > 255:
            GUI.generic_info_popup('<IPs to scan?>\nmust be less than 255')
            return
        subnet_and_port_database[ip_range] = self.port.text
        discovery.convert_CIDR(subnet_and_port_database)

    def append_to_credentials_on_tap(self, event):
        ssh_credentials[self.username.text] = self.password.text

    def append_to_database_on_tap(self, event):
        ip_mac_database[self.ip.text] = self.mac.text

    def shutdown_on_tap(self, event):
        ssh_handler.shutdown_proxmox_via_ssh(self.spinner.text)
        ssh_handler.close_ssh_connection()

    def send_wol_on_tap(self, event):
        udp_socket.send_magic_packet(translate_ip_to_mac(self.spinner.text))

    def change_color_on_status_check(self, event):
        colors = [red, green, blue, purple, yellow, gray]
        if udp_socket.ping_selected_ip(str(self.spinner.text)) == True:
            self.spinner.background_color = colors[1]
        else:
            self.spinner.background_color = colors[0]

    @staticmethod
    def info_popup_wrong_ip():
        info_popup_wrong_ip = Popup(title='Wrong IP', content=Label(text='Please enter a valid IP address!'),
                                    size_hint=(None, None), size=(300, 200))
        info_popup_wrong_ip.open()

    def generic_info_popup(reason):
        # for ~30 chars in line; width should be 0.65
        # single line should have 0.25 height
        n_characters = int(len(str(reason)))
        n_lines = int(n_characters // 30)

        if n_characters % 30 > 0:
            n_lines += 1

        y_dimension = int(0.25)
        y_dimension += n_lines * 0.25

        info_popup = Popup(title='Info', content=Label(text=reason), size_hint=(0.65, y_dimension))
        info_popup.open()

    def poweron_redfish(self, event):
        try:
            irmc_ip_addr = str(irmc_ips[self.spinner.text])
            redfish_handler.poweron(irmc_ip=irmc_ip_addr, user='admin', passwd='admin')
        except KeyError:
            return GUI.generic_info_popup("No iRMC IP for selected server, check your selection")

    def poweroff_redfish(self, event):
        redfish_handler.poweroff(irmc_ip='', user='admin', passwd='admin')

    # Below.: packing the frontend up
    def build(self):
        layout = FloatLayout(size=(100, 100))
        colors = [red, green, blue, purple, yellow, gray]
        self.spinner = Spinner(text='Pick item', values=(ip_mac_database.keys()), background_color=colors[2],
                               size_hint=(0.8, 0.2), pos_hint={'x': 0.1, 'y': 0.75})

        btn_wol = Button(text='Send WOL', size_hint=(0.35, 0.2), background_color=colors[1],
                         pos_hint={'x': 0.05, 'y': 0.1})
        # btn_shutdown = Button(text='Shutdown',size_hint=(0.35,0.2),background_color=colors[0],pos_hint={'x':0.6,'y':0.1})
        btn_shutdown = Button(text='Shutdown', size_hint=(0.35, 0.4), background_color=colors[0],
                              pos_hint={'x': 0.6, 'y': 0.1})
        btn_dump = Button(text='Save DB', size_hint=(0.25, 0.1), background_color=colors[3],
                          pos_hint={'x': 0.05, 'y': 0.6})
        btn_new_entry = Button(text='Add IP-MAC', size_hint=(0.25, 0.1), background_color=colors[3],
                               pos_hint={'x': 0.7, 'y': 0.6})
        btn_proxmox_credentials = Button(text='     Enter\nCredentials', size_hint=(0.25, 0.1),
                                         background_color=colors[3], pos_hint={'x': 0.375, 'y': 0.6})
        btn_check_status = Button(text='Server Status', size_hint=(0.375, 0.075), background_color=colors[5],
                                  pos_hint={'x': 0.05, 'y': 0.5125})
        btn_discover_proxmoxes = Button(text='Discover Proxmoxes', size_hint=(0.375, 0.075), background_color=colors[4],
                                        pos_hint={'x': 0.575, 'y': 0.5125})
        btn_poweron_redfish = Button(text='Power-up via redfish', size_hint=(0.35, 0.2), background_color=colors[1],
                                     pos_hint={'x': 0.05, 'y': 0.3})
        # btn_poweroff_redfish = Button(text='OFF via redfish', size_hint=(0.35,0.2), background_color=colors[5], pos_hint={'x':0.6, 'y':0.3})

        btn_shutdown.bind(on_release=self.shutdown_on_tap)
        btn_wol.bind(on_release=self.send_wol_on_tap)
        btn_dump.bind(on_release=self.dump_data)
        btn_new_entry.bind(on_release=self.database_manager)  # <= REPLACED!!
        btn_proxmox_credentials.bind(on_release=self.add_new_credentials)
        btn_check_status.bind(on_release=self.change_color_on_status_check)
        btn_discover_proxmoxes.bind(on_release=self.input_subnet_and_port)
        btn_poweron_redfish.bind(on_release=self.poweron_redfish)
        # btn_poweroff_redfish.bind(on_release = self.poweroff_redfish)

        layout.add_widget(self.spinner)
        layout.add_widget(btn_wol)
        layout.add_widget(btn_shutdown)
        layout.add_widget(btn_dump)
        layout.add_widget(btn_new_entry)
        layout.add_widget(btn_proxmox_credentials)
        layout.add_widget(btn_check_status)
        layout.add_widget(btn_discover_proxmoxes)
        layout.add_widget(btn_poweron_redfish)
        # layout.add_widget(btn_poweroff_redfish)

        return layout


if __name__ == "__main__":
    database_loader()
    app = GUI()
    app.run()