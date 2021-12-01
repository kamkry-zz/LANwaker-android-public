from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.spinner import Spinner

from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
# ###

import socket
import paramiko as pr

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
     request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE, Permission.ACCESS_NETWORK_STATE, Permission.ACCESS_WIFI_STATE, Permission.INTERNET])

# Below.: is the BROADCAST address for your network; change accordingly
udp_ip = '192.168.0.255'
udp_port = 9

# Below.: Simple conversion of MAC for further use within app; trimming of ':'
def prepare_mac(raw_mac):
    mac = raw_mac.replace(":", "")
    mac = mac.lower()
    mac = bytearray.fromhex(mac)
    return mac

# Below.: by passing IP address, the function returns the MAC address of the device
def translate_ip_to_mac(ip):
    return ip_mac_database.get(ip)

# Below.: reach for the database file and load it as a dictionary; create a new one if not found
def database_loader():
    try:
        file = open("db.tx", 'r')

    except:
        file = open("db.tx", 'x')
        file.write('\n')
        file.close()
        file = open("db.tx", 'r')

    try:
        file_credentials = open("db_creds.tx", 'r')

    except:
        file_credentials = open("db_creds.tx", 'x')
        file_credentials.write('\n')
        file_credentials.close()
        file_credentials = open("db_creds.tx", 'r')

    data = file.readlines()[-1]     # reads the last line of the file; this entry holds the latest additions to the database
    data_credentials = file_credentials.readlines()[-1]

    global ssh_credentials
    global ip_mac_database

    if data == '\n':                # if the file is empty, create a new entry to it
        ip_mac_database = {}
        ip_mac_database['0.0.0.0'] = '00:00:00:00:00:00'        # Placeholder for IP - MAC mapping
    else:
        ip_mac_database = eval(data)        # if the file is not empty, load it as a dictionary
    file.close()

    if data_credentials == '\n':        # if the file is empty, create a new entry to it
        ssh_credentials = {}
    else:
        ssh_credentials = eval(data_credentials)        # if the file is not empty, load it as a dictionary
    file_credentials.close()
    return

# Below.: STRINGIFY the dictionaries and write them to the database files
def dump_database_to_file():
    file = open("db.tx", 'a')
    if "0.0.0.0" in ip_mac_database.keys():
        print(ip_mac_database["0.0.0.0"])
        del ip_mac_database["0.0.0.0"]
    pretreated_data = str(ip_mac_database)
    file.write('\n')
    file.write(pretreated_data)
    file.close()

    file_credentials = open("db_creds.tx", 'a')
    pretreated_data_credentials = str(ssh_credentials)
    file_credentials.write('\n')
    file_credentials.write(pretreated_data_credentials)
    file_credentials.close()
    return

# Below.: ssh_handler CLASS holds functions crucial for the SSH connection
class ssh_handler:

    def test_function(host_to_connect):
        ssh_client = pr.SSHClient()
        ssh_client.set_missing_host_key_policy(pr.AutoAddPolicy())
        usr, passwd = ssh_credentials_list[-1][0], ssh_credentials_list[-1][1]
        ssh_client.connect(host_to_connect, username=usr, password=passwd)
        stdin, stdout, stderr = ssh_client.exec_command('uname -a')
        return

    def shutdown_proxmox_via_ssh(selected_ip):
        if selected_ip == "0.0.0.0":
            return # !!! ADD ERROR HANDLING INFO-BOX HERE !!!
        ssh_client = pr.SSHClient()
        ssh_client.set_missing_host_key_policy(pr.AutoAddPolicy())
        ssh_credentials_list = list(ssh_credentials.items())
        usr, passwd = ssh_credentials_list[-1][0], ssh_credentials_list[-1][1]
        ssh_client.connect(selected_ip,username=usr,password=passwd)
        stdin, stdout, stderr = ssh_client.exec_command('net_dev=$(ip a | grep -Eo "en[a-z0-9]+");'     # get the network device name
                                                        ' ethtool -s $net_dev wol g;'       # set the WOL mode to magic packet
                                                        'qm list | grep "running" | awk `{print $1}` | xargs -n1 shutdown ;'     # shutdown all running VMs 
                                                        'shutdown -h now')      # shutdown the host
        return

    # Below.: terminate established SSH connection
    def close_ssh_connection():
        ssh_client = pr.SSHClient()
        ssh_client.close()

# Below.: udp_socket CLASS holds functions crucial for opening and closing UDP socket PLUS generating the UDP WOL packet
class udp_socket:

    def send_magic_packet(selected_mac):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(b"\xff"*6 + prepare_mac(selected_mac)*16, (udp_ip, udp_port))       # payload for the UDP WOL packet
        sock.close()

# ###
# FRONTEND
# ###

# Below.: simple colors for app
red = [1,0,0,1]
green = [0,1,0,1]
blue =  [0,0,1,1]
purple = [1,0,1,1]

# Below.: main function for frontend
class GUI(App):

    # Below.: event saving data to the database upon clicking the 'Save DB' button
    def dump_data(self, event):
        return dump_database_to_file()#database_creator())

    # Below.: this keeps on displaying the current IP address of the selected device in spinner widget
    def show_picked_item(self):
        return self.spinner.text

    # Below.: entire layout for adding a new entry to the database
    def add_new_entry(self, event):
        containter = BoxLayout(orientation='vertical')

        self.ip = TextInput(text='<IP>', multiline=False, size_hint=(.75, 0.25), pos_hint={'center_x': .5, 'center_y': .5}, halign='center')
        containter.add_widget(Label(text='Enter <IP> address.:', font_size='25sp', size_hint=(1, None)))
        containter.add_widget(self.ip)

        containter.add_widget(Label(text='Enter <MAC> address.:', font_size='25sp', size_hint=(1, None)))
        self.mac = TextInput(text='<MAC>', multiline=False, size_hint=(.75, 0.25), pos_hint={'center_x': .5, 'center_y': .35}, halign='center')
        containter.add_widget(self.mac)

        execute = Button(text='Save', background_color=green, size_hint=(0.8, 0.25), pos_hint={'center_x': .5, 'center_y': .15}, halign='center')
        execute.bind(on_release= self.append_to_database_on_tap)
        containter.add_widget(execute)

        popup = Popup(title='Add new <IP> : <MAC>',
                      content=containter,
                      size_hint=(None, None), size=(900, 1600))
        popup.open()
        return

    def add_new_credentials(self, event):
        container = BoxLayout(orientation='vertical')

        self.username = TextInput(text='<Username>', multiline=False, size_hint=(.75, 0.25), pos_hint={'center_x': .5, 'center_y': .5}, halign='center')
        container.add_widget(Label(text='Enter <Username>.:', font_size='25sp', size_hint=(1, None)))
        container.add_widget(self.username)

        self.password = TextInput(text='<Password>', multiline=False, size_hint=(.75, 0.25), pos_hint={'center_x': .5, 'center_y': .35}, halign='center')
        container.add_widget(Label(text='Enter <Password>.:', font_size='25sp', size_hint=(1, None)))
        container.add_widget(self.password)

        execute = Button(text='Save', background_color=green, size_hint=(0.8, 0.25), pos_hint={'center_x': .5, 'center_y': .15}, halign='center')
        execute.bind(on_release= self.append_to_credentials_on_tap)
        container.add_widget(execute)

        popup = Popup(title='Add new <Username> : <Password>',
                      content=container,
                      size_hint=(None, None), size=(900, 1600))
        popup.open()
        return

    def append_to_credentials_on_tap(self, event):
        ssh_credentials[self.username.text] = self.password.text
        return

    def append_to_database_on_tap(self, event):
        ip_mac_database[self.ip.text] = self.mac.text
        return

    def shutdown_on_tap(self, event):
        ssh_handler.shutdown_proxmox_via_ssh(self.spinner.text)
        ssh_handler.close_ssh_connection()

    def send_wol_on_tap(self, event):
        udp_socket.send_magic_packet(translate_ip_to_mac(self.spinner.text))

    # Below.: packing the frontend up
    def build(self):
        layout = FloatLayout(size=(100, 100))
        colors = [red, green, blue, purple]
        self.spinner = Spinner(text='Pick item', values=(ip_mac_database.keys()),background_color=colors[2], size_hint=(0.8, 0.2), pos_hint={'x': 0.1, 'y': 0.75})

        btn_wol = Button(text='Send WOL',size_hint=(0.35,0.4),background_color=colors[1],pos_hint={'x':0.05,'y':0.1})
        btn_shutdown = Button(text='Shutdown',size_hint=(0.35,0.4),background_color=colors[0],pos_hint={'x':0.6,'y':0.1})
        btn_dump = Button(text='Save DB',size_hint=(0.25,0.1),background_color=colors[3],pos_hint={'x':0.05,'y':0.6})
        btn_new_entry = Button(text='Add IP-MAC',size_hint=(0.25,0.1),background_color=colors[3],pos_hint={'x':0.7,'y':0.6})
        btn_ProxmoX_credentials = Button(text='     Enter\nCredentials',size_hint=(0.25,0.1),background_color=colors[3],pos_hint={'x':0.375,'y':0.6})

        btn_shutdown.bind(on_release = self.shutdown_on_tap)
        btn_wol.bind(on_release = self.send_wol_on_tap)
        btn_dump.bind(on_release = self.dump_data)
        btn_new_entry.bind(on_release = self.add_new_entry)
        btn_ProxmoX_credentials.bind(on_release = self.add_new_credentials)

        layout.add_widget(self.spinner)
        layout.add_widget(btn_wol)
        layout.add_widget(btn_shutdown)
        layout.add_widget(btn_dump)
        layout.add_widget(btn_new_entry)
        layout.add_widget(btn_ProxmoX_credentials)

        return layout

if __name__ == "__main__":
    database_loader()
    app = GUI()
    app.run()