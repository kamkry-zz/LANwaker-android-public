import unittest
import xmlrunner

from main import *
from main import database_loader

class all_test_suite(unittest.TestCase):
    #def test_android_permission(self):
        #from main import platform
        #self.assertRaises(AttributeError, platform.request_permissions("android.permission.INTERNET"))

    def test_udp_ip(self):
        self.assertEqual(udp_ip, '255.255.255.255')
        self.assertEqual(udp_port, 9)

    def test_db_files(self):
        self.assertEqual(database_file, 'db.tx')
        self.assertEqual(credentials_file, 'db_creds.tx')

    def test_prepare_mac(self):
        self.assertEqual(prepare_mac("00:00:00:00:00:00"), bytearray(b'\x00\x00\x00\x00\x00\x00'))

    def test_translate_ip_to_mac(self):
        self.assertIsNone(translate_ip_to_mac("something"))

    def test_database_loader(self):
        self.assertIsNone(database_loader())

    def test_database_loader_exception_no_SSH(self):
        self.assertRaises(Exception, database_loader())

    def test_dump_database_to_file(self):
        self.assertIsNone(dump_database_to_file())

    #####################################################################################

    def test_ssh_handler_shutdown_proxmox_via_ssh(self):
        self.assertIsNone(ssh_handler.shutdown_proxmox_via_ssh("0.0.0.0"))
        self.assertIsNone(ssh_handler.shutdown_proxmox_via_ssh("999.999.999.999"))
        self.assertRaises(Exception, ssh_handler.shutdown_proxmox_via_ssh("999.999.999.999"))

    def test_ssh_handler_close_ssh_connection(self):
        self.assertIsNone(ssh_handler.close_ssh_connection())

    #def test_ssh_handler_test_function(self):
        #self.assertRaises(IndexError, ssh_handler.test_function("192.168.0.3"))

    #####################################################################################

    def test_udp_socket_ping_selected_ip(self):
        self.assertFalse(udp_socket.ping_selected_ip("Pick item"))

    def test_udp_socket_send_magic_packet(self):
        self.assertNotEqual(udp_socket.send_magic_packet("Pick item"), "Magic packet sent")

    #####################################################################################

    def test_discovery_convert_CIDR(self):
        self.assertIsNone(discovery.convert_CIDR({'999.999.999.999': '999'}))
        self.assertIsNone(discovery.convert_CIDR({'999.999.999.999.999': '999'}))

    def test_discovery_scan_network(self):
        self.assertIsNone(discovery.scan_network(start_ip="999.999.999.999", end_ip="999.999.999.999", subnetwork_port="999"))

    def test_discovery_verify_if_proxmox(self):
        self.assertIsNotNone(discovery.verify_if_proxmox(proxmox_ips=[]))

    def test_discovery_retrive_proxmox_mac(self):
        self.assertRaises(Exception, discovery.retrive_proxmox_mac("999.999.999.999"))

    def test_discovery_append_ips_mac_to_list(self):
        self.assertIsNotNone(discovery.append_ips_mac_to_list())

    #####################################################################################

    def test_redfish_handler_get_power_state(self):
        self.assertIsNone(redfish_handler.get_power_state(irmc_ip="999.999.999.999", user="admin", passwd="admin"))

    #####################################################################################

    #def test_GUI_dump_data(self):
        #self.assertRaises(NameError, GUI.dump_data(self="foo", event="bar"))

    def test_GUI(self):
        self.assertIsNotNone(GUI())

def run_test_suite_generate_xml_report(test_class_name):
    test_suite = unittest.TestSuite()
    test = unittest.makeSuite(test_class_name)
    test_suite.addTest(test)
    test_runner = xmlrunner.XMLTestRunner(output='test-reports')
    test_runner.run(test_suite)

run_test_suite_generate_xml_report(all_test_suite)
