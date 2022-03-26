import unittest
import xmlrunner

from main import *
from main import database_loader

class all_test_suite(unittest.TestCase):
    def test_udp_ip(self):
        self.assertEqual(udp_ip, '255.255.255.255')
        self.assertEqual(udp_port, 9)

    def test_db_files(self):
        self.assertEqual(database_file, 'db.tx')
        self.assertEqual(credentials_file, 'db_creds.tx')

    def test_prepare_mac(self):
        self.assertEqual(prepare_mac("00:00:00:00:00:00"), bytearray(b'\x00\x00\x00\x00\x00\x00'))

    #def test_translate_ip_to_mac(self):
        #self.assertIsNone(translate_ip_to_mac("something"))

    def test_database_loader(self):
        self.assertIsNone(database_loader())

    def test_dump_database_to_file(self):
        self.assertIsNone(dump_database_to_file())

    def test_ssh_handler_shutdown_proxmox_via_ssh(self):
        self.assertIsNone(ssh_handler.shutdown_proxmox_via_ssh("0.0.0.0"))
        self.assertIsNone(ssh_handler.shutdown_proxmox_via_ssh("999.999.999.999"))

    def test_ssh_handler_close_ssh_connection(self):
        self.assertIsNone(ssh_handler.close_ssh_connection())

    def test_udp_socket_ping_selected_ip(self):
        self.assertFalse(udp_socket.ping_selected_ip("Pick item"))

    def test_udp_socket_send_magic_packet(self):
        self.assertNotEqual(udp_socket.send_magic_packet("Pick item"), "Magic packet sent")

def run_test_suite_generate_xml_report(test_class_name):
    test_suite = unittest.TestSuite()
    test = unittest.makeSuite(test_class_name)
    test_suite.addTest(test)
    test_runner = xmlrunner.XMLTestRunner(output='test-reports')
    test_runner.run(test_suite)

run_test_suite_generate_xml_report(all_test_suite)